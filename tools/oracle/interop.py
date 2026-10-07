#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
#
# Copyright (C) 2026 Corey Pennycuff
#
# This file is part of Ghoti.io TLS.
#
# Ghoti.io TLS is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License version 3 as
# published by the Free Software Foundation.
"""Interop: this library against OpenSSL, in both roles, over loopback sockets.

    interop.py [--echo PATH] [--only SUBSTRING] [--list] [--plant NAME]

OpenSSL is not linked. It runs in a container (podman by default, or
$GHOTI_CONTAINER_ENGINE) from the image the `certificate` oracle builds
(localhost/ghoti-certificate-oracle-openssl:3.5.7, `make oracle-build` in
libs/certificate), on the host network, with `s_server` against this
library's client and `s_client` against its server. The program on this
side is examples/echo.c, so every case is a real handshake, a line of
application data echoed back, and a close_notify, on credentials from
tests/data/pki.

A population, not a sample: one case per suite, group, signature scheme,
ALPN selection, HelloRetryRequest, key update and compatibility setting, in
each direction, and a set of cases that must be refused (an old version, no
common scheme, a name that does not match, no ALPN overlap). A refusal is
counted in the denominator with the reason it was given. Differences
between the two stacks that are not defects are declared in DIFFERENCES: a
disagreement that is not declared fails the run, and a declared one that no
longer happens fails it too.

  --plant NAME   build a scratch copy with a defect planted (see PLANTS),
                 and require the cases it must break to fail while the
                 unplanted build passes them. A gate that has never been
                 seen to fail may be measuring nothing.
"""

import argparse
import base64
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
PKI = os.path.join(ROOT, "tests", "data", "pki")
DIFFERENCES = os.path.join(HERE, "DIFFERENCES")

ENGINE = os.environ.get("GHOTI_CONTAINER_ENGINE", "podman")
IMAGE = os.environ.get("GHOTI_TLS_ORACLE_IMAGE",
                       "localhost/ghoti-certificate-oracle-openssl:3.5.7")
PIN = "OpenSSL 3.5.7"
CASE_TIMEOUT = 40

KINDS = {
    "ed": "ed.example.com",
    "p256": "www.example.com",
    "p384": "p384.example.com",
    "rsa": "rsa.example.com",
}
SUITES = {  # ours -> (OpenSSL name, wire code)
    "aes128": ("TLS_AES_128_GCM_SHA256", "1301"),
    "aes256": ("TLS_AES_256_GCM_SHA384", "1302"),
    "chacha": ("TLS_CHACHA20_POLY1305_SHA256", "1303"),
}
GROUPS = {
    "x25519": ("X25519", "001d", ("X25519",)),
    "p256": ("P-256", "0017", ("prime256v1", "secp256r1", "P-256")),
    "p384": ("P-384", "0018", ("secp384r1", "P-384")),
}
SCHEMES = {  # ours -> (OpenSSL name, key kind)
    "pss256": ("rsa_pss_rsae_sha256", "rsa"),
    "pss384": ("rsa_pss_rsae_sha384", "rsa"),
    "pss512": ("rsa_pss_rsae_sha512", "rsa"),
    "p256": ("ecdsa_secp256r1_sha256", "p256"),
    "p384": ("ecdsa_secp384r1_sha384", "p384"),
    "ed25519": ("ed25519", "ed"),
}


class Case:
    def __init__(self, role, name, kind="ed", suite=None, group=None, groups=None,
                 scheme=None, alpn_ours=(), alpn_theirs=(), expect_alpn="",
                 retried=0, key_update=False, compat=False, tls12=False,
                 server_name=None, expect="ok", refusal=None, declared=None,
                 no_anchor=False, theirs_sigalgs=None, ours_sigalgs=None):
        self.role = role              # "client": our client, their s_server; "server": the reverse
        self.name = "%s/%s" % (role, name)
        self.kind = kind
        self.suite = suite
        self.group = group
        self.groups = groups          # what our side offers or accepts
        self.scheme = scheme
        self.alpn_ours = list(alpn_ours)
        self.alpn_theirs = list(alpn_theirs)
        self.expect_alpn = expect_alpn
        self.retried = retried
        self.key_update = key_update
        self.compat = compat
        self.tls12 = tls12
        self.server_name = server_name or KINDS[kind]
        self.expect = expect          # "ok" or "refuse"
        self.refusal = refusal        # a regex the refusal must match
        self.declared = declared      # why this case differs from the RFC's answer, if it does
        self.no_anchor = no_anchor
        self.theirs_sigalgs = theirs_sigalgs
        self.ours_sigalgs = ours_sigalgs


def population():
    cases = []
    for role in ("client", "server"):
        for kind in KINDS:
            cases.append(Case(role, "default-%s" % kind, kind=kind))
        for s in SUITES:
            cases.append(Case(role, "suite-%s" % s, suite=s))
        for g in GROUPS:
            cases.append(Case(role, "group-%s" % g, group=g))
        for s, (_, kind) in SCHEMES.items():
            cases.append(Case(role, "scheme-%s" % s, kind=kind, scheme=s))
        for g in ("p256", "p384"):
            cases.append(Case(role, "retry-%s" % g, group=g, groups=["x25519", g], retried=1))
        cases.append(Case(role, "retry-aes256", group="p256", groups=["x25519", "p256"],
                          suite="aes256", retried=1))
        cases.append(Case(role, "alpn-h2", alpn_ours=["h2", "http/1.1"], alpn_theirs=["h2", "http/1.1"],
                          expect_alpn="h2"))
        cases.append(Case(role, "alpn-second", alpn_ours=["http/1.1"], alpn_theirs=["h2", "http/1.1"],
                          expect_alpn="http/1.1"))
        if role == "client":   # OpenSSL's server list wins over ours
            cases.append(Case(role, "alpn-server-order", alpn_ours=["http/1.1", "h2"],
                              alpn_theirs=["h2", "http/1.1"], expect_alpn="h2"))
        else:                  # and this library's server list wins over OpenSSL's client's
            cases.append(Case(role, "alpn-server-order", alpn_ours=["h2", "http/1.1"],
                              alpn_theirs=["http/1.1", "h2"], expect_alpn="h2"))
        cases.append(Case(role, "alpn-silent-client" if role == "server" else "alpn-silent-server",
                          alpn_ours=[] if role == "server" else ["h2"],
                          alpn_theirs=["h2"] if role == "server" else [],
                          expect_alpn=""))
        cases.append(Case(role, "key-update", key_update=True))
        cases.append(Case(role, "compat", compat=True))
        cases.append(Case(role, "everything-chacha-p384-retry", kind="p384", suite="chacha",
                          group="p384", groups=["x25519", "p384"], retried=1, scheme="p384",
                          alpn_ours=["h2"], alpn_theirs=["h2"], expect_alpn="h2", key_update=True))
        # The refusals.
        cases.append(Case(role, "refuse-tls12-only", tls12=True, expect="refuse",
                          refusal=r"(protocol_version|alert=70|peer_alert=70|Unsupported|"
                                  r"alert number 70|protocol version)"))
        cases.append(Case(role, "refuse-no-common-scheme",
                          theirs_sigalgs="rsa_pss_rsae_sha256", ours_sigalgs="ed25519",
                          kind="ed", expect="refuse",
                          refusal=r"(handshake_failure|alert=40|peer_alert=40|alert number 40|"
                                  r"No common|no suitable signature)"))
    cases.append(Case("client", "refuse-wrong-name", server_name="other.example.com", expect="refuse",
                      refusal=r"(does not name|bad_certificate|alert=42|Certificate does not name)"))
    cases.append(Case("client", "refuse-unknown-anchor", no_anchor=True, expect="refuse",
                      refusal=r"(No path to a trust anchor|alert=48|unknown_ca)"))
    cases.append(Case("server", "refuse-alpn-no-overlap", alpn_ours=["h2"], alpn_theirs=["spdy/3"],
                      expect="refuse", refusal=r"(no_application_protocol|alert=120|peer_alert=120|"
                                               r"alert number 120|No application protocol)"))
    cases.append(Case("client", "refuse-alpn-no-overlap", alpn_ours=["h2"], alpn_theirs=["spdy/3"],
                      expect="refuse", refusal=r"(no_application_protocol|alert=0 peer_alert=120|peer_alert=120|"
                                               r"No application protocol)"))
    return cases


# ----------------------------------------------------------------------------- environment

def engine_ok():
    if shutil.which(ENGINE) is None:
        return "no container engine (%s)" % ENGINE
    r = subprocess.run([ENGINE, "run", "--rm", IMAGE, "openssl-version"], capture_output=True, text=True)
    if r.returncode != 0 or r.stdout.strip() != PIN:
        return ("the reference did not report %r: rc %d, stdout %r, stderr %r. Build the image with `make "
                "oracle-build` in libs/certificate." % (PIN, r.returncode, r.stdout.strip(), r.stderr.strip()[:200]))
    return None


def der_to_pem(path, label, out):
    with open(path, "rb") as f:
        der = f.read()
    b64 = base64.encodebytes(der).decode("ascii")
    with open(out, "w") as f:
        f.write("-----BEGIN %s-----\n%s-----END %s-----\n" % (label, b64, label))


def make_pems(directory):
    for kind in KINDS:
        der_to_pem(os.path.join(PKI, kind + "-leaf.der"), "CERTIFICATE", os.path.join(directory, kind + "-leaf.pem"))
        der_to_pem(os.path.join(PKI, kind + "-ca.der"), "CERTIFICATE", os.path.join(directory, kind + "-ca.pem"))
        der_to_pem(os.path.join(PKI, kind + "-leaf.pkcs8"), "PRIVATE KEY", os.path.join(directory, kind + "-key.pem"))


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_listening(port, proc, seconds=25):
    """True once something listens on the port. Asked by trying to bind it:
    a connection would be taken for the one the server is waiting for."""
    end = time.time() + seconds
    while time.time() < end:
        if proc.poll() is not None:
            return False
        probe = socket.socket()
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return True
        finally:
            probe.close()
        time.sleep(0.1)
    return False


_counter = [0]


def container_name():
    _counter[0] += 1
    return "gtls-interop-%d-%d" % (os.getpid(), _counter[0])


def echo_args(case, echo_role, port):
    """The command line of examples/echo for this case."""
    a = []
    if case.suite:
        a += ["--suites", case.suite]
    if echo_role == "client":
        groups = case.groups or ([case.group] if case.group else None)
    else:
        groups = [case.group] if case.group and not case.groups else \
            ([case.groups[-1]] if case.groups and case.retried else (case.groups or None))
    if groups:
        a += ["--groups", ",".join(groups)]
    sig = case.ours_sigalgs or case.scheme
    if sig:
        a += ["--sigalgs", sig]
    for p in case.alpn_ours:
        a += ["--alpn", p]
    if case.compat:
        a += ["--compat"]
    return a


# --------------------------------------------------------------------------------- the cases

class Outcome:
    def __init__(self, ok, detail, ours="", theirs=""):
        self.ok = ok
        self.detail = detail
        self.ours = ours
        self.theirs = theirs


def parse_ours(text):
    m = re.search(r"ok suite=([0-9a-f]{4}) group=([0-9a-f]{4}) alpn=(\S*) retried=(\d)", text)
    if not m:
        return None
    return {"suite": m.group(1), "group": m.group(2), "alpn": m.group(3), "retried": int(m.group(4))}


def group_matches(theirs_text, group):
    names = GROUPS[group][2]
    return any(n in theirs_text for n in names)


def check_negotiated(case, ours, theirs_text, errors):
    """What the two stacks say they negotiated must agree with each other and with the case."""
    if ours is None:
        errors.append("our side printed no result line")
        return
    if case.suite:
        want = SUITES[case.suite]
        if ours["suite"] != want[1]:
            errors.append("suite %s, wanted %s" % (ours["suite"], want[1]))
        if want[0] not in theirs_text:
            errors.append("OpenSSL did not report %s" % want[0])
    else:
        # Whatever was chosen, the other stack names the same one.
        for name, (ossl, code) in SUITES.items():
            if ours["suite"] == code and ossl not in theirs_text:
                errors.append("we chose %s and OpenSSL did not report it" % ossl)
    if case.group:
        want = GROUPS[case.group]
        if ours["group"] != want[1]:
            errors.append("group %s, wanted %s" % (ours["group"], want[1]))
        if not group_matches(theirs_text, case.group):
            errors.append("OpenSSL did not report group %s" % case.group)
    if ours["retried"] != case.retried:
        errors.append("retried=%d, wanted %d" % (ours["retried"], case.retried))
    if ours["alpn"] != case.expect_alpn:
        errors.append("ALPN %r, wanted %r" % (ours["alpn"], case.expect_alpn))
    # What OpenSSL says it selected: s_server "ALPN protocols selected: x",
    # s_client "ALPN protocol: x", and nothing when it selected nothing.
    said = ""
    for l in theirs_text.splitlines():
        mm = re.match(r"ALPN protocols selected: (\S+)", l) or re.match(r"ALPN protocol: (\S+)", l)
        if mm:
            said = mm.group(1)
    if said != case.expect_alpn:
        errors.append("OpenSSL says it selected ALPN %r, wanted %r" % (said, case.expect_alpn))
    scheme = case.scheme
    if scheme and case.role == "server":
        # s_client names the scheme the server signed with, in the registry's words.
        want = SCHEMES[scheme][0]
        if ("Peer signature type: %s" % want) not in theirs_text:
            errors.append("OpenSSL did not report a %s signature" % want)


def run_case(case, echo, pems, tmp):
    port = free_port()
    name = container_name()
    mount = "%s:/pki:ro,z" % pems
    message = "hello"
    if case.role == "client":
        # OpenSSL serves; this library's client dials.
        srv = ["openssl", "s_server", "-accept", "127.0.0.1:%d" % port, "-cert", "/pki/%s-leaf.pem" % case.kind,
               "-key", "/pki/%s-key.pem" % case.kind, "-naccept", "1", "-rev", "-no_ticket"]
        if case.suite:
            srv += ["-ciphersuites", SUITES[case.suite][0]]
        if case.group:
            srv += ["-groups", GROUPS[case.group][0]]
        if case.scheme or case.theirs_sigalgs:
            srv += ["-sigalgs", case.theirs_sigalgs or SCHEMES[case.scheme][0]]
        if case.alpn_theirs:
            srv += ["-alpn", ",".join(case.alpn_theirs)]
        if case.tls12:
            srv += ["-tls1_2"]
        cmd = [ENGINE, "run", "--rm", "--name", name, "--network", "host", "-v", mount, IMAGE] + srv
        theirs_out = os.path.join(tmp, "theirs.out")
        with open(theirs_out, "w") as to:
            proc = subprocess.Popen(cmd, stdout=to, stderr=subprocess.STDOUT)
        try:
            if not wait_listening(port, proc):
                return Outcome(False, "OpenSSL s_server did not start listening")
            ours_cmd = [echo, "client", "--message", message,
                        "--expect", "olleh\nolleh" if case.key_update else "olleh",
                        "--server-name", case.server_name, "--time", str(int(time.time()))]
            if not case.no_anchor:
                ours_cmd += ["--ca", os.path.join(PKI, case.kind + "-ca.der")]
            if case.key_update:
                ours_cmd += ["--key-update"]
            ours_cmd += echo_args(case, "client", port) + ["127.0.0.1", str(port)]
            r = subprocess.run(ours_cmd, capture_output=True, text=True, timeout=CASE_TIMEOUT)
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
        finally:
            subprocess.run([ENGINE, "rm", "-f", name], capture_output=True)
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        theirs = open(theirs_out).read()
        ours_text = r.stdout + r.stderr
        if r.returncode == 0:
            ours = parse_ours(r.stdout)
            return Outcome(True, "", ours, theirs)
        return Outcome(False, ours_text.replace("\n", " ").strip() + " | openssl: " + theirs.replace("\n", " ")[:300], None, theirs)

    # OpenSSL dials; this library serves.
    ours_cmd = [echo, "server", "--chain", os.path.join(PKI, case.kind + "-leaf.der"),
                "--key", os.path.join(PKI, case.kind + "-leaf.pkcs8"), "--name", KINDS[case.kind],
                "--time", str(int(time.time()))]
    ours_cmd += echo_args(case, "server", port) + [str(port)]
    ours_proc = subprocess.Popen(ours_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        if not wait_listening(port, ours_proc):
            out, err = ours_proc.communicate(timeout=5) if ours_proc.poll() is not None else ("", "")
            return Outcome(False, "our server did not start listening: " + (out + err).replace("\n", " "))
        cli = ["openssl", "s_client", "-connect", "127.0.0.1:%d" % port, "-CAfile", "/pki/%s-ca.pem" % case.kind,
               "-servername", case.server_name, "-verify_return_error", "-no_ign_eof"]
        if case.tls12:
            cli += ["-tls1_2"]
        else:
            cli += ["-tls1_3"]
        if case.suite:
            cli += ["-ciphersuites", SUITES[case.suite][0]]
        if case.groups:
            cli += ["-groups", ":".join(GROUPS[g][0] for g in case.groups)]
        elif case.group:
            cli += ["-groups", GROUPS[case.group][0]]
        if case.scheme or case.theirs_sigalgs:
            cli += ["-sigalgs", case.theirs_sigalgs or SCHEMES[case.scheme][0]]
        if case.alpn_theirs:
            cli += ["-alpn", ",".join(case.alpn_theirs)]
        script = "printf '%s\\n'; sleep 0.4; " % message
        if case.key_update:
            script += "printf 'K\\n'; sleep 0.4; printf 'again\\n'; sleep 0.4; "
        script += "sleep 0.6"
        sh = "(%s) | %s 2>&1" % (script, " ".join(shell_quote(x) for x in
                                                  [ENGINE, "run", "-i", "--rm", "--name", name, "--network", "host",
                                                   "-v", mount, IMAGE] + cli))
        r = subprocess.run(["sh", "-c", sh], capture_output=True, text=True, timeout=CASE_TIMEOUT)
        try:
            out, err = ours_proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            ours_proc.kill()
            out, err = ours_proc.communicate()
            err += "\n(our server was still waiting)"
    finally:
        subprocess.run([ENGINE, "rm", "-f", name], capture_output=True)
        if ours_proc.poll() is None:
            ours_proc.kill()
    theirs = r.stdout
    if ours_proc.returncode == 0:
        ours = parse_ours(out)
        need = "hello" if not case.key_update else "again"
        if need not in theirs:
            return Outcome(False, "the echo did not come back to s_client: " + theirs.replace("\n", " ")[:300], ours, theirs)
        return Outcome(True, "", ours, theirs)
    return Outcome(False, (out + err).replace("\n", " ").strip() + " | openssl: " + theirs.replace("\n", " ")[:300], None, theirs)


def shell_quote(s):
    return "'" + s.replace("'", "'\\''") + "'"


def judge(case, outcome):
    """('pass'|'refused'|'fail', detail)."""
    if case.expect == "refuse":
        if outcome.ok:
            return "fail", "was expected to be refused and was accepted"
        if case.refusal and not re.search(case.refusal, outcome.detail, re.I):
            return "fail", "refused for a reason that is not the expected one: " + outcome.detail[:300]
        return "refused", outcome.detail[:160]
    if not outcome.ok:
        return "fail", outcome.detail[:400]
    errors = []
    check_negotiated(case, outcome.ours, outcome.theirs, errors)
    if errors:
        return "fail", "; ".join(errors)
    return "pass", ""


def read_differences():
    names = {}
    if not os.path.exists(DIFFERENCES):
        return names
    with open(DIFFERENCES) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.split("\t")
            names[parts[0]] = parts[1] if len(parts) > 1 else ""
    return names


# ------------------------------------------------------------------------------------ plants

# name, file, text removed, text put in its place, the cases (substrings) it must break
PLANTS = {
    "record-nonce": ("src/record/record.c",
                     "nonce[GTLS_IV_LEN - 1u - i] ^= (unsigned char)(k->seq >> (8u * i));", "(void)i;",
                     ["client/default-ed", "server/default-ed"]),
    "key-update-label": ("src/record/record.c", '"traffic upd"', '"traffic upx"',
                         ["client/key-update", "server/key-update"]),
    "server-cv-label": ("src/client/verify.c", 'static const char server_label[] = "TLS 1.3, server CertificateVerify";',
                        'static const char server_label[] = "TLS 1.3, client CertificateVerify";',
                        ["server/default-ed", "server/default-p256"]),
    "client-finished": ("src/client/client.c", "result = gtls_finished_verify_data(hash, c->sec.schedule.c_hs, th, verify);",
                        "result = gtls_finished_verify_data(hash, c->sec.schedule.s_hs, th, verify);",
                        ["client/default-ed", "client/default-p256"]),
}


def plant_run(name, args):
    if name not in PLANTS:
        print("unknown plant %r; the plants are: %s" % (name, ", ".join(sorted(PLANTS))))
        return 2
    rel, old, new, must_break = PLANTS[name]
    scratch = tempfile.mkdtemp(prefix="gtls-interop-plant.")
    try:
        files = subprocess.run(["git", "ls-files", "-co", "--exclude-standard", "-z"], cwd=ROOT,
                               capture_output=True).stdout.split(b"\0")
        for f in files:
            if not f:
                continue
            src = os.path.join(ROOT, f.decode())
            dst = os.path.join(scratch, f.decode())
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
        path = os.path.join(scratch, rel)
        text = open(path).read()
        if text.count(old) != 1:
            print("plant %s: the text to remove occurs %d times in %s (stale plant): nothing was tested"
                  % (name, text.count(old), rel))
            return 1
        open(path, "w").write(text.replace(old, new))
        prefix = os.environ.get("PREFIX")
        build = subprocess.run(["make", "build/linux/release/apps/examples/echo", "PREFIX=%s" % prefix, "-j4"],
                               cwd=scratch, capture_output=True, text=True)
        planted = os.path.join(scratch, "build/linux/release/apps/examples/echo")
        if build.returncode != 0 or not os.path.exists(planted):
            print("plant %s: the planted copy did not build:\n%s" % (name, build.stderr[-600:]))
            return 1
        env = os.environ.copy()
        env["LD_LIBRARY_PATH"] = "%s:%s" % (os.path.join(prefix, "lib", "ghoti.io"), env.get("LD_LIBRARY_PATH", ""))
        # Every case that must break, planted, and the same cases, unplanted.
        status = 0
        pems = tempfile.mkdtemp(prefix="gtls-interop-pems.")
        make_pems(pems)
        wanted = [c for c in population() if any(c.name == m for m in must_break)]
        if len(wanted) != len(must_break):
            print("plant %s: a case it must break is not in the population" % name)
            return 1
        for c in wanted:
            tmp = tempfile.mkdtemp(prefix="gtls-interop-case.")
            good = judge(c, run_case(c, args.echo, pems, tmp))
            bad = judge(c, run_case(c, planted, pems, tmp))
            if good[0] != "pass":
                print("plant %s: %s fails BEFORE the plant (%s), so nothing was measured" % (name, c.name, good[1]))
                status = 1
            elif bad[0] == "pass":
                print("plant %s: %s still PASSES with the defect planted" % (name, c.name))
                status = 1
            else:
                print("plant %s: %s passes, and fails with the defect planted (%s)" % (name, c.name, bad[1][:100]))
        shutil.rmtree(pems, ignore_errors=True)
        return status
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--echo", default=os.path.join(ROOT, "build/linux/release/apps/examples/echo"))
    ap.add_argument("--only")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--plant")
    args = ap.parse_args()
    cases = population()
    if args.list:
        for c in cases:
            print(c.name, c.expect)
        return 0
    if not os.path.exists(args.echo):
        print("interop: %s was not built (make build/linux/release/apps/examples/echo)" % args.echo, file=sys.stderr)
        return 2
    why = engine_ok()
    if why:
        print("### interop: the reference is not reachable ###\n%s" % why, file=sys.stderr)
        print("The interop gate was NOT run: that is not a pass.", file=sys.stderr)
        return 1
    print("reference: %s in %s (%s)" % (PIN, IMAGE, ENGINE), flush=True)
    if args.plant:
        return plant_run(args.plant, args)

    declared = read_differences()
    in_code = {c.name for c in cases if c.declared}
    problems = []
    for n in sorted(in_code - set(declared)):
        problems.append("%s is declared in the code but not in DIFFERENCES" % n)
    for n in sorted(set(declared) - in_code):
        problems.append("%s is in DIFFERENCES but no case declares it: a list that describes nothing" % n)
    pems = tempfile.mkdtemp(prefix="gtls-interop-pems.")
    make_pems(pems)
    totals = {"client": [0, 0, 0, 0], "server": [0, 0, 0, 0]}  # cases, passed, refused, failed
    seen_declared = set()
    try:
        for c in cases:
            if args.only and args.only not in c.name:
                continue
            tmp = tempfile.mkdtemp(prefix="gtls-interop-case.")
            started = time.time()
            try:
                outcome = run_case(c, args.echo, pems, tmp)
            except subprocess.TimeoutExpired:
                outcome = Outcome(False, "timed out")
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
            verdict, detail = judge(c, outcome)
            t = totals[c.role]
            t[0] += 1
            if verdict == "pass":
                t[1] += 1
                if c.declared:
                    seen_declared.add(c.name)
            elif verdict == "refused":
                t[2] += 1
            else:
                t[3] += 1
                problems.append("%s: %s" % (c.name, detail))
            print("%-8s %-44s %.1fs %s" % (verdict.upper(), c.name, time.time() - started,
                                           ("(" + detail + ")") if detail else ""), flush=True)
    finally:
        shutil.rmtree(pems, ignore_errors=True)
    if not args.only:
        for n in sorted(in_code - seen_declared):
            problems.append("%s: a declared difference that no longer happens" % n)
    print()
    print("%-34s %5s %6s %7s %6s" % ("direction", "cases", "passed", "refused", "failed"))
    for role, label in (("client", "this client, OpenSSL s_server"), ("server", "this server, OpenSSL s_client")):
        t = totals[role]
        print("%-34s %5d %6d %7d %6d" % (label, t[0], t[1], t[2], t[3]))
    if problems:
        print("\n### interop: %d problem(s) ###" % len(problems))
        for p in problems:
            print("  " + p)
        return 1
    print("\ninterop: every case interoperated or was refused for its declared reason")
    return 0


if __name__ == "__main__":
    sys.exit(main())
