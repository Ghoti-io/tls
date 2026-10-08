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
counted in the denominator with the reason it was given.

Resumption is in the population in both roles. This library's server issues
tickets and a first `s_client` saves its session (-sess_out); a second connection
offers it (-sess_in) and must reuse it. This library's client keeps the tickets
an `s_server` sends and offers one on a second connection, which the server
must reuse. Each suite, each group and a HelloRetryRequest, and ALPN; and the
cases in which the second connection must NOT be resumed and must still
complete (a server whose key changed, a clock too far from the client's, an
ALPN protocol not offered again, a server that is a different process) count
in the denominator as full handshakes, with the evidence that the ticket was
offered and not taken. Differences
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
POPULATION_FLOOR = 93   # cases a full run must have run
PASS_FLOOR = 84          # and how many of them must have interoperated

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
                 no_anchor=False, theirs_sigalgs=None, ours_sigalgs=None,
                 our_alert=None, peer_alert=None, theirs_extra=(), ours_extra=(),
                 theirs_has=(), identities=None, resume=None, theirs_lacks=(), psk_count=1,
                 resumption=None, expect_resumed=True, advance=0, second_alpn=None, second_name=None,
                 rekey=False, new_server=False, rename=False, unplanted=None):
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
        # What a refusal must say on this side: the alert this library sent
        # (its own result), or the alert it received. Not a regex on a string.
        self.our_alert = our_alert
        self.peer_alert = peer_alert
        self.theirs_extra = list(theirs_extra)
        self.ours_extra = list(ours_extra)
        self.theirs_has = list(theirs_has)     # text the peer's output must contain
        self.identities = identities           # kinds this library's server holds, default first
        # "ticket": s_client offers a session ticket a first connection to
        # an OpenSSL s_server gave it (-sess_in); "early": and early data too
        # (-early_data). This library's server issues no tickets and accepts
        # no early data, so it must answer with a full handshake.
        self.resume = resume
        self.theirs_lacks = list(theirs_lacks)  # text the peer's output must not contain
        # How many messages of OpenSSL's trace carry its psk extension: the
        # ClientHello, and the second one after a HelloRetryRequest when OpenSSL
        # keeps the PSK in it. A ServerHello that selected one would add a message.
        self.psk_count = psk_count
        # A real resumption (see the docstring): "yes" when the second
        # connection must reuse the first's ticket, "no" when it must be a full
        # handshake that still completes, with how the ticket is made not to
        # qualify: a key that changed (rekey), a server clock `advance` seconds
        # ahead, a server that is another process (new-server, client role),
        # an ALPN list for the second connection (second_alpn), a name for it
        # (second_name).
        self.resumption = resumption
        self.expect_resumed = expect_resumed
        self.advance = advance
        self.second_alpn = second_alpn
        self.second_name = second_name
        self.rekey = rekey
        self.new_server = new_server
        self.rename = rename            # the server's key keeps its bytes and takes a new name
        self.unplanted = unplanted      # why no interop plant can break this case, if none can


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
        cases.append(Case(role, "key-update", key_update=True,
                          theirs_has=["KEYUPDATE"] if role == "server" else []))
        cases.append(Case(role, "compat", compat=True))
        cases.append(Case(role, "everything-chacha-p384-retry", kind="p384", suite="chacha",
                          group="p384", groups=["x25519", "p384"], retried=1, scheme="p384",
                          alpn_ours=["h2"], alpn_theirs=["h2"], expect_alpn="h2", key_update=True))
        # The refusals, each with the alert this side sent or was sent.
        if role == "client":
            cases.append(Case(role, "refuse-tls12-only", tls12=True, expect="refuse", peer_alert=70))
            cases.append(Case(role, "refuse-no-common-scheme", theirs_sigalgs="rsa_pss_rsae_sha256",
                              ours_sigalgs="ed25519", kind="ed", expect="refuse", peer_alert=40))
        else:
            cases.append(Case(role, "refuse-tls12-only", tls12=True, expect="refuse", our_alert=70))
            cases.append(Case(role, "refuse-no-common-scheme", theirs_sigalgs="rsa_pss_rsae_sha256",
                              ours_sigalgs="ed25519", kind="ed", expect="refuse", our_alert=40))
    cases.append(Case("client", "refuse-wrong-name", server_name="other.example.com", expect="refuse",
                      our_alert=42))
    cases.append(Case("client", "refuse-unknown-anchor", no_anchor=True, expect="refuse", our_alert=48))
    cases.append(Case("server", "refuse-wrong-name", expect="refuse",
                      theirs_extra=["-verify_hostname", "other.example.com"], peer_alert=42))
    cases.append(Case("server", "refuse-alpn-no-overlap", alpn_ours=["h2"], alpn_theirs=["spdy/3"],
                      expect="refuse", our_alert=120))
    # Which of the server's identities the client's name picks, seen by the
    # certificate OpenSSL verifies the name against.
    for name, kind, ids in (("sni-first", "ed", ["ed", "rsa"]), ("sni-second", "rsa", ["ed", "rsa"]),
                            ("sni-third", "p256", ["ed", "rsa", "p256"])):
        cases.append(Case("server", name, kind=kind, identities=ids))
    cases.append(Case("server", "sni-default", kind="ed", server_name="unknown.example.org",
                      identities=["ed", "rsa"]))
    cases.append(Case("client", "refuse-alpn-no-overlap", alpn_ours=["h2"], alpn_theirs=["spdy/3"],
                      expect="refuse", peer_alert=120))
    # A client that offers a session ticket (pre_shared_key) and early data to
    # a server that issues neither: RFC 8446 section 4.2.11 says to fall back
    # to a full handshake, and the early-data records are skipped (4.2.10).
    # The evidence that the offer was made is OpenSSL's own trace of its
    # ClientHello; that it was not taken is "New" and not "Reused".
    full = ["New, TLSv1.3"]
    cases.append(Case("server", "psk-ticket-fallback", resume="ticket",
                      theirs_has=["extension_type=psk(41)"] + full,
                      theirs_lacks=["Reused, TLSv1.3"]))
    cases.append(Case("server", "early-data-fallback", resume="early",
                      theirs_has=["extension_type=psk(41)", "extension_type=early_data",
                                  "Early data was rejected"] + full,
                      theirs_lacks=["Reused, TLSv1.3", "early data from the client"]))
    cases.append(Case("server", "early-data-fallback-retry", resume="early", group="p256",
                      groups=["x25519", "p256"], retried=1,
                      theirs_has=["extension_type=psk(41)", "extension_type=early_data", "Early data was rejected"] + full,
                      theirs_lacks=["Reused, TLSv1.3"]))
    # A retry in which OpenSSL keeps the PSK in the second ClientHello (the
    # ticket is for SHA-384, so only a SHA-384 suite can use it again; with
    # AES-128 OpenSSL drops it, which is why the case above sees one psk), so
    # the server meets a refreshed pre_shared_key and no early_data.
    cases.append(Case("server", "early-data-fallback-refresh", resume="early", group="p256",
                      groups=["x25519", "p256"], retried=1, suite="aes256", psk_count=2,
                      theirs_has=["extension_type=psk(41)", "extension_type=early_data",
                                  "Early data was rejected"] + full,
                      theirs_lacks=["Reused, TLSv1.3"]))
    # Resumption, in both roles: the second connection reuses the first's ticket.
    for role in ("client", "server"):
        for s in SUITES:
            cases.append(Case(role, "resume-suite-%s" % s, suite=s, resumption="yes"))
        for g in GROUPS:
            cases.append(Case(role, "resume-group-%s" % g, group=g, resumption="yes"))
        cases.append(Case(role, "resume-retry-p256", group="p256", groups=["x25519", "p256"], retried=1,
                          resumption="yes"))
        cases.append(Case(role, "resume-retry-p384-aes256", group="p384", groups=["x25519", "p384"], suite="aes256",
                          retried=1, resumption="yes"))
        cases.append(Case(role, "resume-alpn", alpn_ours=["h2", "http/1.1"], alpn_theirs=["h2", "http/1.1"],
                          expect_alpn="h2", resumption="yes"))
    # ... and where it must not, and the handshake must still complete in full.
    cases.append(Case("server", "resume-refused-rekey", resumption="no", expect_resumed=False, rekey=True,
                      unplanted="a ticket under a key the server no longer has is refused by the key lookup and "
                                "by the AEAD alike, so removing either leaves the other; tools/controls.sh plants "
                                "the unit tests"))
    cases.append(Case("server", "resume-refused-key-name", resumption="no", expect_resumed=False, rename=True))
    cases.append(Case("server", "resume-refused-clock", resumption="no", expect_resumed=False, advance=100))
    cases.append(Case("server", "resume-refused-alpn", resumption="no", expect_resumed=False,
                      alpn_ours=["h2", "http/1.1"], alpn_theirs=["h2", "http/1.1"], second_alpn=["http/1.1"],
                      expect_alpn="http/1.1"))
    cases.append(Case("server", "resume-refused-name", resumption="no", expect_resumed=False, second_name=""))
    cases.append(Case("client", "resume-refused-new-server", resumption="no", expect_resumed=False,
                      new_server=True))
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
    def __init__(self, ok, detail, ours="", theirs="", ours_text=""):
        self.ok = ok
        self.detail = detail
        self.ours = ours
        self.theirs = theirs
        self.ours_text = ours_text   # what this library's side printed


def parse_ours(text, which=0):
    """The result line of the connection `which` (0 the first, -1 the last)."""
    found = re.findall(r"ok suite=([0-9a-f]{4}) group=([0-9a-f]{4}) alpn=(\S*) retried=(\d)"
                       r"(?: resumed=(\d) sessions=(\d+) offered=(\d))?", text)
    if not found:
        return None
    m = found[which]
    out = {"suite": m[0], "group": m[1], "alpn": m[2], "retried": int(m[3])}
    if m[4] != "":
        out.update({"resumed": int(m[4]), "sessions": int(m[5]), "offered": int(m[6])})
    return out


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


def check_resumption(case, outcome, errors):
    """The second connection was resumed, or was a full handshake, as the case says; both stacks agree."""
    want = 1 if case.expect_resumed else 0
    first, second = getattr(outcome, "first", None), outcome.ours
    if first is None or second is None or "resumed" not in second or "resumed" not in first:
        errors.append("our side printed no resumption result")
        return
    if first["resumed"] != 0:
        errors.append("the first connection says it was resumed")
    if second["resumed"] != want:
        errors.append("the second connection resumed=%d, wanted %d" % (second["resumed"], want))
    if case.role == "client":
        if second["offered"] != 1:
            errors.append("our client did not offer the session")
        hits = [int(x) for x in re.findall(r"^\s*(\d+) session cache hits", outcome.theirs, re.M)]
        # A HelloRetryRequest makes the server look at the ticket twice, once in each ClientHello.
        wanted = want * (1 + case.retried)
        if sum(hits) != wanted:
            errors.append("OpenSSL's s_server counts %d session cache hits, wanted %d" % (sum(hits), wanted))
        if first["sessions"] < 1:
            errors.append("our client was sent no ticket")
    else:
        if first["sessions"] != 0:
            errors.append("a server holds no sessions")
        psks = outcome.theirs.count("extension_type=psk(41)")
        word = "Reused, TLSv1.3" if want else "New, TLSv1.3"
        other = "New, TLSv1.3" if want else "Reused, TLSv1.3"
        if word not in outcome.theirs or other in outcome.theirs:
            errors.append("s_client did not say %r on the second connection" % word)
        if "New, TLSv1.3" not in getattr(outcome, "theirs_first", ""):
            errors.append("s_client did not say New on the first connection")
        if want and psks < 2:
            errors.append("the PSK was in %d messages of s_client's trace, wanted the ClientHello and the ServerHello" % psks)
        if not want and psks != 1:
            errors.append("the PSK was in %d messages of s_client's trace, wanted the ClientHello alone (offered, not taken)" % psks)


def run_case(case, echo, pems, tmp):
    if case.resumption:
        return run_resume_case(case, echo, pems, tmp)
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
        srv += case.theirs_extra
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
            ours_cmd += echo_args(case, "client", port) + case.ours_extra + ["127.0.0.1", str(port)]
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
            return Outcome(True, "", ours, theirs, ours_text)
        return Outcome(False, ours_text.replace("\n", " ").strip() + " | openssl: " + theirs.replace("\n", " ")[:300],
                       None, theirs, ours_text)

    # OpenSSL dials; this library serves.
    if case.resume:
        why = get_session(case, pems, tmp)
        if why:
            return Outcome(False, "setting up the ticket: " + why)
        with open(os.path.join(tmp, "early.txt"), "w") as f:
            f.write("early data from the client\n")
    ours_cmd = [echo, "server", "--time", str(int(time.time()))]
    kinds = case.identities or [case.kind]
    for n, kind in enumerate(kinds):
        if n:
            ours_cmd += ["--next-identity"]
        ours_cmd += ["--chain", os.path.join(PKI, kind + "-leaf.der"),
                     "--key", os.path.join(PKI, kind + "-leaf.pkcs8"), "--name", KINDS[kind]]
    ours_cmd += echo_args(case, "server", port) + case.ours_extra + [str(port)]
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
        cli += case.theirs_extra
        if case.resume:
            cli += ["-sess_in", "/work/sess.pem", "-trace"]
            if case.resume == "early":
                cli += ["-early_data", "/work/early.txt"]
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
        extra_mount = ["-v", "%s:/work:z" % tmp] if case.resume else []
        sh = "(%s) | %s 2>&1" % (script, " ".join(shell_quote(x) for x in
                                                  [ENGINE, "run", "-i", "--rm", "--name", name, "--network", "host",
                                                   "-v", mount] + extra_mount + [IMAGE] + cli))
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
            return Outcome(False, "the echo did not come back to s_client: " + theirs.replace("\n", " ")[:300],
                           ours, theirs, out + err)
        return Outcome(True, "", ours, theirs, out + err)
    return Outcome(False, (out + err).replace("\n", " ").strip() + " | openssl: " + theirs.replace("\n", " ")[:300],
                   None, theirs, out + err)


def theirs_flags(case, alpn):
    """The options both OpenSSL programs take for the suite, group and ALPN of a case."""
    f = []
    if case.suite:
        f += ["-ciphersuites", SUITES[case.suite][0]]
    return f, (["-alpn", ",".join(alpn)] if alpn else [])


def run_resume_case(case, echo, pems, tmp):
    """Two connections, the second offering the first's ticket (see the docstring)."""
    port = free_port()
    mount = "%s:/pki:ro,z" % pems
    suite_flags, _ = theirs_flags(case, None)
    now = str(int(time.time()))
    if case.role == "client":
        def server(naccept, out):
            name = container_name()
            srv = ["openssl", "s_server", "-accept", "127.0.0.1:%d" % port, "-cert", "/pki/%s-leaf.pem" % case.kind,
                   "-key", "/pki/%s-key.pem" % case.kind, "-naccept", str(naccept), "-rev"] + suite_flags
            if case.group:
                srv += ["-groups", GROUPS[case.group][0]]
            if case.alpn_theirs:
                srv += ["-alpn", ",".join(case.alpn_theirs)]
            cmd = [ENGINE, "run", "--rm", "--name", name, "--network", "host", "-v", mount, IMAGE] + srv
            with open(out, "w") as to:
                return subprocess.Popen(cmd, stdout=to, stderr=subprocess.STDOUT), name
        outs = [os.path.join(tmp, "theirs1.out"), os.path.join(tmp, "theirs2.out")]
        names = []
        procs = []
        ours = None
        try:
            proc, name = server(1 if case.new_server else 2, outs[0])
            procs.append(proc)
            names.append(name)
            if not wait_listening(port, proc):
                return Outcome(False, "OpenSSL s_server did not start listening")
            gate = os.path.join(tmp, "gate")
            ours_cmd = [echo, "client", "--message", "hello", "--expect", "olleh", "--server-name", case.server_name,
                        "--time", now, "--ca", os.path.join(PKI, case.kind + "-ca.der"), "--resume"]
            if case.new_server:
                ours_cmd += ["--gate", gate]
            ours_cmd += echo_args(case, "client", port) + ["127.0.0.1", str(port)]
            ours_proc = subprocess.Popen(ours_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if case.new_server:
                # The first server has had its one connection; another process, with ticket keys of its own, takes the next.
                try:
                    proc.wait(timeout=CASE_TIMEOUT)
                except subprocess.TimeoutExpired:
                    pass
                proc2, name2 = server(1, outs[1])
                procs.append(proc2)
                names.append(name2)
                if not wait_listening(port, proc2):
                    return Outcome(False, "the second OpenSSL s_server did not start listening")
                open(gate, "w").close()
            try:
                out, err = ours_proc.communicate(timeout=CASE_TIMEOUT)
            except subprocess.TimeoutExpired:
                ours_proc.kill()
                out, err = ours_proc.communicate()
                err += "\n(our client was still waiting)"
            for pr in procs:
                try:
                    pr.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
        finally:
            for n in names:
                subprocess.run([ENGINE, "rm", "-f", n], capture_output=True)
            for pr in procs:
                try:
                    pr.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    pr.kill()
        theirs = "".join(open(o).read() for o in outs if os.path.exists(o))
        ours_text = out + err
        if ours_proc.returncode != 0:
            return Outcome(False, ours_text.replace("\n", " ").strip() + " | openssl: " + theirs.replace("\n", " ")[:300],
                           None, theirs, ours_text)
        o = Outcome(True, "", parse_ours(out, -1), theirs, ours_text)
        o.first = parse_ours(out, 0)
        return o

    # OpenSSL dials twice; this library serves both.
    with open(os.path.join(tmp, "early.txt"), "w") as f:
        f.write("")
    ours_cmd = [echo, "server", "--time", now, "--tickets", "1", "--connections", "2"]
    if case.rekey:
        ours_cmd += ["--rekey"]
    if case.rename:
        ours_cmd += ["--rename"]
    if case.advance:
        ours_cmd += ["--advance", str(case.advance)]
    ours_cmd += ["--chain", os.path.join(PKI, case.kind + "-leaf.der"),
                 "--key", os.path.join(PKI, case.kind + "-leaf.pkcs8"), "--name", KINDS[case.kind]]
    ours_cmd += echo_args(case, "server", port) + [str(port)]
    ours_proc = subprocess.Popen(ours_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    names = []
    results = []
    try:
        if not wait_listening(port, ours_proc):
            out, err = ours_proc.communicate(timeout=5) if ours_proc.poll() is not None else ("", "")
            return Outcome(False, "our server did not start listening: " + (out + err).replace("\n", " "))
        for n in (1, 2):
            name = container_name()
            names.append(name)
            alpn = case.alpn_theirs if n == 1 or case.second_alpn is None else case.second_alpn
            cli = ["openssl", "s_client", "-connect", "127.0.0.1:%d" % port, "-CAfile", "/pki/%s-ca.pem" % case.kind,
                   "-verify_return_error", "-no_ign_eof", "-tls1_3"] + suite_flags
            if n == 2 and case.second_name == "":
                cli += ["-noservername"]
            else:
                cli += ["-servername", case.second_name if (n == 2 and case.second_name) else case.server_name]
            if case.group and not case.groups:
                cli += ["-groups", GROUPS[case.group][0]]
            elif case.groups:
                cli += ["-groups", ":".join(GROUPS[g][0] for g in case.groups)]
            if alpn:
                cli += ["-alpn", ",".join(alpn)]
            cli += ["-sess_out", "/work/sess.pem"] if n == 1 else ["-sess_in", "/work/sess.pem", "-trace"]
            sh = "(printf 'hello\\n'; sleep 0.4; sleep 1.4) | %s 2>&1" % " ".join(shell_quote(x) for x in
                 [ENGINE, "run", "-i", "--rm", "--name", name, "--network", "host", "-v", mount,
                  "-v", "%s:/work:z" % tmp, IMAGE] + cli)
            r = subprocess.run(["sh", "-c", sh], capture_output=True, text=True, timeout=CASE_TIMEOUT)
            results.append(r.stdout)
        try:
            out, err = ours_proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            ours_proc.kill()
            out, err = ours_proc.communicate()
            err += "\n(our server was still waiting)"
    finally:
        for n in names:
            subprocess.run([ENGINE, "rm", "-f", n], capture_output=True)
        if ours_proc.poll() is None:
            ours_proc.kill()
    theirs = results[1] if len(results) == 2 else ""
    if ours_proc.returncode != 0 or len(results) != 2:
        return Outcome(False, (out + err).replace("\n", " ").strip() + " | openssl: " + theirs.replace("\n", " ")[:300],
                       None, theirs, out + err)
    if "hello" not in results[0] or "hello" not in theirs:
        return Outcome(False, "the echo did not come back to s_client: " + theirs.replace("\n", " ")[:300],
                       parse_ours(out, -1), theirs, out + err)
    o = Outcome(True, "", parse_ours(out, -1), theirs, out + err)
    o.first = parse_ours(out, 0)
    o.theirs_first = results[0]
    return o


def get_session(case, pems, tmp):
    """A session ticket for s_client to offer: one connection to an OpenSSL
    s_server that issues tickets (and takes early data), saved with -sess_out.
    Returns an error string, or None with tmp/sess.pem written."""
    port = free_port()
    sname = container_name()
    cname = container_name()
    mounts = ["-v", "%s:/pki:ro,z" % pems, "-v", "%s:/work:z" % tmp]
    srv = [ENGINE, "run", "-i", "--rm", "--name", sname, "--network", "host"] + mounts + [IMAGE,
           "openssl", "s_server", "-accept", "127.0.0.1:%d" % port, "-cert", "/pki/%s-leaf.pem" % case.kind,
           "-key", "/pki/%s-key.pem" % case.kind, "-naccept", "1", "-early_data", "-ign_eof"]
    out = os.path.join(tmp, "ticket-server.out")
    with open(out, "w") as to:
        # stdin stays open: s_server ends the connection when its input does
        proc = subprocess.Popen(srv, stdin=subprocess.PIPE, stdout=to, stderr=subprocess.STDOUT)
    try:
        if not wait_listening(port, proc):
            return "the ticket-issuing s_server did not start: " + open(out).read()[:200].replace("\n", " ")
        cli = [ENGINE, "run", "-i", "--rm", "--name", cname, "--network", "host"] + mounts + [IMAGE,
               "openssl", "s_client", "-connect", "127.0.0.1:%d" % port, "-CAfile", "/pki/%s-ca.pem" % case.kind,
               "-servername", case.server_name, "-verify_return_error", "-no_ign_eof", "-tls1_3",
               "-sess_out", "/work/sess.pem"]
        sh = "(printf 'x\\n'; sleep 1.5) | %s 2>&1" % " ".join(shell_quote(x) for x in cli)
        r = subprocess.run(["sh", "-c", sh], capture_output=True, text=True, timeout=CASE_TIMEOUT)
    finally:
        subprocess.run([ENGINE, "rm", "-f", cname], capture_output=True)
        subprocess.run([ENGINE, "rm", "-f", sname], capture_output=True)
        proc.stdin.close()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    path = os.path.join(tmp, "sess.pem")
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return "no session was saved: " + r.stdout[-300:].replace("\n", " ")
    return None


def shell_quote(s):
    return "'" + s.replace("'", "'\\''") + "'"


def alerts_of(text):
    """(alert this side sent, alert it received) from the echo program's failure line."""
    m = re.search(r"alert=(\d+) peer_alert=(\d+)", text)
    return (int(m.group(1)), int(m.group(2))) if m else (None, None)


def judge(case, outcome):
    """('pass'|'refused'|'fail', detail)."""
    if case.expect == "refuse":
        if outcome.ok:
            return "fail", "was expected to be refused and was accepted"
        sent, got = alerts_of(outcome.ours_text)
        if case.our_alert is not None and sent != case.our_alert:
            return "fail", "this side sent alert %s, wanted %s: %s" % (sent, case.our_alert, outcome.detail[:200])
        if case.peer_alert is not None and got != case.peer_alert:
            return "fail", "this side was sent alert %s, wanted %s: %s" % (got, case.peer_alert, outcome.detail[:200])
        if case.our_alert is None and case.peer_alert is None:
            return "fail", "a refusal with no alert declared for it"
        return "refused", "alert sent %s, received %s" % (sent, got)
    if not outcome.ok:
        return "fail", outcome.detail[:400]
    errors = []
    check_negotiated(case, outcome.ours, outcome.theirs, errors)
    if case.resumption:
        check_resumption(case, outcome, errors)
    for text in case.theirs_has:
        if text not in outcome.theirs:
            errors.append("OpenSSL's output does not contain %r" % text)
    if case.resume and outcome.theirs.count("extension_type=psk(41)") != case.psk_count:
        errors.append("the PSK extension was in %d messages of the trace, wanted %d (the ClientHello%s; a "
                      "ServerHello that selected it would add one)"
                      % (outcome.theirs.count("extension_type=psk(41)"), case.psk_count,
                         "s" if case.psk_count > 1 else ""))
    for text in case.theirs_lacks:
        if text in outcome.theirs:
            errors.append("OpenSSL's output contains %r" % text)
    if case.identities and case.role == "server":
        # OpenSSL verified the chain it was sent against this kind's CA: it
        # got the identity the name asked for, or the handshake would have failed.
        pass
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

# name: (file, text removed, text put in its place, the cases (exact names) it
# must break). The first four damage what is sent; the rest remove a check or a
# rule, and the case that must break each is a refusal (or a plaintext alert)
# whose alert is then the wrong one, or absent.
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
    "alpn-failure": ("src/server/server.c",
                     "    if (c->alpn_selected_len == 0) {\n      return gtls_conn_fail(c, GTLS_ERR_ALPN,",
                     "    if (0) {\n      return gtls_conn_fail(c, GTLS_ERR_ALPN,",
                     ["server/refuse-alpn-no-overlap"]),
    "supported-versions": ("src/server/server.c",
                           "  if (e == NULL) {\n    return gtls_conn_fail(c, GTLS_ERR_UNSUPPORTED, GTLS_ALERT_PROTOCOL_VERSION);\n  }\n  result = gtls_msg_parse_ch_versions(e, &tls13);\n  if (result != GTLS_OK) {\n    return gtls_conn_fail_parse(c, result);\n  }\n  if (!tls13) {",
                           "  tls13 = 1;\n  if (!tls13) {",
                           ["server/refuse-tls12-only"]),
    "no-common-scheme": ("src/server/server.c",
                         "  if (c->scheme == 0) {\n    return gtls_conn_fail(c, GTLS_ERR_NO_COMMON, GTLS_ALERT_HANDSHAKE_FAILURE);\n  }\n\n  /* ALPN",
                         "  if (c->scheme == 0) {\n    c->scheme = GCERT_SIG_ED25519;\n  }\n\n  /* ALPN",
                         ["server/refuse-no-common-scheme"]),
    "plaintext-alert-rule": ("src/client/stream.c",
                             "type != GTLS_CT_CHANGE_CIPHER_SPEC &&\n      !(type == GTLS_CT_ALERT && c->state != GTLS_STATE_CONNECTED && len == 2u)) {",
                             "type != GTLS_CT_CHANGE_CIPHER_SPEC) {",
                             ["server/refuse-wrong-name"]),
    "early-skip-off": ("src/server/server.c", "c->early_skip = 1;", "(void)0;",
                       ["server/early-data-fallback", "server/early-data-fallback-retry",
                       "server/early-data-fallback-refresh"]),
    "psk-refused": ("src/server/server.c",
                    "result = gtls_msg_parse_ch_psk_offer(e, &c->limits, &o->psk_offer);",
                    "result = GTLS_ERR_UNSUPPORTED; (void)o->psk_offer;",
                    ["server/psk-ticket-fallback", "server/early-data-fallback",
                     "server/early-data-fallback-refresh"]),
    "retry-skip-ends": ("src/client/stream.c",
                        "if (c->early_skip && epoch == GTLS_EPOCH_INITIAL && type == GTLS_CT_APPLICATION_DATA) {",
                        "if (0) {",
                        ["server/early-data-fallback-retry"]),
    # Resumption. A binder that is wrong breaks every resumption the other
    # stack makes or takes. The checks that make a ticket pass over are
    # shown by the refusals: a ticket the clock has aged, the name or the ALPN
    # protocol changed, or the key renamed (the same bytes under a new name).
    # A client that took the PSK for granted breaks on a server that did not.
    "resume-binder-transcript": ("src/server/server.c",
                                 "result = gtls_binder_transcript(&c->sec.transcript, msg, o->psk_trunc, th);",
                                 "result = gtls_binder_transcript(&c->sec.transcript, msg, o->psk_trunc - 1u, th);",
                                 ["server/resume-suite-aes128", "server/resume-suite-aes256", "server/resume-suite-chacha",
                                  "server/resume-group-x25519", "server/resume-group-p256", "server/resume-group-p384",
                                  "server/resume-retry-p256", "server/resume-retry-p384-aes256", "server/resume-alpn"]),
    "resume-client-binder": ("src/client/client.c",
                             "result = patch_binder(c, &empty, &c->hello);", "result = GTLS_OK;",
                             ["client/resume-suite-aes128", "client/resume-suite-aes256", "client/resume-suite-chacha",
                              "client/resume-group-x25519", "client/resume-group-p256", "client/resume-group-p384",
                              "client/resume-alpn"]),
    "resume-client-binder-retry": ("src/client/client.c",
                                   "result = patch_binder(c, &c->sec.transcript, &h2);", "result = GTLS_OK;",
                                   ["client/resume-retry-p256", "client/resume-retry-p384-aes256"]),
    "resume-age-window": ("src/server/server.c",
                          "gtls_ticket_fresh(&t, now, en->age, x->ticket_age_window * 1000u) &&", "1 &&",
                          ["server/resume-refused-clock"]),
    "resume-sni": ("src/server/server.c",
                   "t.sni_len == o->host.len && names_equal(t.sni, o->host.p, t.sni_len) &&", "1 &&",
                   ["server/resume-refused-name"]),
    "resume-key-name": ("src/session/ticket.c",
                        "gsec_equal(keys[i].name, ticket, GTLS_TICKET_KEY_NAME_LEN) == GSEC_OK) {", "1) {",
                        ["server/resume-refused-key-name"]),
    "resume-client-assumes": ("src/client/client.c",
                              "if ((sh.flags & GTLS_SH_FLAG_PSK) != 0) {", "if (c->offer != NULL) {",
                              ["client/resume-refused-new-server"]),
    "resume-alpn": ("src/server/server.c",
                    "(t.alpn_len == 0 || offered_alpn(o, t.alpn, t.alpn_len));", "1;",
                    ["server/resume-refused-alpn"]),
    "resume-selected": ("src/server/server.c", "sp.psk = resumed;", "sp.psk = 0;",
                        ["server/resume-suite-aes128", "server/resume-group-p256", "server/resume-retry-p256"]),
    "sni-selection": ("src/server/server.c",
                      "if (name_rank(&x->identities[i], o->host.p, o->host.len) != rank) {",
                      "if (0) {",
                      ["server/sni-second", "server/sni-third"]),
}


def plant_coverage_problems(cases):
    """The fallback cases only mean something if a plant breaks them: every
    case that offers a ticket must be one a plant is required to break, the
    plants that cut our PSK path must exist, and `make interop-plants` must
    run every plant there is."""
    problems = []
    broken = {m for (_, _, _, must) in PLANTS.values() for m in must}
    for c in cases:
        if c.resume and c.name not in broken:
            problems.append("%s offers a ticket but no plant is required to break it" % c.name)
        if c.resumption and c.name not in broken and not c.unplanted:
            problems.append("%s resumes (or must refuse to) but no plant is required to break it" % c.name)
    for need in ("psk-refused", "early-skip-off", "resume-binder-transcript", "resume-client-binder",
                 "resume-age-window", "resume-sni", "resume-alpn", "resume-key-name", "resume-client-assumes"):
        if need not in PLANTS:
            problems.append("the plant %s, which cuts this library's PSK path, is gone" % need)
    try:
        with open(os.path.join(ROOT, "Makefile")) as f:
            text = f.read()
        rule = text[text.index("\ninterop-plants:"):]
        rule = rule[:rule.index("\n\n")]
        for n in PLANTS:
            if n not in re.findall(r"[\w-]+", rule):
                problems.append("the plant %s is not run by `make interop-plants`" % n)
    except (OSError, ValueError):
        problems.append("could not read the interop-plants rule from the Makefile")
    return problems


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
        build = subprocess.run(["make", "build/linux/release/apps/examples/echo", "PREFIX=%s" % prefix, "-j2"],
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
            if good[0] not in ("pass", "refused"):
                print("plant %s: %s fails BEFORE the plant (%s), so nothing was measured" % (name, c.name, good[1]))
                status = 1
            elif bad[0] != "fail":
                print("plant %s: %s still %s with the defect planted" % (name, c.name, bad[0].upper()))
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

    if args.only and not [c for c in cases if args.only in c.name]:
        print("interop: --only %r matches no case" % args.only, file=sys.stderr)
        return 2
    declared = read_differences()
    in_code = {c.name for c in cases if c.declared}
    problems = plant_coverage_problems(cases)
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
    if args.only:
        print("\nNOTE: --only ran a subset, so the population and pass floors, the declared-difference "
              "check and the plant check were NOT applied: this is not a pass of the gate.")
    if not args.only:
        total = totals["client"][0] + totals["server"][0]
        passed = totals["client"][1] + totals["server"][1]
        if total < POPULATION_FLOOR or totals["client"][0] < POPULATION_FLOOR // 3 or \
                totals["server"][0] < POPULATION_FLOOR // 3 or passed < PASS_FLOOR:
            problems.append("only %d cases ran and %d interoperated: the floors are %d and %d, so a population "
                            "that shrank is not a pass" % (total, passed, POPULATION_FLOOR, PASS_FLOOR))
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
