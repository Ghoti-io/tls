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
"""Write the fuzz seed corpus from the RFC 8448 vectors.

The seeds are the RFC's own server flights, whole and cut after each message,
in the framing fuzz_client expects ([epoch][length][bytes] segments after an
options byte), and each message the parsers read, behind the option byte that
selects its parser. Every byte comes from tests/data/rfc8448; nothing is
typed. `--check` fails if a committed seed differs from what this writes.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "tests" / "data" / "rfc8448"
CORPUS = ROOT / "tests" / "fuzz" / "corpus"


def load(name):
    out = {}
    for line in (DATA / (name + ".vec")).read_text().splitlines():
        if line and not line.startswith("#"):
            key, value = line.split(" ", 1)
            out[key] = bytes.fromhex(value)
    return out


def segment(epoch, data):
    return bytes([epoch]) + len(data).to_bytes(2, "big") + data


def split_messages(flight):
    out = []
    at = 0
    while at + 4 <= len(flight):
        n = 4 + int.from_bytes(flight[at + 1:at + 4], "big")
        out.append(flight[at:at + n])
        at += n
    assert at == len(flight)
    return out


def main():
    check = "--check" in sys.argv
    simple = load("simple-1rtt")
    hrr = load("hrr")
    nst = simple["server.construct-a-newsessionticket-handshake-message.newsessionticket"]
    seeds = {"client": {}, "msg": {}}

    def flight(v, name, extra_initial):
        sh = v["server.construct-a-serverhello-handshake-message%s.serverhello" % ("@2" if extra_initial else "")]
        body = v["server.send-handshake-record@%d.payload" % (3 if extra_initial else 2)]
        msgs = split_messages(body)
        opt = 1 if extra_initial else 0
        prefix = bytes([opt])
        if extra_initial:
            prefix += segment(0, v["server.construct-a-serverhello-handshake-message.serverhello"])
        prefix += segment(0, sh)
        seeds["client"][name + "-sh"] = prefix
        for i in range(1, len(msgs) + 1):
            seeds["client"][name + "-flight-%d" % i] = prefix + segment(2, b"".join(msgs[:i]))
        seeds["client"][name + "-whole"] = prefix + segment(2, body)
        seeds["client"][name + "-whole-and-ticket"] = prefix + segment(2, body) + segment(3, nst)
        seeds["client"][name + "-cut-opt"] = bytes([opt | (1 << 1)]) + prefix[1:] + segment(2, body) + segment(3, nst)
        seeds["client"][name + "-tight-limits"] = bytes([opt | 0x10]) + prefix[1:] + segment(2, body)
        return msgs

    msgs = flight(simple, "simple", False)
    flight(hrr, "hrr", True)
    seeds["client"]["wrong-epoch"] = bytes([0]) + segment(2, simple["server.construct-a-serverhello-handshake-message.serverhello"])

    ch = simple["client.construct-a-clienthello-handshake-message.clienthello"]
    sh = simple["server.construct-a-serverhello-handshake-message.serverhello"]
    hsh = hrr["server.construct-a-serverhello-handshake-message.serverhello"]
    named = [
        (0, "server-hello", sh[4:]),
        (0, "hello-retry-request", hsh[4:]),
        (1, "encrypted-extensions", msgs[0][4:]),
        (2, "certificate", msgs[1][4:]),
        (3, "certificate-verify", msgs[2][4:]),
        (4, "new-session-ticket", nst[4:]),
        (5, "client-hello", ch[4:]),
        (6, "retry-client-hello", ch[4:]),
    ]
    for opt, name, body in named:
        seeds["msg"][name] = bytes([opt]) + body

    bad = 0
    for kind, files in seeds.items():
        directory = CORPUS / kind
        directory.mkdir(parents=True, exist_ok=True)
        for name, data in files.items():
            path = directory / ("seed-" + name)
            if check:
                if not path.is_file() or path.read_bytes() != data:
                    print("make-fuzz-seeds: %s differs" % path.relative_to(ROOT),
                          file=sys.stderr)
                    bad = 1
            else:
                path.write_bytes(data)
    return bad


if __name__ == "__main__":
    sys.exit(main())
