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
"""Extract RFC 8448's traces into vector files.

Reads tests/data/rfc8448/rfc8448.txt (pinned by tools/fetch.sh) and writes

  tests/data/rfc8448/simple-1rtt.vec   section 3, Simple 1-RTT Handshake
  tests/data/rfc8448/hrr.vec           section 5, HelloRetryRequest
  src/core/selftest_kat.h              two secrets from section 3

Every value in them is a hex field the RFC prints; none is typed. A field
whose printed octet count disagrees with the hex that follows it (which is
what a page break in the middle of a value looks like to a parser that does
not handle one) is an error, not a shorter vector.

A vector is named `<role>.<block-title>.<field>`, slugged, with `@N` after the
title when the same title occurs again for that role in the section.

  python3 tools/extract-rfc8448.py          write the files
  python3 tools/extract-rfc8448.py --check  fail if a file would change
"""

import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RFC = ROOT / "tests" / "data" / "rfc8448" / "rfc8448.txt"
PIN = "6564d1376d1ec744fc7a9993da15ebc1b9be361908b166091f47ef605c537fba"

SECTIONS = [
    ("3", "3.  Simple 1-RTT Handshake", "4.  Resumed 0-RTT Handshake",
     "simple-1rtt.vec", "RFC 8448 section 3, Simple 1-RTT Handshake"),
    ("5", "5.  HelloRetryRequest", "6.  Client Authentication",
     "hrr.vec", "RFC 8448 section 5, HelloRetryRequest"),
]

PAGE = re.compile(r"^(Thomson\s+Informational\s+\[Page \d+\]|RFC 8448\s+TLS 1\.3 Traces\s+January 2019)\s*$")
HEADER = re.compile(r"^   \{(client|server)\}  (.*?):?\s*$")
FIELD = re.compile(r"^      (\S[^:]*?)(?: \((\d+) octets\))?:\s+(\S.*)$")
HEXLINE = re.compile(r"^         ((?:[0-9a-f]{2} ?)+)\s*$")
HEXVAL = re.compile(r"^(?:[0-9a-f]{2} ?)+$")


def slug(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def fail(message):
    print("extract-rfc8448: %s" % message, file=sys.stderr)
    sys.exit(1)


def section_lines(lines, start, stop):
    begin = None
    for i, line in enumerate(lines):
        if line.startswith(start):
            begin = i
        elif begin is not None and line.startswith(stop):
            return lines[begin:i]
    fail("section %r not found" % start)


def parse(lines):
    """Yield (key, hex) for every hex field in the section."""
    seen = {}
    block = None
    field = None
    out = []

    def close_field():
        nonlocal field
        if field is None:
            return
        label, count, hexwords = field
        field = None
        text = " ".join(hexwords).strip()
        if not HEXVAL.match(text):
            return
        data = text.replace(" ", "")
        if count is not None and len(data) != 2 * int(count):
            fail("%s: %s says %s octets and has %d" %
                 (block, label, count, len(data) // 2))
        out.append((block + "." + slug(label), data))

    for raw in lines:
        line = raw.replace("\f", "").rstrip("\n")
        if PAGE.match(line):
            continue
        m = HEADER.match(line)
        if m:
            close_field()
            role, title = m.group(1), m.group(2)
            base = role + "." + slug(title)
            seen[base] = seen.get(base, 0) + 1
            block = base if seen[base] == 1 else "%s@%d" % (base, seen[base])
            continue
        if block is None:
            continue
        m = FIELD.match(line)
        if m:
            close_field()
            field = (m.group(1).strip(), m.group(2), [m.group(3).strip()])
            continue
        m = HEXLINE.match(line)
        if m and field is not None:
            field[2].append(m.group(1).strip())
            continue
    close_field()
    return out


def render(title, pairs):
    lines = [
        "# %s" % title,
        "# Source: https://www.rfc-editor.org/rfc/rfc8448.txt, sha256 %s." % PIN,
        "# Written by tools/extract-rfc8448.py; do not edit. Each line is a name",
        "# and the hex the RFC prints for it.",
    ]
    names = set()
    for key, data in pairs:
        if key in names:
            fail("duplicate vector name %s" % key)
        names.add(key)
        lines.append("%s %s" % (key, data))
    return "\n".join(lines) + "\n"


KAT_HEADER = """/*
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * Copyright (C) 2026 Corey Pennycuff
 *
 * This file is part of Ghoti.io TLS.
 *
 * Ghoti.io TLS is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * Ghoti.io TLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file selftest_kat.h
 *
 * Generated by tools/extract-rfc8448.py from RFC 8448 section 3. Do not
 * edit: `make check-foundation` fails if this is not what the generator
 * writes.
 */

#ifndef GHOTI_IO_GTLS_SRC_CORE_SELFTEST_KAT_H
#define GHOTI_IO_GTLS_SRC_CORE_SELFTEST_KAT_H

#include <ghoti.io/tls/macros.h>

"""


def c_array(name, data):
    raw = bytes.fromhex(data)
    rows = []
    for i in range(0, len(raw), 8):
        rows.append("  " + ", ".join("0x%02x" % b for b in raw[i:i + 8]))
    return "static const unsigned char %s[%d] = {\n%s\n};\n" % (
        name, len(raw), ",\n".join(rows))


def main():
    check = "--check" in sys.argv
    data = RFC.read_bytes()
    got = hashlib.sha256(data).hexdigest()
    if got != PIN:
        fail("%s has sha256 %s, the pin says %s" % (RFC, got, PIN))
    lines = data.decode("ascii").splitlines()
    outputs = {}
    simple = None
    for number, start, stop, filename, title in SECTIONS:
        pairs = parse(section_lines(lines, start, stop))
        if not pairs:
            fail("section %s yielded no vectors" % number)
        outputs[ROOT / "tests" / "data" / "rfc8448" / filename] = \
            render(title, pairs)
        if number == "3":
            simple = dict(pairs)
    kat = KAT_HEADER
    kat += c_array("gtls_kat_early_secret",
                   simple["server.extract-secret-early.secret"])
    kat += c_array("gtls_kat_derived_secret",
                   simple["server.derive-secret-for-handshake-tls13-derived.expanded"])
    kat += "\n#endif /* GHOTI_IO_GTLS_SRC_CORE_SELFTEST_KAT_H */\n"
    outputs[ROOT / "src" / "core" / "selftest_kat.h"] = kat
    bad = 0
    for path, text in outputs.items():
        if check:
            if not path.is_file() or path.read_text(encoding="ascii") != text:
                print("extract-rfc8448: %s differs from what the RFC yields" %
                      path.relative_to(ROOT), file=sys.stderr)
                bad = 1
        else:
            path.write_text(text, encoding="ascii")
    return bad


if __name__ == "__main__":
    sys.exit(main())
