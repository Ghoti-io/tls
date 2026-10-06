#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
#
# Copyright (C) 2026 Corey Pennycuff
#
# This file is part of Ghoti.io TLS.
#
# Ghoti.io TLS is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3 as
# published by the Free Software Foundation.
"""Reject a secret-dependent idiom anywhere under src/.

The patterns are applied to a planted snippet first. A pattern that matches
nothing, including the plant, fails the build: a check that has rotted into
matching nothing reports a clean tree.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

# Each pattern is a defect on its own. Comments count: a comment that names
# the call is how the next edit copies it into the file.
PATTERNS = [
    ("memcmp", re.compile(r"\bmemcmp\b")),
    ("bcmp", re.compile(r"\bbcmp\b")),
    ("timingsafe_bcmp", re.compile(r"\btimingsafe_bcmp\b")),
    ("mt", re.compile(r"\bgcu_random_mt")),
    ("urandom", re.compile(r"/dev/urandom")),
    ("RAND_bytes", re.compile(r"\bRAND_bytes\b")),
    ("printf", re.compile(r"\b(?:f|s|sn)?printf\b")),
]

PLANT = "memcmp(a, b, n); bcmp(a, b, n); timingsafe_bcmp(a, b, n);\n" \
        "gcu_random_mt32_next(s); fopen(\"/dev/urandom\", \"r\");\n" \
        "RAND_bytes(p, n); printf(\"%s\", key); fprintf(stderr, \"x\");\n"


def hits(text):
    found = []
    for name, pattern in PATTERNS:
        if pattern.search(text):
            found.append(name)
    return found


def main():
    planted = set(hits(PLANT))
    missing = [name for name, _ in PATTERNS if name not in planted]
    if missing:
        print("check-secret: the plant was not matched by %s, so this gate "
              "is measuring nothing" % ", ".join(missing), file=sys.stderr)
        return 1
    problems = []
    for path in sorted(SRC.rglob("*.c")) + sorted(SRC.rglob("*.h")):
        text = path.read_text(encoding="utf-8")
        found = hits(text)
        if found:
            problems.append("%s: %s" % (path.relative_to(ROOT),
                ", ".join(found)))
    if problems:
        print("check-secret: secret-dependent or disclosing calls:",
            file=sys.stderr)
        for problem in problems:
            print("  " + problem, file=sys.stderr)
        return 1
    print("check-secret: no memcmp, userspace generator, or printf under src/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
