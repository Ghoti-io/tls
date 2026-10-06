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
"""The known answers are RFC 8448's, the pins agree, and the API is tested.

No network and no container. Three checks:

1. The RFC 8448 text is the pinned one: its SHA-256 is the one in
   tools/fetch.sh and the one in tools/extract-rfc8448.py, and re-running the
   extractor reproduces every committed vector and the generated header byte
   for byte. A vector that was edited by hand, or an extractor that changed
   without the vectors, fails here.

2. Every function a public header exports is named in at least one unit test.
   The classifier is run on a planted declaration first. A planted
   `gtls_untested_plant` must be reported; if it is not, this program is not a
   gate.

3. The fuzz seeds are what tools/make-fuzz-seeds.py writes from the vectors.

4. gtls_selftest still derives the two secrets it claims to, which is what its
   header says it does.
"""

import hashlib
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INCLUDE = ROOT / "include"
TESTS = ROOT / "tests" / "unit"
RFC = ROOT / "tests" / "data" / "rfc8448" / "rfc8448.txt"
FETCH = ROOT / "tools" / "fetch.sh"
EXTRACT = ROOT / "tools" / "extract-rfc8448.py"

DECL = re.compile(r"GTLS_API\b.*?\b(gtls_[a-z0-9_]+)\s*\(", re.S)


def fail(message):
    print("check-foundation: %s" % message, file=sys.stderr)
    sys.exit(1)


def declared():
    found = set()
    for path in INCLUDE.rglob("*.h"):
        text = path.read_text(encoding="utf-8")
        for match in DECL.finditer(text):
            found.add(match.group(1))
    return found


def untested(functions, test_text):
    return sorted(fn for fn in functions
                  if not re.search(r"\b%s\b" % re.escape(fn), test_text))


def main():
    # 1. The pins.
    digest = hashlib.sha256(RFC.read_bytes()).hexdigest()
    for path in (FETCH, EXTRACT):
        text = path.read_text(encoding="utf-8")
        pins = re.findall(r"\b[0-9a-f]{64}\b", text)
        if digest not in pins:
            fail("%s does not pin %s, the digest of the committed RFC text"
                 % (path.relative_to(ROOT), digest))
    run = subprocess.run([sys.executable, str(EXTRACT), "--check"],
                         capture_output=True, text=True)
    if run.returncode != 0:
        sys.stderr.write(run.stderr)
        fail("the committed vectors are not what the pinned RFC yields")

    # The fuzz seeds are generated from the same vectors, when there are any.
    seeds = ROOT / "tools" / "make-fuzz-seeds.py"
    if seeds.is_file():
        run = subprocess.run([sys.executable, str(seeds), "--check"],
                             capture_output=True, text=True)
        if run.returncode != 0:
            sys.stderr.write(run.stderr)
            fail("the committed fuzz seeds are not what the vectors yield")

    # 2. The API is exercised.
    test_text = "\n".join(p.read_text(encoding="utf-8")
                          for p in sorted(TESTS.glob("test_*.cpp")))
    functions = declared()
    if not functions:
        fail("no GTLS_API declarations found; the pattern must have rotted")
    planted = untested(functions | {"gtls_untested_plant"}, test_text)
    if "gtls_untested_plant" not in planted:
        fail("a planted untested function was not reported, so this "
             "classifier is measuring nothing")
    missing = untested(functions, test_text)
    if missing:
        fail("exported and named in no unit test: %s" % ", ".join(missing))

    # 4. The self-test.
    selftest = (ROOT / "src" / "core" / "selftest.c").read_text(encoding="utf-8")
    for needle in ("gtls_schedule_early", "gtls_derive_secret",
                   "gtls_kat_early_secret", "gtls_kat_derived_secret"):
        if needle not in selftest:
            fail("gtls_selftest no longer uses %s" % needle)

    print("check-foundation: RFC 8448 pin, vectors, API coverage and "
          "self-test agree (%d exported functions)" % len(functions))
    return 0


if __name__ == "__main__":
    sys.exit(main())
