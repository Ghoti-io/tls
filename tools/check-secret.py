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
"""Reject a secret-dependent or secret-disclosing idiom under src/, include/
and examples/.

The patterns are applied to a planted snippet first. A pattern that matches
nothing, including the plant, fails the build: a check that has rotted into
matching nothing reports a clean tree.

src/ and include/ take no exceptions. An example parses a command line, and
comparing a flag name is not comparing a secret, so a file under examples/
may say so once, at file scope:

    /* check-secret: allow strcmp -- command-line words, never secret */

That waives the named patterns for that file only. The same line in a file
under src/ or include/ is ignored and reported like any other hit, and a
waiver for a pattern that does not exist is itself an error.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCANNED = ("src", "include", "examples")
WAIVABLE = ("examples",)

# Each pattern is a defect on its own. Comments count: a comment that names
# the call is how the next edit copies it into the file.
PATTERNS = [
    ("memcmp", re.compile(r"\bmemcmp\b")),
    ("bcmp", re.compile(r"\bbcmp\b")),
    ("timingsafe_bcmp", re.compile(r"\btimingsafe_bcmp\b")),
    ("mt", re.compile(r"\bgcu_random_mt")),
    ("urandom", re.compile(r"/dev/urandom")),
    ("RAND_bytes", re.compile(r"\bRAND_bytes\b")),
    ("printf", re.compile(r"\bv?(?:f|s|sn|d|as)?printf\b")),
    # A comparison that stops at the first difference, on a secret or a tag.
    ("strcmp", re.compile(r"\bstrn?(?:case)?cmp\b")),
    # Output: a secret that reaches a stream, a descriptor or a terminal.
    ("puts", re.compile(r"\bf?puts\s*\(")),
    ("write", re.compile(r"\b[fp]?write\s*\(")),
]
WAIVER = re.compile(r"check-secret:\s*allow\s+([a-zA-Z_ ]+?)\s*(?:--|\*/|$)", re.M)

PLANT = "memcmp(a, b, n); bcmp(a, b, n); timingsafe_bcmp(a, b, n);\n" \
        "gcu_random_mt32_next(s); fopen(\"/dev/urandom\", \"r\");\n" \
        "RAND_bytes(p, n); printf(\"%s\", key); fprintf(stderr, \"x\");\n" \
        "strcmp(a, b); strncmp(a, b, n); puts(s); fputs(s, f);\n" \
        "write(fd, p, n); fwrite(p, 1, n, f); dprintf(fd, \"%s\", key);\n"


def hits(text, waivable=False):
    found = []
    waived = set()
    if waivable:
        for m in WAIVER.finditer(text):
            waived.update(m.group(1).split())
    for name, pattern in PATTERNS:
        if name in waived:
            continue
        if pattern.search(text):
            found.append(name)
    return found


def bad_waivers(text):
    known = {name for name, _ in PATTERNS}
    return sorted({w for m in WAIVER.finditer(text) for w in m.group(1).split()} - known)


def scan(root):
    """Problems under @p root, as strings; one per file."""
    problems = []
    for tree in SCANNED:
        base = root / tree
        files = sorted(base.rglob("*.c")) + sorted(base.rglob("*.h"))
        for path in files:
            text = path.read_text(encoding="utf-8")
            waivable = tree in WAIVABLE
            found = hits(text, waivable)
            if waivable:
                found += ["waiver for unknown pattern %s" % w for w in bad_waivers(text)]
            elif WAIVER.search(text):
                found.append("a waiver, which only examples/ may carry")
            if found:
                problems.append("%s: %s" % (path.relative_to(root), ", ".join(found)))
    return problems


def selftest():
    """The scan fails where it should and passes where it should. A scan that
    cannot be seen to fail on a planted tree reports a clean one."""
    import tempfile
    waiver = "/* check-secret: allow strcmp -- flags */\n"
    cases = [
        ("src/a.c", "int f(void) { return strcmp(a, b); }\n", True),
        ("include/a.h", "static inline int f(void) { return strncmp(a, b, 3); }\n", True),
        ("examples/a.c", "int main(void) { puts(key); }\n", True),
        ("examples/a.c", "int main(void) { write(1, key, 8); }\n", True),
        ("src/a.c", waiver + "int f(void) { return strcmp(a, b); }\n", True),
        ("include/a.h", waiver + "int f(void) { return strcmp(a, b); }\n", True),
        ("examples/a.c", waiver + "int main(void) { return strcmp(a, b); }\n", False),
        ("examples/a.c", waiver + "int main(void) { puts(key); }\n", True),
        ("examples/a.c", "/* check-secret: allow nothing -- x */\n", True),
        ("src/a.c", "int f(void) { return 0; }\n", False),
    ]
    for rel, text, want_problem in cases:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for tree in SCANNED:
                (root / tree).mkdir()
            (root / rel).write_text(text, encoding="utf-8")
            got = bool(scan(root))
            if got != want_problem:
                print("check-secret: the planted tree %r (%s) %s, so this gate is "
                      "measuring nothing" % (rel, text.strip().splitlines()[-1],
                      "was clean" if want_problem else "was refused"), file=sys.stderr)
                return False
    return True


def main():
    planted = set(hits(PLANT))
    missing = [name for name, _ in PATTERNS if name not in planted]
    if missing:
        print("check-secret: the plant was not matched by %s, so this gate "
              "is measuring nothing" % ", ".join(missing), file=sys.stderr)
        return 1
    if not selftest():
        return 1
    problems = scan(ROOT)
    if problems:
        print("check-secret: secret-dependent or disclosing calls:",
            file=sys.stderr)
        for problem in problems:
            print("  " + problem, file=sys.stderr)
        return 1
    print("check-secret: no memcmp, strcmp, userspace generator, printf or "
          "output call under src/, include/ or examples/ (examples may waive "
          "strcmp-class names with a stated reason)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
