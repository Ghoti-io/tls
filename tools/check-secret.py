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
comparing a flag name is not comparing a secret, so a line under examples/
may say so, with its reason, on the line itself or on the comment line
directly above it:

    /* check-secret: allow strcmp -- command-line word, never secret */
    return strcmp(a, b) == 0;

A waiver covers the named patterns on that one line and nothing else: not the
rest of the file, and not a sibling pattern (strcmp does not waive strcasecmp
or memcmp). A waiver with no reason after the "--" is not a waiver. The same
comment in a file under src/ or include/ is ignored and reported like any
other hit, and a waiver for a pattern that does not exist is itself an error.

Each pattern is anchored by "not preceded by a letter or digit" rather than by
a word boundary, because an underscore is a word character: \bmemcmp does not
match __builtin_memcmp, which is the same variable-time compare.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCANNED = ("src", "include", "examples")
WAIVABLE = ("examples",)

# A call spelled with any prefix but a letter or digit: memcmp, __builtin_memcmp,
# CRYPTO_memcmp and timingsafe_bcmp all match, my2memcmp does not.
B = r"(?<![A-Za-z0-9])"

# Each pattern is a defect on its own. Comments count: a comment that names
# the call is how the next edit copies it into the file.
PATTERNS = [
    ("memcmp", re.compile(B + r"memcmp\b")),
    ("bcmp", re.compile(B + r"bcmp\b")),
    ("mt", re.compile(r"\bgcu_random_mt")),
    ("urandom", re.compile(r"/dev/urandom")),
    ("RAND_bytes", re.compile(r"\bRAND_bytes\b")),
    ("printf", re.compile(B + r"v?(?:f|s|sn|d|as)?printf\b")),
    # A comparison that stops at the first difference, on a secret or a tag.
    ("strcmp", re.compile(B + r"strn?cmp\b")),
    ("strcasecmp", re.compile(B + r"strn?casecmp\b")),
    # Output: a secret that reaches a stream, a descriptor or a terminal.
    ("puts", re.compile(r"\bf?puts\s*\(")),
    ("write", re.compile(r"\b[fp]?write\s*\(")),
]
# One waiver per comment: names, then "--", then a reason that is not empty.
WAIVER = re.compile(r"check-secret:\s*allow\s+([a-zA-Z_ ]+?)\s+--\s+((?!\*/)\S[^\n]*?)\s*(?:\*/|$)")
# What names a waiver at all, with or without a reason, to catch the bare ones.
WAIVER_WORD = re.compile(r"check-secret:\s*allow")

PLANT = "memcmp(a, b, n); bcmp(a, b, n); timingsafe_bcmp(a, b, n);\n" \
        "__builtin_memcmp(a, b, n); __builtin_bcmp(a, b, n);\n" \
        "gcu_random_mt32_next(s); fopen(\"/dev/urandom\", \"r\");\n" \
        "RAND_bytes(p, n); printf(\"%s\", key); fprintf(stderr, \"x\");\n" \
        "strcmp(a, b); strncmp(a, b, n); puts(s); fputs(s, f);\n" \
        "strcasecmp(a, b); strncasecmp(a, b, n); __builtin_strcmp(a, b);\n" \
        "write(fd, p, n); fwrite(p, 1, n, f); dprintf(fd, \"%s\", key);\n"


def hits(text):
    """Pattern names present anywhere in @p text; no waivers."""
    return [name for name, pattern in PATTERNS if pattern.search(text)]


def line_hits(text, waivable=False):
    """(line number, pattern name) for every hit not waived on its own line or
    by the comment line directly above it."""
    lines = text.split("\n")
    found = []
    for n, line in enumerate(lines):
        waived = set()
        if waivable:
            sources = [line]
            if n > 0 and lines[n - 1].lstrip().startswith(("/*", "//")):
                sources.append(lines[n - 1])
            for src in sources:
                m = WAIVER.search(src)
                if m:
                    waived.update(m.group(1).split())
        for name, pattern in PATTERNS:
            if name not in waived and pattern.search(line):
                found.append((n + 1, name))
    return found


def bad_waivers(text):
    known = {name for name, _ in PATTERNS}
    out = set()
    for line in text.split("\n"):
        if WAIVER_WORD.search(line):
            m = WAIVER.search(line)
            if m is None:
                out.add("a waiver with no reason (%s)" % line.strip())
            else:
                out.update("waiver for unknown pattern %s" % w
                           for w in m.group(1).split() if w not in known)
    return sorted(out)


def scan(root):
    """Problems under @p root, as strings; one per file."""
    problems = []
    for tree in SCANNED:
        base = root / tree
        files = sorted(base.rglob("*.c")) + sorted(base.rglob("*.h"))
        for path in files:
            text = path.read_text(encoding="utf-8")
            waivable = tree in WAIVABLE
            found = ["line %d: %s" % h for h in line_hits(text, waivable)]
            if waivable:
                found += bad_waivers(text)
            elif WAIVER_WORD.search(text):
                found.append("a waiver, which only examples/ may carry")
            if found:
                problems.append("%s: %s" % (path.relative_to(root), ", ".join(found)))
    return problems


def selftest():
    """The scan fails where it should and passes where it should. A scan that
    cannot be seen to fail on a planted tree reports a clean one."""
    import tempfile
    waiver = "/* check-secret: allow strcmp -- flags */\n"
    cases = []
    # Every pattern, and each spelling that once escaped, in every scanned tree
    # and in the one example that holds real code.
    calls = ["memcmp(a, b, n)", "__builtin_memcmp(a, b, n)", "CRYPTO_memcmp(a, b, n)",
             "bcmp(a, b, n)", "__builtin_bcmp(a, b, n)", "timingsafe_bcmp(a, b, n)",
             "strcmp(a, b)", "strncmp(a, b, n)", "__builtin_strcmp(a, b)",
             "strcasecmp(a, b)", "strncasecmp(a, b, n)", "printf(\"%s\", k)",
             "fprintf(stderr, \"%s\", k)", "puts(k)", "write(1, k, 8)"]
    for rel in ("src/a.c", "include/a.h", "examples/echo.c"):
        for call in calls:
            cases.append((rel, "int f(void) { return %s; }\n" % call, True))
    cases += [
        ("src/a.c", waiver + "int f(void) { return strcmp(a, b); }\n", True),
        ("include/a.h", waiver + "int f(void) { return strcmp(a, b); }\n", True),
        # A waiver covers its line, or the comment line above, and no more.
        ("examples/a.c", waiver + "int main(void) { return strcmp(a, b); }\n", False),
        ("examples/a.c", "int main(void) { return strcmp(a, b); /* check-secret: allow strcmp -- flags */ }\n", False),
        ("examples/a.c", waiver + "int f(void);\nint main(void) { return strcmp(a, b); }\n", True),
        ("examples/a.c", waiver + "\nint main(void) { return strcmp(a, b); }\n", True),
        ("examples/a.c", waiver + "int main(void) { puts(key); }\n", True),
        # A sibling is not covered: strcmp does not waive strcasecmp or memcmp.
        ("examples/a.c", waiver + "int main(void) { return strcasecmp(a, b); }\n", True),
        ("examples/echo.c", waiver + "int main(void) { return memcmp(a, b, 4); }\n", True),
        ("examples/echo.c", waiver + "int main(void) { return __builtin_memcmp(a, b, 4); }\n", True),
        # A waiver with no reason is refused, and so is an unknown name.
        ("examples/a.c", "/* check-secret: allow strcmp */\nint main(void) { return strcmp(a, b); }\n", True),
        ("examples/a.c", "/* check-secret: allow strcmp -- */\nint main(void) { return strcmp(a, b); }\n", True),
        ("examples/a.c", "/* check-secret: allow nothing -- x */\n", True),
        ("src/a.c", "int f(void) { return 0; }\n", False),
        ("examples/a.c", "int g(void) { return mymemcmp9(a); }\n", False),
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
          "a single line, with a stated reason)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
