#!/usr/bin/env python3
"""Fail if an object tree does not track its header dependencies.

Every tree that compiles `src/*.c` must pass `-MMD` and must have its `.d`
files read back with `-include`.  Both halves matter and the failure mode of
missing either is the same: a header changes, some objects rebuild and others
do not, and the archive ends up holding two versions of the same declaration.

That is not hypothetical.  The constant-time tree wrote `.d` files from the
day it was added and nothing ever included them.  On 2026-09-28 a field was
added to `GTLS_Limits`; `core.c` recompiled because `core.c` had changed,
`random.c` did not because `random.c` had not, and the two objects disagreed
about how big the struct was.  `gtls_limits_default` wrote past the caller's
local and the freshly enabled stack protector reported stack smashing inside
`gtls_random_bytes` - a report that read exactly like a buffer overflow in
the entropy call.  The fuzz tree had no `-MMD` at all.

A stale gate certifies nothing, and it does it quietly, which is why this is
a build-time check rather than a comment.

Usage: check-depfiles.py [Makefile]
"""

import re
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
makefile_path = Path(sys.argv[1]) if len(sys.argv) > 1 else root / "Makefile"


def fail(message):
    print("check-depfiles: %s" % message, file=sys.stderr)
    sys.exit(1)


text = re.sub(r"\\\n", " ", makefile_path.read_text())

# Rules whose target is an object under a build directory and whose
# prerequisite is a C source: `$(SOMETHING)/%.o: src/%.c ...`.
rules = re.findall(
    r"^(\$\(\w+\))/%\.o: src/%\.c[^\n]*\n((?:\t[^\n]*\n)+)", text, re.M)
if not rules:
    fail("no object rules found; this check is looking at the wrong file")

included = set(re.findall(r"^-include \$\((\w+)\)", text, re.M))
if not included:
    fail("no -include line at all, so nothing reads a depfile")

problems = []
for target, recipe in rules:
    name = target.strip("$()")
    if "-MMD" not in recipe:
        problems.append("%s/%%.o does not pass -MMD, so no depfile is written"
                        % target)
        continue
    if "-MF" not in recipe:
        problems.append("%s/%%.o passes -MMD with no -MF, so the depfile lands "
                        "beside the source rather than the object" % target)
    # The variable holding this tree's depfiles has to be included. Accept any
    # -include whose name shares the tree's prefix: OBJ_DIR -> DEPFILES,
    # CT_OBJ -> CT_DEPFILES, ASAN_OBJ_DIR -> ASAN_DEPFILES, and so on.
    prefix = name.split("_")[0]
    if prefix == "OBJ":
        # The release tree's variable is the unprefixed one.
        want = ["DEPFILES"]
        ok = "DEPFILES" in included
    else:
        want = [prefix + "_*"]
        ok = any(inc.startswith(prefix + "_") for inc in included)
    if not ok:
        problems.append(
            "%s/%%.o writes depfiles and no -include reads them (looked for "
            "%s)" % (target, want[0]))

# The fuzz harnesses are C++ files compiled and linked in one step by a rule
# the Makefile expands once per harness. They include fuzz_common.h and the
# headers in tests/, which no prerequisite names, so without -MMD a changed
# header leaves a stale fuzzer behind (found 2026-10-09: fuzz_common.h was
# edited and the binaries were removed by hand).
harness = re.search(r"^\$\$\(FUZZ_APP_DIR\)/\$1:[^\n]*\n((?:\t[^\n]*\n)+)", text, re.M)
if not harness:
    problems.append("no fuzz harness rule found, so nothing tracks fuzz_common.h")
else:
    if "-MMD" not in harness.group(1) or "-MF" not in harness.group(1):
        problems.append("the fuzz harness rule does not pass -MMD with -MF, so a "
                        "changed header does not rebuild a fuzzer")
    if not re.search(r"^-include \$\(FUZZ_HARNESS_DEPFILES\)", text, re.M):
        problems.append("the fuzz harness depfiles are never included")

if problems:
    for problem in problems:
        print("check-depfiles: %s" % problem, file=sys.stderr)
    sys.exit(1)

print("check-depfiles: %d object trees and the fuzz harnesses pass -MMD, and every "
      "one has its depfiles included" % len(rules))
