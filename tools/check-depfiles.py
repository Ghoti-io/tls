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

The text of the Makefile is not enough for the fuzz harnesses: a glob that
matches nothing, or an -MF path that no longer matches the one the glob names,
passes every line-level test and tracks nothing.  So the harness half asks make
what it would run (`make -n`, `make -p`), and then runs each harness's own
compile arguments with -MM into a scratch directory and reads the
depfile back.

Usage: check-depfiles.py [Makefile]
"""

import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parent.parent
makefile_path = (Path(sys.argv[1]) if len(sys.argv) > 1 else root / "Makefile").resolve()


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


def make_output(args):
    cmd = ["make", "-f", str(makefile_path), "-C", str(root)] + args
    done = subprocess.run(cmd, capture_output=True, text=True)
    return done.returncode, done.stdout, done.stderr


def check_harnesses():
    """Dry-run every fuzzer and read back the depfile its arguments write."""
    code, out, err = make_output(["-pn"])
    if code != 0:
        tail = err.strip().splitlines()[-1] if err.strip() else ""
        problems.append("make -pn failed, so the fuzz depfiles cannot be "
                        "checked: " + tail)
        return
    m = re.search(r"^FUZZ_HARNESS_DEPFILES :?= ?(.*)$", out, re.M)
    listed = m.group(1).split() if m else []
    sources = sorted((root / "tests" / "fuzz").glob("fuzz_*.cpp"))
    if not sources:
        problems.append("tests/fuzz has no fuzz_*.cpp, so there is nothing to check")
        return
    if not listed:
        problems.append("FUZZ_HARNESS_DEPFILES expands to nothing: its wildcard "
                        "matches no harness, so no fuzzer's header dependencies "
                        "are ever read")
        return
    if len(listed) != len(sources):
        problems.append("FUZZ_HARNESS_DEPFILES names %d depfiles for %d harness "
                        "sources" % (len(listed), len(sources)))
    app_dir = re.search(r"^FUZZ_APP_DIR :?= ?(.*)$", out, re.M)
    compiler = shutil.which("clang++") or shutil.which("g++") or shutil.which("c++")
    if compiler is None or app_dir is None:
        problems.append("no C++ compiler (or no FUZZ_APP_DIR) to read a depfile "
                        "back with")
        return
    with tempfile.TemporaryDirectory() as tmp:
        for src in sources:
            stem = src.stem
            code, out, err = make_output(["-n", "%s/%s" % (app_dir.group(1), stem)])
            lines = [l for l in out.replace("\\\n", " ").splitlines()
                     if "tests/fuzz/%s.cpp" % stem in l and "-MF" in l]
            if code != 0 or len(lines) != 1:
                problems.append("make -n for %s did not print one compile command "
                                "that passes -MF" % stem)
                continue
            argv = shlex.split(lines[0])
            if "-MMD" not in argv:
                problems.append("%s: the compile command has no -MMD" % stem)
                continue
            mf = argv[argv.index("-MF") + 1]
            if os.path.normpath(mf) not in [os.path.normpath(x) for x in listed]:
                problems.append("%s writes its depfile to %s, which is not in "
                                "FUZZ_HARNESS_DEPFILES, so nothing includes it"
                                % (stem, mf))
            # The same include and define arguments, preprocessing only, with the
            # depfile in the scratch directory.
            # (-I takes its directory as a separate word in this Makefile.)
            keep = []
            for i, a in enumerate(argv):
                if a == "-I":
                    keep += [a, argv[i + 1]]
                elif a.startswith(("-I", "-D", "-std=")):
                    keep.append(a)
            dep = Path(tmp) / (stem + ".d")
            cmd = [compiler] + keep + ["-MM", "-MG", "-MP",
                                       "-MT", stem, "-MF", str(dep), str(src)]
            done = subprocess.run(cmd, cwd=root, capture_output=True, text=True)
            if done.returncode != 0 or not dep.exists() or dep.stat().st_size == 0:
                problems.append("%s: the harness did not produce a non-empty depfile"
                                % stem)
            elif "fuzz_common.h" not in dep.read_text():
                problems.append("%s: its depfile does not list tests/fuzz/"
                                "fuzz_common.h" % stem)


if harness:
    check_harnesses()

if problems:
    for problem in problems:
        print("check-depfiles: %s" % problem, file=sys.stderr)
    sys.exit(1)

print("check-depfiles: %d object trees and the fuzz harnesses pass -MMD, and every "
      "one has its depfiles included" % len(rules))
