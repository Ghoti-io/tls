#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-only
#
# Copyright (C) 2026 Corey Pennycuff
#
# This file is part of Ghoti.io TLS.
#
# Ghoti.io TLS is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License version 3 as
# published by the Free Software Foundation.
#
# The checks listed in plants() below are each removed, one at a time, in a
# scratch copy of the tree, and the test that is meant to catch the absence
# must start failing. Those are the ones planted, not every check in the
# library. A control that does not fail means the test accepts the
# very thing the check was there to refuse.
#
#   PREFIX=/path/to/prefix tools/controls.sh [name...]
#
# The scratch copy is built against PREFIX (and PKG_CONFIG_PATH as the
# environment has it). Each plant first runs the test unplanted, so that a
# failure is the plant's and not the build's.

set -u

root=$(cd "$(dirname "$0")/.." && pwd)
: "${PREFIX:?set PREFIX to the prefix holding cutil, security and certificate}"
scratch=$(mktemp -d "${TMPDIR:-/tmp}/gtls-controls.XXXXXX")
trap 'rm -rf "$scratch"' EXIT

# name, file, text removed, text put in its place, test binary; tab-separated
# (a bar is part of the text a plant removes)
plants() {
  cat <<'PLANTS'
finished	src/schedule/schedule.c	return same == GSEC_ERR_MISMATCH ? GTLS_ERR_FINISHED : gtls_from_gsec(same);	return GTLS_OK;	testNegative
certificate-verify	src/client/client.c	if (verdict != GCERT_OK) {	if (0) {	testNegative
downgrade	src/client/client.c	if (len >= 34u \&\& gtls_msg_downgrade_sentinel(body + 2) != 0) {	if (0) {	testNegative
host	src/client/verify.c	return GTLS_ERR_CERT_HOST;	return GTLS_OK;	testNegative
purpose	src/client/verify.c	if (gcert_x509_purpose(\&leaf, GCERT_X509_EKU_SERVER_AUTH) != GCERT_OK) {	if (0) {	testNegative
key-schedule-label	src/schedule/schedule.c	"c hs traffic"	"s hs traffic"	testRfc8448
transcript-restart	src/client/client.c	result = gtls_transcript_restart(\&c->sec.transcript, hash);	result = GTLS_OK;	testRfc8448
message-size-cap	src/client/client.c	if (body > c->limits.max_handshake_message) {	if (0) {	testNegative
wipe-on-failure	src/client/client.c	(void)gsec_wipe(\&c->sec, sizeof c->sec);\n}\n\nstatic GTLS_Result fail	(void)c;\n}\n\nstatic GTLS_Result fail	testNegative
epoch-rule	src/client/client.c	if (epoch != expected_epoch(c->state)) {	if (0) {	testNegative
share-group	src/client/client.c	if (sh.group != (unsigned)c->share_group) {	if (0) {	testNegative
scalar-range	src/client/client.c	return (int)(borrow & (((acc | (0u - acc)) >> 31) & 1u));	return 1;	testClient
chain-verdict	src/client/verify.c	case GCERT_ERR_MISMATCH:\n      switch (chain.failure) {	case GCERT_ERR_MISMATCH:\n      if (1) {\n        break;\n      }\n      switch (chain.failure) {	testNegative
session-id-echo	src/client/client.c	sh.session_id_len != c->session_id_len \|\|	0 \|\|	testClient
PLANTS
}

copy_tree() {
  rm -rf "$scratch/tree"
  mkdir -p "$scratch/tree"
  (cd "$root" && git ls-files -co --exclude-standard -z | xargs -0 -I{} cp --parents {} "$scratch/tree/")
}

run_test() {
  (cd "$scratch/tree" && make "build/linux/release/apps/$1" PREFIX="$PREFIX" -j4 >/dev/null 2>&1 &&
    LD_LIBRARY_PATH="build/linux/release/apps:$PREFIX/lib/ghoti.io" \
      "build/linux/release/apps/$1" --gtest_brief=1 >"$scratch/out.txt" 2>&1)
}

status=0
want="$*"
tab=$(printf '\t')
plants | while IFS="$tab" read -r name file from to test; do
  if [ -n "$want" ] && ! echo " $want " | grep -q " $name "; then
    continue
  fi
  copy_tree
  if ! run_test "$test"; then
    echo "controls: $name: $test fails BEFORE the plant, so nothing was measured" >&2
    tail -5 "$scratch/out.txt" >&2
    echo FAIL >"$scratch/status"
    continue
  fi
  python3 - "$scratch/tree/$file" "$from" "$to" <<'PY' || { echo "controls: $name: the plant did not apply" >&2; echo FAIL >"$scratch/status"; continue; }
import sys
path, old, new = sys.argv[1:4]
old = old.replace("\\&", "&").replace("\\|", "|").replace("\\n", "\n")
new = new.replace("\\&", "&").replace("\\|", "|").replace("\\n", "\n")
s = open(path).read()
if s.count(old) != 1:
    sys.exit("expected exactly one match, found %d" % s.count(old))
open(path, "w").write(s.replace(old, new))
PY
  if run_test "$test"; then
    echo "controls: $name: $test still PASSES with the check removed" >&2
    echo FAIL >"$scratch/status"
  else
    echo "controls: $name: $test fails with the check removed, and passes with it"
  fi
done
[ -f "$scratch/status" ] && status=1
exit $status
