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
message-size-cap	src/client/client.c	if (body > c->limits.max_handshake_message \|\|	if (0 \|\|	testNegative
wipe-on-failure	src/client/client.c	(void)gsec_wipe(\&c->sec, sizeof c->sec);\n}\n\nGTLS_Result gtls_conn_fail	(void)c;\n}\n\nGTLS_Result gtls_conn_fail	testNegative
epoch-rule	src/client/client.c	if (epoch != gtls_conn_expected_epoch(c->state)) {	if (0) {	testNegative
share-group	src/client/client.c	if (sh.group != (unsigned)c->share_group) {	if (0) {	testNegative
scalar-range	src/client/client.c	return (int)(borrow & (((acc | (0u - acc)) >> 31) & 1u));	return 1;	testClient
chain-verdict	src/client/verify.c	case GCERT_ERR_MISMATCH:\n      switch (chain.failure) {	case GCERT_ERR_MISMATCH:\n      if (1) {\n        break;\n      }\n      switch (chain.failure) {	testNegative
session-id-echo	src/client/client.c	sh.session_id_len != c->session_id_len \|\|	0 \|\|	testClient
record-nonce	src/record/record.c	nonce[GTLS_IV_LEN - 1u - i] ^= (unsigned char)(k->seq >> (8u * i));	(void)i;	testRecord
record-nonce-byte-order	src/record/record.c	(unsigned char)(k->seq >> (8u * i));	(unsigned char)(k->seq >> (8u * (7u - i)));	testRecord
traffic-update-label	src/record/record.c	"traffic upd"	"traffic upx"	testRecord
record-padding-strip	src/record/record.c	for (i = body; i > 0 \&\& pt[i - 1u] == 0; i--) {	for (i = body; i > 0 \&\& 0; i--) {	testRecord
record-padding-cap	src/record/record.c	if (pad > max_padding \|\| i - 1u > GTLS_RECORD_PLAIN_MAX) {	if (0) {	testRecord
record-seq-limit	src/record/record.c	if (k->seq >= k->limit) {\n    return GTLS_ERR_LIMIT;\n  }\n  if (out->err != GTLS_OK) {	if (0) {\n    return GTLS_ERR_LIMIT;\n  }\n  if (out->err != GTLS_OK) {	testRecord
record-type-zero	src/record/record.c	(void)gsec_wipe(pt, body);\n    return GTLS_ERR_PROTOCOL;	(void)gsec_wipe(pt, body);\n    return GTLS_ERR_MISMATCH;	testRecord
record-authentication	src/record/record.c	if (result != GTLS_OK) {\n    (void)gsec_wipe(pt, body);\n    return result;\n  }	if (0) {\n    (void)gsec_wipe(pt, body);\n    return result;\n  }	testRecord
record-overflow	src/client/stream.c	if (len > GTLS_RECORD_CIPHERTEXT_MAX \|\|	if (0 \|\|	testStream
stream-truncation	src/client/stream.c	return gtls_conn_fail(c, GTLS_ERR_TRUNCATED, GTLS_ALERT_NONE);	return GTLS_OK;	testStream
stream-ccs-limit	src/client/stream.c	\|\| ++c->ccs_seen > GTLS_CCS_MAX	\|\| 0	testStream
key-update-answer	src/client/stream.c	if (request == 1u \&\& c->ku_queued == 0) {	if (0) {	testStream
key-update-limit	src/client/stream.c	if (c->sec.wr.seq + 1u >= c->sec.wr.limit) {	if (0) {	testStream
bad-record-mac-alert	src/client/stream.c	return gtls_conn_fail(c, result, GTLS_ALERT_BAD_RECORD_MAC);	return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);	testStream
server-alpn-overlap	src/server/server.c	if (c->alpn_selected_len == 0) {\n      return gtls_conn_fail(c, GTLS_ERR_ALPN,	if (0) {\n      return gtls_conn_fail(c, GTLS_ERR_ALPN,	testServer
server-sni-match	src/server/server.c	return plen == hlen \&\& names_equal(pat, host, plen);	return 1;	testServer
server-client-finished	src/server/server.c	result = gtls_finished_check(hash, c->sec.schedule.c_hs, th, got, hlen);	result = GTLS_OK;	testServer
server-second-retry	src/server/server.c	/* The retry would need another retry, which RFC 8446 does not allow. */\n      return gtls_conn_unexpected(c);	/* The retry would need another retry, which RFC 8446 does not allow. */\n      return gtls_conn_illegal(c);	testServer
server-early-data	src/server/server.c	if (gtls_msg_find_ext(ch->exts, ch->ext_count, GTLS_EXT_EARLY_DATA) != NULL) {	if (0) {	testServer
server-version	src/server/server.c	if (!tls13) {	if (0) {	testServer
server-scheme-fits	src/server/server.c	gcert_key_scheme_fits((GCERT_SigScheme)s, id->key_kind)	1	testServer
server-cv-label	src/client/verify.c	static const char server_label[] = "TLS 1.3, server CertificateVerify";	static const char server_label[] = "TLS 1.3, client CertificateVerify";	testRfc8448
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
