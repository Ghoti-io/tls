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
key-update-answer	src/client/stream.c	if (request == 1u \&\& c->ku_queued == 0 \&\& !c->local_closed) {	if (0) {	testStream
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
plain-alert-connected	src/client/stream.c	!(type == GTLS_CT_ALERT \&\& c->state != GTLS_STATE_CONNECTED \&\& len == 2u)	!(type == GTLS_CT_ALERT \&\& len == 2u)	testEdges
plain-alert-length	src/client/stream.c	c->state != GTLS_STATE_CONNECTED \&\& len == 2u	c->state != GTLS_STATE_CONNECTED	testEdges
plain-alert-clean-close	src/client/stream.c	if (!authenticated) {	if (0) {	testEdges
fragment-interleave	src/client/stream.c	if (c->in.len != 0 \&\& (type == GTLS_CT_CHANGE_CIPHER_SPEC \|\| type == GTLS_CT_ALERT)) {	if (0) {	testEdges
fragment-alert-inner	src/client/stream.c	      if (c->in.len != 0) {\n        result = gtls_conn_unexpected(c);	      if (0) {\n        result = gtls_conn_unexpected(c);	testEdges
fragment-app-data	src/client/stream.c	if (c->state != GTLS_STATE_CONNECTED \|\| c->in.len != 0) {	if (c->state != GTLS_STATE_CONNECTED) {	testEdges
key-update-last	src/client/client.c	        (was_key_update \&\& c->mode == GTLS_MODE_STREAM))) {	        0)) {	testEdges
key-update-after-close	src/client/stream.c	c->ku_queued == 0 \&\& !c->local_closed) {	c->ku_queued == 0) {	testEdges
key-update-run-reset	src/client/stream.c	c->ku_run = 0; /* data between updates: they are not a flood */	(void)0;	testEdges
key-update-queued-count	src/client/stream.c	    if (c->ku_queued > 0) {\n      c->ku_queued--;\n    }	    if (c->ku_queued > 0) {\n    }	testEdges
key-update-answer-once	src/client/stream.c	if (request == 1u \&\& c->ku_queued == 0 \&\& !c->local_closed) {	if (request == 1u \&\& !c->local_closed) {	testEdges
server-alert-key	src/client/stream.c	(c->state == GTLS_STATE_CONNECTED \|\| c->state == GTLS_STATE_S_WAIT_FIN)) {	(c->state == GTLS_STATE_CONNECTED)) {	testEdges
client-dummy-record	src/client/stream.c	if (c->role == GTLS_ROLE_CLIENT \&\& c->context->middlebox_compat) {	if (0) {	testEdges
alpn-bytes	src/server/server.c	o->alpn[k].len == n \&\& gsec_equal(o->alpn[k].p, x->alpn + off + 1u, n) == GSEC_OK	o->alpn[k].len == n	testEdges
alpn-length	src/server/server.c	o->alpn[k].len == n \&\& gsec_equal(	gsec_equal(	testEdges
retry-suites	src/server/server.c	gsec_equal(first.suites, o->ch.suites, first.suites_len) != GSEC_OK \|\|	0 \|\|	testEdges
retry-extension-bytes	src/server/server.c	b == NULL \|\| a->len != b->len \|\| gsec_equal(a->data, b->data, a->len) != GSEC_OK	b == NULL \|\| a->len != b->len	testEdges
retry-extension-length	src/server/server.c	b == NULL \|\| a->len != b->len \|\| gsec_equal(a->data, b->data, a->len) != GSEC_OK	b == NULL \|\| gsec_equal(a->data, b->data, a->len < b->len ? a->len : b->len) != GSEC_OK	testEdges
context-chain-count	src/client/context.c	in->chain_count > GTLS_CERT_MAX \|\|	0 \|\|	testEdges
context-chain-empty	src/client/context.c	in->chain[i] == NULL \|\| in->chain_lens[i] == 0 \|\|	in->chain[i] == NULL \|\|	testEdges
context-chain-total	src/client/context.c	in->chain_lens[i] > 0xffffffu - total) {	0) {	testEdges
context-chain-fit	src/client/context.c	if (msg + 1024u > x->limits.max_output_bytes) {	if (0) {	testEdges
context-hello-cap	src/client/context.c	config->limits->max_client_hello > GTLS_HELLO_MAX - 4u) {	0) {	testEdges
sni-exact-first	src/server/server.c	    if (plen == hlen \&\& names_equal(pat, host, plen)) {\n      return 2;	    if (0) {\n      return 2;	testEdges
sni-fallback	src/server/server.c	        if (s != 0) {\n          c->identity_index = i;	        if (1) {\n          c->identity_index = i;	testEdges
sni-first-match	src/server/server.c	          found = 1;\n          break;	          found = 1;	testEdges
sni-length	src/server/server.c	if (o->host.len > 255u) {	if (0) {	testEdges
seal-padding-wrap	src/record/record.c	padding > GTLS_RECORD_PLAIN_MAX + 256u - GTLS_RECORD_TAG - 1u - pt_len	pt_len + 1u + padding > GTLS_RECORD_PLAIN_MAX + 256u - GTLS_RECORD_TAG	testEdges
signer-length	src/server/server.c	if (result == GTLS_OK \&\& (*sig_len == 0 \|\| *sig_len > GCERT_SIG_MAX)) {	if (0) {	testEdges
handshake-key-limit	src/client/stream.c	epoch == GTLS_EPOCH_APPLICATION ? c->limits.max_records_per_key : 0	c->limits.max_records_per_key	testEdges
wire-room	src/client/client.c	2u * (size_t)c->limits.max_output_bytes + 4096u + GTLS_RECORD_HEADER +\n          GTLS_RECORD_CIPHER_MAX);	2u * (size_t)c->limits.max_output_bytes + 4096u);	testEdges
oom-in-flight	src/server/server.c	    (void)gsec_wipe(k->ecdhe, sizeof k->ecdhe);\n    return c->state == GTLS_STATE_FAILED ? result\n        : gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);	    (void)gsec_wipe(k->ecdhe, sizeof k->ecdhe);\n    return c->state == GTLS_STATE_FAILED ? result\n        : gtls_conn_fail(c, GTLS_ERR_INTERNAL, GTLS_ALERT_INTERNAL_ERROR);	testAlloc
oom-in-record-buffer	src/client/stream.c	      *consumed = pos;\n      return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);	      *consumed = pos;\n      return gtls_conn_fail(c, GTLS_ERR_INTERNAL, GTLS_ALERT_INTERNAL_ERROR);	testAlloc
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
if [ "${1:-}" = "--anchors" ]; then
  # Fast and needs no build: every plant's text is in the tree exactly once,
  # so a plant that stopped applying (the code moved) fails `make test` rather
  # than going quietly unmeasured.
  plants | python3 -c '
import sys
root = sys.argv[1]
bad = 0
n = 0
for line in sys.stdin:
    line = line.rstrip("\n")
    if not line:
        continue
    name, path, old = line.split("\t")[:3]
    old = old.replace("\\&", "&").replace("\\|", "|").replace("\\n", "\n")
    text = open(root + "/" + path).read()
    n += 1
    if text.count(old) != 1:
        print("controls: %s: its text occurs %d times in %s (stale plant)" % (name, text.count(old), path), file=sys.stderr)
        bad = 1
if n < 40:
    print("controls: only %d plants" % n, file=sys.stderr)
    bad = 1
print("controls: %d plants, each applying exactly once" % n)
sys.exit(bad)
' "$root"
  exit $?
fi
: "${PREFIX:?set PREFIX to the prefix holding cutil, security and certificate}"
scratch=$(mktemp -d "${TMPDIR:-/tmp}/gtls-controls.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
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
