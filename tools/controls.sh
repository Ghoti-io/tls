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
# The checks listed in plants() below are each removed, one at a time, and the
# test that is meant to catch the absence must start failing. Those are the
# ones planted, not every check in the library. A control that does not fail
# means the test accepts the very thing the check was there to refuse.
#
#   PREFIX=/path/to/prefix tools/controls.sh [name...]
#   tools/controls.sh --anchors
#
# It is incremental, because a full copy-and-build per plant took minutes and
# made the committed gate too slow to run:
#
#   1. The tree is copied once into a scratch directory and the test binaries
#      the plants name are built once, against PREFIX.
#   2. Each distinct test (binary, filter, memory checker) is run unplanted
#      once. A failure there is the build's, and every plant that uses it is
#      reported as nothing measured.
#   3. A plant changes the one source file in the scratch copy, rebuilds the
#      one object that changed and relinks the one test binary it runs, runs
#      the test, and puts the file and its pristine object back. The next
#      plant therefore starts from a state that was built from the real source.
#
# The result of each plant is one of: caught (the test fails with the check
# removed), SURVIVED (it passes), or ERROR (the baseline fails, the text does
# not apply exactly once, the planted copy does not build, the test runs for
# more than $CONTROLS_TIMEOUT seconds (600 by default), it dies of a signal outside a matching test, or
# it exits non-zero without any gtest test reporting FAILED, or only one outside
# the plant's filter does: a broken scratch tree must not be credited with a
# catch, so a hang is an ERROR, never a failed test; a crash is a catch only when the last test gtest announced with [ RUN ] never reported and it matches the plant's filter or expect, and is printed as caught by crash in that test). A caught plant
# prints the test that caught it. The exit status is non-zero for
# any SURVIVED or ERROR, and the last line says how many of each and how long
# it took. CONTROLS_VERBOSE=N prints the first N failure lines of each caught plant.

set -u

root=$(cd "$(dirname "$0")/.." && pwd)
start=$(date +%s)

# name, file, text removed, text put in its place, test binary; tab-separated
# (a bar is part of the text a plant removes). Three optional fields follow: a
# gtest filter, and "valgrind" to run the filtered test under Valgrind; and a
# last one, a gtest name glob that must be among the tests that fail (the
# filter, when there is one, is the default), for a plant that runs a whole
# binary. "valgrind" is for a check whose removal changes no result but lets the code read
# past the end of its input (a later check refuses what was read), which only a
# memory checker sees.
plants() {
  if [ -n "${CONTROLS_PLANTS_FILE:-}" ]; then
    # For testing this runner itself: these rows, in the same format, instead.
    cat "$CONTROLS_PLANTS_FILE"
    return
  fi
  cat <<'PLANTS'
finished	src/schedule/schedule.c	        : (same == GSEC_ERR_MISMATCH ? GTLS_ERR_FINISHED : gtls_from_gsec(same));	        : GTLS_OK;	testNegative
certificate-verify	src/client/client.c	if (verdict != GCERT_OK) {	if (verdict != GCERT_OK \&\& 0) {	testNegative
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
record-padding-cap	src/record/record.c	if (pad > max_padding \|\| i - 1u > GTLS_RECORD_PLAIN_MAX) {	if ((pad > max_padding \|\| i - 1u > GTLS_RECORD_PLAIN_MAX) \&\& 0) {	testRecord
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
server-client-finished	src/server/server.c	result = gtls_finished_check(hash, c->sec.schedule.c_hs, c->scratch.th, got, hlen,\n        \&c->scratch.mac);	result = GTLS_OK;	testServer
server-second-retry	src/server/server.c	/* The retry would need another retry, which RFC 8446 does not allow. */\n      return gtls_conn_unexpected(c);	/* The retry would need another retry, which RFC 8446 does not allow. */\n      return gtls_conn_illegal(c);	testServer
server-version	src/server/server.c	if (!tls13) {	if (0) {	testServer
server-scheme-fits	src/server/server.c	gcert_key_scheme_fits((GCERT_SigScheme)s, id->key_kind)	(id->key_kind \|\| 1)	testServer
server-cv-label	src/client/verify.c	static const char server_label[] = "TLS 1.3, server CertificateVerify";	static const char server_label[] = "TLS 1.3, client CertificateVerify";	testRfc8448
plain-alert-connected	src/client/stream.c	!(type == GTLS_CT_ALERT \&\& c->state != GTLS_STATE_CONNECTED \&\& len == 2u)	!(type == GTLS_CT_ALERT \&\& len == 2u)	testEdges
plain-alert-length	src/client/stream.c	c->state != GTLS_STATE_CONNECTED \&\& len == 2u	c->state != GTLS_STATE_CONNECTED	testEdges
plain-alert-clean-close	src/client/stream.c	if (!authenticated) {	if (!authenticated \&\& 0) {	testEdges
fragment-interleave	src/client/stream.c	if (c->in.len != 0 \&\& (type == GTLS_CT_CHANGE_CIPHER_SPEC \|\| type == GTLS_CT_ALERT)) {	if (0) {	testEdges
fragment-alert-inner	src/client/stream.c	      if (c->in.len != 0) {\n        result = gtls_conn_unexpected(c);	      if (0) {\n        result = gtls_conn_unexpected(c);	testEdges
fragment-app-data	src/client/stream.c	if (c->state != GTLS_STATE_CONNECTED \|\| c->in.len != 0) {	if (c->state != GTLS_STATE_CONNECTED) {	testEdges
key-update-last	src/client/client.c	        (was_key_update \&\& c->mode == GTLS_MODE_STREAM))) {	(was_key_update \&\& 0))) {	testEdges
key-update-after-close	src/client/stream.c	c->ku_queued == 0 \&\& !c->local_closed) {	c->ku_queued == 0) {	testEdges
key-update-run-reset	src/client/stream.c	c->ku_run = 0; /* data between updates: they are not a flood */	(void)0;	testEdges
key-update-queued-count	src/client/stream.c	      if (c->ku_queued > 0) {\n        c->ku_queued--;\n      }	      if (c->ku_queued > 0) {\n      }	testEdges
key-update-answer-once	src/client/stream.c	if (request == 1u \&\& c->ku_queued == 0 \&\& !c->local_closed) {	if (request == 1u \&\& !c->local_closed) {	testEdges
server-alert-key	src/client/stream.c	(c->state == GTLS_STATE_CONNECTED \|\| c->state == GTLS_STATE_S_WAIT_FIN \|\|\n          c->state == GTLS_STATE_S_WAIT_EOED)) {	(c->state == GTLS_STATE_CONNECTED \|\| c->state == GTLS_STATE_S_WAIT_FIN)) {	testEarly	EarlyClose.*
client-dummy-record	src/client/stream.c	if (c->role == GTLS_ROLE_CLIENT \&\& c->context->middlebox_compat) {	if (0) {	testEdges
alpn-bytes	src/server/server.c	o->alpn[k].len == n \&\& gsec_equal(o->alpn[k].p, x->alpn + off + 1u, n) == GSEC_OK	o->alpn[k].len == n	testEdges
alpn-length	src/server/server.c	o->alpn[k].len == n \&\& gsec_equal(	gsec_equal(	testEdges
retry-suites	src/server/server.c	gsec_equal(first.suites, o->ch.suites, first.suites_len) != GSEC_OK \|\|	0 \|\|	testEdges
retry-extension-bytes	src/server/server.c	b == NULL \|\| a->len != b->len \|\| gsec_equal(a->data, b->data, a->len) != GSEC_OK	b == NULL \|\| a->len != b->len	testEdges
retry-extension-length	src/server/server.c	b == NULL \|\| a->len != b->len \|\| gsec_equal(a->data, b->data, a->len) != GSEC_OK	b == NULL \|\| gsec_equal(a->data, b->data, a->len < b->len ? a->len : b->len) != GSEC_OK	testEdges
context-chain-count	src/client/context.c	in->chain_count > GTLS_CERT_MAX \|\|	0 \|\|	testEdges
context-chain-empty	src/client/context.c	in->chain[i] == NULL \|\| in->chain_lens[i] == 0 \|\|	in->chain[i] == NULL \|\|	testEdges
context-chain-total	src/client/context.c	in->chain_lens[i] > 0xffffffu - total) {	0) {	testEdges
context-chain-fit	src/client/context.c	if (msg + 1024u > x->limits.max_output_bytes) {	if (msg + 1024u > x->limits.max_output_bytes \&\& 0) {	testEdges
context-hello-cap	src/client/context.c	config->limits->max_client_hello > GTLS_HELLO_MAX - 4u) {	0) {	testEdges
sni-exact-first	src/server/server.c	    if (plen == hlen \&\& names_equal(pat, host, plen)) {\n      return 2;	    if (0) {\n      return 2;	testEdges
sni-fallback	src/server/server.c	        if (s != 0) {\n          c->identity_index = i;	        if (1) {\n          c->identity_index = i;	testEdges
sni-first-match	src/server/server.c	          found = 1;\n          break;	          found = 1;	testEdges
sni-length	src/server/server.c	if (o->host.len > 255u) {	if (0) {	testEdges
seal-padding-wrap	src/record/record.c	padding > GTLS_RECORD_PLAIN_MAX + 256u - GTLS_RECORD_TAG - 1u - pt_len	pt_len + 1u + padding > GTLS_RECORD_PLAIN_MAX + 256u - GTLS_RECORD_TAG	testEdges
signer-length	src/server/server.c	if (result == GTLS_OK \&\& (*sig_len == 0 \|\| *sig_len > GCERT_SIG_MAX)) {	if (0) {	testEdges
handshake-key-limit	src/client/stream.c	epoch == GTLS_EPOCH_APPLICATION ? c->limits.max_records_per_key : 0	c->limits.max_records_per_key	testEdges
wire-room	src/client/client.c	2u * (size_t)c->limits.max_output_bytes + 4096u + GTLS_RECORD_HEADER +\n          GTLS_RECORD_CIPHER_MAX);	2u * (size_t)c->limits.max_output_bytes + 4096u);	testEdges
oom-in-flight	src/server/server.c	  if (result != GTLS_OK) {\n    return c->state == GTLS_STATE_FAILED ? result\n        : gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);\n  }\n  result = gtls_transcript_snapshot(\&c->sec.transcript, hash, k->th);\n  if (result == GTLS_OK) {\n    result = resumed	  if (result != GTLS_OK) {\n    return c->state == GTLS_STATE_FAILED ? result\n        : gtls_conn_fail(c, GTLS_ERR_INTERNAL, GTLS_ALERT_INTERNAL_ERROR);\n  }\n  result = gtls_transcript_snapshot(\&c->sec.transcript, hash, k->th);\n  if (result == GTLS_OK) {\n    result = resumed	testAlloc
oom-in-record-buffer	src/client/stream.c	      *consumed = pos;\n      return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);	      *consumed = pos;\n      return gtls_conn_fail(c, GTLS_ERR_INTERNAL, GTLS_ALERT_INTERNAL_ERROR);	testAlloc
psk-last	src/server/server.c	if (ch->exts[ch->ext_count - 1u].type != GTLS_EXT_PRE_SHARED_KEY) {	if (0) {	testPsk
psk-modes-present	src/server/server.c	if (modes == NULL) {\n      return missing(c);	if (modes == NULL) {\n      return gtls_conn_illegal(c);	testPsk
psk-offer-parsed	src/server/server.c	result = gtls_msg_parse_ch_psk_offer(e, \&c->limits, \&o->psk_offer);	result = GTLS_OK; (void)o->psk_offer;	testPsk
psk-count-equal	src/msg/msg.c	if (n_ids != n_binders) {	if (0) {	testPsk
psk-count-cap	src/msg/msg.c	++n_ids > limits->max_tickets	(++n_ids > limits->max_tickets \&\& 0)	testTicket
psk-binder-length	src/msg/msg.c	result = gtls_reader_vector(\&binders, 1, 32, 0, \&binder);	result = gtls_reader_vector(\&binders, 1, 0, 0, \&binder);	testPsk
early-data-empty	src/msg/msg.c	return e->len == 0 ? GTLS_OK : GTLS_ERR_CORRUPT;	(void)e->len; return GTLS_OK;	testPsk
early-data-seen	src/server/server.c	c->early_skip = 1;	(void)0;	testPsk
early-skip-needs-offer	src/client/stream.c	result == GTLS_ERR_MISMATCH \&\& c->early_skip \&\&	result == GTLS_ERR_MISMATCH \&\&	testPsk
early-skip-ends-on-open	src/client/stream.c	c->early_skip = 0; /* a record that opens ends the early data */	(void)0;	testPsk
early-skip-cap	src/client/stream.c	if (cost > budget - c->early_skipped) {	if (0) {	testPsk
early-skip-after-retry	src/client/stream.c	if (c->early_skip \&\& epoch == GTLS_EPOCH_INITIAL \&\& type == GTLS_CT_APPLICATION_DATA) {	if (0) {	testPsk
early-skip-header	src/client/stream.c	!(c->early_skip \&\& type == GTLS_CT_APPLICATION_DATA)	1	testPsk
retry-early-data	src/server/server.c	if (o->early_data) {\n    return gtls_conn_illegal(c);	if (0) {\n    return gtls_conn_illegal(c);	testPsk
retry-ends-skip	src/server/server.c	    c->early_skip = 0;\n  } else {	    (void)0;\n  } else {	testPsk
retry-may-drop-early-data	src/server/server.c	a->type == GTLS_EXT_EARLY_DATA \|\|	0 \|\|	testPsk
retry-may-refresh-psk	src/server/server.c	a->type == GTLS_EXT_PRE_SHARED_KEY) {	0) {	testPsk
psk-count-cap-edge	src/msg/msg.c	++n_ids > limits->max_tickets	++n_ids >= limits->max_tickets	testPsk
psk-binder-cap	src/msg/msg.c	++n_binders > limits->max_tickets	(++n_binders > limits->max_tickets \&\& 0)	testPsk
psk-binder-cap-edge	src/msg/msg.c	++n_binders > limits->max_tickets	++n_binders >= limits->max_tickets	testPsk
psk-empty-identity	src/msg/msg.c	gtls_reader_vector(\&ids, 2, 1, 0, \&identity)	gtls_reader_vector(\&ids, 2, 0, 0, \&identity)	testPsk
psk-ids-min-high	src/msg/msg.c	gtls_reader_vector(\&r, 2, 7, 0, \&ids)	gtls_reader_vector(\&r, 2, 8, 0, \&ids)	testPsk
psk-ids-min-zero	src/msg/msg.c	gtls_reader_vector(\&r, 2, 7, 0, \&ids)	gtls_reader_vector(\&r, 2, 0, 0, \&ids)	testPsk
psk-binder-31	src/msg/msg.c	gtls_reader_vector(\&binders, 1, 32, 0, \&binder)	gtls_reader_vector(\&binders, 1, 31, 0, \&binder)	testPsk
psk-modes-parse-result	src/server/server.c	result = gtls_msg_parse_ch_psk_modes(modes, \&o->psk_dhe);\n    if (result != GTLS_OK) {	result = gtls_msg_parse_ch_psk_modes(modes, \&o->psk_dhe);\n    if (0) {	testPsk
early-data-parse-result	src/server/server.c	result = gtls_msg_parse_ch_early_data(e);\n    if (result != GTLS_OK) {	result = gtls_msg_parse_ch_early_data(e);\n    if (0) {	testPsk
early-data-needs-psk	src/server/server.c	    if (o.early_data \&\& o.psk) {	    if (o.early_data) {	testPsk
early-limit-resolve	src/core/core.c	  GTLS_RESOLVE_ZERO(max_early_skip_bytes)\n	  (void)0;\n	testPsk
early-skip-only-mismatch	src/client/stream.c	if (result == GTLS_ERR_MISMATCH \&\& c->early_skip	if (result != GTLS_OK \&\& c->early_skip	testPsk
early-skip-header-type	src/client/stream.c	!(c->early_skip \&\& type == GTLS_CT_APPLICATION_DATA)	!c->early_skip	testPsk
early-skip-seq-advance	src/client/stream.c	      return skip_early(c, blen);\n    }\n    if (result == GTLS_ERR_MISMATCH \&\& c->state == GTLS_STATE_S_WAIT_EOED \&\&	      c->sec.rd.seq++;\n      return skip_early(c, blen);\n    }\n    if (result == GTLS_ERR_MISMATCH \&\& c->state == GTLS_STATE_S_WAIT_EOED \&\&	testPsk
early-skip-pending-fragment	src/client/stream.c	and early data is not that. */\n    return gtls_conn_unexpected(c);	and early data is not that. */\n    (void)0;	testPsk
binder-check	src/server/server.c	    result = gtls_binder_check(hash,	    result = GTLS_OK; (void)gtls_binder_check(hash,	testResume
binder-compare	src/schedule/schedule.c	        : (same == GSEC_ERR_MISMATCH ? GTLS_ERR_MISMATCH : gtls_from_gsec(same));	        : GTLS_OK;	testTicket
binder-length	src/schedule/schedule.c	if (got_len != hlen) {\n    return GTLS_ERR_MISMATCH;	if (0 \&\& got_len != hlen) {\n    return GTLS_ERR_MISMATCH;	testResume
binder-transcript	src/server/server.c	o->psk_trunc, c->scratch.th);	o->psk_trunc - 1u, c->scratch.th);	testResume
ticket-key-name	src/session/ticket.c	gsec_equal(keys[i].name, ticket, GTLS_TICKET_KEY_NAME_LEN) == GSEC_OK) {	1) {	testTicket
ticket-key-expiry	src/session/ticket.c	if (now < keys[i].not_after \&\&	if ((now < keys[i].not_after \|\| 1) \&\&	testTicket
ticket-sealing-newest	src/session/ticket.c	(best == NULL \|\| keys[i].not_before > best->not_before)	(best == NULL)	testTicket
ticket-sealing-window	src/session/ticket.c	if (keys[i].not_before <= now \&\& now < keys[i].not_after \&\&	if (now < keys[i].not_after \&\&	testTicket
ticket-state-version	src/session/ticket.c	  if (version != GTLS_TICKET_STATE_VERSION \&\& version != GTLS_TICKET_STATE_VERSION_EARLY) {	  if (0) {	testTicket
ticket-state-lifetime	src/session/ticket.c	  if (t->lifetime > GTLS_TICKET_LIFETIME_MAX) {	  if (0) {	testTicket
ticket-state-exact	src/session/ticket.c	if (n - at != t->sni_len) {	if (n - at < t->sni_len) {	testTicket
ticket-fresh-lifetime	src/session/ticket.c	if (elapsed_s >= p->lifetime) {	if (0) {	testTicket
ticket-fresh-window	src/session/ticket.c	return diff <= (int64_t)window_ms;	return diff <= (int64_t)window_ms \|\| 1;	testTicket
ticket-fresh-age-add	src/session/ticket.c	client_ms = (int64_t)(uint32_t)(obfuscated_age - p->age_add);	client_ms = (int64_t)obfuscated_age;	testTicket
ticket-fresh-future	src/session/ticket.c	if (elapsed_s > GTLS_TICKET_AGE_WINDOW_MAX) {	if (0) {	testTicket
ticket-fresh-lifetime-max	src/session/ticket.c	if (p->lifetime > GTLS_TICKET_LIFETIME_MAX) {\n    return 0;	if (0) {\n    return 0;	testTicket
resume-sni	src/server/server.c	t->sni_len == o->host.len \&\& names_equal(t->sni, o->host.p, t->sni_len) \&\&	1 \&\&	testResume
resume-alpn	src/server/server.c	(t->alpn_len == 0 \|\| offered_alpn(o, t->alpn, t->alpn_len));	1;	testResume
resume-suite-context	src/server/server.c	offered_suite(o, t->suite) \&\& context_suite(x, t->suite) \&\&	offered_suite(o, t->suite) \&\& 1 \&\&	testResume
resume-suite-offered	src/server/server.c	good = offered_suite(o, t->suite) \&\& context_suite(x, t->suite) \&\&	good = 1 \&\& context_suite(x, t->suite) \&\&	testResume
resume-fresh	src/server/server.c	gtls_ticket_fresh(t, now, en->age, x->ticket_age_window * 1000u) \&\&	1 \&\&	testResume
resume-dhe	src/server/server.c	if (!o->psk \|\| !o->psk_dhe \|\| x->ticket_key_count == 0) {	if (!o->psk \|\| x->ticket_key_count == 0) {	testResume
resume-retry-suite	src/server/server.c	if (second \&\& r->active \&\& r->plain.suite != (uint32_t)c->suite) {	if (0) {	testResume
resume-suite-choice	src/server/server.c	} else if (r->active) {\n    c->suite = (GTLS_Suite)r->plain.suite;	} else if (0) {\n    c->suite = (GTLS_Suite)r->plain.suite;	testResume
resume-needs-no-scheme	src/server/server.c	if (c->scheme == 0 \&\& !r->active) {	if (c->scheme == 0) {	testResume
resume-no-certificate	src/server/server.c	if (!resumed) {\n    result = send_authentication	if (1) {\n    result = send_authentication	testResume
resume-selects-psk	src/server/server.c	sp.psk = resumed;	sp.psk = 0;	testResume
resume-early-secret	src/server/server.c	result = resumed ? gtls_schedule_early_psk(	result = 0 ? gtls_schedule_early_psk(	testResume
ticket-resumption-secret-server	src/server/server.c	result = gtls_schedule_keep_resumption(\&c->sec.schedule, c->scratch.th);	result = gtls_schedule_keep_resumption(\&c->sec.schedule, c->sec.schedule.c_hs);	testResume
ticket-nonce	src/server/server.c	unsigned char nonce = (unsigned char)i;	unsigned char nonce = 0;	testResume
ticket-count	src/server/server.c	for (i = 0; i < x->ticket_count; i++) {	for (i = 0; i < x->ticket_count + 1u; i++) {	testResume
ticket-lifetime-sent	src/server/server.c	t.lifetime = p->lifetime;	t.lifetime = 0;	testResume
ticket-age-add-sent	src/server/server.c	t.age_add = p->age_add;	t.age_add = 0;	testResume
client-binder	src/client/client.c	result = patch_binder(c, \&empty, \&c->hello);	result = GTLS_OK;	testResume
client-binder-retry	src/client/client.c	result = patch_binder(c, \&c->sec.transcript, \&h2);	result = GTLS_OK;	testResume
client-retry-hash	src/client/client.c	if (hash == gtls_suite_hash(c->offer->suite)) {	if (1) {	testResume
client-age	src/client/client.c	return (uint32_t)(elapsed * 1000u) + s->age_add;	return (uint32_t)(elapsed * 1000u);	testResume
client-psk-index	src/client/client.c	sh.psk_identity != 0 \|\|	0 \|\|	testResume
client-psk-hash	src/client/client.c	gtls_suite_hash(sh.suite) != offered_hash(c)	0	testResume
client-skips-certificate	src/client/client.c	c->state = c->resumed ? GTLS_STATE_WAIT_FIN : GTLS_STATE_WAIT_CERT;	c->state = GTLS_STATE_WAIT_CERT;	testResume
client-lifetime-zero	src/client/client.c	if (t.lifetime == 0) {	if (0) {	testResume
client-lifetime-cap	src/client/client.c	s->lifetime = t->lifetime < GTLS_TICKET_LIFETIME_MAX ? t->lifetime : GTLS_TICKET_LIFETIME_MAX;	s->lifetime = t->lifetime;	testResume
ticket-resumption-secret-client	src/client/client.c	result = gtls_schedule_keep_resumption(\&c->sec.schedule, c->scratch.th);	result = gtls_schedule_keep_resumption(\&c->sec.schedule, c->sec.schedule.c_hs);	testResume
session-host-length	src/session/session.c	session->host_len != c->host_len \|\|	0 \|\|	testResume
session-host-name	src/session/session.c	!names_match(session->host, c->host, c->host_len)) {	0) {	testResume
session-suite-offered	src/session/session.c	if (!offered) {	if (!offered \&\& 0) {	testResume
session-expiry	src/session/session.c	(uint64_t)unix_time - (uint64_t)session->received >= session->lifetime) {	(uint64_t)unix_time - (uint64_t)session->received > session->lifetime) {	testResume
session-digest	src/session/session.c	if (gsec_equal(digest, p + at + ticket_len, GSEC_SHA256_DIGEST_LEN) != GSEC_OK) {	if (0) {	testTicket
session-version	src/session/session.c	if (p[0] != SESSION_VERSION) {	if (0) {	testTicket
session-ticket-limit	src/session/session.c	if (ticket_len > l.max_ticket_bytes) {	if (0) {	testTicket
session-psk-size	src/session/session.c	psk_len != gtls_hash_len(hash) \|\| host_len == 0 \|\|	host_len == 0 \|\|	testTicket
session-lifetime	src/session/session.c	r32(p + 3) > GTLS_TICKET_LIFETIME_MAX	0	testTicket
session-length-exact	src/session/session.c	if (len - at != ticket_len + GSEC_SHA256_DIGEST_LEN) {	if (len - at < ticket_len + GSEC_SHA256_DIGEST_LEN) {	testTicket
session-blob-bound	src/session/session.c	(size_t)l.max_ticket_bytes + GSEC_SHA256_DIGEST_LEN) {	(size_t)l.max_ticket_bytes + GSEC_SHA256_DIGEST_LEN + 1000000u) {	testTicket
context-ticket-window	src/client/context.c	config->ticket_keys[i].not_after <= config->ticket_keys[i].not_before	0	testTicket
context-ticket-duplicate	src/client/context.c	GTLS_TICKET_KEY_NAME_LEN) == GSEC_OK) {	GTLS_TICKET_KEY_NAME_LEN) != GSEC_OK) {	testTicket
context-ticket-lifetime	src/client/context.c	config->ticket_lifetime > GTLS_TICKET_LIFETIME_MAX \|\|	0 \|\|	testTicket
context-ticket-window-max	src/client/context.c	config->ticket_age_window > GTLS_TICKET_AGE_WINDOW_MAX) {	0) {	testTicket
context-ticket-count	src/client/context.c	if (config->ticket_count > c->limits.max_tickets) {	if (0) {	testTicket
context-ticket-fit	src/client/context.c	if (config->ticket_key_count != 0 \&\& c->limits.max_ticket_bytes < GTLS_TICKET_MAX) {	if (0) {	testTicket
context-ticket-keys-max	src/client/context.c	config->ticket_key_count > GTLS_TICKET_KEYS_MAX \|\|	0 \|\|	testTicket
context-ticket-client	src/client/context.c	if (config->role == GTLS_ROLE_CLIENT \&\&\n      (config->ticket_keys != NULL	if (0 \&\&\n      (config->ticket_keys != NULL	testTicket
stream-ticket-flush	src/client/stream.c	if (type == GTLS_HS_KEY_UPDATE) {\n      if (c->ku_queued > 0) {	if (type == GTLS_HS_KEY_UPDATE \|\| 1) {\n      if (c->ku_queued > 0) {	testResume
resumption-label	src/schedule/schedule.c	return gtls_hkdf_expand_label(hash, res_master, hlen, "resumption", nonce,	return gtls_hkdf_expand_label(hash, res_master, hlen, "resumptiox", nonce,	testTicket
binder-label	src/schedule/schedule.c	result = gtls_derive_secret(s->hash, s->early, s->hlen, "res binder", empty,	result = gtls_derive_secret(s->hash, s->early, s->hlen, "res binderx", empty,	testTicket
res-master-label	src/schedule/schedule.c	return gtls_derive_secret(s->hash, s->master, s->hlen, "res master",	return gtls_derive_secret(s->hash, s->master, s->hlen, "res masterx",	testTicket
psk-identity-oversize-fallback	src/msg/msg.c	if (++n_ids > limits->max_tickets) {	if (identity.len > limits->max_ticket_bytes \|\| ++n_ids > limits->max_tickets) {	testPsk
ticket-count-max	src/client/context.c	if (config->ticket_count > GTLS_TICKET_COUNT_MAX) {	if (0) {	testTicket
ticket-nonce-byte	src/server/server.c	unsigned char nonce = (unsigned char)i;	unsigned char nonce = (unsigned char)(i \& 0x7f);	testResume
session-expires-saturate	src/session/session.c	info->expires = s->received > INT64_MAX - (int64_t)s->lifetime\n      ? INT64_MAX : s->received + (int64_t)s->lifetime;	info->expires = s->received + (int64_t)s->lifetime;	testTicket
session-parse-overflow	src/session/session.c	r32(p + 3) > GTLS_TICKET_LIFETIME_MAX \|\|\n      (int64_t)r > INT64_MAX - (int64_t)r32(p + 3)) {	r32(p + 3) > GTLS_TICKET_LIFETIME_MAX \|\|\n      0) {	testTicket
client-ticket-oversize-discard	src/client/client.c	if (t.ticket_len > c->limits.max_ticket_bytes) {	if (0) {	testNegative
client-ticket-cap-edge	src/client/client.c	if (t.ticket_len > c->limits.max_ticket_bytes) {	if (t.ticket_len >= c->limits.max_ticket_bytes) {	testNegative
client-keep-needs-res	src/client/client.c	if (!c->sec.schedule.has_res) {	if (0) {	testResume
server-issue-needs-res	src/server/server.c	if (!c->sec.schedule.has_res) {	if (0) {	testResume
server-issue-size	src/server/server.c	if (result == GTLS_OK \&\& ticket_len > c->limits.max_ticket_bytes) {	if (0) {	testResume
server-issue-size-edge	src/server/server.c	if (result == GTLS_OK \&\& ticket_len > c->limits.max_ticket_bytes) {	if (result == GTLS_OK \&\& ticket_len >= c->limits.max_ticket_bytes) {	testResume
server-binder-second-hello	src/server/server.c	if (r->active) {\n    result = verify_binder(c, \&o, r, msg);	if (r->active \&\& !second) {\n    result = verify_binder(c, \&o, r, msg);	testResume
ticket-open-len-min-edge	src/session/ticket.c	len < GTLS_TICKET_MIN \|\|	len <= GTLS_TICKET_MIN \|\|	testTicket
ticket-open-len-max	src/session/ticket.c	len < GTLS_TICKET_MIN \|\| len > GTLS_TICKET_MAX) {	len < GTLS_TICKET_MIN) {	testTicket
ticket-open-len-max-edge	src/session/ticket.c	len > GTLS_TICKET_MAX) {	len >= GTLS_TICKET_MAX) {	testTicket
ticket-state-psk-len	src/session/ticket.c	t->psk_len != gtls_hash_len(gtls_suite_hash(t->suite))	0	testTicket
ticket-state-lifetime-edge	src/session/ticket.c	if (t->lifetime > GTLS_TICKET_LIFETIME_MAX) {	if (t->lifetime >= GTLS_TICKET_LIFETIME_MAX) {	testTicket
ticket-fresh-lifetime-edge	src/session/ticket.c	if (p->lifetime > GTLS_TICKET_LIFETIME_MAX) {\n    return 0;	if (p->lifetime >= GTLS_TICKET_LIFETIME_MAX) {\n    return 0;	testTicket
ticket-fresh-future-edge	src/session/ticket.c	if (elapsed_s > GTLS_TICKET_AGE_WINDOW_MAX) {	if (elapsed_s >= GTLS_TICKET_AGE_WINDOW_MAX) {	testTicket
ticket-fresh-future-sign	src/session/ticket.c	server_ms = -(int64_t)(elapsed_s * 1000u);	server_ms = (int64_t)(elapsed_s * 1000u);	testTicket
ticket-sealing-not-before-edge	src/session/ticket.c	if (keys[i].not_before <= now \&\& now < keys[i].not_after \&\&	if (keys[i].not_before < now \&\& now < keys[i].not_after \&\&	testTicket
session-min-length	src/session/session.c	if (len < FIXED_PREFIX + 1u + 1u + 1u + 2u + GSEC_SHA256_DIGEST_LEN) {	if (0) {	testTicket	SessionBlob.EveryPrefixOfAGoodBlobWithAValidDigestIsRefused:SessionBlob.EachLengthAndEachFieldIsCheckedOnItsOwnUnderAValidDigest	valgrind
session-host-room	src/session/session.c	if (len - at < host_len + 1u) {	if (0) {	testTicket	SessionBlob.EveryPrefixOfAGoodBlobWithAValidDigestIsRefused:SessionBlob.EachLengthAndEachFieldIsCheckedOnItsOwnUnderAValidDigest	valgrind
session-alpn-room	src/session/session.c	if (len - at < alpn_len + 1u) {	if (0) {	testTicket	SessionBlob.EveryPrefixOfAGoodBlobWithAValidDigestIsRefused:SessionBlob.EachLengthAndEachFieldIsCheckedOnItsOwnUnderAValidDigest	valgrind
session-psk-room	src/session/session.c	if (len - at < psk_len + 2u) {	if (0) {	testTicket	SessionBlob.EveryPrefixOfAGoodBlobWithAValidDigestIsRefused:SessionBlob.EachLengthAndEachFieldIsCheckedOnItsOwnUnderAValidDigest	valgrind
session-ticket-empty	src/session/session.c	ticket_len == 0 \|\| r32(p + 3)	r32(p + 3)	testTicket
session-host-empty	src/session/session.c	host_len == 0 \|\|\n      ticket_len == 0	ticket_len == 0	testTicket
session-suite-none	src/session/session.c	hash == GTLS_HASH_NONE \|\| psk_len	psk_len	testTicket
session-lifetime-edge	src/session/session.c	r32(p + 3) > GTLS_TICKET_LIFETIME_MAX \|\|	r32(p + 3) >= GTLS_TICKET_LIFETIME_MAX \|\|	testTicket
session-blob-bound-edge	src/session/session.c	if (len > FIXED_PREFIX + 1u + 255u	if (len >= FIXED_PREFIX + 1u + 255u	testTicket
session-name-fold-a	src/session/session.c	if (x >= 'A' \&\& x <= 'Z') {	if (0) {	testResume
session-name-fold-b	src/session/session.c	if (y >= 'A' \&\& y <= 'Z') {	if (0) {	testResume
session-name-fold-a-low	src/session/session.c	if (x >= 'A' \&\& x <= 'Z') {	if (x >= '@' \&\& x <= 'Z') {	testResume
session-name-fold-a-high	src/session/session.c	if (x >= 'A' \&\& x <= 'Z') {	if (x >= 'A' \&\& x <= '[') {	testResume
session-name-fold-b-low	src/session/session.c	if (y >= 'A' \&\& y <= 'Z') {	if (y >= '@' \&\& y <= 'Z') {	testResume
session-name-fold-b-high	src/session/session.c	if (y >= 'A' \&\& y <= 'Z') {	if (y >= 'A' \&\& y <= '[') {	testResume
early-label	src/schedule/schedule.c	"c e traffic"	"c e traffiq"	testEarly	EarlyKat.*
early-traffic-stage	src/schedule/schedule.c	if (s == NULL \|\| s->stage != 1 \|\| th_client_hello == NULL) {	if (s == NULL \|\| th_client_hello == NULL) {	testEarly	EarlyKat.*
early-msg-builder-psk	src/msg/msg.c	(p->early_data \&\& p->psk == NULL) \|\|	0 \|\|	testEarly	EarlyKat.*
early-msg-hello-ext	src/msg/msg.c	  if (p->early_data) {\n    ext_begin(out, GTLS_EXT_EARLY_DATA, \&at);\n    gtls_buf_end(out, at, 2);\n  }\n  finish_hello(out, ext_at, p->psk);	  finish_hello(out, ext_at, p->psk);	testEarly	EarlyKat.*
early-msg-retry-drop	src/msg/msg.c	    if (e->type == GTLS_EXT_EARLY_DATA) {\n      continue; /* the second hello offers none (section 4.2.10) */\n    }\n		testEarly	EarlyKat.*
early-msg-ee-empty	src/msg/msg.c	    if (e->len != 0) {\n      return GTLS_ERR_CORRUPT;\n    }\n    ee.has_early_data = 1;	    ee.has_early_data = 1;	testEarly	EarlyKat.*
early-msg-ee-build	src/msg/msg.c	  if (p->early_data) {\n    ext_begin(out, GTLS_EXT_EARLY_DATA, \&at);\n    gtls_buf_end(out, at, 2);\n  }\n  gtls_buf_end(out, ext_at, 2);\n  return finish_message(out, start);\n}\n\nGTLS_Result gtls_msg_build_certificate(	  gtls_buf_end(out, ext_at, 2);\n  return finish_message(out, start);\n}\n\nGTLS_Result gtls_msg_build_certificate(	testEarly	EarlyKat.*
early-msg-eoed-body	src/msg/msg.c	  (void)body;\n  return len == 0 ? GTLS_OK : GTLS_ERR_CORRUPT;	  (void)body;\n  (void)len;\n  return GTLS_OK;	testEarly	EarlyKat.*
ticket-v2-written	src/session/ticket.c	  plain[n++] = (unsigned char)(p->max_early_data != 0 ? GTLS_TICKET_STATE_VERSION_EARLY\n                                                     : GTLS_TICKET_STATE_VERSION);	  plain[n++] = (unsigned char)GTLS_TICKET_STATE_VERSION;	testTicket	Ticket.*
ticket-v2-allowance-read	src/session/ticket.c	    t->max_early_data = get32(plain + at);\n    at += 4;	    at += 4;	testTicket	Ticket.*
context-early-pair	src/client/context.c	(config->max_early_data != 0) != (config->anti_replay != NULL))) {	0)) {	testEarly	EarlyContext.*
context-early-limit	src/client/context.c	if (config->max_early_data > c->limits.max_early_data_bytes \|\|	if (config->max_early_data > c->limits.max_early_data_bytes + 1u \|\|	testEarly	EarlyContext.*
context-client-replay	src/client/context.c	if (config->role == GTLS_ROLE_CLIENT \&\& config->anti_replay != NULL) {	if (0) {	testEarly	EarlyContext.*
early-accept-offered	src/server/server.c	  if (!o->early_data \|\| r->index != 0 \|\| x->anti_replay == NULL \|\|	  if (r->index != 0 \|\| x->anti_replay == NULL \|\|	testEarly	EarlyRejected.*
early-accept-allowance	src/server/server.c	x->anti_replay == NULL \|\|\n      r->plain.max_early_data == 0 \|\|	x->anti_replay == NULL \|\|	testEarly	EarlyRejected.*
early-accept-alpn-len	src/server/server.c	      r->plain.alpn_len != c->alpn_selected_len \|\|\n      gsec_equal(	      gsec_equal(	testEarly	EarlyRejected.*
early-accept-alpn-bytes	src/server/server.c	      gsec_equal(r->plain.alpn, c->alpn_selected, c->alpn_selected_len) != GSEC_OK) {	      0) {	testEarly	EarlyRejected.*
early-accept-verdict	src/server/server.c	  return verdict == 1;	  return verdict != 0;	testEarly	EarlyRejected.*
early-accept-id	src/server/server.c	  if (gsec_sha256(en->identity, en->identity_len, id) != GSEC_OK) {	  if (gsec_sha256(en->identity, en->identity_len - 1u, id) != GSEC_OK) {	testEarly	Early.*
early-accept-age	src/server/server.c	      en->age - r->plain.age_add);	      en->age);	testEarly	Early.*
early-accept-issued	src/server/server.c	  verdict = x->anti_replay(x->anti_replay_user, id, r->plain.issued,	  verdict = x->anti_replay(x->anti_replay_user, id, 0,	testEarly	Early.*
early-accept-cap	src/server/server.c	    uint32_t cap = r->plain.max_early_data < c->context->max_early_data\n        ? r->plain.max_early_data : c->context->max_early_data;	    uint32_t cap = r->plain.max_early_data;	testEarly	EarlyLimits.*
early-accept-skip-off	src/server/server.c	    c->early_skip = 0; /* the records that follow are opened, not skipped */	    (void)0;	testEarly	EarlyEnd.*
early-server-status	src/server/server.c	    c->early_status = o.early_data ? GTLS_EARLY_REJECTED : GTLS_EARLY_NONE;	    c->early_status = GTLS_EARLY_NONE;	testEarly	EarlyRejected.*
early-server-reserve	src/server/server.c	    result = gtls_buf_reserve(\&c->early_in, cap); /* once, so nothing is left behind by a growth */\n    if (result != GTLS_OK) {\n      return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);\n    }\n		testWipe	WipeEarly.*
early-server-ee	src/server/server.c	  ee.early_data = early;	  ee.early_data = 0;	testEarly	Early.*
early-server-secret	src/server/server.c	  if (result == GTLS_OK \&\& early) {\n    result = gtls_schedule_early_traffic(\&c->sec.schedule, k->th_ch);\n  }\n		testEarly	Early.*
early-server-transcript	src/server/server.c	    result = gtls_transcript_snapshot(\&c->sec.transcript, hash, k->th_ch);	    result = GTLS_OK;	testEarly	Early.*
early-server-state	src/server/server.c	  c->state = early \&\& !c->context->omit_end_of_early_data ? GTLS_STATE_S_WAIT_EOED\n                                                           : GTLS_STATE_S_WAIT_FIN;	  (void)early;\n  c->state = GTLS_STATE_S_WAIT_FIN;	testEarly	EarlyEnd.*
early-eoed-state	src/server/server.c	  c->state = GTLS_STATE_S_WAIT_FIN;\n  return GTLS_OK;\n}\n\nstatic GTLS_Result on_client_finished_inner(	  return GTLS_OK;\n}\n\nstatic GTLS_Result on_client_finished_inner(	testEarly	EarlyEnd.*
early-eoed-transcript	src/server/server.c	  result = gtls_transcript_update(\&c->sec.transcript, msg, msg_len);\n  if (result != GTLS_OK) {\n    return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);\n  }\n  /* The early key has done its work: nothing is read under it again. */	  result = GTLS_OK;\n  if (result != GTLS_OK) {\n    return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);\n  }\n  /* The early key has done its work: nothing is read under it again. */	testEarly	Early.*
early-eoed-parse	src/server/server.c	  GTLS_Result result = gtls_msg_parse_end_of_early_data(msg + 4, msg_len - 4u);\n\n  if (result != GTLS_OK) {\n    return gtls_conn_fail_parse(c, result);\n  }	  GTLS_Result result = gtls_msg_parse_end_of_early_data(msg + 4, msg_len - 4u);\n\n  (void)result;	testEarly	EarlyEnd.*
early-eoed-type	src/server/server.c	    case GTLS_STATE_S_WAIT_EOED:\n      if (type != GTLS_HS_END_OF_EARLY_DATA) {\n        return gtls_conn_unexpected(c);\n      }\n	    case GTLS_STATE_S_WAIT_EOED:\n	testEarly	EarlyEnd.*
early-ccs-eoed	src/client/stream.c	c->state == GTLS_STATE_S_WAIT_FIN \|\|\n        c->state == GTLS_STATE_S_WAIT_EOED;	c->state == GTLS_STATE_S_WAIT_FIN;	testEarly	Early.*
early-ccs-after-hello	src/client/stream.c	  if (c->role == GTLS_ROLE_CLIENT \&\& c->early_status != GTLS_EARLY_NONE \&\&\n      c->context->middlebox_compat \&\& c->hello_flushed) {	  if (0) {	testEarly	Early.*
early-cost	src/client/stream.c	  size_t cost = n != 0 ? n : 1u;	  size_t cost = n;	testEarly	EarlyLimits.*
early-allowance-edge	src/client/stream.c	  if (cost > c->early_max - c->early_used) {	  if (cost >= c->early_max - c->early_used) {	testEarly	EarlyLimits.*
early-partial-message	src/client/stream.c	  if (c->in.len != 0) {\n    return gtls_conn_unexpected(c);\n  }\n  if (cost > c->early_max - c->early_used) {	  if (cost > c->early_max - c->early_used) {	testEarly	EarlyEnd.*
early-diagnose-missing-end	src/client/stream.c	c->state == GTLS_STATE_S_WAIT_EOED \&\&\n        opens_under_handshake(c, header, body, blen)) {	c->state == GTLS_STATE_S_WAIT_EOED \&\& 0) {	testEarly	EarlyEnd.*
early-secret-direction	src/client/client.c	    if (!c->sec.schedule.has_e \|\| (direction == GTLS_DIR_WRITE) != (c->role == GTLS_ROLE_CLIENT)) {	    if (!c->sec.schedule.has_e) {	testEarly	EarlyEnd.*
early-secret-exists	src/client/client.c	    if (!c->sec.schedule.has_e \|\| (direction == GTLS_DIR_WRITE) != (c->role == GTLS_ROLE_CLIENT)) {	    if ((direction == GTLS_DIR_WRITE) != (c->role == GTLS_ROLE_CLIENT)) {	testEarly	EarlyEnd.*
early-offer-context	src/client/client.c	  p_early = c->offer != NULL \&\& c->offer->max_early_data != 0 \&\&\n      c->context->max_early_data != 0;	  p_early = c->offer != NULL \&\& c->offer->max_early_data != 0;	testEarly	EarlyRejected.*
early-offer-allowance	src/client/client.c	  p_early = c->offer != NULL \&\& c->offer->max_early_data != 0 \&\&\n      c->context->max_early_data != 0;	  p_early = c->offer != NULL \&\& c->context->max_early_data != 0;	testEarly	EarlyContext.*:EarlyRejected.*
early-client-cap	src/client/client.c	  c->early_max = o->max_early_data < c->context->max_early_data\n      ? o->max_early_data : c->context->max_early_data;	  c->early_max = o->max_early_data;	testEarly	EarlyClient.*
early-client-reserve	src/client/client.c	  result = gtls_buf_reserve(\&c->early_sent, c->early_max);\n  if (result != GTLS_OK) {\n    return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);\n  }\n		testWipe	WipeEarly.*
early-client-th	src/client/client.c	  result = gtls_transcript_snapshot(\&c->sec.transcript, hash, c->scratch.th);\n  if (result == GTLS_OK) {\n    result = gtls_schedule_early_psk(	  memset(c->scratch.th, 0, sizeof c->scratch.th);\n  result = GTLS_OK;\n  if (result == GTLS_OK) {\n    result = gtls_schedule_early_psk(	testEarly	Early.*
early-client-hrr	src/client/client.c	  if (c->early_status == GTLS_EARLY_PENDING) {\n    /* The second ClientHello offers none	  if (0) {\n    /* The second ClientHello offers none	testEarly	EarlyClient.*
early-client-no-psk	src/client/client.c	  } else if (c->early_status == GTLS_EARLY_PENDING) {\n    reject_early(c);	  } else if (0) {\n    reject_early(c);	testEarly	EarlyClient.*
early-client-unoffered	src/client/client.c	  if (ee.has_early_data \&\& c->early_status != GTLS_EARLY_PENDING) {	  if (0) {	testEarly	EarlyClientChecks.*
early-client-accepts-only-if-told	src/client/client.c	    if (!ee.has_early_data) {\n      reject_early(c);	    if (0) {\n      reject_early(c);	testEarly	EarlyRejected.*
early-client-alpn	src/client/client.c	        c->alpn_selected_len != c->early_alpn_len \|\|\n        gsec_equal(c->alpn_selected, c->early_alpn, c->early_alpn_len) != GSEC_OK) {	        0) {	testEarly	EarlyClientChecks.*
early-client-eoed-queue	src/client/client.c	      result = gtls_conn_queue(c, GTLS_EPOCH_EARLY, eoed.data, eoed.len);	      result = GTLS_OK;	testEarly	Early.*
early-client-eoed-transcript	src/client/client.c	      result = gtls_transcript_update(\&c->sec.transcript, eoed.data, eoed.len);	      result = GTLS_OK;	testEarly	Early.*
early-client-resnapshot	src/client/client.c	    if (result == GTLS_OK) {\n      result = gtls_transcript_snapshot(\&c->sec.transcript, hash, c->scratch.th);\n    }\n  }\n  /* The client's Finished is over the transcript through the server's. */	    }\n  /* The client's Finished is over the transcript through the server's. */	testEarly	Early.*
early-client-suite	src/client/stream.c	      ? (uint32_t)c->early_suite : (uint32_t)c->suite;	      ? (uint32_t)c->suite : (uint32_t)c->suite;	testEarly	Early.*
early-issue-allowance	src/server/server.c	p->max_early_data = x->max_early_data;	p->max_early_data = 0;	testEarly	Early.*
early-issue-extension	src/server/server.c	t.early_data = p->max_early_data != 0;	t.early_data = 0;	testEarly	Early.*
early-fail-wipe-server	src/client/client.c	    if (c->early_in.data != NULL) {\n      (void)gsec_wipe(c->early_in.data, c->early_in.cap);\n    }\n		testWipe	WipeEarly.*
early-fail-wipe-client	src/client/client.c	    if (c->early_sent.data != NULL) {\n      (void)gsec_wipe(c->early_sent.data, c->early_sent.cap);\n    }\n		testEarly	EarlyEnd.*
early-free-wipe	src/client/stream.c	  wipe_buf(\&c->early_in);\n  wipe_buf(\&c->early_sent);\n		testWipe	WipeEarly.*
early-read-role	src/client/stream.c	  if (c->role != GTLS_ROLE_SERVER \|\| stream_ready(c) != GTLS_OK) {	  if (stream_ready(c) != GTLS_OK) {	testEarly	EarlyClient.*
early-resend-status	src/client/stream.c	  if (c->role != GTLS_ROLE_CLIENT \|\| c->early_status != GTLS_EARLY_REJECTED) {	  if (c->role != GTLS_ROLE_CLIENT) {	testEarly	EarlyClient.*
early-write-limit	src/client/stream.c	  if (len > c->early_max - c->early_used) {	  if (len > c->early_max - c->early_used + 1u) {	testEarly	EarlyClient.*
early-write-state	src/client/stream.c	  if (c->role != GTLS_ROLE_CLIENT \|\| c->early_status != GTLS_EARLY_PENDING \|\|\n      c->state != GTLS_STATE_WAIT_SH) {	  if (c->role != GTLS_ROLE_CLIENT \|\| c->early_status != GTLS_EARLY_PENDING) {	testEarly	EarlyClient.*
early-accept-first-psk	src/server/server.c	  if (!o->early_data \|\| r->index != 0 \|\| x->anti_replay == NULL \|\|	  if (!o->early_data \|\| x->anti_replay == NULL \|\|	testEarly	EarlyRejected.*
early-skip-cost	src/client/stream.c	size_t cost = body_len > GTLS_RECORD_TAG + 1u ? body_len - (GTLS_RECORD_TAG + 1u) : 1u;	size_t cost = GTLS_RECORD_HEADER + body_len;	testEarly	EarlyRejected.*
early-skip-cost-tag	src/client/stream.c	size_t cost = body_len > GTLS_RECORD_TAG + 1u ? body_len - (GTLS_RECORD_TAG + 1u) : 1u;	size_t cost = body_len > GTLS_RECORD_TAG ? body_len - GTLS_RECORD_TAG : 1u;	testPsk	EarlySkip.*
early-skip-cost-min	src/client/stream.c	body_len - (GTLS_RECORD_TAG + 1u) : 1u;	body_len - (GTLS_RECORD_TAG + 1u) : 0u;	testEarly	EarlyRejected.*
early-skip-budget	src/client/stream.c	  if (c->context->max_early_data > budget) {	  if (0) {	testEarly	EarlyRejected.*
early-accept-cap-ticket	src/server/server.c	    uint32_t cap = r->plain.max_early_data < c->context->max_early_data\n        ? r->plain.max_early_data : c->context->max_early_data;	    uint32_t cap = c->context->max_early_data;	testEarly	EarlyLimits.*
early-client-suite-equal	src/client/client.c	c->suite != c->early_suite \|\|	0 \|\|	testEarly	EarlyClientChecks.*
psk-hash-check	src/client/client.c	if (sh.psk_identity != 0 \|\| gtls_suite_hash(sh.suite) != offered_hash(c)) {	if (sh.psk_identity != 0) {	testEarly	EarlyClientChecks.*
ticket-early-extension-end	src/msg/msg.c	      result = gtls_reader_bytes(\&er, 4, \&p);\n      if (result == GTLS_OK) {\n        result = gtls_reader_end(\&er);\n      }	      result = gtls_reader_bytes(\&er, 4, \&p);	testMsg	NewSessionTicket.*
early-read-overrun	src/client/stream.c	c->early_in.len < cap ? c->early_in.len : cap;	c->early_in.len < cap + 1u ? c->early_in.len : cap + 1u;	testEarly	EarlyRead.*
early-resend-overrun	src/client/stream.c	c->early_sent.len < cap ? c->early_sent.len : cap;	c->early_sent.len < cap + 1u ? c->early_sent.len : cap + 1u;	testEarly	EarlyRead.*
early-read-wipe	src/client/stream.c	    (void)gsec_wipe(c->early_in.data + keep, take);\n	    (void)keep;\n	testEarly	EarlyRead.*
early-resend-wipe	src/client/stream.c	    (void)gsec_wipe(c->early_sent.data + keep, take); /* the stale copy the move left */\n	    (void)keep;\n	testEarly	EarlyRead.*
early-write-zero	src/client/stream.c	  if (len == 0) {\n    return GTLS_OK;\n  }\n  /* The ClientHello goes first, and the dummy record after it. */	  /* The ClientHello goes first, and the dummy record after it. */	testEarly	Early.*
early-eoed-in-handshake	src/server/server.c	      if (type != GTLS_HS_FINISHED) {	      if (type != GTLS_HS_FINISHED \&\& type != GTLS_HS_END_OF_EARLY_DATA) {	testEarly	EarlyEnd.*
early-feed-ends-epoch	src/client/client.c	if (len > 0 \&\& (gtls_conn_expected_epoch(c->state) != gtls_conn_expected_epoch(before) \|\|	if (len > 0 \&\& (0 \|\|	testEarly	EarlyEnd.EndOfEarlyDataAndFinishedInOneEarlyRecord*
early-reject-wr	src/client/client.c	    (void)gsec_wipe(\&c->sec.wr, sizeof c->sec.wr);\n    (void)gsec_wipe(c->sec.wr_secret	    (void)gsec_wipe(c->sec.wr_secret	testEarly	EarlyClient.*
early-reject-wr-secret	src/client/client.c	    (void)gsec_wipe(c->sec.wr_secret, sizeof c->sec.wr_secret);\n    c->wr_epoch = GTLS_EPOCH_INITIAL;	    c->wr_epoch = GTLS_EPOCH_INITIAL;	testEarly	EarlyClient.*
early-reject-secret	src/client/client.c	  (void)gsec_wipe(c->sec.schedule.c_e, sizeof c->sec.schedule.c_e);\n  c->sec.schedule.has_e = 0;\n  if (c->wr_epoch == GTLS_EPOCH_EARLY) {	  c->sec.schedule.has_e = 0;\n  if (c->wr_epoch == GTLS_EPOCH_EARLY) {	testEarly	EarlyClient.*
early-client-eoed-wipe	src/client/client.c	    (void)gsec_wipe(c->sec.schedule.c_e, sizeof c->sec.schedule.c_e);\n    c->sec.schedule.has_e = 0;\n    if (result == GTLS_OK) {	    c->sec.schedule.has_e = 0;\n    if (result == GTLS_OK) {	testEarly	EarlyEnd.*
early-client-eoed-has-e	src/client/client.c	    c->sec.schedule.has_e = 0;\n    if (result == GTLS_OK) {	    if (result == GTLS_OK) {	testEarly	EarlyEnd.*
early-client-pin	src/client/client.c	      result = gtls_stream_pin_early(c);	      result = GTLS_OK;	testEarly	Early.*
early-server-eoed-wipe	src/server/server.c	  (void)gsec_wipe(c->sec.schedule.c_e, sizeof c->sec.schedule.c_e);\n  c->sec.schedule.has_e = 0;\n  (void)gsec_wipe(\&c->sec.rd	  c->sec.schedule.has_e = 0;\n  (void)gsec_wipe(\&c->sec.rd	testEarly	EarlyEnd.*
early-server-eoed-has-e	src/server/server.c	  c->sec.schedule.has_e = 0;\n  (void)gsec_wipe(\&c->sec.rd, sizeof c->sec.rd);	  (void)gsec_wipe(\&c->sec.rd, sizeof c->sec.rd);	testEarly	EarlyEnd.*
early-server-eoed-rd	src/server/server.c	  (void)gsec_wipe(\&c->sec.rd, sizeof c->sec.rd);\n  (void)gsec_wipe(c->sec.rd_secret	  (void)gsec_wipe(c->sec.rd_secret	testEarly	EarlyEnd.*
early-server-eoed-rd-secret	src/server/server.c	  (void)gsec_wipe(c->sec.rd_secret, sizeof c->sec.rd_secret);\n  c->rd_epoch = GTLS_EPOCH_INITIAL;	  c->rd_epoch = GTLS_EPOCH_INITIAL;	testEarly	EarlyEnd.*
early-close-window	src/client/stream.c	  if (c->wr_epoch == GTLS_EPOCH_EARLY \&\& c->state != GTLS_STATE_CONNECTED) {	  if (0) {	testEarly	EarlyClose.*
early-close-connected	src/client/stream.c	c->wr_epoch == GTLS_EPOCH_EARLY \&\& c->state != GTLS_STATE_CONNECTED	c->wr_epoch == GTLS_EPOCH_EARLY	testEarly	EarlyClose.*
early-close-discard	src/client/stream.c	    wipe_buf(\&c->wire);\n    c->wire.len = 0;\n	    (void)0;\n	testEarly	EarlyClose.*
early-close-report	src/client/stream.c	    return gtls_conn_fail(c, GTLS_ERR_CLOSED, GTLS_ALERT_NONE);	    return GTLS_OK;	testEarly	EarlyClose.*
ccs-once	src/client/stream.c	  if (c->ccs_sent) {\n    return GTLS_OK;\n  }\n  c->ccs_sent = 1;	  c->ccs_sent = 1;	testEarly	Early.*
fuzz-early-client-suite-equal	src/client/client.c	c->suite != c->early_suite \|\|	0 \|\|	testFuzzseeds	FuzzSeeds.EverySeedRunsCleanThroughItsHarness
fuzz-early-ee-alpn-offered	src/client/client.c	    if (!offered_alpn(c, ee.alpn, ee.alpn_len)) {	    if (0) {	testFuzzseeds	FuzzSeeds.EverySeedRunsCleanThroughItsHarness
fuzz-early-ee-unoffered	src/client/client.c	  if (ee.has_early_data \&\& c->early_status != GTLS_EARLY_PENDING) {	  if (0) {	testFuzzseeds	FuzzSeeds.EverySeedRunsCleanThroughItsHarness
fuzz-early-alpn-tickets	src/client/client.c	        c->alpn_selected_len != c->early_alpn_len \|\|\n        gsec_equal(c->alpn_selected, c->early_alpn, c->early_alpn_len) != GSEC_OK) {	        0) {	testFuzzseeds	FuzzSeeds.EverySeedRunsCleanThroughItsHarness
fuzz-early-diagnose-missing-end	src/client/stream.c	c->state == GTLS_STATE_S_WAIT_EOED \&\&\n        opens_under_handshake(c, header, body, blen)) {	c->state == GTLS_STATE_S_WAIT_EOED \&\& 0) {	testFuzzseeds	FuzzSeeds.EverySeedRunsCleanThroughItsHarness
fuzz-early-close-window	src/client/stream.c	  if (c->wr_epoch == GTLS_EPOCH_EARLY \&\& c->state != GTLS_STATE_CONNECTED) {	  if (0) {	testFuzzseeds	FuzzSeeds.EverySeedRunsCleanThroughItsHarness
fuzz-early-write-limit	src/client/stream.c	  if (len > c->early_max - c->early_used) {\n    return GTLS_ERR_LIMIT;\n  }\n  if (len == 0) {	  if (0) {\n    return GTLS_ERR_LIMIT;\n  }\n  if (len == 0) {	testFuzzseeds	FuzzSeeds.EverySeedRunsCleanThroughItsHarness
fuzz-early-write-zero	src/client/stream.c	  if (len == 0) {\n    return GTLS_OK;\n  }\n  /* The ClientHello goes first, and the dummy record after it. */	  /* The ClientHello goes first, and the dummy record after it. */	testFuzzseeds	FuzzSeeds.EverySeedRunsCleanThroughItsHarness
fuzz-early-pin	src/client/client.c	      result = gtls_stream_pin_early(c);	      result = GTLS_OK;	testFuzzseeds	FuzzSeeds.EverySeedRunsCleanThroughItsHarness
limit-zero-const	src/core/core.c	  } else if (out->field == GTLS_LIMIT_ZERO) { \	  } else if (0) { \	testCore	Limits.AZeroCap*
limit-zero-padding	src/core/core.c	  GTLS_RESOLVE_ZERO(max_record_padding)	  GTLS_RESOLVE(max_record_padding)	testStream	Stream.AZeroPaddingCap*
limit-zero-key-updates	src/core/core.c	  GTLS_RESOLVE_ZERO(max_key_updates)	  GTLS_RESOLVE(max_key_updates)	testStream	KeyUpdate.AZeroCap*
limit-zero-ticket-bytes	src/core/core.c	  GTLS_RESOLVE_ZERO(max_ticket_bytes)	  GTLS_RESOLVE(max_ticket_bytes)	testNegative	Limits.AZeroTicketCap*
limit-zero-cookie	src/core/core.c	  GTLS_RESOLVE_ZERO(max_cookie_bytes)	  GTLS_RESOLVE(max_cookie_bytes)	testMsg	ServerHello.AZeroCookieCap*
limit-zero-early-bytes	src/core/core.c	  GTLS_RESOLVE_ZERO(max_early_data_bytes)	  GTLS_RESOLVE(max_early_data_bytes)	testEarly	EarlyContext.AZeroLimit*
limit-zero-early-skip	src/core/core.c	  GTLS_RESOLVE_ZERO(max_early_skip_bytes)	  GTLS_RESOLVE(max_early_skip_bytes)	testEarly	EarlyRejected.AZeroSkip*
quic-client-eoed	src/client/client.c	c->early_status == GTLS_EARLY_ACCEPTED \&\&\n      !c->context->omit_end_of_early_data) {	c->early_status == GTLS_EARLY_ACCEPTED) {	testEarly	QuicNoEndOfEarlyData.*
quic-server-wait	src/server/server.c	early \&\& !c->context->omit_end_of_early_data ?	early ?	testEarly	QuicNoEndOfEarlyData.*
quic-secret-wipe	src/client/client.c	  if (c->context->omit_end_of_early_data \&\& c->sec.schedule.has_e \&\&\n      c->sec.schedule.stage >= 2) {	  if (0) {	testEarly	QuicNoEndOfEarlyData.*
quic-secret-wipe-early	src/client/client.c	      c->sec.schedule.stage >= 2) {\n    /* Nothing under QUIC	      c->sec.schedule.stage >= 1) {\n    /* Nothing under QUIC	testEarly	QuicNoEndOfEarlyData.*
quic-no-stream	src/client/stream.c	c->mode == GTLS_MODE_MESSAGE || c->context->omit_end_of_early_data	c->mode == GTLS_MODE_MESSAGE	testEarly	QuicNoEndOfEarlyData.*
quic-context-copy	src/client/context.c	  c->omit_end_of_early_data = config->omit_end_of_early_data != 0;	  c->omit_end_of_early_data = 0;	testEarly	QuicNoEndOfEarlyData.*
wipe-client-binder-th	src/client/client.c	  (void)gsec_wipe(c->scratch.th, sizeof c->scratch.th);\n  (void)gsec_wipe(c->scratch.binder, sizeof c->scratch.binder);	  (void)gsec_wipe(c->scratch.binder, sizeof c->scratch.binder);	testResume
wipe-client-binder	src/client/client.c	  (void)gsec_wipe(c->scratch.th, sizeof c->scratch.th);\n  (void)gsec_wipe(c->scratch.binder, sizeof c->scratch.binder);	  (void)gsec_wipe(c->scratch.th, sizeof c->scratch.th);	testResume
wipe-client-early-th	src/client/client.c	  (void)gsec_wipe(c->scratch.th, sizeof c->scratch.th);\n  if (result != GTLS_OK) {\n    return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);\n  }\n  c->early_suite	  if (result != GTLS_OK) {\n    return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);\n  }\n  c->early_suite	testEarly
wipe-client-hello-ecdhe	src/client/client.c	  (void)gsec_wipe(c->scratch.ecdhe, sizeof c->scratch.ecdhe);\n  (void)gsec_wipe(c->scratch.th, sizeof c->scratch.th);\n  return result;	  (void)gsec_wipe(c->scratch.th, sizeof c->scratch.th);\n  return result;	testClient
wipe-client-hello-th	src/client/client.c	  (void)gsec_wipe(c->scratch.ecdhe, sizeof c->scratch.ecdhe);\n  (void)gsec_wipe(c->scratch.th, sizeof c->scratch.th);\n  return result;	  (void)gsec_wipe(c->scratch.ecdhe, sizeof c->scratch.ecdhe);\n  return result;	testClient
wipe-client-finished-th	src/client/client.c	  (void)gsec_wipe(c->scratch.th, sizeof c->scratch.th);\n  (void)gsec_wipe(c->scratch.verify, sizeof c->scratch.verify);\n  (void)gsec_wipe(c->scratch.fin, sizeof c->scratch.fin);\n	  (void)gsec_wipe(c->scratch.verify, sizeof c->scratch.verify);\n  (void)gsec_wipe(c->scratch.fin, sizeof c->scratch.fin);\n	testClient
wipe-client-finished-verify	src/client/client.c	  (void)gsec_wipe(c->scratch.th, sizeof c->scratch.th);\n  (void)gsec_wipe(c->scratch.verify, sizeof c->scratch.verify);\n  (void)gsec_wipe(c->scratch.fin, sizeof c->scratch.fin);\n	  (void)gsec_wipe(c->scratch.th, sizeof c->scratch.th);\n  (void)gsec_wipe(c->scratch.fin, sizeof c->scratch.fin);\n	testClient
wipe-client-finished-fin	src/client/client.c	  (void)gsec_wipe(c->scratch.th, sizeof c->scratch.th);\n  (void)gsec_wipe(c->scratch.verify, sizeof c->scratch.verify);\n  (void)gsec_wipe(c->scratch.fin, sizeof c->scratch.fin);\n	  (void)gsec_wipe(c->scratch.th, sizeof c->scratch.th);\n  (void)gsec_wipe(c->scratch.verify, sizeof c->scratch.verify);\n	testClient
wipe-server-opened-ticket	src/server/server.c	  /* The one place the opened ticket is wiped: a good one is copied into r first. */\n  (void)gsec_wipe(t, sizeof *t);	  /* (planted) */	testResume
wipe-server-binder-th	src/server/server.c	  (void)gsec_wipe(c->scratch.th, sizeof c->scratch.th);\n  if (result != GTLS_OK) {\n    return gtls_conn_fail(c, result, result == GTLS_ERR_MISMATCH	  if (result != GTLS_OK) {\n    return gtls_conn_fail(c, result, result == GTLS_ERR_MISMATCH	testResume
wipe-server-flight-ecdhe	src/server/server.c	  (void)gsec_wipe(c->scratch.flight.ecdhe, sizeof c->scratch.flight.ecdhe);\n	  /* planted: no wipe */\n	testServer
wipe-server-flight-th	src/server/server.c	  (void)gsec_wipe(c->scratch.flight.th, sizeof c->scratch.flight.th);\n	  /* planted: no wipe */\n	testServer
wipe-server-flight-verify	src/server/server.c	  (void)gsec_wipe(c->scratch.flight.verify, sizeof c->scratch.flight.verify);\n	  /* planted: no wipe */\n	testServer
wipe-server-flight-content	src/server/server.c	  (void)gsec_wipe(c->scratch.flight.content, sizeof c->scratch.flight.content);\n	  /* planted: no wipe */\n	testServer
wipe-server-flight-sig	src/server/server.c	  (void)gsec_wipe(c->scratch.flight.sig, sizeof c->scratch.flight.sig);\n	  /* planted: no wipe */\n	testServer
wipe-server-flight-th-ch	src/server/server.c	  (void)gsec_wipe(c->scratch.flight.th_ch, sizeof c->scratch.flight.th_ch);\n	  /* planted: no wipe */\n	testEarly
wipe-server-resume	src/server/server.c	  /* The one place what the tickets gave is wiped, on every path out. */\n  (void)gsec_wipe(r, sizeof *r);	  /* (planted) */	testResume
wipe-server-finished-th	src/server/server.c	  /* The one place the hash is wiped, on every path out. */\n  (void)gsec_wipe(c->scratch.th, sizeof c->scratch.th);\n	  /* (planted) */\n	testServer
wipe-server-issue-state	src/server/server.c	    (void)gsec_wipe(p, sizeof *p);\n	  /* planted: no wipe */\n	testResume
wipe-server-issue-ticket	src/server/server.c	    (void)gsec_wipe(c->scratch.ticket_wire, sizeof c->scratch.ticket_wire);\n	  /* planted: no wipe */\n	testResume
wipe-server-issue-iv	src/server/server.c	    (void)gsec_wipe(c->scratch.iv, sizeof c->scratch.iv);\n	  /* planted: no wipe */\n	testResume
wipe-server-issue-age	src/server/server.c	    (void)gsec_wipe(c->scratch.age, sizeof c->scratch.age);\n	  /* planted: no wipe */\n	testResume
wipe-stream-record	src/client/stream.c	  if (c->rec_scratch != NULL) {\n    (void)gsec_wipe(c->rec_scratch, GTLS_RECORD_CIPHERTEXT_MAX);\n  }\n  return result;	  return result;	testStream
wipe-stream-eoed-keys	src/client/stream.c	  (void)gsec_wipe(\&c->scratch.keys, sizeof c->scratch.keys);\n  (void)gsec_wipe(c->scratch.secret, sizeof c->scratch.secret);\n	  (void)gsec_wipe(c->scratch.secret, sizeof c->scratch.secret);\n	testEarly	EarlyEnd.*
wipe-stream-eoed-secret	src/client/stream.c	  (void)gsec_wipe(\&c->scratch.keys, sizeof c->scratch.keys);\n  (void)gsec_wipe(c->scratch.secret, sizeof c->scratch.secret);\n	  (void)gsec_wipe(\&c->scratch.keys, sizeof c->scratch.keys);\n	testEarly	EarlyEnd.*
wipe-record-next-tmp	src/record/record.c	  (void)gsec_wipe(tmp, GTLS_HASH_MAX);	  (void)tmp;	testRecord
wipe-record-seal-nonce	src/record/record.c	  (void)gsec_wipe(k->nonce, sizeof k->nonce);\n  if (result == GTLS_OK) {	  if (result == GTLS_OK) {	testStream
wipe-record-open-nonce	src/record/record.c	  (void)gsec_wipe(k->nonce, sizeof k->nonce);\n  if (result != GTLS_OK) {\n    (void)gsec_wipe(pt, body);	  if (result != GTLS_OK) {\n    (void)gsec_wipe(pt, body);	testStream
wipe-schedule-derived-hs	src/schedule/schedule.c	  (void)gsec_wipe(s->derived, sizeof s->derived);\n  if (result != GTLS_OK) {\n    gtls_schedule_wipe(s);\n    return result;\n  }\n  s->stage = 2;	  if (result != GTLS_OK) {\n    gtls_schedule_wipe(s);\n    return result;\n  }\n  s->stage = 2;	testClient
wipe-schedule-derived-master	src/schedule/schedule.c	  (void)gsec_wipe(s->derived, sizeof s->derived);\n  if (result != GTLS_OK) {\n    gtls_schedule_wipe(s);\n    return result;\n  }\n  s->stage = 3;	  if (result != GTLS_OK) {\n    gtls_schedule_wipe(s);\n    return result;\n  }\n  s->stage = 3;	testClient
wipe-schedule-finished-key	src/schedule/schedule.c	  (void)gsec_wipe(m->fkey, sizeof m->fkey);\n  return result;	  return result;	testSchedule
wipe-schedule-finished-want	src/schedule/schedule.c	GTLS_ERR_FINISHED : gtls_from_gsec(same));\n  }\n  (void)gsec_wipe(m->want, sizeof m->want);	GTLS_ERR_FINISHED : gtls_from_gsec(same));\n  }	testSchedule
wipe-schedule-binder-want	src/schedule/schedule.c	GTLS_ERR_MISMATCH : gtls_from_gsec(same));\n  }\n  (void)gsec_wipe(m->want, sizeof m->want);	GTLS_ERR_MISMATCH : gtls_from_gsec(same));\n  }	testResume
wipe-schedule-binder-early	src/schedule/schedule.c	  gtls_schedule_wipe(\&m->schedule);\n  (void)gsec_wipe(m->bkey, sizeof m->bkey);	  (void)gsec_wipe(m->bkey, sizeof m->bkey);	testResume
wipe-schedule-binder-key	src/schedule/schedule.c	  gtls_schedule_wipe(\&m->schedule);\n  (void)gsec_wipe(m->bkey, sizeof m->bkey);	  gtls_schedule_wipe(\&m->schedule);	testResume
wipe-ticket-seal-plain	src/session/ticket.c	  (void)gsec_wipe(w->plain, sizeof w->plain);\n  (void)gsec_wipe(w->aad, sizeof w->aad);\n  return result;\n}\n\nGTLS_Result gtls_ticket_open(	  (void)gsec_wipe(w->aad, sizeof w->aad);\n  return result;\n}\n\nGTLS_Result gtls_ticket_open(	testTicket
wipe-ticket-seal-aad	src/session/ticket.c	  (void)gsec_wipe(w->plain, sizeof w->plain);\n  (void)gsec_wipe(w->aad, sizeof w->aad);\n  return result;\n}\n\nGTLS_Result gtls_ticket_open(	  (void)gsec_wipe(w->plain, sizeof w->plain);\n  return result;\n}\n\nGTLS_Result gtls_ticket_open(	testTicket
wipe-ticket-open-plain	src/session/ticket.c	  (void)gsec_wipe(w->plain, sizeof w->plain);\n  (void)gsec_wipe(w->aad, sizeof w->aad);\n  (void)gsec_wipe(\&w->decoded, sizeof w->decoded);\n	  (void)gsec_wipe(w->aad, sizeof w->aad);\n  (void)gsec_wipe(\&w->decoded, sizeof w->decoded);\n	testTicket
wipe-ticket-open-aad	src/session/ticket.c	  (void)gsec_wipe(w->plain, sizeof w->plain);\n  (void)gsec_wipe(w->aad, sizeof w->aad);\n  (void)gsec_wipe(\&w->decoded, sizeof w->decoded);\n	  (void)gsec_wipe(w->plain, sizeof w->plain);\n  (void)gsec_wipe(\&w->decoded, sizeof w->decoded);\n	testTicket
wipe-ticket-open-decoded	src/session/ticket.c	  (void)gsec_wipe(w->plain, sizeof w->plain);\n  (void)gsec_wipe(w->aad, sizeof w->aad);\n  (void)gsec_wipe(\&w->decoded, sizeof w->decoded);\n	  (void)gsec_wipe(w->plain, sizeof w->plain);\n  (void)gsec_wipe(w->aad, sizeof w->aad);\n	testTicket
cert-oom-mapped	src/client/verify.c	    case GCERT_ERR_OOM:\n      return GTLS_ERR_OOM;	    case GCERT_ERR_OOM:\n      return GTLS_ERR_CERT_INVALID;	testAlloc	CertificateAllocation.*
early-flush-keys-guard	src/client/stream.c	    if (c->wr_epoch != GTLS_EPOCH_EARLY) {\n      /* The client installed them	    if (0) {\n      /* The client installed them	testEarly	EarlyInternal.*
early-accept-callback	src/server/server.c	r->index != 0 \|\| x->anti_replay == NULL \|\|	r->index != 0 \|\|	testEarly	EarlyRejected.*
ctx-dup-group	src/client/context.c	if (config->groups[j] == config->groups[i]) {	if (0) {	testArgs	ContextArguments.*
ctx-dup-sigalg	src/client/context.c	if (config->sig_algs[j] == config->sig_algs[i]) {	if (0) {	testArgs	ContextArguments.*
ctx-null-alpn	src/client/context.c	if (config->alpn[i] == NULL) {	if (0) {	testArgs	ContextArguments.*
ctx-role	src/client/context.c	if (config->role != GTLS_ROLE_CLIENT \&\& config->role != GTLS_ROLE_SERVER) {	if (0) {	testArgs	ContextArguments.*
ctx-null-name	src/client/context.c	if (in->names[i] == NULL) {	if (0) {	testArgs	ContextArguments.*
server-start-failed	src/server/server.c	GTLS_Result gtls_server_start(GTLS_Conn * c) {\n  if (c->state == GTLS_STATE_FAILED) {	GTLS_Result gtls_server_start(GTLS_Conn * c) {\n  if (0) {	testArgs	ConnectionArguments.*
set-session-failed	src/session/session.c	  if (c->state == GTLS_STATE_FAILED) {\n    return GTLS_ERR_FAILED;\n  }\n  if (c->role != GTLS_ROLE_CLIENT \|\| c->state != GTLS_STATE_NEW	  if (c->role != GTLS_ROLE_CLIENT \|\| c->state != GTLS_STATE_NEW	testArgs	ConnectionArguments.*
cert-limit-alert	src/client/client.c	    case GTLS_ERR_LIMIT:\n      return GTLS_ALERT_DECODE_ERROR;	    case GTLS_ERR_LIMIT:\n      return GTLS_ALERT_INTERNAL_ERROR;	testArgs	ConnectionArguments.*
record-seal-in-error	src/record/record.c	  if (out->err != GTLS_OK) {\n    return out->err;\n  }\n  inner_len	  inner_len	testArgs	InternalArguments.*
session-parse-oom	src/session/session.c	  if (s == NULL) {\n    return GTLS_ERR_OOM;	  if (s == NULL) {\n    return GTLS_ERR_INTERNAL;	testArgs	ConnectionArguments.*
server-sigs-list	src/server/server.c	  result = gtls_msg_parse_ch_u16_list(e, o->sigs, GTLS_CH_LIST_MAX, \&o->sig_count);\n  if (result != GTLS_OK) {\n    return gtls_conn_fail_parse(c, result);\n  }	  result = gtls_msg_parse_ch_u16_list(e, o->sigs, GTLS_CH_LIST_MAX, \&o->sig_count);	testServer	ServerHello.EveryRefusal*
server-sni-parse	src/server/server.c	    result = gtls_msg_parse_ch_server_name(e, \&o->host);\n    if (result != GTLS_OK) {\n      return gtls_conn_fail_parse(c, result);\n    }	    result = gtls_msg_parse_ch_server_name(e, \&o->host);	testServer	ServerHello.EveryRefusal*
write-output-cap	src/client/stream.c	  while (len > 0 \&\& c->wire.len < c->limits.max_output_bytes) {\n    size_t n = len < GTLS_RECORD_PLAIN_MAX ? len : GTLS_RECORD_PLAIN_MAX;\n\n    /* The last number this key may use	  while (len > 0) {\n    size_t n = len < GTLS_RECORD_PLAIN_MAX ? len : GTLS_RECORD_PLAIN_MAX;\n\n    /* The last number this key may use	testArgs	ConnectionArguments.*
wipe-open-success-tail	src/record/record.c	  (void)gsec_wipe(pt + i - 1u, body - (i - 1u));\n  k->seq++;	  k->seq++;	testRecord	Records.AnOpenLeaves*
wipe-open-padding-cap	src/record/record.c	    (void)gsec_wipe(pt, body);\n    return GTLS_ERR_LIMIT;	    return GTLS_ERR_LIMIT;	testRecord	Records.AnOpenThatFails*
PLANTS
}

bindir=build/linux/release/apps

copy_tree() {
  rm -rf "$scratch/tree" "$scratch/src" "$scratch/obj"
  mkdir -p "$scratch/tree"
  (cd "$root" && git ls-files -co --exclude-standard -z | xargs -0 -I{} cp -p --parents {} "$scratch/tree/")
}

# 0: built and passed; 1: built, and the test failed; 2: did not build.
build_test() {
  (cd "$scratch/tree" && make "$bindir/$1" PREFIX="$PREFIX" -j2 >"$scratch/build.txt" 2>&1)
}

run_test() {
  # $1 binary, $2 filter, $3 mode
  if [ "${3:-}" = valgrind ]; then
    (cd "$scratch/tree" && LD_LIBRARY_PATH="$bindir:$PREFIX/lib/ghoti.io" \
        timeout "$limit" valgrind --error-exitcode=1 --track-origins=yes --suppressions=tests/valgrind.supp \
        "$bindir/$1" --gtest_brief=1 ${2:+--gtest_filter="$2"} >"$scratch/out.txt" 2>&1)
    return $?
  fi
  (cd "$scratch/tree" && LD_LIBRARY_PATH="$bindir:$PREFIX/lib/ghoti.io" \
      timeout "$limit" "$bindir/$1" ${2:+--gtest_filter="$2"} >"$scratch/out.txt" 2>&1)
}

# Apply a plant to the scratch copy: exactly one match, or an error.
apply_plant() {
  python3 - "$scratch/tree/$1" "$2" "$3" <<'PY'
import sys
path, old, new = sys.argv[1:4]
old = old.replace("\\&", "&").replace("\\|", "|").replace("\\n", "\n")
new = new.replace("\\&", "&").replace("\\|", "|").replace("\\n", "\n")
s = open(path).read()
if s.count(old) != 1:
    sys.exit("expected exactly one match, found %d" % s.count(old))
open(path, "w").write(s.replace(old, new))
PY
}


# What a failing run means. $1 exit status, $2 gtest filter, $3 mode, $4 the
# output file. Prints "caught NAMES" or "error WHY"; the caller has already
# dealt with a status of 0. A non-zero status alone is not a catch: a timeout
# (124), a signal (128 and up: a crash, or the kill that follows a timeout), or
# an exit with no gtest FAILED line (a tree that does not run, a missing
# library, a harness that died) is a broken scratch tree, and crediting it
# would let a broken tree "catch" every plant. A catch is a gtest test
# reported FAILED, one that matches the plant's filter when it has one. A
# Valgrind plant is caught by Valgrind reporting errors, since the test itself
# passes.
classify() {
  python3 - "$1" "$2" "$3" "$4" <<'PY'
import fnmatch, re, sys
rc, flt, mode, path = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
text = open(path, errors="replace").read()
if rc == 124:
    print("error timed out (a hang is not a failed test)")
elif rc >= 128:
    # A crash is a catch only when it is attributable: the last test gtest
    # announced ([ RUN ]) never reported OK or FAILED, so the binary died in
    # it, and it matches the plant's filter (or expect). Unplanted, the whole
    # run passed, so that test passes without the plant.
    running = None
    for line in text.splitlines():
        m = re.match(r"\[ RUN      \] (\S+)", line)
        if m:
            running = m.group(1)
        elif running and re.match(r"\[       OK \] %s[ $]|\[  FAILED  \] %s[ $,]" % (re.escape(running), re.escape(running)), line + " "):
            running = None
    want = [f for f in flt.split("-")[0].split(":") if f] if flt else []
    if running is None:
        print("error killed by signal %d with no test running (a crash is not a failed test)" % (rc - 128))
    elif want and not any(fnmatch.fnmatchcase(running, w) for w in want):
        print("error killed by signal %d in %s, outside the filter '%s'" % (rc - 128, running, flt))
    else:
        print("caught by crash in %s (signal %d)" % (running, rc - 128))
elif mode == "valgrind":
    m = re.findall(r"ERROR SUMMARY: (\d+) errors", text)
    if m and int(m[-1]) > 0:
        print("caught valgrind (%s errors)" % m[-1])
    else:
        print("error exit %d with no Valgrind error reported" % rc)
else:
    failed = []
    for line in text.splitlines():
        m = re.match(r"\[  FAILED  \] (\S+\.\S+?)(?:,| \(|\s*$)", line)
        if m and m.group(1) not in failed:
            failed.append(m.group(1))
    if not failed:
        print("error exit %d with no gtest FAILED line" % rc)
    else:
        want = [f for f in flt.split("-")[0].split(":") if f] if flt else []
        hit = [f for f in failed if not want or any(fnmatch.fnmatchcase(f, w) for w in want)]
        if hit:
            print("caught %s%s" % (hit[0], " (+%d more)" % (len(hit) - 1) if len(hit) > 1 else ""))
        else:
            print("error only tests outside the filter '%s' failed: %s" % (flt, failed[0]))
PY
}

# classify() on made-up output: the runner's own gate, run with --anchors.
classify_selftest() {
  t=$(mktemp "${TMPDIR:-/tmp}/gtls-classify.XXXXXX")
  bad=0
  check() { # want-prefix rc filter mode text
    printf '%s\n' "$5" >"$t"
    got=$(classify "$2" "$3" "$4" "$t")
    case "$got" in "$1"*) ;; *) echo "controls: classify($2,'$3','$4') said '$got', wanted '$1...'" >&2; bad=1 ;; esac
  }
  f='[  FAILED  ] Records.OpenWipes (3 ms)
[  FAILED  ] 1 test, listed below:
[  FAILED  ] Records.OpenWipes'
  check "caught Records.OpenWipes" 1 "" "" "$f"
  check "caught Records.OpenWipes" 1 "Records.Open*" "" "$f"
  check "caught Records.OpenWipes" 1 "Other.*:Records.Open*" "" "$f"
  check "error only tests outside" 1 "Other.*" "" "$f"
  check "error killed by signal 11 with no test running" 139 "" "" "$f"
  check "error killed by signal 9 with no test running" 137 "" "" "$f"
  c='[ RUN      ] Records.A
[       OK ] Records.A (1 ms)
[ RUN      ] Records.OpenWipes'
  check "caught by crash in Records.OpenWipes" 139 "" "" "$c"
  check "caught by crash in Records.OpenWipes" 134 "Records.Open*" "" "$c"
  check "error killed by signal 11 in Records.OpenWipes, outside" 139 "Other.*" "" "$c"
  check "error killed by signal 11 with no test running" 139 "" "" "[ RUN      ] Records.A
[       OK ] Records.A (1 ms)"
  check "error killed by signal 11 with no test running" 139 "" "" "[ RUN      ] Records.A
[  FAILED  ] Records.A (1 ms)"
  check "error timed out" 124 "" "" "$f"
  check "error exit 1 with no gtest" 1 "" "" "error while loading shared libraries"
  check "error exit 1 with no gtest" 1 "" "" "[  PASSED  ] 4 tests."
  check "caught valgrind" 1 "" valgrind "==1== ERROR SUMMARY: 3 errors from 2 contexts"
  check "error exit 1 with no Valgrind" 1 "" valgrind "==1== ERROR SUMMARY: 0 errors from 0 contexts"
  check "error killed" 139 "" valgrind "==1== ERROR SUMMARY: 3 errors from 2 contexts"
  rm -f "$t"
  return $bad
}

# The object a source file builds into, in the release tree.
object_of() {
  echo "build/linux/release/objects/${1#src/}" | sed 's/\.c$/.o/'
}

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
' "$root" || exit 1
  classify_selftest || exit 1
  echo "controls: the verdict on a run (caught, or an error for a crash, a timeout, no FAILED line, a failure outside the filter) holds on made-up output"
  exit 0
fi

: "${PREFIX:?set PREFIX to the prefix holding cutil, security and certificate}"
limit=${CONTROLS_TIMEOUT:-600}
scratch=$(mktemp -d "${TMPDIR:-/tmp}/gtls-controls.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
want="$*"
# Fields are separated by a tab in plants() but read with a separator the shell
# does not collapse: a tab is IFS whitespace, so two in a row (an empty field)
# would read as one and shift every field after it.
us=$(printf '\037')

# Which plants run, and which distinct tests they need.
plants | tr '\t' '\037' | while IFS="$us" read -r name file from to test filter mode expect; do
  if [ -n "$want" ] && ! echo " $want " | grep -q " $name "; then
    continue
  fi
  printf '%s\n' "$name$us$file$us$from$us$to$us$test$us${filter:-}$us${mode:-}$us${expect:-}"
done >"$scratch/selected"
count=$(grep -c . "$scratch/selected")
if [ "$count" -eq 0 ]; then
  echo "controls: no plant matches '$want'" >&2
  exit 1
fi

copy_tree
# One build of every test binary the selected plants run.
cut -d "$us" -f5 "$scratch/selected" | sort -u >"$scratch/binaries"
for b in $(cat "$scratch/binaries"); do
  if ! build_test "$b"; then
    echo "controls: the unplanted tree does not build $b, so nothing was measured" >&2
    grep -m5 "error" "$scratch/build.txt" >&2
    exit 1
  fi
done
mkdir -p "$scratch/src" "$scratch/obj"
(cd "$scratch/tree" && find build/linux/release/objects -name '*.o' ! -path '*/tests/*' -print0 \
    | xargs -0 -I{} cp -p --parents {} "$scratch/obj/")

# The unplanted run of each distinct test.
cut -d "$us" -f5-7 "$scratch/selected" | sort -u >"$scratch/tests"
: >"$scratch/bad-baselines"
while IFS="$us" read -r test filter mode; do
  if ! run_test "$test" "$filter" "$mode"; then
    printf '%s\n' "$test$us$filter$us$mode" >>"$scratch/bad-baselines"
    echo "controls: $test ${filter:+($filter) }${mode:+[$mode] }fails BEFORE any plant, so nothing was measured for it" >&2
    tail -5 "$scratch/out.txt" >&2
  fi
done <"$scratch/tests"

caught=0
survived=0
errors=0
while IFS="$us" read -r name file from to test filter mode expect; do
  if grep -qxF "$test$us$filter$us$mode" "$scratch/bad-baselines"; then
    errors=$((errors + 1))
    continue
  fi
  obj=$(object_of "$file")
  if [ ! -f "$scratch/src/$file" ]; then
    mkdir -p "$scratch/src/$(dirname "$file")"
    cp -p "$scratch/tree/$file" "$scratch/src/$file"
  fi
  if ! apply_plant "$file" "$from" "$to"; then
    echo "controls: $name: the plant did not apply" >&2
    errors=$((errors + 1))
    continue
  fi
  built=0
  build_test "$test" && built=1
  if [ "$built" -eq 1 ]; then
    run_test "$test" "$filter" "$mode"
    rc=$?
  fi
  # Put the source back, and the object it built from, newer than the archive
  # so the next relink takes it.
  cp -p "$scratch/src/$file" "$scratch/tree/$file"
  cp -p "$scratch/obj/$obj" "$scratch/tree/$obj"
  touch "$scratch/tree/$obj"
  if [ "$built" -ne 1 ]; then
    echo "controls: $name: the planted copy did not build, so nothing was measured" >&2
    grep -m3 "error" "$scratch/build.txt" >&2
    errors=$((errors + 1))
  elif [ "$rc" -eq 0 ]; then
    echo "controls: $name: $test still PASSES with the check removed" >&2
    survived=$((survived + 1))
  else
    verdict=$(classify "$rc" "${expect:-$filter}" "$mode" "$scratch/out.txt")
    if [ -n "${CONTROLS_VERBOSE:-}" ]; then
      grep -E "Failure|FAILED|Segmentation|Expected|Which is|actual" "$scratch/out.txt" | head -${CONTROLS_VERBOSE} >&2
    fi
    case "$verdict" in
      caught*)
        echo "controls: $name: $test fails with the check removed, and passes with it: ${verdict#caught }"
        caught=$((caught + 1)) ;;
      *)
        echo "controls: $name: ERROR, $test ${verdict#error }, so this is not a catch" >&2
        errors=$((errors + 1)) ;;
    esac
  fi
done <"$scratch/selected"

# The tree is back to the real source: rebuild what the last plants touched
# and run every distinct test once more. A restore that left a planted object
# behind would have made every plant after it measure the wrong thing.
for b in $(cat "$scratch/binaries"); do
  if ! build_test "$b"; then
    echo "controls: after the last plant the restored tree does not build $b" >&2
    errors=$((errors + 1))
  fi
done
while IFS="$us" read -r test filter mode; do
  if grep -qxF "$test$us$filter$us$mode" "$scratch/bad-baselines"; then
    continue
  fi
  if ! run_test "$test" "$filter" "$mode"; then
    echo "controls: $test ${filter:+($filter) }fails after the plants were put back, so the restore left one in" >&2
    errors=$((errors + 1))
  fi
done <"$scratch/tests"

end=$(date +%s)
echo "controls: $count plants: $caught caught, $survived SURVIVED, $errors ERROR, in $((end - start)) s"
[ "$survived" -eq 0 ] && [ "$errors" -eq 0 ]
