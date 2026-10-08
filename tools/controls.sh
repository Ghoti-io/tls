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
server-client-finished	src/server/server.c	result = gtls_finished_check(hash, c->sec.schedule.c_hs, th, got, hlen);	result = GTLS_OK;	testServer
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
oom-in-flight	src/server/server.c	    (void)gsec_wipe(k->ecdhe, sizeof k->ecdhe);\n    return c->state == GTLS_STATE_FAILED ? result\n        : gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);	    (void)gsec_wipe(k->ecdhe, sizeof k->ecdhe);\n    return c->state == GTLS_STATE_FAILED ? result\n        : gtls_conn_fail(c, GTLS_ERR_INTERNAL, GTLS_ALERT_INTERNAL_ERROR);	testAlloc
oom-in-record-buffer	src/client/stream.c	      *consumed = pos;\n      return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);	      *consumed = pos;\n      return gtls_conn_fail(c, GTLS_ERR_INTERNAL, GTLS_ALERT_INTERNAL_ERROR);	testAlloc
psk-last	src/server/server.c	if (ch->exts[ch->ext_count - 1u].type != GTLS_EXT_PRE_SHARED_KEY) {	if (0) {	testPsk
psk-modes-present	src/server/server.c	if (modes == NULL) {\n      return missing(c);	if (modes == NULL) {\n      return gtls_conn_illegal(c);	testPsk
psk-offer-parsed	src/server/server.c	result = gtls_msg_parse_ch_psk_offer(e, \&c->limits, \&o->psk_offer);	result = GTLS_OK; (void)o->psk_offer;	testPsk
psk-count-equal	src/msg/msg.c	if (n_ids != n_binders) {	if (0) {	testPsk
psk-identity-cap	src/msg/msg.c	identity.len > limits->max_ticket_bytes \|\|	0 \|\|	testPsk
psk-count-cap	src/msg/msg.c	++n_ids > limits->max_tickets	(++n_ids > limits->max_tickets \&\& 0)	testTicket
psk-binder-length	src/msg/msg.c	result = gtls_reader_vector(\&binders, 1, 32, 0, \&binder);	result = gtls_reader_vector(\&binders, 1, 0, 0, \&binder);	testPsk
early-data-empty	src/msg/msg.c	return e->len == 0 ? GTLS_OK : GTLS_ERR_CORRUPT;	(void)e->len; return GTLS_OK;	testPsk
early-data-seen	src/server/server.c	c->early_skip = 1;	(void)0;	testPsk
early-skip-needs-offer	src/client/stream.c	result == GTLS_ERR_MISMATCH \&\& c->early_skip \&\&	result == GTLS_ERR_MISMATCH \&\&	testPsk
early-skip-ends-on-open	src/client/stream.c	c->early_skip = 0; /* a record that opens ends the early data */	(void)0;	testPsk
early-skip-cap	src/client/stream.c	if (cost > c->limits.max_early_skip_bytes - c->early_skipped) {	if (0) {	testPsk
early-skip-after-retry	src/client/stream.c	if (c->early_skip \&\& epoch == GTLS_EPOCH_INITIAL \&\& type == GTLS_CT_APPLICATION_DATA) {	if (0) {	testPsk
early-skip-header	src/client/stream.c	!(c->early_skip \&\& type == GTLS_CT_APPLICATION_DATA)	1	testPsk
retry-early-data	src/server/server.c	if (o->early_data) {\n    return gtls_conn_illegal(c);	if (0) {\n    return gtls_conn_illegal(c);	testPsk
retry-ends-skip	src/server/server.c	    c->early_skip = 0;\n  } else if (o.early_data \&\& o.psk) {	    (void)0;\n  } else if (o.early_data \&\& o.psk) {	testPsk
retry-may-drop-early-data	src/server/server.c	a->type == GTLS_EXT_EARLY_DATA \|\|	0 \|\|	testPsk
retry-may-refresh-psk	src/server/server.c	a->type == GTLS_EXT_PRE_SHARED_KEY) {	0) {	testPsk
psk-count-cap-edge	src/msg/msg.c	++n_ids > limits->max_tickets	++n_ids >= limits->max_tickets	testPsk
psk-binder-cap	src/msg/msg.c	++n_binders > limits->max_tickets	(++n_binders > limits->max_tickets \&\& 0)	testPsk
psk-binder-cap-edge	src/msg/msg.c	++n_binders > limits->max_tickets	++n_binders >= limits->max_tickets	testPsk
psk-identity-cap-edge	src/msg/msg.c	identity.len > limits->max_ticket_bytes \|\|	identity.len >= limits->max_ticket_bytes \|\|	testPsk
psk-empty-identity	src/msg/msg.c	gtls_reader_vector(\&ids, 2, 1, 0, \&identity)	gtls_reader_vector(\&ids, 2, 0, 0, \&identity)	testPsk
psk-ids-min-high	src/msg/msg.c	gtls_reader_vector(\&r, 2, 7, 0, \&ids)	gtls_reader_vector(\&r, 2, 8, 0, \&ids)	testPsk
psk-ids-min-zero	src/msg/msg.c	gtls_reader_vector(\&r, 2, 7, 0, \&ids)	gtls_reader_vector(\&r, 2, 0, 0, \&ids)	testPsk
psk-binder-31	src/msg/msg.c	gtls_reader_vector(\&binders, 1, 32, 0, \&binder)	gtls_reader_vector(\&binders, 1, 31, 0, \&binder)	testPsk
psk-modes-parse-result	src/server/server.c	result = gtls_msg_parse_ch_psk_modes(modes, \&o->psk_dhe);\n    if (result != GTLS_OK) {	result = gtls_msg_parse_ch_psk_modes(modes, \&o->psk_dhe);\n    if (0) {	testPsk
early-data-parse-result	src/server/server.c	result = gtls_msg_parse_ch_early_data(e);\n    if (result != GTLS_OK) {	result = gtls_msg_parse_ch_early_data(e);\n    if (0) {	testPsk
early-data-needs-psk	src/server/server.c	} else if (o.early_data \&\& o.psk) {	} else if (o.early_data) {	testPsk
early-limit-resolve	src/core/core.c	  GTLS_RESOLVE(max_early_skip_bytes)\n	  (void)0;\n	testPsk
early-skip-only-mismatch	src/client/stream.c	if (result == GTLS_ERR_MISMATCH \&\& c->early_skip	if (result != GTLS_OK \&\& c->early_skip	testPsk
early-skip-header-type	src/client/stream.c	!(c->early_skip \&\& type == GTLS_CT_APPLICATION_DATA)	!c->early_skip	testPsk
early-skip-seq-advance	src/client/stream.c	(void)gsec_wipe(scratch, sizeof scratch);\n      return skip_early(c, blen);	c->sec.rd.seq++;\n      (void)gsec_wipe(scratch, sizeof scratch);\n      return skip_early(c, blen);	testPsk
early-skip-pending-fragment	src/client/stream.c	and early data is not that. */\n    return gtls_conn_unexpected(c);	and early data is not that. */\n    (void)0;	testPsk
binder-check	src/server/server.c	result = gtls_binder_check(hash, r->plain.psk, r->plain.psk_len, th, en->binder,	result = GTLS_OK; (void)gtls_binder_check(hash, r->plain.psk, r->plain.psk_len, th, en->binder,	testResume
binder-compare	src/schedule/schedule.c	return same == GSEC_ERR_MISMATCH ? GTLS_ERR_MISMATCH : gtls_from_gsec(same);	return GTLS_OK;	testTicket
binder-length	src/schedule/schedule.c	if (got_len != hlen) {\n    return GTLS_ERR_MISMATCH;	if (0 \&\& got_len != hlen) {\n    return GTLS_ERR_MISMATCH;	testResume
binder-transcript	src/server/server.c	result = gtls_binder_transcript(\&c->sec.transcript, msg, o->psk_trunc, th);	result = gtls_binder_transcript(\&c->sec.transcript, msg, o->psk_trunc - 1u, th);	testResume
ticket-key-name	src/session/ticket.c	gsec_equal(keys[i].name, ticket, GTLS_TICKET_KEY_NAME_LEN) == GSEC_OK) {	1) {	testTicket
ticket-key-expiry	src/session/ticket.c	if (now < keys[i].not_after \&\&	if ((now < keys[i].not_after \|\| 1) \&\&	testTicket
ticket-sealing-newest	src/session/ticket.c	(best == NULL \|\| keys[i].not_before > best->not_before)	(best == NULL)	testTicket
ticket-sealing-window	src/session/ticket.c	if (keys[i].not_before <= now \&\& now < keys[i].not_after \&\&	if (now < keys[i].not_after \&\&	testTicket
ticket-state-version	src/session/ticket.c	if (n < 1u + 2u + 1u \|\| plain[at++] != GTLS_TICKET_STATE_VERSION) {	if (n < 1u + 2u + 1u \|\| (at++, 0)) {	testTicket
ticket-state-lifetime	src/session/ticket.c	if (t.lifetime > GTLS_TICKET_LIFETIME_MAX \|\| n - at < t.alpn_len + 1u) {	if (n - at < t.alpn_len + 1u) {	testTicket
ticket-state-exact	src/session/ticket.c	if (n - at != t.sni_len) {	if (n - at < t.sni_len) {	testTicket
ticket-fresh-lifetime	src/session/ticket.c	if (elapsed_s >= p->lifetime) {	if (0) {	testTicket
ticket-fresh-window	src/session/ticket.c	return diff <= (int64_t)window_ms;	return diff <= (int64_t)window_ms \|\| 1;	testTicket
ticket-fresh-age-add	src/session/ticket.c	client_ms = (int64_t)(uint32_t)(obfuscated_age - p->age_add);	client_ms = (int64_t)obfuscated_age;	testTicket
ticket-fresh-future	src/session/ticket.c	if (elapsed_s > GTLS_TICKET_AGE_WINDOW_MAX) {	if (0) {	testTicket
ticket-fresh-lifetime-max	src/session/ticket.c	if (p->lifetime > GTLS_TICKET_LIFETIME_MAX) {\n    return 0;	if (0) {\n    return 0;	testTicket
resume-sni	src/server/server.c	t.sni_len == o->host.len \&\& names_equal(t.sni, o->host.p, t.sni_len) \&\&	1 \&\&	testResume
resume-alpn	src/server/server.c	(t.alpn_len == 0 \|\| offered_alpn(o, t.alpn, t.alpn_len));	1;	testResume
resume-suite-context	src/server/server.c	offered_suite(o, t.suite) \&\& context_suite(x, t.suite) \&\&	offered_suite(o, t.suite) \&\& 1 \&\&	testResume
resume-suite-offered	src/server/server.c	good = offered_suite(o, t.suite) \&\& context_suite(x, t.suite) \&\&	good = 1 \&\& context_suite(x, t.suite) \&\&	testResume
resume-fresh	src/server/server.c	gtls_ticket_fresh(\&t, now, en->age, x->ticket_age_window * 1000u) \&\&	1 \&\&	testResume
resume-dhe	src/server/server.c	if (!o->psk \|\| !o->psk_dhe \|\| x->ticket_key_count == 0) {	if (!o->psk \|\| x->ticket_key_count == 0) {	testResume
resume-retry-suite	src/server/server.c	if (second \&\& r->active \&\& r->plain.suite != (uint32_t)c->suite) {	if (0) {	testResume
resume-suite-choice	src/server/server.c	} else if (r->active) {\n    c->suite = (GTLS_Suite)r->plain.suite;	} else if (0) {\n    c->suite = (GTLS_Suite)r->plain.suite;	testResume
resume-needs-no-scheme	src/server/server.c	if (c->scheme == 0 \&\& !r->active) {	if (c->scheme == 0) {	testResume
resume-no-certificate	src/server/server.c	if (!resumed) {\n    result = send_authentication	if (1) {\n    result = send_authentication	testResume
resume-selects-psk	src/server/server.c	sp.psk = resumed;	sp.psk = 0;	testResume
resume-early-secret	src/server/server.c	result = resumed ? gtls_schedule_early_psk(	result = 0 ? gtls_schedule_early_psk(	testResume
ticket-resumption-secret-server	src/server/server.c	result = gtls_schedule_keep_resumption(\&c->sec.schedule, th);	result = gtls_schedule_keep_resumption(\&c->sec.schedule, c->sec.schedule.c_hs);	testResume
ticket-nonce	src/server/server.c	unsigned char nonce = (unsigned char)i;	unsigned char nonce = 0;	testResume
ticket-count	src/server/server.c	for (i = 0; i < x->ticket_count; i++) {	for (i = 0; i < x->ticket_count + 1u; i++) {	testResume
ticket-lifetime-sent	src/server/server.c	t.lifetime = p.lifetime;	t.lifetime = 0;	testResume
ticket-age-add-sent	src/server/server.c	t.age_add = p.age_add;	t.age_add = 0;	testResume
client-binder	src/client/client.c	result = patch_binder(c, \&empty, \&c->hello);	result = GTLS_OK;	testResume
client-binder-retry	src/client/client.c	result = patch_binder(c, \&c->sec.transcript, \&h2);	result = GTLS_OK;	testResume
client-retry-hash	src/client/client.c	if (hash == gtls_suite_hash(c->offer->suite)) {	if (1) {	testResume
client-age	src/client/client.c	return (uint32_t)(elapsed * 1000u) + s->age_add;	return (uint32_t)(elapsed * 1000u);	testResume
client-psk-index	src/client/client.c	sh.psk_identity != 0 \|\|	0 \|\|	testResume
client-psk-hash	src/client/client.c	gtls_suite_hash(sh.suite) != offered_hash(c)	0	testResume
client-skips-certificate	src/client/client.c	c->state = c->resumed ? GTLS_STATE_WAIT_FIN : GTLS_STATE_WAIT_CERT;	c->state = GTLS_STATE_WAIT_CERT;	testResume
client-lifetime-zero	src/client/client.c	if (t.lifetime == 0) {	if (0) {	testResume
client-lifetime-cap	src/client/client.c	s->lifetime = t->lifetime < GTLS_TICKET_LIFETIME_MAX ? t->lifetime : GTLS_TICKET_LIFETIME_MAX;	s->lifetime = t->lifetime;	testResume
ticket-resumption-secret-client	src/client/client.c	result = gtls_schedule_keep_resumption(\&c->sec.schedule, th);	result = gtls_schedule_keep_resumption(\&c->sec.schedule, c->sec.schedule.c_hs);	testResume
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
PLANTS
}

copy_tree() {
  rm -rf "$scratch/tree"
  mkdir -p "$scratch/tree"
  (cd "$root" && git ls-files -co --exclude-standard -z | xargs -0 -I{} cp --parents {} "$scratch/tree/")
}

# 0: built and passed; 1: built, and the test failed; 2: did not build. A plant
# that does not compile has caught nothing (-Werror turns a parameter the plant
# stopped using into one), and must not be counted as a test that failed.
run_test() {
  (cd "$scratch/tree" && make "build/linux/release/apps/$1" PREFIX="$PREFIX" -j2 >"$scratch/build.txt" 2>&1) || return 2
  (cd "$scratch/tree" && LD_LIBRARY_PATH="build/linux/release/apps:$PREFIX/lib/ghoti.io" \
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
    echo "controls: $name: $test fails (or does not build) BEFORE the plant, so nothing was measured" >&2
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
  run_test "$test"
  case $? in
    0)
      echo "controls: $name: $test still PASSES with the check removed" >&2
      echo FAIL >"$scratch/status" ;;
    2)
      echo "controls: $name: the planted copy did not build, so nothing was measured" >&2
      grep -m3 "error" "$scratch/build.txt" >&2
      echo FAIL >"$scratch/status" ;;
    *)
      echo "controls: $name: $test fails with the check removed, and passes with it" ;;
  esac
done
[ -f "$scratch/status" ] && status=1
exit $status
