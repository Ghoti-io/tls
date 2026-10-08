/*
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * Copyright (C) 2026 Corey Pennycuff
 *
 * This file is part of Ghoti.io TLS.
 *
 * Ghoti.io TLS is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * Ghoti.io TLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file schedule_internal.h
 *
 * The key schedule's private half: the transcript hash and the chain of
 * secrets a handshake walks (RFC 8446 section 7.1).
 *
 * Tests reach these through the static archive; the shared library does not
 * export them.
 */

#ifndef GHOTI_IO_GTLS_SRC_SCHEDULE_SCHEDULE_INTERNAL_H
#define GHOTI_IO_GTLS_SRC_SCHEDULE_SCHEDULE_INTERNAL_H

#include <ghoti.io/tls/macros.h>

#include <ghoti.io/tls/core.h>
#include <ghoti.io/tls/schedule.h>
#include <ghoti.io/security/sha256.h>
#include <ghoti.io/security/sha384.h>

#include <stddef.h>
#include <stdint.h>

/**
 * The hash of every handshake message so far.
 *
 * Before ServerHello the suite, and so the hash, is not known, and the
 * ClientHello has to be hashed already. Both are run until the suite is
 * chosen, and the one that was not chosen is wiped. After a HelloRetryRequest
 * the transcript restarts as a synthetic message_hash message (RFC 8446
 * section 4.4.1).
 */
typedef struct GTLS_Transcript {
  GTLS_Hash hash;     /* GTLS_HASH_NONE while both run */
  int live256;
  int live384;
  GSEC_Sha256 s256;
  GSEC_Sha384 s384;
} GTLS_Transcript;

/** Begin a transcript with both hashes running. */
GTLS_Result gtls_transcript_init(GTLS_Transcript * t);

/** Absorb one whole handshake message, header included. */
GTLS_Result gtls_transcript_update(GTLS_Transcript * t, const void * data,
    size_t len);

/** Choose the suite's hash and wipe the other. Only valid while both run. */
GTLS_Result gtls_transcript_select(GTLS_Transcript * t, GTLS_Hash hash);

/**
 * The hash of what has been absorbed, without disturbing the running state.
 * @p hash must be one of the running hashes. @p out is one digest of it.
 */
GTLS_Result gtls_transcript_snapshot(const GTLS_Transcript * t, GTLS_Hash hash,
    void * out);

/**
 * Replace the transcript, for a HelloRetryRequest, with
 * `message_hash || 00 00 Hash.length || Hash(ClientHello1)`, under @p hash
 * (the HelloRetryRequest's suite). The caller then absorbs the
 * HelloRetryRequest and the second ClientHello.
 */
GTLS_Result gtls_transcript_restart(GTLS_Transcript * t, GTLS_Hash hash);

/** Wipe every byte. Safe on a zeroed or already wiped transcript. */
void gtls_transcript_wipe(GTLS_Transcript * t);

/** The secrets of one handshake, and the hash they are under. */
typedef struct GTLS_Schedule {
  GTLS_Hash hash;
  size_t hlen;
  int stage; /* 0 empty, 1 early, 2 handshake, 3 master */
  unsigned char early[GTLS_HASH_MAX];
  unsigned char handshake[GTLS_HASH_MAX];
  unsigned char master[GTLS_HASH_MAX];
  unsigned char c_hs[GTLS_HASH_MAX];
  unsigned char s_hs[GTLS_HASH_MAX];
  unsigned char c_ap[GTLS_HASH_MAX];
  unsigned char s_ap[GTLS_HASH_MAX];
  unsigned char res[GTLS_HASH_MAX];   /* resumption_master_secret, once the client's Finished is in the transcript */
  int has_res;
} GTLS_Schedule;

/** Begin: Early Secret = HKDF-Extract(0, 0^Hash.length), no PSK. */
GTLS_Result gtls_schedule_early(GTLS_Schedule * s, GTLS_Hash hash);

/**
 * Begin a resumed handshake: Early Secret = HKDF-Extract(0, @p psk), where
 * the PSK is one digest of @p hash (RFC 8446 section 7.1; a resumption PSK
 * is Hash.length long). A PSK of any other length is ::GTLS_ERR_INVALID.
 */
GTLS_Result gtls_schedule_early_psk(GTLS_Schedule * s, GTLS_Hash hash,
    const void * psk, size_t psk_len);

/**
 * Handshake Secret from the (EC)DHE shared secret, and the two handshake
 * traffic secrets from @p th_server_hello, the transcript hash through
 * ServerHello.
 */
GTLS_Result gtls_schedule_handshake(GTLS_Schedule * s, const void * ecdhe,
    size_t ecdhe_len, const void * th_server_hello);

/**
 * Master Secret, and the two application traffic secrets from
 * @p th_server_finished, the transcript hash through the server's Finished.
 */
GTLS_Result gtls_schedule_master(GTLS_Schedule * s,
    const void * th_server_finished);

/** exporter_master_secret, from the same hash as the application secrets. */
GTLS_Result gtls_schedule_exporter(const GTLS_Schedule * s,
    const void * th_server_finished, void * out);

/** resumption_master_secret, from the hash through the client's Finished. */
GTLS_Result gtls_schedule_resumption(const GTLS_Schedule * s,
    const void * th_client_finished, void * out);

/**
 * Compute and keep resumption_master_secret in the schedule (it is wiped with
 * it), from the transcript hash through the client's Finished.
 */
GTLS_Result gtls_schedule_keep_resumption(GTLS_Schedule * s,
    const void * th_client_finished);

/**
 * The PSK one ticket stands for (RFC 8446 section 4.6.1):
 * HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce,
 * Hash.length). @p out is one digest of @p hash.
 */
GTLS_Result gtls_resumption_psk(GTLS_Hash hash, const void * res_master,
    const void * nonce, size_t nonce_len, void * out);

/**
 * The binder key of a PSK (section 7.1): Derive-Secret(Early Secret,
 * "res binder", ""), with the Early Secret taken from @p s, which must hold
 * a PSK's early stage. @p out is one digest.
 */
GTLS_Result gtls_schedule_binder_key(const GTLS_Schedule * s, void * out);

/**
 * The binder for @p psk over @p th, the transcript hash of everything the
 * binder covers (section 4.2.11.2): HMAC(finished_key(binder_key), th).
 * Self-contained: the Early Secret is derived and wiped here. @p out is one
 * digest.
 */
GTLS_Result gtls_binder_compute(GTLS_Hash hash, const void * psk, size_t psk_len,
    const void * th, void * out);

/**
 * Check a received binder without branching on it. A binder of the wrong
 * length is ::GTLS_ERR_MISMATCH (the length is public); one that differs is
 * ::GTLS_ERR_MISMATCH too.
 */
GTLS_Result gtls_binder_check(GTLS_Hash hash, const void * psk, size_t psk_len,
    const void * th, const void * got, size_t got_len);

/**
 * The transcript hash a binder covers: @p t as it stands with the truncated
 * ClientHello (@p trunc, @p trunc_len, the message cut before the binders
 * list) absorbed, which leaves @p t itself untouched. @p t must have its
 * hash chosen; @p out is one digest of it.
 */
GTLS_Result gtls_binder_transcript(const GTLS_Transcript * t, const void * trunc,
    size_t trunc_len, void * out);

/** Wipe every secret. */
void gtls_schedule_wipe(GTLS_Schedule * s);

/**
 * `verify_data` for a Finished message: HMAC(finished_key, @p th), where the
 * finished key is expanded from @p base_key, a handshake traffic secret.
 * @p out is one digest.
 */
GTLS_Result gtls_finished_verify_data(GTLS_Hash hash, const void * base_key,
    const void * th, void * out);

/**
 * Check a received verify_data without branching on it.
 *
 * @return ::GTLS_OK, ::GTLS_ERR_FINISHED when it differs or has the wrong
 *   length, or another failure of the primitives.
 */
GTLS_Result gtls_finished_check(GTLS_Hash hash, const void * base_key,
    const void * th, const void * got, size_t got_len);

#endif /* GHOTI_IO_GTLS_SRC_SCHEDULE_SCHEDULE_INTERNAL_H */
