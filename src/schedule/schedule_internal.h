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
} GTLS_Schedule;

/** Begin: Early Secret = HKDF-Extract(0, 0^Hash.length), no PSK. */
GTLS_Result gtls_schedule_early(GTLS_Schedule * s, GTLS_Hash hash);

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
