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
 * @file record_internal.h
 *
 * One direction of the TLS 1.3 record protection (RFC 8446 section 5): the
 * AEAD key, the static IV, the sequence number, and the functions that seal
 * and open a record with them.
 *
 * **The caller cannot supply a nonce.** The nonce is the static IV xor the
 * sequence number (section 5.3) and is built inside ::gtls_record_seal and
 * ::gtls_record_open from the counter this structure holds, which only
 * those two functions advance. A counter at its limit refuses the record
 * rather than wrap or repeat.
 *
 * Plain records, which carry the first handshake messages before any key
 * exists, and the helpers for the five-byte header are here too.
 */

#ifndef GHOTI_IO_GTLS_SRC_RECORD_RECORD_INTERNAL_H
#define GHOTI_IO_GTLS_SRC_RECORD_RECORD_INTERNAL_H

#include <ghoti.io/tls/macros.h>

#include <ghoti.io/tls/core.h>
#include <ghoti.io/tls/schedule.h>

#include "../msg/msg_internal.h"

#include <stddef.h>
#include <stdint.h>

/** Bytes in a record header: type, legacy version, length. */
#define GTLS_RECORD_HEADER 5u
/** Most plaintext one record carries (RFC 8446 section 5.1). */
#define GTLS_RECORD_PLAIN_MAX 16384u
/** Most ciphertext a record may carry (section 5.2): plaintext, type, padding, tag. */
#define GTLS_RECORD_CIPHER_MAX (16384u + 256u)
/** Both AEADs here write a 16-byte tag. */
#define GTLS_RECORD_TAG 16u

/* Content types, RFC 8446 section 5.1. */
#define GTLS_CT_CHANGE_CIPHER_SPEC 20u
#define GTLS_CT_ALERT 21u
#define GTLS_CT_HANDSHAKE 22u
#define GTLS_CT_APPLICATION_DATA 23u

/** One direction's record protection. Holds a key: wipe it with ::gtls_record_keys_wipe. */
typedef struct GTLS_RecordKeys {
  int active;                      /* 0 until keys are installed */
  uint32_t suite;
  unsigned char key[GTLS_KEY_MAX];
  unsigned char iv[GTLS_IV_LEN];
  uint64_t seq;                    /* records protected under this key so far */
  uint64_t limit;                  /* a record with seq at or past this is refused */
  /** Work area: the per-record nonce (the IV xor the counter). Zero between calls, which a test checks. */
  unsigned char nonce[GTLS_IV_LEN];
} GTLS_RecordKeys;

/**
 * Install the key and IV a traffic secret yields (section 7.3), the
 * sequence number at 0. @p limit is the record count after which the key
 * must not be used again; 0 means the largest the counter allows.
 */
GTLS_Result gtls_record_keys_from_secret(GTLS_RecordKeys * k, uint32_t suite,
    const void * traffic_secret, uint64_t limit);

/** Install a key and IV directly. For the known-answer tests, which have the RFC's. */
GTLS_Result gtls_record_keys_from_raw(GTLS_RecordKeys * k, uint32_t suite,
    const void * key, const void * iv, uint64_t limit);

/** Wipe every byte. Safe on a zeroed structure. */
void gtls_record_keys_wipe(GTLS_RecordKeys * k);

/**
 * The traffic secret that follows @p secret (section 7.2):
 * HKDF-Expand-Label(secret, "traffic upd", "", Hash.length). @p out is one
 * digest of the suite's hash and may be @p secret. @p tmp is
 * ::GTLS_HASH_MAX bytes of work area the caller owns, left zero.
 */
GTLS_Result gtls_record_next_secret(uint32_t suite, const void * secret,
    void * out, unsigned char * tmp);

/**
 * Append one protected record to @p out: the header, then the AEAD sealing
 * of `pt || inner_type || padding zeros`, with the header as additional data.
 *
 * The plaintext is copied into @p out and sealed there, in place: it is never
 * anywhere else, so there is no second copy to wipe, and a failure wipes the
 * space it used.
 *
 * @param padding Zero bytes to add inside the record. The connection always
 *   passes 0 (nothing here sends padding); the tests pass more.
 * @return ::GTLS_OK; ::GTLS_ERR_LIMIT when the plaintext and padding do not
 *   fit one record, when the counter has reached its limit, or when @p out is
 *   full; ::GTLS_ERR_INVALID without keys; ::GTLS_ERR_OOM. On any failure the
 *   counter is not advanced and @p out is as it was.
 */
GTLS_Result gtls_record_seal(GTLS_RecordKeys * k, unsigned inner_type,
    const void * pt, size_t pt_len, size_t padding, GTLS_Buf * out);

/** Append one unprotected record: the header, then @p pt. */
GTLS_Result gtls_record_plain(unsigned type, unsigned version, const void * pt,
    size_t pt_len, GTLS_Buf * out);

/**
 * Open a protected record.
 *
 * @param header The five header bytes as received (they are the additional data).
 * @param ct The ciphertext, tag included, as many bytes as the header says.
 * @param max_padding The most zero padding accepted.
 * @param pt Receives the content, at most ::GTLS_RECORD_PLAIN_MAX bytes; at
 *   least ::GTLS_RECORD_CIPHER_MAX bytes of room.
 * @param inner_type Receives the content type found inside.
 * @return ::GTLS_OK; ::GTLS_ERR_LIMIT for a ciphertext past the cap, padding
 *   past @p max_padding, content past the plaintext cap, or a counter at its
 *   limit; ::GTLS_ERR_MISMATCH when the tag does not verify (or the record
 *   is too short to hold one); ::GTLS_ERR_PROTOCOL when the plaintext has no
 *   nonzero byte, so no content type. The counter advances only on success.
 */
GTLS_Result gtls_record_open(GTLS_RecordKeys * k, const unsigned char * header,
    const unsigned char * ct, size_t ct_len, size_t max_padding,
    unsigned char * pt, size_t * pt_len, unsigned * inner_type);

#endif /* GHOTI_IO_GTLS_SRC_RECORD_RECORD_INTERNAL_H */
