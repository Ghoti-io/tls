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
 * @file schedule.h
 *
 * The TLS 1.3 key schedule's public pieces: cipher suites, HKDF-Expand-Label,
 * Derive-Secret, and the key and IV a traffic secret yields.
 *
 * RFC 8446 section 7. A QUIC caller derives its packet protection keys from
 * a traffic secret with HKDF-Expand-Label and its own labels (RFC 9001
 * section 5.1), so that function is exported rather than hidden behind the
 * connection. Nothing here prints or returns a secret except into a buffer
 * the caller supplied, and every function wipes its intermediate keys.
 *
 * The three TLS 1.3 suites differ here only in hash and key length; the AEAD
 * itself belongs to the record layer, which is a later piece.
 */

#ifndef GHOTI_IO_GTLS_SCHEDULE_H
#define GHOTI_IO_GTLS_SCHEDULE_H

#include <ghoti.io/tls/core.h>
#include <ghoti.io/tls/macros.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief A hash a suite uses, which is also the HKDF hash and the transcript hash. */
typedef enum GTLS_Hash {
  GTLS_HASH_NONE = 0,   ///< Not selected.
  GTLS_HASH_SHA256 = 1, ///< SHA-256, 32 bytes.
  GTLS_HASH_SHA384 = 2  ///< SHA-384, 48 bytes.
} GTLS_Hash;

/** Longest digest any suite here uses, in bytes. */
#define GTLS_HASH_MAX 48u

/** Longest AEAD key any suite here uses, in bytes. */
#define GTLS_KEY_MAX 32u

/** Every TLS 1.3 AEAD uses a 12-byte IV. */
#define GTLS_IV_LEN 12u

/** @brief A TLS 1.3 cipher suite, by its IANA code point. */
typedef enum GTLS_Suite {
  GTLS_SUITE_NONE = 0,                          ///< Not selected.
  GTLS_SUITE_AES_128_GCM_SHA256 = 0x1301,       ///< TLS_AES_128_GCM_SHA256.
  GTLS_SUITE_AES_256_GCM_SHA384 = 0x1302,       ///< TLS_AES_256_GCM_SHA384.
  GTLS_SUITE_CHACHA20_POLY1305_SHA256 = 0x1303  ///< TLS_CHACHA20_POLY1305_SHA256.
} GTLS_Suite;

/** @brief 1 if @p suite is one of the three TLS 1.3 suites, else 0. */
GTLS_API int gtls_suite_valid(uint32_t suite);

/** @brief The hash of @p suite, or ::GTLS_HASH_NONE for an unknown suite. */
GTLS_API GTLS_Hash gtls_suite_hash(uint32_t suite);

/** @brief The AEAD key length of @p suite, or 0 for an unknown suite. */
GTLS_API size_t gtls_suite_key_len(uint32_t suite);

/** @brief The digest length of @p hash, or 0 for ::GTLS_HASH_NONE. */
GTLS_API size_t gtls_hash_len(GTLS_Hash hash);

/**
 * @brief HKDF-Expand-Label (RFC 8446 section 7.1).
 *
 * @param hash The suite's hash.
 * @param secret The PRK, @p secret_len bytes.
 * @param label The label without the "tls13 " prefix, which is added here.
 *   At most 249 characters.
 * @param context The context, or NULL when @p context_len is 0.
 * @param out Receives @p out_len bytes. Wiped on failure.
 * @param out_len At most 65535.
 * @return ::GTLS_OK, ::GTLS_ERR_INVALID, or ::GTLS_ERR_LIMIT.
 */
GTLS_API GTLS_Result gtls_hkdf_expand_label(GTLS_Hash hash, const void * secret,
    size_t secret_len, const char * label, const void * context,
    size_t context_len, void * out, size_t out_len);

/**
 * @brief Derive-Secret: HKDF-Expand-Label with the transcript hash as context.
 *
 * @param transcript_hash The hash of the messages so far, one digest of @p hash.
 * @param out One digest of @p hash.
 * @return As ::gtls_hkdf_expand_label.
 */
GTLS_API GTLS_Result gtls_derive_secret(GTLS_Hash hash, const void * secret,
    size_t secret_len, const char * label, const void * transcript_hash,
    void * out);

/**
 * @brief The AEAD key and IV a traffic secret yields (RFC 8446 section 7.3).
 *
 * @param suite One of ::GTLS_Suite.
 * @param secret A traffic secret, one digest long.
 * @param key Receives ::gtls_suite_key_len bytes. At most ::GTLS_KEY_MAX.
 * @param iv Receives ::GTLS_IV_LEN bytes.
 * @return ::GTLS_OK or ::GTLS_ERR_INVALID.
 */
GTLS_API GTLS_Result gtls_traffic_keys(uint32_t suite, const void * secret,
    void * key, void * iv);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GTLS_SCHEDULE_H */
