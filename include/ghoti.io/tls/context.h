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
 * @file context.h
 *
 * The configuration shared by connections.
 *
 * A ::GTLS_Context is built once from a ::GTLS_ContextConfig, copies what it
 * needs, and is never changed afterwards, so any number of connections may
 * read it at once. The lifetime rule is one line: **the context, and the
 * trust store and allocator it was given, outlive every connection made
 * from it.**
 *
 * The configuration already has room for what later pieces add: the server
 * role, TLS 1.2, a pre-shared key, and a client certificate. Those fields
 * are refused with ::GTLS_ERR_UNSUPPORTED while they are not built, rather
 * than ignored, so a caller who sets one finds out.
 */

#ifndef GHOTI_IO_GTLS_CONTEXT_H
#define GHOTI_IO_GTLS_CONTEXT_H

#include <ghoti.io/tls/allocator.h>
#include <ghoti.io/tls/core.h>
#include <ghoti.io/tls/macros.h>
#include <ghoti.io/tls/schedule.h>

#include <ghoti.io/certificate/certificate.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Which end of the connection this endpoint is. */
typedef enum GTLS_Role {
  GTLS_ROLE_CLIENT = 1, ///< Dials; authenticates the server.
  GTLS_ROLE_SERVER = 2  ///< Accepts. Not built yet.
} GTLS_Role;

/** @name Protocol versions, as a mask
 * Only TLS 1.3 is built. */
/** @{ */
#define GTLS_VERSION_TLS13 0x01u
#define GTLS_VERSION_TLS12 0x02u
/** @} */

/** @brief A key-exchange group, by its IANA NamedGroup code point. */
typedef enum GTLS_Group {
  GTLS_GROUP_NONE = 0,         ///< Not selected.
  GTLS_GROUP_SECP256R1 = 0x0017, ///< P-256.
  GTLS_GROUP_SECP384R1 = 0x0018, ///< P-384.
  GTLS_GROUP_X25519 = 0x001d   ///< X25519.
} GTLS_Group;

/**
 * @brief What a context is made from. Fill it with ::gtls_context_config_default.
 *
 * A NULL list with a count of 0 means the default list.
 */
typedef struct GTLS_ContextConfig {
  GTLS_Role role;                 ///< ::GTLS_ROLE_CLIENT, the default.
  unsigned versions;              ///< Mask of ::GTLS_VERSION_TLS13 and later others; default TLS 1.3 only.
  /**
   * The anchors the server's chain must end at. Borrowed, and it must
   * outlive the context. Required for a client: there is no mode that
   * skips the chain check.
   */
  const GCERT_TrustStore * trust;
  const char * const * alpn;      ///< Protocol names to offer, in preference order; NUL-terminated, 1 to 255 bytes each.
  size_t alpn_count;              ///< Length of @p alpn. Default 0: none offered.
  const GTLS_Suite * suites;      ///< Suites to offer, in preference order. Default: AES-128-GCM, ChaCha20-Poly1305, AES-256-GCM.
  size_t suite_count;             ///< Length of @p suites.
  const GTLS_Group * groups;      ///< Groups to offer, in preference order. Default: X25519, P-256, P-384.
  size_t group_count;             ///< Length of @p groups.
  const GCERT_SigScheme * sig_algs; ///< Signature schemes to offer. Default: the RSA-PSS, ECDSA and Ed25519 ones, then RSA PKCS#1 for certificate signatures.
  size_t sig_alg_count;           ///< Length of @p sig_algs.
  /**
   * Non-zero to send a random 32-byte legacy_session_id and so look like
   * the handshake middleboxes were built around (RFC 8446 appendix D.4).
   * Zero, the default, sends an empty one, which is what QUIC requires.
   */
  int middlebox_compat;
  const GTLS_Limits * limits;     ///< NULL for the defaults. Copied.
  /** @name Reserved for later pieces; must be zero or NULL today.
   * @{ */
  const void * const * chain;     ///< A certificate chain to present (server, or client authentication), DER.
  const size_t * chain_lens;      ///< Length of each entry of @p chain.
  size_t chain_count;             ///< Length of @p chain.
  const GCERT_Key * key;          ///< The private key for @p chain.
  const void * psk;               ///< A pre-shared key.
  size_t psk_len;                 ///< Length of @p psk.
  const void * psk_identity;      ///< Its identity.
  size_t psk_identity_len;        ///< Length of @p psk_identity.
  /** @} */
} GTLS_ContextConfig;

/** @brief An immutable configuration shared by connections. */
typedef struct GTLS_Context GTLS_Context;

/**
 * @brief Fill in the default configuration.
 *
 * @param config Structure to populate. NULL is ignored.
 */
GTLS_API void gtls_context_config_default(GTLS_ContextConfig * config);

/**
 * @brief Make a context.
 *
 * @param allocator NULL for cutil's default. Kept; it must outlive the context.
 * @param config Not NULL. Copied, except the trust store, which is borrowed.
 * @param out Receives the context. Not NULL; written only on success.
 * @return ::GTLS_OK; ::GTLS_ERR_INVALID for a missing trust store, an empty
 *   or oversized name, an unknown suite or group, or a count with a NULL
 *   list; ::GTLS_ERR_UNSUPPORTED for a reserved field, the server role, or a
 *   version other than TLS 1.3; ::GTLS_ERR_LIMIT for an ALPN list that does
 *   not fit in the extension; ::GTLS_ERR_OOM.
 */
GTLS_API GTLS_Result gtls_context_new(const GTLS_Allocator * allocator,
    const GTLS_ContextConfig * config, GTLS_Context ** out);

/** @brief Free a context. NULL is allowed. No connection may still use it. */
GTLS_API void gtls_context_free(GTLS_Context * context);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GTLS_CONTEXT_H */
