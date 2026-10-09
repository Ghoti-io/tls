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
 * trust store, the allocator and the private keys it was given, outlive every
 * connection made from it.**
 *
 * A context is a client's or a server's, by ::GTLS_ContextConfig::role. A
 * server's carries one or more identities (a chain, the key that signs for
 * it, and the names it serves); the connection picks one by the client's
 * server_name, and the first is the default.
 *
 * The configuration already has room for what later pieces add: TLS 1.2, a
 * pre-shared key, and a client certificate. Those fields are refused with
 * ::GTLS_ERR_UNSUPPORTED while they are not built, rather than ignored, so a
 * caller who sets one finds out.
 */

#ifndef GHOTI_IO_GTLS_CONTEXT_H
#define GHOTI_IO_GTLS_CONTEXT_H

#include <ghoti.io/tls/allocator.h>
#include <ghoti.io/tls/core.h>
#include <ghoti.io/tls/macros.h>
#include <ghoti.io/tls/schedule.h>
#include <ghoti.io/tls/session.h>

#include <ghoti.io/certificate/certificate.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Which end of the connection this endpoint is. */
typedef enum GTLS_Role {
  GTLS_ROLE_CLIENT = 1, ///< Dials; authenticates the server.
  GTLS_ROLE_SERVER = 2  ///< Accepts; presents an identity. Client authentication is not built.
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
 * @brief One certificate chain a server presents, and what it is for.
 *
 * The chain is copied. The key is not: it is borrowed and must outlive the
 * context. The leaf must match the key (::gcert_key_matches), and the
 * name check is the client's.
 */
typedef struct GTLS_Identity {
  const void * const * chain;     ///< The chain in DER, leaf first. Not NULL.
  const size_t * chain_lens;      ///< Length of each entry of @p chain.
  size_t chain_count;             ///< Length of @p chain: 1 to 32.
  const GCERT_Key * key;          ///< The private key for the leaf. Not NULL.
  const char * const * names;     ///< The server names this identity is chosen for, NUL-terminated, 1 to 255 bytes each. A leading "*." stands for one label. NULL with a count of 0: chosen only as the default.
  size_t name_count;              ///< Length of @p names.
} GTLS_Identity;

/**
 * @brief A server's replay decision for early data (RFC 8446 section 8).
 *
 * Called once for a ClientHello that offers early data with a ticket this
 * server sealed, after every check that can be made locally has passed and the
 * binder has verified, and so only for a ticket whose holder proved it has
 * the PSK. The library keeps no state across connections, so it cannot know
 * whether this ticket was shown before; the caller can.
 *
 * @param user ::GTLS_ContextConfig::anti_replay_user.
 * @param ticket_id SHA-256 of the identity the client offered: stable for a
 *   ticket, and the same each time it is presented. Use it as the key of the
 *   store; it is not secret.
 * @param issued The Unix second the ticket was sealed.
 * @param age_ms The age the client reports for the ticket, in milliseconds.
 * @return 1 to accept the early data. 0 rejects it, and so does any other
 *   value: the handshake continues without early data and the client resends.
 *   The callback must not block for long and must not call back into the
 *   connection.
 */
typedef int (*GTLS_AntiReplayFn)(void * user, const unsigned char ticket_id[32],
    int64_t issued, uint32_t age_ms);

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
   * skips the chain check. Optional for a server, which has no client
   * certificate to check yet.
   */
  const GCERT_TrustStore * trust;
  const char * const * alpn;      ///< Protocol names, in preference order; NUL-terminated, 1 to 255 bytes each. A client offers them; a server picks the first that the client offered.
  size_t alpn_count;              ///< Length of @p alpn. Default 0: none offered, or none selected.
  const GTLS_Suite * suites;      ///< Suites, in preference order (a server's order wins). Default: AES-128-GCM, ChaCha20-Poly1305, AES-256-GCM.
  size_t suite_count;             ///< Length of @p suites.
  const GTLS_Group * groups;      ///< Groups, in preference order. Default: X25519, P-256, P-384.
  size_t group_count;             ///< Length of @p groups.
  const GCERT_SigScheme * sig_algs; ///< Signature schemes to offer (a client) or to sign with, in preference order (a server). Default: the RSA-PSS, ECDSA and Ed25519 ones, then RSA PKCS#1 for certificate signatures.
  size_t sig_alg_count;           ///< Length of @p sig_algs.
  /**
   * Non-zero to send a random 32-byte legacy_session_id and so look like
   * the handshake middleboxes were built around (RFC 8446 appendix D.4).
   * Zero, the default, sends an empty one, which is what QUIC requires.
   */
  int middlebox_compat;
  const GTLS_Limits * limits;     ///< NULL for the defaults. Copied.
  /**
   * A server's identities. Either this list, or the single chain below, and
   * not both. A server needs at least one.
   */
  const GTLS_Identity * identities;
  size_t identity_count;          ///< Length of @p identities.
  size_t default_identity;        ///< Index of the identity chosen when the client's name matches none, or sends none. Default 0.
  /**
   * A single identity, as a shorthand for a server with one: the chain, its
   * key, and no names. For a client these are client authentication, which is
   * not built, and are refused.
   */
  const void * const * chain;     ///< A certificate chain to present, DER.
  const size_t * chain_lens;      ///< Length of each entry of @p chain.
  size_t chain_count;             ///< Length of @p chain.
  const GCERT_Key * key;          ///< The private key for @p chain.
  /**
   * @name Session tickets (server)
   * A server seals the state of a session into the ticket it sends, under a
   * key it is given here, and keeps nothing (session.h). With no key, or with
   * ::ticket_count of 0, it issues none and accepts none: a ClientHello that
   * offers a ticket gets the full handshake. A client context refuses these
   * fields (::GTLS_ERR_INVALID); a client's tickets are in the connection.
   * @{ */
  const GTLS_TicketKey * ticket_keys; ///< The keyring, copied. The newest key valid at the time seals; every unexpired one opens. NULL with a count of 0: no tickets.
  size_t ticket_key_count;        ///< Length of @p ticket_keys: at most ::GTLS_TICKET_KEYS_MAX, names distinct.
  unsigned ticket_count;          ///< NewSessionTicket messages sent after each handshake (the default of 1 is set by ::gtls_context_config_default; 0 disables them). At most ::GTLS_Limits::max_tickets and ::GTLS_TICKET_COUNT_MAX.
  uint32_t ticket_lifetime;       ///< Seconds a ticket is good for, sent to the client. 0: ::GTLS_TICKET_LIFETIME_DEFAULT. At most ::GTLS_TICKET_LIFETIME_MAX.
  uint32_t ticket_age_window;     ///< Seconds the age a client reports may differ from the server's own. 0: ::GTLS_TICKET_AGE_WINDOW_DEFAULT. At most ::GTLS_TICKET_AGE_WINDOW_MAX.
  /** @} */
  /**
   * @name Early data (0-RTT), RFC 8446 section 2.3
   * Off unless set. Bytes sent as early data can be replayed by anyone who
   * recorded them, so a server accepts them only on a caller's say-so.
   * A server sets both ::max_early_data (the allowance its tickets carry) and
   * ::anti_replay (the decision); either alone is ::GTLS_ERR_LIMIT. A client
   * sets ::max_early_data to offer early data when the session it resumes
   * permits it, up to that many bytes; a client refuses ::anti_replay
   * (::GTLS_ERR_INVALID). Both are at most ::GTLS_Limits::max_early_data_bytes
   * (::GTLS_ERR_LIMIT otherwise).
   * @{ */
  uint32_t max_early_data;        ///< 0: none (the default).
  GTLS_AntiReplayFn anti_replay;  ///< A server's replay decision.
  void * anti_replay_user;        ///< Passed to ::anti_replay.
  /** @} */
  /** @name Reserved for later pieces; must be zero or NULL today.
   * @{ */
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
 * @return ::GTLS_OK; ::GTLS_ERR_INVALID for a client with no trust store, a
 *   server with no identity (or with both forms of one), an identity whose key
 *   does not match its leaf or whose names are empty or oversized, a server with a max_client_hello above 65536, an empty
 *   or oversized name, an unknown suite or group, a count with a NULL
 *   list, a ticket key list that is too long, repeats a name or has a window
 *   that ends before it begins, a ticket count above ::GTLS_Limits::max_tickets,
 *   a lifetime or a window above its maximum, ticket fields on a client, or
 *   a replay callback on a client;
 *   ::GTLS_ERR_UNSUPPORTED for a reserved field or a version other
 *   than TLS 1.3; ::GTLS_ERR_LIMIT for an ALPN list that does not fit in the
 *   extension, a chain too large to send within ::GTLS_Limits::max_output_bytes,
 *   or a ticket key list with ::GTLS_Limits::max_ticket_bytes too small for
 *   the largest ticket this library seals, a ticket count above
 *   ::GTLS_TICKET_COUNT_MAX (the ticket nonce is one byte), a server with
 *   ::GTLS_ContextConfig::max_early_data and no replay callback or the
 *   callback without it, or a ::GTLS_ContextConfig::max_early_data above
 *   ::GTLS_Limits::max_early_data_bytes;
 *   ::GTLS_ERR_OOM.
 */
GTLS_API GTLS_Result gtls_context_new(const GTLS_Allocator * allocator,
    const GTLS_ContextConfig * config, GTLS_Context ** out);

/** @brief Free a context. NULL is allowed. No connection may still use it. */
GTLS_API void gtls_context_free(GTLS_Context * context);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GTLS_CONTEXT_H */
