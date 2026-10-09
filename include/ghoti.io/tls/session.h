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
 * @file session.h
 *
 * Session tickets and resumption (RFC 8446 sections 2.2, 4.2.11 and 4.6.1).
 *
 * **Stateless.** A server keeps nothing per session. It seals what it needs
 * to resume one (the PSK, the suite, the ages, the ALPN protocol and the
 * server name of the original session, and nothing else) into the ticket
 * under a key *the caller supplies*, and opens the ticket when it comes back.
 * The library never generates, stores or persists a ticket key: a
 * ::GTLS_TicketKey is a name, 32 bytes of key and a window of Unix seconds,
 * and a context is given a list of them
 * (::GTLS_ContextConfig::ticket_keys). The newest key that is valid at the
 * time seals; every key that has not expired opens, which is what rotation is.
 * The caller is the one who decides how the keys are shared between the
 * processes that serve one name, and for how long.
 *
 * **A client keeps nothing either.** After the handshake a connection holds the
 * tickets the server sent as sessions (::gtls_conn_session, one per ticket),
 * each an opaque object the caller may serialise, store, and hand to a new
 * connection with ::gtls_conn_set_session before ::gtls_conn_start. A session
 * holds the PSK the ticket stands for: **it is a secret.** Serialising it
 * yields the secret in the clear, protected from corruption by a digest and
 * from nothing else; the caller keeps the blob as it would a private key.
 * ::gtls_session_free wipes.
 *
 * A session is for the host name and the hash of the cipher suite it was
 * issued for, and a connection refuses it for any other. **It is bound to
 * nothing else.** In particular it is not bound to the trust store or the
 * verification hook that authenticated the connection it came from: a resumed
 * connection sends no certificate and runs no chain check, so a session
 * carried to a connection with a different (or looser) trust configuration
 * resumes on the authority of the first. A caller must not share sessions,
 * or their serialised blobs, across contexts whose trust differs, and should
 * key its session store by host and by the trust configuration alike.
 *
 * **Rotate ticket keys long before they wear out.** A ticket's AES-256-GCM
 * nonce is drawn at random (96 bits), so the chance that two tickets under one
 * key repeat a nonce grows with the square of the number issued; NIST SP
 * 800-38D bounds random-nonce GCM at 2^32 invocations per key. The
 * recommended maximum is far inside that: replace the sealing key (a new
 * ::GTLS_TicketKey with a later ::GTLS_TicketKey::not_before) before it has
 * sealed 2^28 tickets, and in practice daily, keeping the old key in the list
 * until the tickets it sealed have run out. A server that issues
 * ::GTLS_ContextConfig::ticket_count tickets per connection reaches the figure
 * that many times sooner.
 *
 * A server that does not accept a ticket (expired, a key it no longer has, another name, another
 * suite, an ALPN protocol the client no longer offers, an age outside its
 * window) is not an error: the handshake continues as a full one, and
 * ::gtls_conn_resumed says which happened. A ticket whose *binder* is wrong is
 * an error, and fatal (RFC 8446 section 4.2.11.2): whoever sent it did not know
 * the PSK.
 *
 * Early data is not built; a ticket never permits it.
 */

#ifndef GHOTI_IO_GTLS_SESSION_H
#define GHOTI_IO_GTLS_SESSION_H

#include <ghoti.io/tls/allocator.h>
#include <ghoti.io/tls/core.h>
#include <ghoti.io/tls/macros.h>
#include <ghoti.io/tls/schedule.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Bytes in a ticket key's name, which is sent in the clear at the front of every ticket. */
#define GTLS_TICKET_KEY_NAME_LEN 16u

/** Bytes in a ticket key (AES-256-GCM). */
#define GTLS_TICKET_KEY_LEN 32u

/** Most ticket keys a context holds. */
#define GTLS_TICKET_KEYS_MAX 8u

/**
 * Most tickets one connection may be sent (::GTLS_ContextConfig::ticket_count).
 * Each stands for a PSK derived from a one-byte ticket nonce, so a 256th would
 * repeat the first's.
 */
#define GTLS_TICKET_COUNT_MAX 255u

/** RFC 8446 section 4.6.1: no ticket may live longer than seven days. */
#define GTLS_TICKET_LIFETIME_MAX 604800u

/** Default lifetime of a ticket this server issues, in seconds: six hours. */
#define GTLS_TICKET_LIFETIME_DEFAULT 21600u

/** Default window, in seconds, for how far the age a client reports may differ from the one the server computes. */
#define GTLS_TICKET_AGE_WINDOW_DEFAULT 10u

/** The most a ticket window may be configured to, in seconds. */
#define GTLS_TICKET_AGE_WINDOW_MAX 86400u

/**
 * @brief One key a server seals and opens tickets under.
 *
 * Supplied by the caller and copied into the context, which wipes its copy
 * when it is freed. Names must differ within a context. The key seals while
 * @p not_before <= now < @p not_after and opens while now < @p not_after.
 */
typedef struct GTLS_TicketKey {
  unsigned char name[GTLS_TICKET_KEY_NAME_LEN]; ///< Sent in the clear; says which key opens the ticket.
  unsigned char key[GTLS_TICKET_KEY_LEN];       ///< The AES-256-GCM key. Secret.
  int64_t not_before;                           ///< Unix second from which this key seals.
  int64_t not_after;                            ///< Unix second from which this key neither seals nor opens.
} GTLS_TicketKey;

/** @brief A ticket and the PSK it stands for, as a client holds them. Opaque. */
typedef struct GTLS_Session GTLS_Session;

/** @brief What a caller may ask of a session without opening it. */
typedef struct GTLS_SessionInfo {
  GTLS_Suite suite;               ///< The suite of the session it came from.
  const unsigned char * host;     ///< The host name it is for, into the session.
  size_t host_len;                ///< Its length.
  const unsigned char * alpn;     ///< The ALPN protocol of the original session, or NULL.
  size_t alpn_len;                ///< Its length; 0 when there was none.
  int64_t received;               ///< The Unix second the ticket arrived.
  uint32_t lifetime;              ///< Seconds the server said it is good for, at most seven days.
  int64_t expires;                ///< ::received plus ::lifetime, saturating at INT64_MAX (a parsed session never needs it to).
  uint32_t max_early_data;        ///< What the server would accept as early data; this library does not send any.
} GTLS_SessionInfo;

/** @brief Wipe and free a session. NULL is allowed. */
GTLS_API void gtls_session_free(GTLS_Session * session);

/**
 * @brief What the session is for and until when.
 *
 * @param info Receives the description; pointers in it live as long as the
 *   session. Not NULL.
 * @return ::GTLS_OK or ::GTLS_ERR_INVALID.
 */
GTLS_API GTLS_Result gtls_session_info(const GTLS_Session * session,
    GTLS_SessionInfo * info);

/**
 * @brief Write the session as bytes a later process can hand to ::gtls_session_parse.
 *
 * Version 1: a version byte, the fields, the ticket and the PSK, and a
 * SHA-256 digest of all of it that catches damage (it is not a MAC: whoever
 * can write the blob can write the digest, and whoever can read it has the
 * PSK). The caller protects the blob.
 *
 * @param out Receives the bytes; NULL to ask only for the length.
 * @param cap Room in @p out.
 * @param len Receives the length, also when @p cap is too small. Not NULL.
 * @return ::GTLS_OK; ::GTLS_ERR_LIMIT when @p cap is too small (nothing
 *   written); ::GTLS_ERR_INVALID.
 */
GTLS_API GTLS_Result gtls_session_serialize(const GTLS_Session * session,
    void * out, size_t cap, size_t * len);

/**
 * @brief Read a session ::gtls_session_serialize wrote.
 *
 * Every length is checked against the data and against @p limits (a ticket
 * above ::GTLS_Limits::max_ticket_bytes is ::GTLS_ERR_LIMIT) before anything
 * is allocated, and the digest is checked before the result is returned, so a
 * blob with any byte changed, cut short or extended is refused.
 *
 * @param allocator NULL for the default; used for the session.
 * @param limits NULL for the defaults.
 * @param out Receives the session. Not NULL; written only on success.
 * @return ::GTLS_OK; ::GTLS_ERR_CORRUPT (truncated, extended, a length that
 *   does not fit, a digest that differs, a PSK of the wrong size for the
 *   suite, a received time so late that adding the lifetime would overflow); ::GTLS_ERR_UNSUPPORTED (another version); ::GTLS_ERR_LIMIT;
 *   ::GTLS_ERR_INVALID; ::GTLS_ERR_OOM.
 */
GTLS_API GTLS_Result gtls_session_parse(const GTLS_Allocator * allocator,
    const GTLS_Limits * limits, const void * data, size_t len,
    GTLS_Session ** out);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GTLS_SESSION_H */
