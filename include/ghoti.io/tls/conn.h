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
 * @file conn.h
 *
 * One TLS 1.3 handshake, as a state machine over buffers.
 *
 * **Handshake messages in, handshake messages out, never records.** The
 * caller owns the socket, the timers and the record layer (or QUIC's CRYPTO
 * frames). Bytes of handshake messages go in with ::gtls_conn_feed, tagged
 * with the epoch they arrived at; bytes to send come out of
 * ::gtls_conn_pending_output, tagged with the epoch they must be protected
 * at; and ::gtls_conn_secret hands out the traffic secrets by epoch. That is
 * the whole interface RFC 9001 section 4 asks of a TLS stack.
 *
 * A message may arrive in any number of pieces, down to one byte at a time,
 * but it may not span a change of epoch (RFC 8446 section 5.1 says the same
 * of a key change), and nothing may follow ServerHello within its epoch. Both
 * are protocol errors.
 *
 * The client authenticates the server and itself stays anonymous. The chain
 * and the name are checked by `certificate`; there is no mode that skips
 * either. A refusal is a specific ::GTLS_Result, an alert for the caller to
 * send, and a connection whose secrets have been wiped.
 */

#ifndef GHOTI_IO_GTLS_CONN_H
#define GHOTI_IO_GTLS_CONN_H

#include <ghoti.io/tls/context.h>
#include <ghoti.io/tls/core.h>
#include <ghoti.io/tls/macros.h>
#include <ghoti.io/tls/schedule.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief The keys a piece of handshake is protected with (RFC 9001 section 4). */
typedef enum GTLS_Epoch {
  GTLS_EPOCH_INITIAL = 0,     ///< No keys: ClientHello and ServerHello.
  GTLS_EPOCH_EARLY = 1,       ///< Early data keys. Not built; never produced.
  GTLS_EPOCH_HANDSHAKE = 2,   ///< Handshake traffic keys.
  GTLS_EPOCH_APPLICATION = 3, ///< Application traffic keys.
  GTLS_EPOCH_COUNT = 4
} GTLS_Epoch;

/** @brief Which key a secret is, from this endpoint's point of view. */
typedef enum GTLS_Direction {
  GTLS_DIR_WRITE = 0, ///< Protects what this endpoint sends.
  GTLS_DIR_READ = 1   ///< Protects what this endpoint receives.
} GTLS_Direction;

/** @brief One handshake in progress. Holds secrets; free it with ::gtls_conn_free. */
typedef struct GTLS_Conn GTLS_Conn;

/**
 * @brief Make a connection for dialing @p host.
 *
 * @p host is what the caller meant to reach. It is the server_name sent
 * (unless it is an IP literal, which is never sent) and the name the
 * certificate must carry (see ::gcert_x509_verify_host). A literal in
 * brackets is not one: the caller removes them.
 *
 * @param context Outlives the connection. Not NULL.
 * @param host The name or address, not NUL-terminated. Not NULL; 1 to 255
 *   bytes of ASCII with no NUL and no trailing dot (an A-label: this library
 *   has no IDNA). Anything else is ::GTLS_ERR_INVALID.
 * @param host_len Its length in bytes.
 * @param out Receives the connection. Not NULL; written only on success.
 * @return ::GTLS_OK, ::GTLS_ERR_INVALID, ::GTLS_ERR_UNSUPPORTED, or
 *   ::GTLS_ERR_OOM.
 */
GTLS_API GTLS_Result gtls_conn_new(const GTLS_Context * context,
    const char * host, size_t host_len, GTLS_Conn ** out);

/** @brief Wipe and free a connection. NULL is allowed. */
GTLS_API void gtls_conn_free(GTLS_Conn * conn);

/**
 * @brief Build the ClientHello and queue it at ::GTLS_EPOCH_INITIAL.
 *
 * Draws the random and the ephemeral key from the kernel generator.
 *
 * @return ::GTLS_OK; ::GTLS_ERR_INVALID if already started;
 *   ::GTLS_ERR_FAILED if the connection has already failed;
 *   ::GTLS_ERR_IO if the generator failed; ::GTLS_ERR_OOM. After a failure
 *   the connection is failed.
 */
GTLS_API GTLS_Result gtls_conn_start(GTLS_Conn * conn);

/**
 * @brief Give the connection bytes the peer sent.
 *
 * Complete messages are processed as they become complete. Output they
 * cause is queued; ::gtls_conn_pending_output has it.
 *
 * @param epoch The keys the bytes were protected with.
 * @param data The bytes; NULL only when @p len is 0.
 * @param unix_time Seconds since 1970-01-01 UTC, used to check the
 *   certificates. The library has no clock.
 * @return ::GTLS_OK when everything given was accepted (including when the
 *   last message is still incomplete); otherwise the reason the handshake
 *   failed, and the connection is failed and its secrets have been wiped.
 *   After that ::gtls_conn_start, ::gtls_conn_feed, ::gtls_conn_secret,
 *   ::gtls_conn_alpn, ::gtls_conn_server_name_acknowledged and
 *   ::gtls_conn_peer_certificate return ::GTLS_ERR_FAILED; the accessors that
 *   report the failure, and ::gtls_conn_pending_output and
 *   ::gtls_conn_consume_output, keep working.
 */
GTLS_API GTLS_Result gtls_conn_feed(GTLS_Conn * conn, GTLS_Epoch epoch,
    const void * data, size_t len, int64_t unix_time);

/**
 * @brief The bytes waiting to be sent at @p epoch.
 *
 * The pointer is valid until the next call that changes the connection.
 * @p len is 0 when there is nothing. Handshake bytes only: the caller frames
 * them as records or CRYPTO frames.
 *
 * @return ::GTLS_OK or ::GTLS_ERR_INVALID.
 */
GTLS_API GTLS_Result gtls_conn_pending_output(const GTLS_Conn * conn,
    GTLS_Epoch epoch, const unsigned char ** data, size_t * len);

/**
 * @brief Drop the first @p n pending bytes at @p epoch, which were sent.
 *
 * A short write is therefore never a protocol event: consume what was
 * written and ask again.
 *
 * @return ::GTLS_OK, or ::GTLS_ERR_INVALID when @p n exceeds what is pending.
 */
GTLS_API GTLS_Result gtls_conn_consume_output(GTLS_Conn * conn,
    GTLS_Epoch epoch, size_t n);

/**
 * @brief 1 when the handshake has completed and the application secrets exist.
 */
GTLS_API int gtls_conn_is_connected(const GTLS_Conn * conn);

/** @brief 1 when the connection has failed and been wiped. */
GTLS_API int gtls_conn_is_failed(const GTLS_Conn * conn);

/** @brief Why it failed: the result that failed it, or ::GTLS_OK if it has not. */
GTLS_API GTLS_Result gtls_conn_failure(const GTLS_Conn * conn);

/**
 * @brief The alert the caller should send, or ::GTLS_ALERT_NONE.
 *
 * Set when the connection fails. The library does not frame it.
 */
GTLS_API unsigned gtls_conn_alert(const GTLS_Conn * conn);

/**
 * @brief A traffic secret.
 *
 * The handshake secrets exist once ServerHello has been accepted, and the
 * application secrets once the server's Finished has verified. Asking for
 * one earlier is ::GTLS_ERR_INVALID, and a failed connection answers
 * ::GTLS_ERR_FAILED: no secret outlives the failure that wiped it.
 *
 * @param epoch ::GTLS_EPOCH_HANDSHAKE or ::GTLS_EPOCH_APPLICATION.
 *   ::GTLS_EPOCH_EARLY is ::GTLS_ERR_UNSUPPORTED.
 * @param out Receives one digest of the suite's hash; at least
 *   ::GTLS_HASH_MAX bytes unless @p cap is exact.
 * @param len Receives the digest length. Not NULL.
 * @return ::GTLS_OK, ::GTLS_ERR_INVALID, ::GTLS_ERR_UNSUPPORTED,
 *   ::GTLS_ERR_LIMIT when @p cap is too small, or ::GTLS_ERR_FAILED.
 */
GTLS_API GTLS_Result gtls_conn_secret(const GTLS_Conn * conn, GTLS_Epoch epoch,
    GTLS_Direction direction, void * out, size_t cap, size_t * len);

/** @brief The negotiated suite, or ::GTLS_SUITE_NONE before ServerHello. */
GTLS_API GTLS_Suite gtls_conn_suite(const GTLS_Conn * conn);

/** @brief The negotiated group, or ::GTLS_GROUP_NONE before ServerHello. */
GTLS_API GTLS_Group gtls_conn_group(const GTLS_Conn * conn);

/**
 * @brief The ALPN protocol the server chose.
 *
 * @param protocol Receives a pointer into the connection, valid until it is
 *   freed; NULL with @p len 0 when none was chosen or EncryptedExtensions has
 *   not arrived.
 * @param len Receives its length. Not NULL.
 * @return ::GTLS_OK, ::GTLS_ERR_INVALID, or ::GTLS_ERR_FAILED.
 */
GTLS_API GTLS_Result gtls_conn_alpn(const GTLS_Conn * conn,
    const unsigned char ** protocol, size_t * len);

/**
 * @brief Whether the server acknowledged the server_name it was sent.
 *
 * @param out Receives 1 or 0 (0 until EncryptedExtensions has arrived).
 * @return ::GTLS_OK, ::GTLS_ERR_INVALID, or ::GTLS_ERR_FAILED.
 */
GTLS_API GTLS_Result gtls_conn_server_name_acknowledged(const GTLS_Conn * conn,
    int * out);

/** @brief 1 when a HelloRetryRequest was answered. */
GTLS_API int gtls_conn_retried(const GTLS_Conn * conn);

/**
 * @brief The server's end-entity certificate, once the handshake has completed.
 *
 * Before that, though the chain may already have been accepted, it is NULL:
 * the certificate is trusted only after CertificateVerify and Finished. A
 * failed connection answers ::GTLS_ERR_FAILED.
 *
 * @param der Receives a pointer into the connection, valid until it is
 *   freed; NULL until the connection is connected.
 * @param len Receives its length. Not NULL.
 */
GTLS_API GTLS_Result gtls_conn_peer_certificate(const GTLS_Conn * conn,
    const unsigned char ** der, size_t * len);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GTLS_CONN_H */
