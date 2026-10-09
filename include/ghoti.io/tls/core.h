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
 * @file core.h
 *
 * Result codes, alerts, limits, and the version this build reports.
 *
 * No function here, and no function in this library, formats key material
 * into a string. ::gtls_result_string returns one of a fixed set of static
 * strings. There is no `_dump` for a secret, a key share or a transcript.
 *
 * This library does no I/O and reads no clock. Everything that has to know
 * the time is handed a Unix second by its caller.
 */

#ifndef GHOTI_IO_GTLS_CORE_H
#define GHOTI_IO_GTLS_CORE_H

#include <ghoti.io/tls/allocator.h>
#include <ghoti.io/tls/macros.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Result of an operation.
 *
 * Zero is success. ::GTLS_RESULT_COUNT closes the enum so a test can check
 * the string table is complete.
 *
 * The first nine are the suite's fixed vocabulary. The rest say *why* a
 * handshake was refused, because a caller that logs "handshake failed" cannot
 * tell an attack from a misconfiguration. Each refusal that must be sent to
 * the peer also sets an alert, see ::gtls_conn_alert.
 */
typedef enum {
  GTLS_OK = 0,                 ///< The operation succeeded.
  GTLS_ERR_IO,                 ///< The entropy source failed.
  GTLS_ERR_FORMAT,             ///< Well-formed bytes, but not something handled here.
  GTLS_ERR_UNSUPPORTED,        ///< A known feature that is not implemented.
  GTLS_ERR_LIMIT,              ///< A ::GTLS_Limits field was exceeded.
  GTLS_ERR_CORRUPT,            ///< The bytes are not a valid encoding.
  GTLS_ERR_OOM,                ///< The allocator returned NULL.
  GTLS_ERR_INVALID,            ///< A caller-supplied argument is wrong, or a call was out of order.
  GTLS_ERR_INTERNAL,           ///< The library's own invariant failed.
  GTLS_ERR_MISMATCH,           ///< A comparison, MAC or signature did not match.
  GTLS_ERR_PROTOCOL,           ///< The peer broke the protocol: a message out of order, an illegal value.
  GTLS_ERR_DOWNGRADE,          ///< ServerHello.random carried a downgrade sentinel.
  GTLS_ERR_FINISHED,           ///< The peer's Finished did not verify.
  GTLS_ERR_SIGNATURE,          ///< CertificateVerify did not verify.
  GTLS_ERR_CERT_HOST,          ///< The certificate does not name the host that was dialed.
  GTLS_ERR_CERT_EXPIRED,       ///< A certificate on the only fitting path is past its notAfter.
  GTLS_ERR_CERT_NOT_YET_VALID, ///< A certificate on the only fitting path is before its notBefore.
  GTLS_ERR_CERT_ISSUER,        ///< No path leads to an anchor in the trust store.
  GTLS_ERR_CERT_PURPOSE,       ///< The leaf's extendedKeyUsage does not permit serverAuth.
  GTLS_ERR_CERT_INVALID,       ///< A path to an anchor exists and policy refused it, or a signature on it failed.
  GTLS_ERR_FAILED,             ///< The connection has already failed; see ::gtls_conn_failure.
  GTLS_ERR_TRUNCATED,          ///< The stream ended without a close_notify: the peer may have been cut off.
  GTLS_ERR_CLOSED,             ///< The stream ended cleanly (close_notify), or this end has closed it; nothing more will come or go.
  GTLS_ERR_ALERT,              ///< The peer sent a fatal alert; see ::gtls_conn_peer_alert.
  GTLS_ERR_NO_COMMON,          ///< The server found no suite, group or signature scheme both ends accept.
  GTLS_ERR_ALPN,               ///< Both ends have ALPN lists and no protocol is in both.
  GTLS_ERR_EARLY_REJECTED,     ///< Early data was offered and the server did not accept it; see ::gtls_conn_early_status.
  GTLS_RESULT_COUNT
} GTLS_Result;

/**
 * @brief Static description of a result code.
 *
 * The string is never NULL, never allocated, and never contains peer data.
 *
 * @param result The result code, including values outside the enum.
 * @return A static string.
 */
GTLS_API const char * gtls_result_string(GTLS_Result result);

/** @name Alert descriptions (RFC 8446 section 6)
 * The ones this library can ask a caller to send. 0 means none. */
/** @{ */
#define GTLS_ALERT_NONE 0u
#define GTLS_ALERT_UNEXPECTED_MESSAGE 10u
#define GTLS_ALERT_BAD_RECORD_MAC 20u
#define GTLS_ALERT_RECORD_OVERFLOW 22u
#define GTLS_ALERT_HANDSHAKE_FAILURE 40u
#define GTLS_ALERT_BAD_CERTIFICATE 42u
#define GTLS_ALERT_UNSUPPORTED_CERTIFICATE 43u
#define GTLS_ALERT_CERTIFICATE_EXPIRED 45u
#define GTLS_ALERT_CERTIFICATE_UNKNOWN 46u
#define GTLS_ALERT_ILLEGAL_PARAMETER 47u
#define GTLS_ALERT_UNKNOWN_CA 48u
#define GTLS_ALERT_USER_CANCELED 90u
#define GTLS_ALERT_DECODE_ERROR 50u
#define GTLS_ALERT_DECRYPT_ERROR 51u
#define GTLS_ALERT_PROTOCOL_VERSION 70u
#define GTLS_ALERT_INTERNAL_ERROR 80u
#define GTLS_ALERT_MISSING_EXTENSION 109u
#define GTLS_ALERT_UNSUPPORTED_EXTENSION 110u
#define GTLS_ALERT_NO_APPLICATION_PROTOCOL 120u
/** @} */

/** Default for ::GTLS_Limits::max_handshake_message. */
#define GTLS_HANDSHAKE_MESSAGE_DEFAULT 262144u

/**
 * @brief Caps on quantities a peer can ask the library to spend.
 *
 * NULL at a call means these defaults, and 0 in a field means that field's
 * default. A cap reached is ::GTLS_ERR_LIMIT, never a truncation.
 */
typedef struct GTLS_Limits {
  /**
   * Largest handshake message body, in bytes. The reassembly buffer never
   * grows past this plus the 4-byte header. Default
   * ::GTLS_HANDSHAKE_MESSAGE_DEFAULT: ten certificates of 16 KiB with room.
   */
  uint32_t max_handshake_message;
  /**
   * Most bytes of handshake messages one connection accepts in all,
   * counting every message before the handshake completes. Default 1 MiB.
   */
  uint32_t max_handshake_total;
  /** Most entries in a Certificate's list. Default 10. */
  uint32_t max_certificates;
  /** Largest single certificate, in bytes. Default 16384. */
  uint32_t max_certificate_bytes;
  /** Most extensions in one message. Default 32. */
  uint32_t max_extensions;
  /** Largest CertificateVerify signature, in bytes. Default 1024. */
  uint32_t max_signature_bytes;
  /**
   * Largest NewSessionTicket ticket a client keeps, in bytes, and largest
   * identity in a ClientHello's `pre_shared_key` a server will try to open.
   * Neither is an error when exceeded: a client counts a larger ticket
   * and discards it, and a server passes over a larger identity as not its
   * own (the handshake is a full one). Default 16384. A server with ticket
   * keys needs at least the largest ticket it seals (::GTLS_ERR_LIMIT at
   * context creation otherwise).
   */
  uint32_t max_ticket_bytes;
  /** Largest cookie a HelloRetryRequest may ask to be echoed. Default 1024. */
  uint32_t max_cookie_bytes;
  /**
   * Most post-handshake NewSessionTicket messages one connection accepts,
   * and most identities a ClientHello's `pre_shared_key` may offer to a
   * server (more is fatal on either side). Default 16.
   */
  uint32_t max_tickets;
  /** Most bytes of output a connection holds unconsumed, per epoch. Default 65536. */
  uint32_t max_output_bytes;
  /**
   * Largest ClientHello a server accepts, body only. Default 16384, which is
   * more than any browser sends (a post-quantum key share is about 1.2 KiB).
   * A server context refuses a value above 65536, the most a ClientHello
   * can come to.
   */
  uint32_t max_client_hello;
  /**
   * Records one key protects before the sending side must update it (a
   * KeyUpdate is sent by itself when the next record would reach the cap).
   * RFC 8446 section 5.5 puts the AES-GCM limit at 2^24.5 full records.
   * Default 2^24.
   */
  uint32_t max_records_per_key;
  /** Most bytes of zero padding accepted inside one received record. Default 16384. */
  uint32_t max_record_padding;
  /**
   * Most bytes of decrypted application data a connection holds unread. When
   * the buffer is full ::gtls_conn_stream_feed stops taking bytes until the
   * caller reads. Default 65536.
   */
  uint32_t max_app_buffer;
  /** Most KeyUpdate messages one connection accepts. Default 65536. */
  uint32_t max_key_updates;
  /**
   * Most bytes (headers included) of a client's early-data records a server
   * discards without reading them, after a ClientHello that offered
   * `early_data` and does not accept it (RFC 8446 section 4.2.10). Past this
   * the connection fails with ::GTLS_ERR_LIMIT. Default 16384 plus the record
   * overhead (one maximal record: 16384 + 256 + 5 bytes).
   */
  uint32_t max_early_skip_bytes;
  /**
   * Most early data a context may allow: a server's tickets carry at most
   * this as `max_early_data_size`, and a client holds at most this many bytes
   * it has sent as early data until the server's answer is known. A context
   * whose @c max_early_data is above it is ::GTLS_ERR_LIMIT. Default 16384.
   */
  uint32_t max_early_data_bytes;
} GTLS_Limits;

/**
 * @brief Fill in the default limits.
 *
 * @param limits Structure to populate. NULL is ignored.
 */
GTLS_API void gtls_limits_default(GTLS_Limits * limits);

/**
 * @brief This build's version, as the string the Makefile generated.
 *
 * @return A static string, never NULL.
 */
GTLS_API const char * gtls_version_string(void);

/**
 * @brief This build's version, packed as ::GTLS_MAKE_VERSION packs it.
 *
 * @return `(major << 16) | (minor << 8) | patch`.
 */
GTLS_API unsigned gtls_version_number(void);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GTLS_CORE_H */
