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
 * @file record.h
 *
 * The TLS 1.3 record layer over a byte stream (RFC 8446 section 5), for a
 * connection of either role.
 *
 * A connection is driven through **one** of two interfaces, and the first
 * call decides which. The message interface of conn.h carries handshake
 * messages tagged by epoch and hands out traffic secrets: that is what QUIC
 * wants (RFC 9001 section 4), and a connection used that way never frames a
 * record. This file is the other one: the caller hands in the bytes that
 * arrived on a stream, takes the bytes to send, writes and reads
 * application data, and the library does the records, the handshake inside
 * them, the key changes, `KeyUpdate`, `close_notify` and the truncation
 * check. Mixing the two on one connection is ::GTLS_ERR_INVALID.
 *
 * The library does no I/O. A short write to the socket is not a protocol
 * event: take what is in ::gtls_conn_stream_output, send as much as the
 * socket takes, and tell ::gtls_conn_stream_consume how much that was.
 *
 * **The nonce is not the caller's.** Every record is sealed with the static
 * IV xor the record's sequence number (RFC 8446 section 5.3), held inside the
 * connection and advanced only by sealing and opening. A sequence number is
 * never reused or wrapped: before the key's record count (::GTLS_Limits::max_records_per_key)
 * is reached the sending side updates its key by itself.
 *
 * The usual loop, for either role:
 *
 *     // bytes arrived from the socket:
 *     gtls_conn_stream_feed(c, buf, n, now, &used);      // may take less than n
 *     while (gtls_conn_read(c, out, sizeof out, &got) == GTLS_OK && got) { ... }
 *     // anything to send (handshake, replies, application data, alerts):
 *     gtls_conn_stream_output(c, &p, &m);  send(p, m);  gtls_conn_stream_consume(c, sent);
 *     // the socket reported end of file:
 *     gtls_conn_stream_eof(c);       // GTLS_ERR_TRUNCATED unless close_notify came first
 *
 * What is sent: plaintext records only until keys exist; protected records
 * with no padding; at most 2^14 bytes of content per record. What is
 * accepted: protected records with padding up to ::GTLS_Limits::max_record_padding,
 * and, before the peer's Finished, a dummy change_cipher_spec record
 * (RFC 8446 appendix D.4), at most twice.
 */

#ifndef GHOTI_IO_GTLS_RECORD_H
#define GHOTI_IO_GTLS_RECORD_H

#include <ghoti.io/tls/conn.h>
#include <ghoti.io/tls/core.h>
#include <ghoti.io/tls/macros.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Most content one record carries (RFC 8446 section 5.1). */
#define GTLS_RECORD_PLAINTEXT_MAX 16384u
/** Most ciphertext a record may carry (section 5.2). A longer one is ::GTLS_ERR_LIMIT with `record_overflow`. */
#define GTLS_RECORD_CIPHERTEXT_MAX (16384u + 256u)

/**
 * @brief Give the connection bytes that arrived on the stream.
 *
 * Records are assembled from any number of pieces, down to one byte at a
 * time, and many may arrive in one call. What they carry is routed:
 * handshake messages to the handshake, application data to ::gtls_conn_read,
 * alerts to the connection's state. The handshake's replies (and the alert,
 * if it fails) are queued for ::gtls_conn_stream_output.
 *
 * Fewer bytes than offered may be taken. Decrypted application data waits
 * for ::gtls_conn_read, in at most ::GTLS_Limits::max_app_buffer bytes, and
 * when that is full no more is taken until some is read: the caller keeps the
 * rest and offers it again. After a close_notify, whatever follows is
 * ignored and counted as consumed.
 *
 * @param data The bytes; NULL only when @p len is 0.
 * @param unix_time Seconds since 1970-01-01 UTC, for the certificate checks.
 * @param consumed Receives how many of the bytes were taken, also on failure.
 *   Not NULL.
 * @return ::GTLS_OK; otherwise the reason the connection failed
 *   (::GTLS_ERR_MISMATCH for a record that does not authenticate, with
 *   `bad_record_mac`; ::GTLS_ERR_LIMIT for a record past its size with
 *   `record_overflow`; ::GTLS_ERR_ALERT when the peer sent a fatal alert; the
 *   handshake's own results), after which every secret has been wiped and the
 *   alert, if there is one, waits in the output. ::GTLS_ERR_FAILED for a
 *   connection that had already failed; ::GTLS_ERR_INVALID before
 *   ::gtls_conn_start, or after the message interface was used.
 */
GTLS_API GTLS_Result gtls_conn_stream_feed(GTLS_Conn * conn, const void * data,
    size_t len, int64_t unix_time, size_t * consumed);

/**
 * @brief The stream ended: the socket was closed or reset by the peer.
 *
 * If the peer sent close_notify first, the end is clean and this is
 * ::GTLS_OK. If not, the data may have been cut off by an attacker, and the
 * connection fails with ::GTLS_ERR_TRUNCATED, which is not the result of a
 * clean close, and no alert (there is no one to tell). Read what is
 * available before calling this: a failed connection discards what it held.
 *
 * @return ::GTLS_OK, ::GTLS_ERR_TRUNCATED, ::GTLS_ERR_FAILED (it had
 *   failed), or ::GTLS_ERR_INVALID.
 */
GTLS_API GTLS_Result gtls_conn_stream_eof(GTLS_Conn * conn);

/**
 * @brief The bytes waiting to be sent on the stream.
 *
 * Turns whatever the handshake has queued into records first. The pointer is
 * valid until the next call that changes the connection; @p len is 0 when
 * there is nothing. A failed connection keeps its alert here until it is
 * consumed. This always succeeds for a valid connection: whether it failed is
 * ::gtls_conn_is_failed's to say.
 *
 * @return ::GTLS_OK, or ::GTLS_ERR_INVALID (bad argument, or the message
 *   interface was used).
 */
GTLS_API GTLS_Result gtls_conn_stream_output(GTLS_Conn * conn,
    const unsigned char ** data, size_t * len);

/** @brief Drop the first @p n bytes of the output, which were sent. ::GTLS_ERR_INVALID if @p n is more than is waiting. */
GTLS_API GTLS_Result gtls_conn_stream_consume(GTLS_Conn * conn, size_t n);

/**
 * @brief Send application data.
 *
 * Only once the handshake has completed (a client's Finished is queued
 * before the first record of data, and a server writes once the client's
 * Finished has verified). The data is sealed into records at once; they wait
 * in the output. At most ::GTLS_Limits::max_output_bytes of output are held,
 * so a write may take fewer bytes than offered, and then the caller drains
 * the output and writes the rest.
 *
 * @param written Receives the bytes taken, also when it is 0. Not NULL.
 * @return ::GTLS_OK; ::GTLS_ERR_INVALID before the handshake has completed;
 *   ::GTLS_ERR_CLOSED after ::gtls_conn_close; ::GTLS_ERR_FAILED;
 *   ::GTLS_ERR_LIMIT if the key's record limit is below 2.
 */
GTLS_API GTLS_Result gtls_conn_write(GTLS_Conn * conn, const void * data,
    size_t len, size_t * written);

/**
 * @brief Take decrypted application data.
 *
 * @param n Receives the bytes copied; 0 when there is none yet. Not NULL.
 * @return ::GTLS_OK (with @p n possibly 0: more has to arrive);
 *   ::GTLS_ERR_CLOSED when the peer sent close_notify and everything it sent
 *   before has been read; ::GTLS_ERR_FAILED, once the connection has
 *   failed (data not yet read was discarded); ::GTLS_ERR_INVALID.
 */
GTLS_API GTLS_Result gtls_conn_read(GTLS_Conn * conn, void * out, size_t cap,
    size_t * n);

/**
 * @brief Send close_notify: this end will write no more.
 *
 * The peer's own close_notify is still read. Writes after this are
 * ::GTLS_ERR_CLOSED. Calling it again is ::GTLS_OK.
 */
GTLS_API GTLS_Result gtls_conn_close(GTLS_Conn * conn);

/**
 * @brief Update this end's write key (RFC 8446 section 4.6.3).
 *
 * The KeyUpdate message goes out under the old key, and every record after
 * it uses the new one. A connection does this by itself when a key has
 * protected ::GTLS_Limits::max_records_per_key records.
 *
 * @param request_peer Non-zero to ask the peer to update its own write key
 *   too, which it does, and this end's read key follows when the peer's
 *   KeyUpdate arrives.
 * @return ::GTLS_OK; ::GTLS_ERR_INVALID before the handshake has completed;
 *   ::GTLS_ERR_CLOSED; ::GTLS_ERR_FAILED.
 */
GTLS_API GTLS_Result gtls_conn_key_update(GTLS_Conn * conn, int request_peer);

/** @brief 1 once the peer's close_notify has been received. */
GTLS_API int gtls_conn_peer_closed(const GTLS_Conn * conn);

/**
 * @brief The description of the fatal alert the peer sent, or 0.
 *
 * Set when the connection failed with ::GTLS_ERR_ALERT.
 */
GTLS_API unsigned gtls_conn_peer_alert(const GTLS_Conn * conn);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GTLS_RECORD_H */
