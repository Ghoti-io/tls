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
 * @file stream.c
 *
 * The record layer over a stream, for both roles: records assembled from
 * bytes, their protection opened, their content routed to the handshake, to
 * the application or to the connection's own state; and the other way, the
 * handshake's queued messages, application data, alerts and KeyUpdate sealed
 * into records. RFC 8446 section 5, section 6 and section 4.6.3.
 *
 * Which keys protect what is decided here and nowhere else. The read keys
 * follow the state of the handshake (the epoch it is waiting for); the write
 * keys follow what has been sent: they change when the first record of a
 * later epoch is made, so a record is always sealed under the keys the peer
 * has been told about.
 */

#include <ghoti.io/tls/macros.h>

#include <ghoti.io/tls/record.h>

#include "../core/core_internal.h"
#include "client_internal.h"

#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/security/secret.h>

#include <string.h>

/** The most dummy change_cipher_spec records one connection accepts. */
#define GTLS_CCS_MAX 2u
/** Alert levels (RFC 8446 section 6). */
#define GTLS_ALERT_WARNING 1u
#define GTLS_ALERT_FATAL 2u

static void wipe_buf(GTLS_Buf * b) {
  if (b->data != NULL) {
    (void)gsec_wipe(b->data, b->cap);
  }
}

void gtls_stream_free(GTLS_Conn * c) {
  wipe_buf(&c->rbuf);
  wipe_buf(&c->wire);
  wipe_buf(&c->app_in);
  gtls_buf_free(&c->rbuf);
  gtls_buf_free(&c->wire);
  gtls_buf_free(&c->app_in);
}

/* -------------------------------------------------------------------- keys */

static const unsigned char * traffic_secret(const GTLS_Conn * c, GTLS_Epoch epoch,
    int write) {
  const GTLS_Schedule * s = &c->sec.schedule;
  int client_secret = write == (c->role == GTLS_ROLE_CLIENT);

  if (epoch == GTLS_EPOCH_HANDSHAKE && s->stage >= 2) {
    return client_secret ? s->c_hs : s->s_hs;
  }
  if (epoch == GTLS_EPOCH_APPLICATION && s->stage >= 3) {
    return client_secret ? s->c_ap : s->s_ap;
  }
  return NULL;
}

static GTLS_Result install_keys(GTLS_Conn * c, GTLS_Epoch epoch, int write) {
  const unsigned char * secret = traffic_secret(c, epoch, write);
  size_t hlen = c->sec.schedule.hlen;
  GTLS_Result result;

  if (secret == NULL || hlen == 0) {
    return gtls_conn_fail(c, GTLS_ERR_INTERNAL, GTLS_ALERT_INTERNAL_ERROR);
  }
  if (write) {
    memcpy(c->sec.wr_secret, secret, hlen);
    result = gtls_record_keys_from_secret(&c->sec.wr, (uint32_t)c->suite,
        c->sec.wr_secret,
        epoch == GTLS_EPOCH_APPLICATION ? c->limits.max_records_per_key : 0);
    c->wr_epoch = epoch;
  } else {
    memcpy(c->sec.rd_secret, secret, hlen);
    result = gtls_record_keys_from_secret(&c->sec.rd, (uint32_t)c->suite,
        c->sec.rd_secret, 0);
    c->rd_epoch = epoch;
  }
  if (result != GTLS_OK) {
    return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }
  return GTLS_OK;
}

/** Replace a direction's traffic secret with its successor and derive its keys (section 7.2). */
static GTLS_Result rotate(GTLS_Conn * c, int write) {
  unsigned char * secret = write ? c->sec.wr_secret : c->sec.rd_secret;
  GTLS_RecordKeys * keys = write ? &c->sec.wr : &c->sec.rd;
  GTLS_Result result = gtls_record_next_secret((uint32_t)c->suite, secret, secret);

  if (result == GTLS_OK) {
    result = gtls_record_keys_from_secret(keys, (uint32_t)c->suite, secret,
        write ? c->limits.max_records_per_key : 0);
  }
  if (result != GTLS_OK) {
    return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }
  return GTLS_OK;
}

/* ------------------------------------------------------------------ output */

static GTLS_Result record_failed(GTLS_Conn * c, GTLS_Result result) {
  /* The caps here are the library's own (the wire buffer's), not the peer's. */
  return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
}

static GTLS_Result put_plain(GTLS_Conn * c, unsigned type, unsigned version,
    const void * data, size_t n) {
  GTLS_Result result = gtls_record_plain(type, version, data, n, &c->wire);

  return result == GTLS_OK ? GTLS_OK : record_failed(c, result);
}

static GTLS_Result put_sealed(GTLS_Conn * c, unsigned type, const void * data,
    size_t n) {
  GTLS_Result result = gtls_record_seal(&c->sec.wr, type, data, n, 0, &c->wire);

  return result == GTLS_OK ? GTLS_OK : record_failed(c, result);
}

GTLS_Result gtls_stream_send_alert(GTLS_Conn * c, unsigned level, unsigned description) {
  unsigned char a[2];

  a[0] = (unsigned char)level;
  a[1] = (unsigned char)description;
  if (c->wr_epoch == GTLS_EPOCH_INITIAL) {
    return gtls_record_plain(GTLS_CT_ALERT, 0x0303, a, 2, &c->wire);
  }
  return gtls_record_seal(&c->sec.wr, GTLS_CT_ALERT, a, 2, 0, &c->wire);
}

/** The dummy change_cipher_spec of RFC 8446 appendix D.4, once. */
static GTLS_Result put_ccs(GTLS_Conn * c) {
  static const unsigned char one = 1;

  if (c->ccs_sent) {
    return GTLS_OK;
  }
  c->ccs_sent = 1;
  return put_plain(c, GTLS_CT_CHANGE_CIPHER_SPEC, 0x0303, &one, 1);
}

GTLS_Result gtls_stream_flush(GTLS_Conn * c) {
  GTLS_Buf * q;
  GTLS_Result result;

  if (c->state == GTLS_STATE_FAILED) {
    return GTLS_ERR_FAILED;
  }
  /* The first flight, in the clear. A ClientHello's record says 1.0, for
   * the servers and middleboxes that look (section 5.1); the rest say 1.2. */
  q = &c->out[GTLS_EPOCH_INITIAL];
  while (q->len > 0) {
    size_t n = q->len < GTLS_RECORD_PLAIN_MAX ? q->len : GTLS_RECORD_PLAIN_MAX;
    unsigned version = c->role == GTLS_ROLE_CLIENT && !c->hello_flushed ? 0x0301u : 0x0303u;

    result = put_plain(c, GTLS_CT_HANDSHAKE, version, q->data, n);
    if (result != GTLS_OK) {
      return result;
    }
    c->hello_flushed = 1;
    gtls_buf_consume(q, n);
    /* A server answering a client that asked for compatibility mode (a
     * non-empty legacy_session_id) sends the dummy record after its first
     * message, whether that is ServerHello or HelloRetryRequest. */
    if (c->role == GTLS_ROLE_SERVER && c->session_id_len != 0) {
      result = put_ccs(c);
      if (result != GTLS_OK) {
        return result;
      }
    }
  }
  q = &c->out[GTLS_EPOCH_HANDSHAKE];
  if (q->len > 0 && c->wr_epoch < GTLS_EPOCH_HANDSHAKE) {
    if (c->role == GTLS_ROLE_CLIENT && c->context->middlebox_compat) {
      result = put_ccs(c);
      if (result != GTLS_OK) {
        return result;
      }
    }
    result = install_keys(c, GTLS_EPOCH_HANDSHAKE, 1);
    if (result != GTLS_OK) {
      return result;
    }
  }
  while (q->len > 0) {
    size_t n = q->len < GTLS_RECORD_PLAIN_MAX ? q->len : GTLS_RECORD_PLAIN_MAX;

    result = put_sealed(c, GTLS_CT_HANDSHAKE, q->data, n);
    if (result != GTLS_OK) {
      return result;
    }
    gtls_buf_consume(q, n);
  }
  /* Once its Finished has gone, an end speaks under its application key:
   * the client's right after its Finished, and the server's right after its
   * flight, before the client's Finished has come back. An alert, or
   * close_notify, from then on is sealed under that key, which is the one
   * the peer reads with. */
  if (q->len == 0 && c->out[GTLS_EPOCH_HANDSHAKE].len == 0 &&
      c->wr_epoch == GTLS_EPOCH_HANDSHAKE && c->sec.schedule.stage >= 3 &&
      (c->state == GTLS_STATE_CONNECTED || c->state == GTLS_STATE_S_WAIT_FIN)) {
    result = install_keys(c, GTLS_EPOCH_APPLICATION, 1);
    if (result != GTLS_OK) {
      return result;
    }
  }
  /* What is queued at the application epoch is, a message at a time,
   * KeyUpdate (sealed under the key it is replacing, and the key then moves)
   * and NewSessionTicket (sealed under the key in use). */
  q = &c->out[GTLS_EPOCH_APPLICATION];
  if (q->len > 0 && c->wr_epoch < GTLS_EPOCH_APPLICATION) {
    result = install_keys(c, GTLS_EPOCH_APPLICATION, 1);
    if (result != GTLS_OK) {
      return result;
    }
  }
  while (q->len >= 4u) {
    size_t mlen = 4u + (((size_t)q->data[1] << 16) | ((size_t)q->data[2] << 8) | q->data[3]);
    unsigned type = q->data[0];

    if (mlen > q->len || mlen > GTLS_RECORD_PLAIN_MAX) {
      return gtls_conn_fail(c, GTLS_ERR_INTERNAL, GTLS_ALERT_INTERNAL_ERROR);
    }
    result = put_sealed(c, GTLS_CT_HANDSHAKE, q->data, mlen);
    if (result != GTLS_OK) {
      return result;
    }
    gtls_buf_consume(q, mlen);
    if (type == GTLS_HS_KEY_UPDATE) {
      if (c->ku_queued > 0) {
        c->ku_queued--;
      }
      result = rotate(c, 1);
      if (result != GTLS_OK) {
        return result;
      }
    }
  }
  return GTLS_OK;
}

/* ------------------------------------------------------------------- input */

static GTLS_Result on_ccs(GTLS_Conn * c, const unsigned char * body, size_t n) {
  int allowed;

  /* Before the first ClientHello, or after the peer's Finished, it is an
   * unexpected record; between them it is skipped (appendix D.4). */
  if (c->role == GTLS_ROLE_CLIENT) {
    allowed = c->state >= GTLS_STATE_WAIT_SH && c->state < GTLS_STATE_CONNECTED;
  } else {
    allowed = c->state == GTLS_STATE_S_WAIT_CH2 || c->state == GTLS_STATE_S_WAIT_FIN;
  }
  if (!allowed || n != 1u || body[0] != 1u || ++c->ccs_seen > GTLS_CCS_MAX) {
    return gtls_conn_unexpected(c);
  }
  return GTLS_OK;
}

static GTLS_Result on_alert(GTLS_Conn * c, const unsigned char * body, size_t n,
    int authenticated) {
  if (n != 2u) {
    /* An alert is one record of two bytes, never split and never empty. */
    return gtls_conn_fail(c, GTLS_ERR_CORRUPT, GTLS_ALERT_DECODE_ERROR);
  }
  if (!authenticated) {
    /* Nobody vouched for this record. It can end the handshake, which anyone
     * on the path can do by closing the connection, but it can neither be a
     * clean close (that would be a truncation nobody could tell from the
     * peer's own) nor be ignored. */
    c->peer_alert = body[1];
    return gtls_conn_fail(c, GTLS_ERR_ALERT, GTLS_ALERT_NONE);
  }
  if (body[1] == 0) {
    c->peer_closed = 1; /* close_notify */
    return GTLS_OK;
  }
  if (body[1] == GTLS_ALERT_USER_CANCELED) {
    return GTLS_OK; /* a warning that closure follows, section 6.1 */
  }
  /* Every other alert is fatal, whatever its level says (section 6). */
  c->peer_alert = body[1];
  return gtls_conn_fail(c, GTLS_ERR_ALERT, GTLS_ALERT_NONE);
}

static GTLS_Result open_failed(GTLS_Conn * c, GTLS_Result result) {
  switch (result) {
    case GTLS_ERR_MISMATCH:
      return gtls_conn_fail(c, result, GTLS_ALERT_BAD_RECORD_MAC);
    case GTLS_ERR_LIMIT:
      return gtls_conn_fail(c, result, GTLS_ALERT_RECORD_OVERFLOW);
    case GTLS_ERR_PROTOCOL:
      return gtls_conn_fail(c, result, GTLS_ALERT_UNEXPECTED_MESSAGE);
    default:
      return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }
}

/**
 * Discard one record of early data that was offered and not accepted. Only
 * the number of bytes is kept: they never reach the application, and the cap
 * is what keeps a peer from sending them for ever.
 */
static GTLS_Result skip_early(GTLS_Conn * c, size_t body_len) {
  size_t cost = GTLS_RECORD_HEADER + body_len;

  if (c->in.len != 0) {
    /* A handshake message is in pieces: only its next piece may follow
     * (RFC 8446 section 5.1), and early data is not that. */
    return gtls_conn_unexpected(c);
  }
  if (cost > c->limits.max_early_skip_bytes - c->early_skipped) {
    return gtls_conn_fail(c, GTLS_ERR_LIMIT, GTLS_ALERT_UNEXPECTED_MESSAGE);
  }
  c->early_skipped += cost;
  return GTLS_OK;
}

/** One whole record is in rbuf. */
static GTLS_Result process_record(GTLS_Conn * c, int64_t now) {
  const unsigned char * header = c->rbuf.data;
  const unsigned char * body = header + GTLS_RECORD_HEADER;
  size_t blen = c->rbuf.len - GTLS_RECORD_HEADER;
  unsigned type = header[0];
  GTLS_Epoch epoch = gtls_conn_expected_epoch(c->state);
  unsigned char scratch[GTLS_RECORD_CIPHERTEXT_MAX];
  const unsigned char * pt;
  size_t pt_len;
  unsigned inner;
  GTLS_Result result;

  if (c->in.len != 0 && (type == GTLS_CT_CHANGE_CIPHER_SPEC || type == GTLS_CT_ALERT)) {
    /* A handshake message is in pieces: only its next piece may follow
     * (RFC 8446 section 5.1). */
    return gtls_conn_unexpected(c);
  }
  if (type == GTLS_CT_CHANGE_CIPHER_SPEC) {
    return on_ccs(c, body, blen);
  }
  if (type == GTLS_CT_ALERT && epoch != GTLS_EPOCH_INITIAL) {
    /* A peer that fails before it has sent a protected record sends its
     * alert in the clear, and this end may already be reading under keys. An
     * alert nobody authenticated can only end the handshake, which anyone
     * on the path can do by closing it. */
    return on_alert(c, body, blen, 0);
  }
  if (c->early_skip && epoch == GTLS_EPOCH_INITIAL && type == GTLS_CT_APPLICATION_DATA) {
    /* After a HelloRetryRequest the client's early records arrive before
     * its second ClientHello, and no key exists to try them with. */
    return skip_early(c, blen);
  }
  if (epoch == GTLS_EPOCH_INITIAL) {
    pt = body;
    pt_len = blen;
    inner = type;
  } else {
    if (c->rd_epoch != epoch) {
      result = install_keys(c, epoch, 0);
      if (result != GTLS_OK) {
        return result;
      }
    }
    result = gtls_record_open(&c->sec.rd, header, body, blen,
        c->limits.max_record_padding, scratch, &pt_len, &inner);
    if (result == GTLS_ERR_MISMATCH && c->early_skip && type == GTLS_CT_APPLICATION_DATA) {
      /* Early data, which was offered and not accepted, is encrypted under a
       * key this server never had: a record that does not open is skipped
       * (RFC 8446 section 4.2.10). The counter did not move. */
      (void)gsec_wipe(scratch, sizeof scratch);
      return skip_early(c, blen);
    }
    if (result != GTLS_OK) {
      (void)gsec_wipe(scratch, sizeof scratch);
      return open_failed(c, result);
    }
    c->early_skip = 0; /* a record that opens ends the early data */
    pt = scratch;
  }
  switch (inner) {
    case GTLS_CT_HANDSHAKE:
      if (pt_len == 0) {
        result = gtls_conn_unexpected(c);
      } else {
        result = gtls_conn_feed_stream(c, epoch, pt, pt_len, now);
      }
      break;
    case GTLS_CT_ALERT:
      if (c->in.len != 0) {
        result = gtls_conn_unexpected(c);
        break;
      }
      result = on_alert(c, pt, pt_len, epoch != GTLS_EPOCH_INITIAL);
      break;
    case GTLS_CT_APPLICATION_DATA:
      if (c->state != GTLS_STATE_CONNECTED || c->in.len != 0) {
        result = gtls_conn_unexpected(c);
      } else {
        c->ku_run = 0; /* data between updates: they are not a flood */
        result = gtls_buf_append(&c->app_in, pt, pt_len);
        if (result != GTLS_OK) {
          /* The room was checked before the record was read. */
          result = gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
        }
      }
      break;
    default:
      result = gtls_conn_unexpected(c);
      break;
  }
  (void)gsec_wipe(scratch, sizeof scratch);
  return result;
}

/** The header of a record is in rbuf: refuse what no record may be, early. */
static GTLS_Result check_header(GTLS_Conn * c) {
  const unsigned char * h = c->rbuf.data;
  unsigned type = h[0];
  size_t len = ((size_t)h[3] << 8) | h[4];
  GTLS_Epoch epoch = gtls_conn_expected_epoch(c->state);

  if (type != GTLS_CT_CHANGE_CIPHER_SPEC && type != GTLS_CT_ALERT &&
      type != GTLS_CT_HANDSHAKE && type != GTLS_CT_APPLICATION_DATA) {
    return gtls_conn_unexpected(c);
  }
  if (h[1] != 3u) {
    return gtls_conn_fail(c, GTLS_ERR_PROTOCOL, GTLS_ALERT_PROTOCOL_VERSION);
  }
  if (len > GTLS_RECORD_CIPHERTEXT_MAX ||
      (epoch == GTLS_EPOCH_INITIAL && len > GTLS_RECORD_PLAIN_MAX &&
          !(c->early_skip && type == GTLS_CT_APPLICATION_DATA))) {
    return gtls_conn_fail(c, GTLS_ERR_LIMIT, GTLS_ALERT_RECORD_OVERFLOW);
  }
  if (type == GTLS_CT_CHANGE_CIPHER_SPEC && len != 1u) {
    return gtls_conn_unexpected(c);
  }
  /* Under keys, every record says it is application data: the real type is
   * inside (section 5.2). The plaintext exceptions are the dummy CCS and,
   * until the handshake is done, an alert of the right size. */
  if (epoch != GTLS_EPOCH_INITIAL && type != GTLS_CT_APPLICATION_DATA &&
      type != GTLS_CT_CHANGE_CIPHER_SPEC &&
      !(type == GTLS_CT_ALERT && c->state != GTLS_STATE_CONNECTED && len == 2u)) {
    return gtls_conn_unexpected(c);
  }
  return GTLS_OK;
}

static GTLS_Result stream_ready(GTLS_Conn * c) {
  if (c->mode == GTLS_MODE_MESSAGE) {
    return GTLS_ERR_INVALID;
  }
  c->mode = GTLS_MODE_STREAM;
  return GTLS_OK;
}

GTLS_Result gtls_conn_stream_feed(GTLS_Conn * c, const void * data, size_t len,
    int64_t unix_time, size_t * consumed) {
  const unsigned char * p = data;
  size_t pos = 0;
  GTLS_Result result;

  if (c == NULL || consumed == NULL || (data == NULL && len != 0)) {
    return GTLS_ERR_INVALID;
  }
  *consumed = 0;
  if (stream_ready(c) != GTLS_OK) {
    return GTLS_ERR_INVALID;
  }
  if (c->state == GTLS_STATE_FAILED) {
    return GTLS_ERR_FAILED;
  }
  if (c->state == GTLS_STATE_NEW) {
    return GTLS_ERR_INVALID;
  }
  while (pos < len) {
    size_t have;
    size_t want;
    size_t take;
    int crossing;

    if (c->peer_closed) {
      pos = len; /* anything after a closure alert is ignored (section 6.1) */
      break;
    }
    /* Room for what the next record could hold, or no more bytes taken. */
    if (c->app_in.len != 0 && c->app_in.len + GTLS_RECORD_PLAIN_MAX > c->app_in.max) {
      break;
    }
    have = c->rbuf.len;
    if (have < GTLS_RECORD_HEADER) {
      want = GTLS_RECORD_HEADER - have;
    } else {
      want = GTLS_RECORD_HEADER + (((size_t)c->rbuf.data[3] << 8) | c->rbuf.data[4]) - have;
    }
    take = len - pos < want ? len - pos : want;
    crossing = have < GTLS_RECORD_HEADER && have + take >= GTLS_RECORD_HEADER;
    result = gtls_buf_append(&c->rbuf, p + pos, take);
    if (result != GTLS_OK) {
      *consumed = pos;
      return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
    }
    pos += take;
    if (crossing) {
      result = check_header(c);
      if (result != GTLS_OK) {
        *consumed = pos;
        return result;
      }
    }
    if (c->rbuf.len < GTLS_RECORD_HEADER ||
        c->rbuf.len < GTLS_RECORD_HEADER + (((size_t)c->rbuf.data[3] << 8) | c->rbuf.data[4])) {
      continue;
    }
    result = process_record(c, unix_time);
    c->rbuf.len = 0;
    if (result != GTLS_OK) {
      *consumed = pos;
      return result;
    }
  }
  *consumed = pos;
  return GTLS_OK;
}

GTLS_Result gtls_conn_stream_eof(GTLS_Conn * c) {
  if (c == NULL || stream_ready(c) != GTLS_OK) {
    return GTLS_ERR_INVALID;
  }
  if (c->state == GTLS_STATE_FAILED) {
    return GTLS_ERR_FAILED;
  }
  if (c->peer_closed) {
    return GTLS_OK;
  }
  /* No close_notify: the end may be the peer's, or someone's who cut the
   * stream. There is no one to send an alert to. */
  return gtls_conn_fail(c, GTLS_ERR_TRUNCATED, GTLS_ALERT_NONE);
}

GTLS_Result gtls_conn_stream_output(GTLS_Conn * c, const unsigned char ** data,
    size_t * len) {
  if (c == NULL || data == NULL || len == NULL || stream_ready(c) != GTLS_OK) {
    return GTLS_ERR_INVALID;
  }
  if (c->state != GTLS_STATE_FAILED && c->state != GTLS_STATE_NEW) {
    (void)gtls_stream_flush(c);
  }
  *data = c->wire.data;
  *len = c->wire.len;
  return GTLS_OK;
}

GTLS_Result gtls_conn_stream_consume(GTLS_Conn * c, size_t n) {
  if (c == NULL || stream_ready(c) != GTLS_OK || n > c->wire.len) {
    return GTLS_ERR_INVALID;
  }
  gtls_buf_consume(&c->wire, n);
  return GTLS_OK;
}

/* ----------------------------------------------------------- application data */

/** Queue a KeyUpdate; it is sealed, and the write key moved, when the output is next flushed. */
static GTLS_Result queue_key_update(GTLS_Conn * c, unsigned request) {
  GTLS_Buf m;
  GTLS_Result result;

  gtls_buf_init(&m, c->allocator, 16u);
  result = gtls_msg_build_key_update(request, &m);
  if (result == GTLS_OK) {
    result = gtls_conn_queue(c, GTLS_EPOCH_APPLICATION, m.data, m.len);
  }
  gtls_buf_free(&m);
  if (result != GTLS_OK) {
    return c->state == GTLS_STATE_FAILED ? result
        : gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }
  c->ku_queued++;
  return GTLS_OK;
}

GTLS_Result gtls_conn_on_key_update(GTLS_Conn * c, const unsigned char * msg,
    size_t msg_len) {
  unsigned request = 0;
  GTLS_Result result;

  result = gtls_msg_parse_key_update(msg + 4, msg_len - 4u, &request);
  if (result != GTLS_OK) {
    return gtls_conn_fail_parse(c, result);
  }
  c->key_updates++;
  if (++c->ku_run > c->limits.max_key_updates) {
    return gtls_conn_fail(c, GTLS_ERR_LIMIT, GTLS_ALERT_UNEXPECTED_MESSAGE);
  }
  result = rotate(c, 0);
  if (result != GTLS_OK) {
    return result;
  }
  /* A request is answered before the next application data, with a
   * KeyUpdate that asks for nothing back (section 4.6.3). One already
   * waiting to go is the answer. */
  if (request == 1u && c->ku_queued == 0 && !c->local_closed) {
    return queue_key_update(c, 0);
  }
  return GTLS_OK;
}

GTLS_Result gtls_conn_key_update(GTLS_Conn * c, int request_peer) {
  GTLS_Result result;

  if (c == NULL || stream_ready(c) != GTLS_OK) {
    return GTLS_ERR_INVALID;
  }
  if (c->state == GTLS_STATE_FAILED) {
    return GTLS_ERR_FAILED;
  }
  if (c->state != GTLS_STATE_CONNECTED) {
    return GTLS_ERR_INVALID;
  }
  if (c->local_closed) {
    return GTLS_ERR_CLOSED;
  }
  /* Anything queued ahead of it goes first, under the key it was meant for. */
  result = gtls_stream_flush(c);
  if (result != GTLS_OK) {
    return result;
  }
  return queue_key_update(c, request_peer != 0 ? 1u : 0u);
}

GTLS_Result gtls_conn_write(GTLS_Conn * c, const void * data, size_t len,
    size_t * written) {
  const unsigned char * p = data;
  GTLS_Result result;

  if (c == NULL || written == NULL || (data == NULL && len != 0)) {
    return GTLS_ERR_INVALID;
  }
  *written = 0;
  if (stream_ready(c) != GTLS_OK) {
    return GTLS_ERR_INVALID;
  }
  if (c->state == GTLS_STATE_FAILED) {
    return GTLS_ERR_FAILED;
  }
  if (c->state != GTLS_STATE_CONNECTED) {
    return GTLS_ERR_INVALID;
  }
  if (c->local_closed) {
    return GTLS_ERR_CLOSED;
  }
  if (c->limits.max_records_per_key < 2u) {
    return GTLS_ERR_LIMIT; /* no room for a record and the KeyUpdate that follows */
  }
  /* A client's Finished (and a KeyUpdate waiting) go before any data. */
  result = gtls_stream_flush(c);
  if (result != GTLS_OK) {
    return result;
  }
  if (c->wr_epoch != GTLS_EPOCH_APPLICATION) {
    result = install_keys(c, GTLS_EPOCH_APPLICATION, 1);
    if (result != GTLS_OK) {
      return result;
    }
  }
  while (len > 0 && c->wire.len < c->limits.max_output_bytes) {
    size_t n = len < GTLS_RECORD_PLAIN_MAX ? len : GTLS_RECORD_PLAIN_MAX;

    /* The last number this key may use is for its own replacement. */
    if (c->sec.wr.seq + 1u >= c->sec.wr.limit) {
      result = queue_key_update(c, 0);
      if (result == GTLS_OK) {
        result = gtls_stream_flush(c);
      }
      if (result != GTLS_OK) {
        return result;
      }
    }
    result = gtls_record_seal(&c->sec.wr, GTLS_CT_APPLICATION_DATA, p, n, 0, &c->wire);
    if (result == GTLS_ERR_LIMIT && c->wire.len != 0) {
      break; /* the output is full */
    }
    if (result != GTLS_OK) {
      return record_failed(c, result);
    }
    p += n;
    len -= n;
    *written += n;
  }
  return GTLS_OK;
}

GTLS_Result gtls_conn_read(GTLS_Conn * c, void * out, size_t cap, size_t * n) {
  size_t take;

  if (c == NULL || n == NULL || (out == NULL && cap != 0)) {
    return GTLS_ERR_INVALID;
  }
  *n = 0;
  if (stream_ready(c) != GTLS_OK) {
    return GTLS_ERR_INVALID;
  }
  if (c->state == GTLS_STATE_FAILED) {
    return GTLS_ERR_FAILED;
  }
  if (c->app_in.len == 0) {
    return c->peer_closed ? GTLS_ERR_CLOSED : GTLS_OK;
  }
  take = c->app_in.len < cap ? c->app_in.len : cap;
  memcpy(out, c->app_in.data, take);
  gtls_buf_consume(&c->app_in, take);
  *n = take;
  return GTLS_OK;
}

GTLS_Result gtls_conn_close(GTLS_Conn * c) {
  GTLS_Result result;

  if (c == NULL || stream_ready(c) != GTLS_OK) {
    return GTLS_ERR_INVALID;
  }
  if (c->state == GTLS_STATE_FAILED) {
    return GTLS_ERR_FAILED;
  }
  if (c->state == GTLS_STATE_NEW) {
    return GTLS_ERR_INVALID;
  }
  if (c->local_closed) {
    return GTLS_OK;
  }
  result = gtls_stream_flush(c);
  if (result != GTLS_OK) {
    return result;
  }
  result = gtls_stream_send_alert(c, GTLS_ALERT_WARNING, 0);
  if (result != GTLS_OK) {
    return result; /* the close_notify did not fit: this end is not closed */
  }
  c->local_closed = 1;
  return GTLS_OK;
}

int gtls_conn_peer_closed(const GTLS_Conn * c) {
  return c != NULL && c->peer_closed;
}

unsigned gtls_conn_peer_alert(const GTLS_Conn * c) {
  return c == NULL ? 0u : c->peer_alert;
}
