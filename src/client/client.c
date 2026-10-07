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
 * @file client.c
 *
 * The client's side of the TLS 1.3 handshake: the state table, message
 * reassembly, and what each state does with the message it is waiting for.
 * RFC 8446 sections 4 and 7 and appendix A.1.
 *
 * Every failure goes through gtls_conn_fail(), which records the reason and the alert,
 * wipes the secrets, and makes the connection terminal, so no failure leaves
 * a secret behind. A handshake that succeeds keeps its secrets until the
 * connection is freed or fails.
 */

#include <ghoti.io/tls/macros.h>

#include <ghoti.io/tls/conn.h>

#include "../core/core_internal.h"
#include "client_internal.h"

#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/security/ecdh_p256.h>
#include <ghoti.io/security/ecdh_p384.h>
#include <ghoti.io/security/random.h>
#include <ghoti.io/security/secret.h>
#include <ghoti.io/security/x25519.h>

#include <string.h>

/* Orders of the two NIST curves, big-endian, for rejection sampling. */
static const unsigned char p256_order[32] = {
  0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17,
  0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
};

static const unsigned char p384_order[48] = {
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf, 0x58,
  0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a,
  0xcc, 0xc5, 0x29, 0x73
};

/** The most a ClientHello this library builds can come to, header included. */

/**
 * Limits for parsing a hello this library wrote itself. The caps in a
 * connection's limits are for what a peer sends; applying them to our own
 * message would let a small cap break the connection's memory of what it
 * offered.
 */
GTLS_Limits gtls_conn_own_limits(const GTLS_Conn * c) {
  GTLS_Limits l = c->limits;

  l.max_extensions = GTLS_EXT_MAX;
  return l;
}

/* ----------------------------------------------------------------- failure */

static void wipe_secrets(GTLS_Conn * c) {
  (void)gsec_wipe(&c->sec, sizeof c->sec);
}

GTLS_Result gtls_conn_fail(GTLS_Conn * c, GTLS_Result result, unsigned alert) {
  if (c->state != GTLS_STATE_FAILED) {
    /* The alert is sealed under the keys the peer has been sent, which are
     * wiped just below: it has to be built first. */
    if (c->mode == GTLS_MODE_STREAM && alert != GTLS_ALERT_NONE) {
      gtls_stream_send_alert(c, 2u, alert);
    }
    c->state = GTLS_STATE_FAILED;
    c->failure = result;
    c->alert = alert;
    wipe_secrets(c);
    if (c->app_in.data != NULL) {
      (void)gsec_wipe(c->app_in.data, c->app_in.cap);
    }
    c->app_in.len = 0;
  }
  return result;
}

/** Failure of a parser or a buffer, with the alert its result calls for. */
GTLS_Result gtls_conn_fail_parse(GTLS_Conn * c, GTLS_Result result) {
  switch (result) {
    case GTLS_ERR_CORRUPT:
    case GTLS_ERR_LIMIT:
      return gtls_conn_fail(c, result, GTLS_ALERT_DECODE_ERROR);
    case GTLS_ERR_PROTOCOL:
      return gtls_conn_fail(c, result, GTLS_ALERT_ILLEGAL_PARAMETER);
    default:
      return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }
}

GTLS_Result gtls_conn_illegal(GTLS_Conn * c) {
  return gtls_conn_fail(c, GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER);
}

GTLS_Result gtls_conn_unexpected(GTLS_Conn * c) {
  return gtls_conn_fail(c, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNEXPECTED_MESSAGE);
}

/* ------------------------------------------------------------------ object */

GTLS_Result gtls_conn_alloc(const GTLS_Context * context, GTLS_Conn ** out) {
  GTLS_Conn * c;
  const GTLS_Allocator * allocator = context->allocator;
  size_t i;

  c = gcu_allocator_calloc(allocator, 1, sizeof *c);
  if (c == NULL) {
    return GTLS_ERR_OOM;
  }
  c->context = context;
  c->allocator = allocator;
  c->role = context->role;
  c->state = GTLS_STATE_NEW;
  c->limits = context->limits;
  c->random_fn = NULL;
  gtls_buf_init(&c->in, allocator, (size_t)c->limits.max_handshake_message + 4u);
  gtls_buf_init(&c->hello, allocator, GTLS_HELLO_MAX);
  for (i = 0; i < GTLS_EPOCH_COUNT; i++) {
    gtls_buf_init(&c->out[i], allocator, c->limits.max_output_bytes);
  }
  gtls_buf_init(&c->rbuf, allocator, GTLS_RECORD_HEADER + GTLS_RECORD_CIPHER_MAX);
  /* Room for what a flush of a full handshake queue can add, besides the
   * application data, which stops at max_output_bytes, and for one whole
   * record on top of that, so a write into an empty output always fits. */
  gtls_buf_init(&c->wire, allocator,
      2u * (size_t)c->limits.max_output_bytes + 4096u + GTLS_RECORD_HEADER +
          GTLS_RECORD_CIPHER_MAX);
  gtls_buf_init(&c->app_in, allocator,
      c->limits.max_app_buffer > GTLS_RECORD_PLAIN_MAX
          ? c->limits.max_app_buffer
          : GTLS_RECORD_PLAIN_MAX);
  *out = c;
  return GTLS_OK;
}

GTLS_Result gtls_conn_new(const GTLS_Context * context, const char * host,
    size_t host_len, GTLS_Conn ** out) {
  GTLS_Conn * c;
  unsigned char ip[16];
  size_t ip_len = 0;
  const GTLS_Allocator * allocator;
  GTLS_Result result;

  size_t i;

  if (context == NULL || host == NULL || host_len == 0 || host_len > 255u ||
      out == NULL) {
    return GTLS_ERR_INVALID;
  }
  /* What reaches the wire and the name check is ASCII, with no NUL and no
   * trailing dot: an A-label, as gcert_x509_verify_host wants it. */
  for (i = 0; i < host_len; i++) {
    if (host[i] == 0 || (unsigned char)host[i] > 0x7fu) {
      return GTLS_ERR_INVALID;
    }
  }
  if (host[host_len - 1u] == '.') {
    return GTLS_ERR_INVALID;
  }
  if (context->role != GTLS_ROLE_CLIENT) {
    return GTLS_ERR_INVALID;
  }
  allocator = context->allocator;
  result = gtls_conn_alloc(context, &c);
  if (result != GTLS_OK) {
    return result;
  }
  c->host = gcu_allocator_malloc(allocator, host_len);
  if (c->host == NULL) {
    gtls_conn_free(c);
    return GTLS_ERR_OOM;
  }
  memcpy(c->host, host, host_len);
  c->host_len = host_len;
  c->host_is_ip = gcert_ip_parse(host, host_len, ip, &ip_len) == GCERT_OK;
  (void)gsec_wipe(ip, sizeof ip);
  *out = c;
  return GTLS_OK;
}

void gtls_conn_free(GTLS_Conn * c) {
  size_t i;
  const GTLS_Allocator * allocator;

  if (c == NULL) {
    return;
  }
  allocator = c->allocator;
  wipe_secrets(c);
  gtls_buf_free(&c->in);
  gtls_buf_free(&c->hello);
  for (i = 0; i < GTLS_EPOCH_COUNT; i++) {
    gtls_buf_free(&c->out[i]);
  }
  gtls_stream_free(c);
  gcu_allocator_free(allocator, c->host);
  gcu_allocator_free(allocator, c->leaf);
  gcu_allocator_free(allocator, c->client_sni);
  (void)gsec_wipe(c, sizeof *c);
  gcu_allocator_free(allocator, c);
}

void gtls_conn_set_hooks(GTLS_Conn * c, GTLS_RandomFn random_fn,
    void * random_user, GTLS_ChainFn chain_fn, void * chain_user) {
  c->random_fn = random_fn;
  c->random_user = random_user;
  c->chain_fn = chain_fn;
  c->chain_user = chain_user;
}

GTLS_Result gtls_conn_draw(GTLS_Conn * c, void * out, size_t n) {
  if (c->random_fn != NULL) {
    return c->random_fn(c->random_user, out, n);
  }
  return gtls_from_gsec(gsec_random_bytes(out, n, NULL));
}

/* ------------------------------------------------------ what was offered */

static GTLS_Result hello_view(const GTLS_Conn * c, GTLS_ClientHello * v) {
  GTLS_Limits l = gtls_conn_own_limits(c);

  if (c->hello.len < 4u) {
    return GTLS_ERR_INTERNAL;
  }
  return gtls_msg_parse_client_hello(c->hello.data + 4, c->hello.len - 4u, &l,
      v);
}

static int offered_suite(const GTLS_Conn * c, unsigned suite) {
  GTLS_ClientHello v;
  size_t i;

  if (hello_view(c, &v) != GTLS_OK) {
    return 0;
  }
  for (i = 0; i + 1u < v.suites_len; i += 2u) {
    if ((((unsigned)v.suites[i] << 8) | v.suites[i + 1u]) == suite) {
      return 1;
    }
  }
  return 0;
}

/** 1 when the u16-length-prefixed list of u16 values in extension @p type holds @p want. */
static int offered_u16(const GTLS_Conn * c, unsigned type, unsigned want) {
  GTLS_ClientHello v;
  const GTLS_Ext * e;
  GTLS_Reader r;
  GTLS_Reader list;

  if (hello_view(c, &v) != GTLS_OK) {
    return 0;
  }
  e = gtls_msg_find_ext(v.exts, v.ext_count, type);
  if (e == NULL) {
    return 0;
  }
  gtls_reader_init(&r, e->data, e->len);
  if (gtls_reader_vector(&r, 2, 2, 0, &list) != GTLS_OK) {
    return 0;
  }
  while (gtls_reader_left(&list) >= 2u) {
    unsigned x = 0;

    (void)gtls_reader_u16(&list, &x);
    if (x == want) {
      return 1;
    }
  }
  return 0;
}

static int offered_ext(const GTLS_Conn * c, unsigned type) {
  GTLS_ClientHello v;

  if (hello_view(c, &v) != GTLS_OK) {
    return 0;
  }
  return gtls_msg_find_ext(v.exts, v.ext_count, type) != NULL;
}

static int offered_alpn(const GTLS_Conn * c, const unsigned char * name,
    size_t len) {
  GTLS_ClientHello v;
  const GTLS_Ext * e;
  GTLS_Reader r;
  GTLS_Reader list;

  if (hello_view(c, &v) != GTLS_OK) {
    return 0;
  }
  e = gtls_msg_find_ext(v.exts, v.ext_count, GTLS_EXT_ALPN);
  if (e == NULL) {
    return 0;
  }
  gtls_reader_init(&r, e->data, e->len);
  if (gtls_reader_vector(&r, 2, 2, 0, &list) != GTLS_OK) {
    return 0;
  }
  while (gtls_reader_left(&list) != 0) {
    GTLS_Reader one;

    if (gtls_reader_vector(&list, 1, 1, 0, &one) != GTLS_OK) {
      return 0;
    }
    if (one.len == len && gsec_equal(one.p, name, len) == GSEC_OK) {
      return 1;
    }
  }
  return 0;
}

/* -------------------------------------------------------------- key shares */

/** 1 when 0 < s < n, without branching on s. */
static int scalar_in_range(const unsigned char * s, const unsigned char * n,
    size_t len) {
  unsigned borrow = 0;
  unsigned acc = 0;
  size_t i;

  for (i = len; i > 0; i--) {
    unsigned d = (unsigned)s[i - 1u] - n[i - 1u] - borrow;
    borrow = (d >> 8) & 1u;
    acc |= s[i - 1u];
  }
  return (int)(borrow & (((acc | (0u - acc)) >> 31) & 1u));
}

void gtls_conn_wipe_kx(GTLS_Conn * c) {
  (void)gsec_wipe(c->sec.x25519, sizeof c->sec.x25519);
  (void)gsec_wipe(c->sec.p256, sizeof c->sec.p256);
  (void)gsec_wipe(c->sec.p384, sizeof c->sec.p384);
}

GTLS_Result gtls_conn_gen_share(GTLS_Conn * c, GTLS_Group group,
    GTLS_KeyShare * share) {
  unsigned char * priv;
  const unsigned char * order;
  size_t plen;
  unsigned attempt;
  GTLS_Result result = GTLS_OK;

  gtls_conn_wipe_kx(c);
  memset(share, 0, sizeof *share);
  share->group = (uint16_t)group;
  switch (group) {
    case GTLS_GROUP_X25519:
      priv = c->sec.x25519;
      plen = 32;
      order = NULL;
      break;
    case GTLS_GROUP_SECP256R1:
      priv = c->sec.p256;
      plen = 32;
      order = p256_order;
      break;
    case GTLS_GROUP_SECP384R1:
      priv = c->sec.p384;
      plen = 48;
      order = p384_order;
      break;
    default:
      return GTLS_ERR_INVALID;
  }
  for (attempt = 0; attempt < 8u; attempt++) {
    result = gtls_conn_draw(c, priv, plen);
    if (result != GTLS_OK) {
      gtls_conn_wipe_kx(c);
      return result;
    }
    if (order == NULL || scalar_in_range(priv, order, plen)) {
      break;
    }
    (void)gsec_wipe(priv, plen);
    result = GTLS_ERR_INTERNAL;
  }
  if (result != GTLS_OK) {
    return result;
  }
  if (group == GTLS_GROUP_X25519) {
    result = gtls_from_gsec(gsec_x25519_public(priv, share->pub));
    share->pub_len = 32;
  } else if (group == GTLS_GROUP_SECP256R1) {
    share->pub[0] = 4;
    result = gtls_from_gsec(gsec_ecdh_p256_public(priv, share->pub + 1));
    share->pub_len = 65;
  } else {
    share->pub[0] = 4;
    result = gtls_from_gsec(gsec_ecdh_p384_public(priv, share->pub + 1));
    share->pub_len = 97;
  }
  if (result != GTLS_OK) {
    gtls_conn_wipe_kx(c);
  }
  return result;
}

/**
 * The shared secret with the server's share. A bad point or a small-order
 * one is the peer's fault and says so.
 */
GTLS_Result gtls_conn_shared_secret(GTLS_Conn * c, GTLS_Group group,
    const unsigned char * kx, size_t kx_len, unsigned char * out,
    size_t * out_len) {
  GSEC_Result r;

  switch (group) {
    case GTLS_GROUP_X25519:
      if (kx_len != 32u) {
        return GTLS_ERR_PROTOCOL;
      }
      r = gsec_x25519(c->sec.x25519, kx, out);
      *out_len = 32;
      break;
    case GTLS_GROUP_SECP256R1:
      if (kx_len != 65u || kx[0] != 4u) {
        return GTLS_ERR_PROTOCOL;
      }
      r = gsec_ecdh_p256(c->sec.p256, kx + 1, out);
      *out_len = 32;
      break;
    case GTLS_GROUP_SECP384R1:
      if (kx_len != 97u || kx[0] != 4u) {
        return GTLS_ERR_PROTOCOL;
      }
      r = gsec_ecdh_p384(c->sec.p384, kx + 1, out);
      *out_len = 48;
      break;
    default:
      return GTLS_ERR_PROTOCOL;
  }
  return r == GSEC_OK ? GTLS_OK : GTLS_ERR_PROTOCOL;
}

/* ------------------------------------------------------------------ output */

GTLS_Result gtls_conn_queue(GTLS_Conn * c, GTLS_Epoch epoch, const void * data,
    size_t n) {
  GTLS_Result result = gtls_buf_append(&c->out[epoch], data, n);

  if (result != GTLS_OK) {
    /* The cap is ours (max_output_bytes), not something the peer sent. */
    return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }
  return GTLS_OK;
}

/* ------------------------------------------------------------------- start */

static GTLS_Result begin_handshake(GTLS_Conn * c) {
  GTLS_Result result = gtls_transcript_init(&c->sec.transcript);

  if (result == GTLS_OK) {
    result = gtls_transcript_update(&c->sec.transcript, c->hello.data,
        c->hello.len);
  }
  if (result == GTLS_OK) {
    result = gtls_conn_queue(c, GTLS_EPOCH_INITIAL, c->hello.data, c->hello.len);
  }
  if (result != GTLS_OK) {
    return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }
  c->state = GTLS_STATE_WAIT_SH;
  return GTLS_OK;
}

GTLS_Result gtls_conn_start(GTLS_Conn * c) {
  GTLS_HelloParams p;
  GTLS_Result result;

  if (c == NULL) {
    return GTLS_ERR_INVALID;
  }
  if (c->role == GTLS_ROLE_SERVER) {
    return gtls_server_start(c);
  }
  if (c->state == GTLS_STATE_FAILED) {
    return GTLS_ERR_FAILED;
  }
  if (c->state != GTLS_STATE_NEW) {
    return GTLS_ERR_INVALID;
  }
  memset(&p, 0, sizeof p);
  result = gtls_conn_draw(c, p.random, 32);
  if (result == GTLS_OK && c->context->middlebox_compat) {
    result = gtls_conn_draw(c, p.session_id, 32);
    p.session_id_len = 32;
  }
  if (result == GTLS_OK) {
    c->share_group = c->context->groups[0];
    result = gtls_conn_gen_share(c, c->share_group, &p.share);
  }
  if (result != GTLS_OK) {
    (void)gsec_wipe(&p, sizeof p);
    return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }
  p.suites = c->context->suites;
  p.suite_count = c->context->suite_count;
  p.host = c->host_is_ip ? NULL : (const char *)c->host;
  p.host_len = c->host_is_ip ? 0 : c->host_len;
  p.alpn = c->context->alpn;
  p.alpn_len = c->context->alpn_len;
  p.groups = c->context->groups;
  p.group_count = c->context->group_count;
  p.sig_algs = c->context->sig_algs;
  p.sig_alg_count = c->context->sig_alg_count;
  memcpy(c->session_id, p.session_id, 32);
  c->session_id_len = p.session_id_len;
  result = gtls_msg_build_client_hello(&p, &c->hello);
  (void)gsec_wipe(&p, sizeof p);
  if (result != GTLS_OK) {
    return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }
  return begin_handshake(c);
}

GTLS_Result gtls_conn_start_raw(GTLS_Conn * c, const void * hello,
    size_t hello_len, const void * x25519_private) {
  GTLS_ClientHello v;
  GTLS_Result result;

  if (c == NULL || hello == NULL || x25519_private == NULL || hello_len < 4u ||
      c->role != GTLS_ROLE_CLIENT) {
    return GTLS_ERR_INVALID;
  }
  if (c->state == GTLS_STATE_FAILED) {
    return GTLS_ERR_FAILED;
  }
  if (c->state != GTLS_STATE_NEW) {
    return GTLS_ERR_INVALID;
  }
  result = gtls_buf_append(&c->hello, hello, hello_len);
  if (result == GTLS_OK) {
    result = hello_view(c, &v);
  }
  if (result != GTLS_OK) {
    return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }
  memcpy(c->session_id, v.session_id, v.session_id_len);
  c->session_id_len = v.session_id_len;
  memcpy(c->sec.x25519, x25519_private, 32);
  c->share_group = GTLS_GROUP_X25519;
  return begin_handshake(c);
}

/* ------------------------------------------------------------- the messages */

static GTLS_Result on_hrr(GTLS_Conn * c, const GTLS_ServerHello * sh,
    const unsigned char * msg, size_t msg_len) {
  GTLS_Hash hash = gtls_suite_hash(sh->suite);
  GTLS_KeyShare share;
  const GTLS_KeyShare * sp = NULL;
  GTLS_Buf h2;
  GTLS_Result result;
  size_t i;
  int ours = 0;

  if (c->state == GTLS_STATE_WAIT_SH2) {
    return gtls_conn_unexpected(c); /* a second HelloRetryRequest */
  }
  if ((sh->flags & (GTLS_SH_FLAG_KEY_SHARE | GTLS_SH_FLAG_COOKIE)) == 0) {
    return gtls_conn_illegal(c); /* it asks for nothing: the retry would be identical */
  }
  if ((sh->flags & GTLS_SH_FLAG_KEY_SHARE) != 0) {
    for (i = 0; i < c->context->group_count; i++) {
      if ((unsigned)c->context->groups[i] == sh->group) {
        ours = 1;
      }
    }
    if (!ours || !offered_u16(c, GTLS_EXT_SUPPORTED_GROUPS, sh->group) ||
        sh->group == (unsigned)c->share_group) {
      return gtls_conn_illegal(c);
    }
  }
  result = gtls_transcript_select(&c->sec.transcript, hash);
  if (result == GTLS_OK) {
    result = gtls_transcript_restart(&c->sec.transcript, hash);
  }
  if (result == GTLS_OK) {
    result = gtls_transcript_update(&c->sec.transcript, msg, msg_len);
  }
  if (result != GTLS_OK) {
    return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }
  if ((sh->flags & GTLS_SH_FLAG_KEY_SHARE) != 0) {
    result = gtls_conn_gen_share(c, (GTLS_Group)sh->group, &share);
    if (result != GTLS_OK) {
      return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
    }
    sp = &share;
    c->share_group = (GTLS_Group)sh->group;
  }
  gtls_buf_init(&h2, c->allocator, GTLS_HELLO_MAX);
  {
    GTLS_Limits l = gtls_conn_own_limits(c);

    result = gtls_msg_retry_client_hello(c->hello.data, c->hello.len, sp,
        (sh->flags & GTLS_SH_FLAG_COOKIE) != 0 ? sh->cookie : NULL,
        (sh->flags & GTLS_SH_FLAG_COOKIE) != 0 ? sh->cookie_len : 0, &l, &h2);
  }
  if (result == GTLS_OK) {
    result = gtls_transcript_update(&c->sec.transcript, h2.data, h2.len);
  }
  if (result == GTLS_OK) {
    result = gtls_conn_queue(c, GTLS_EPOCH_INITIAL, h2.data, h2.len);
  }
  gtls_buf_free(&h2);
  (void)gsec_wipe(&share, sizeof share);
  if (result != GTLS_OK) {
    return c->state == GTLS_STATE_FAILED
        ? result
        : gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }
  c->suite = (GTLS_Suite)sh->suite;
  c->hrr_group = c->share_group;
  c->retried = 1;
  c->state = GTLS_STATE_WAIT_SH2;
  return GTLS_OK;
}

static GTLS_Result on_server_hello(GTLS_Conn * c, const unsigned char * msg,
    size_t msg_len) {
  const unsigned char * body = msg + 4;
  size_t len = msg_len - 4u;
  GTLS_ServerHello sh;
  GTLS_Result result;
  unsigned char ecdhe[GTLS_KX_MAX];
  unsigned char th[GTLS_HASH_MAX];
  size_t ecdhe_len = 0;
  GTLS_Hash hash;

  /* Before anything else is believed: a sentinel here means a 1.2 server
   * answered a 1.3 offer because someone made it say so. */
  if (len >= 34u && gtls_msg_downgrade_sentinel(body + 2) != 0) {
    return gtls_conn_fail(c, GTLS_ERR_DOWNGRADE, GTLS_ALERT_ILLEGAL_PARAMETER);
  }
  result = gtls_msg_parse_server_hello(body, len, &c->limits, &sh);
  if (result != GTLS_OK) {
    return gtls_conn_fail_parse(c, result);
  }
  if (sh.legacy_version != 0x0303u || sh.compression != 0 ||
      sh.session_id_len != c->session_id_len ||
      gsec_equal(sh.session_id, c->session_id, sh.session_id_len) != GSEC_OK) {
    return gtls_conn_illegal(c);
  }
  if ((sh.flags & GTLS_SH_FLAG_VERSION) == 0) {
    /* No supported_versions: a server that speaks something older. */
    return gtls_conn_fail(c, GTLS_ERR_UNSUPPORTED, GTLS_ALERT_PROTOCOL_VERSION);
  }
  if (sh.selected_version != 0x0304u) {
    return gtls_conn_illegal(c);
  }
  if ((sh.flags & (GTLS_SH_FLAG_PSK | GTLS_SH_FLAG_UNKNOWN)) != 0 ||
      (!sh.is_hrr && (sh.flags & GTLS_SH_FLAG_COOKIE) != 0)) {
    return gtls_conn_fail(c, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNSUPPORTED_EXTENSION);
  }
  if (!gtls_suite_valid(sh.suite) || !offered_suite(c, sh.suite)) {
    return gtls_conn_illegal(c);
  }
  if (sh.is_hrr) {
    return on_hrr(c, &sh, msg, msg_len);
  }
  if (c->retried && sh.suite != (unsigned)c->suite) {
    return gtls_conn_illegal(c);
  }
  if ((sh.flags & GTLS_SH_FLAG_KEY_SHARE) == 0) {
    return gtls_conn_fail(c, GTLS_ERR_PROTOCOL, GTLS_ALERT_MISSING_EXTENSION);
  }
  if (sh.group != (unsigned)c->share_group) {
    return gtls_conn_illegal(c);
  }
  hash = gtls_suite_hash(sh.suite);
  c->suite = (GTLS_Suite)sh.suite;
  c->group = (GTLS_Group)sh.group;
  result = gtls_conn_shared_secret(c, c->group, sh.key_exchange, sh.key_exchange_len,
      ecdhe, &ecdhe_len);
  if (result != GTLS_OK) {
    (void)gsec_wipe(ecdhe, sizeof ecdhe);
    return gtls_conn_illegal(c);
  }
  if (!c->retried) {
    result = gtls_transcript_select(&c->sec.transcript, hash);
  }
  if (result == GTLS_OK) {
    result = gtls_transcript_update(&c->sec.transcript, msg, msg_len);
  }
  if (result == GTLS_OK) {
    result = gtls_transcript_snapshot(&c->sec.transcript, hash, th);
  }
  if (result == GTLS_OK) {
    result = gtls_schedule_early(&c->sec.schedule, hash);
  }
  if (result == GTLS_OK) {
    result = gtls_schedule_handshake(&c->sec.schedule, ecdhe, ecdhe_len, th);
  }
  (void)gsec_wipe(ecdhe, sizeof ecdhe);
  (void)gsec_wipe(th, sizeof th);
  gtls_conn_wipe_kx(c);
  if (result != GTLS_OK) {
    return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }
  c->state = GTLS_STATE_WAIT_EE;
  return GTLS_OK;
}

/** Extensions an EncryptedExtensions message may carry, RFC 8446 section 4.2. */
static int ee_allowed(unsigned type) {
  switch (type) {
    case GTLS_EXT_SERVER_NAME:
    case GTLS_EXT_MAX_FRAGMENT_LENGTH:
    case GTLS_EXT_SUPPORTED_GROUPS:
    case GTLS_EXT_USE_SRTP:
    case GTLS_EXT_HEARTBEAT:
    case GTLS_EXT_ALPN:
    case GTLS_EXT_CLIENT_CERT_TYPE:
    case GTLS_EXT_SERVER_CERT_TYPE:
    case GTLS_EXT_EARLY_DATA:
    case GTLS_EXT_RECORD_SIZE_LIMIT:
      return 1;
    default:
      return 0;
  }
}

static GTLS_Result on_encrypted_extensions(GTLS_Conn * c,
    const unsigned char * msg, size_t msg_len) {
  GTLS_EncryptedExtensions ee;
  GTLS_Result result;
  size_t i;

  result = gtls_msg_parse_encrypted_extensions(msg + 4, msg_len - 4u,
      &c->limits, &ee);
  if (result != GTLS_OK) {
    return gtls_conn_fail_parse(c, result);
  }
  for (i = 0; i < ee.ext_count; i++) {
    unsigned type = ee.exts[i].type;

    /* An extension the client did not offer may not be answered, except
     * supported_groups, which a server may send on its own. */
    if (!ee_allowed(type) ||
        (type != GTLS_EXT_SUPPORTED_GROUPS && !offered_ext(c, type))) {
      return gtls_conn_fail(c, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNSUPPORTED_EXTENSION);
    }
  }
  if (ee.has_alpn) {
    if (!offered_alpn(c, ee.alpn, ee.alpn_len)) {
      return gtls_conn_illegal(c);
    }
    memcpy(c->alpn_selected, ee.alpn, ee.alpn_len);
    c->alpn_selected_len = ee.alpn_len;
  }
  c->sni_acknowledged = ee.has_server_name;
  result = gtls_transcript_update(&c->sec.transcript, msg, msg_len);
  if (result != GTLS_OK) {
    return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }
  c->state = GTLS_STATE_WAIT_CERT;
  return GTLS_OK;
}

static unsigned alert_for_certificate(GTLS_Result result) {
  switch (result) {
    case GTLS_ERR_CERT_EXPIRED:
    case GTLS_ERR_CERT_NOT_YET_VALID:
      return GTLS_ALERT_CERTIFICATE_EXPIRED;
    case GTLS_ERR_CERT_ISSUER:
      return GTLS_ALERT_UNKNOWN_CA;
    case GTLS_ERR_LIMIT:
      return GTLS_ALERT_DECODE_ERROR;
    case GTLS_ERR_OOM:
      return GTLS_ALERT_INTERNAL_ERROR;
    default:
      return GTLS_ALERT_BAD_CERTIFICATE;
  }
}

static GTLS_Result on_certificate(GTLS_Conn * c, const unsigned char * msg,
    size_t msg_len, int64_t now) {
  GTLS_CertificateMsg cert;
  GTLS_Result result;

  result = gtls_msg_parse_certificate(msg + 4, msg_len - 4u, &c->limits,
      &cert);
  if (result != GTLS_OK) {
    return gtls_conn_fail_parse(c, result);
  }
  if (cert.context_len != 0) {
    return gtls_conn_illegal(c); /* only a CertificateRequest gives a nonempty one */
  }
  if (cert.count == 0) {
    /* RFC 8446 section 4.4.2: a server's Certificate must not be empty, and
     * the alert for one that is is decode_error. */
    return gtls_conn_fail(c, GTLS_ERR_CERT_INVALID, GTLS_ALERT_DECODE_ERROR);
  }
  if (cert.has_entry_extensions) {
    /* status_request and signed_certificate_timestamp were not offered. */
    return gtls_conn_fail(c, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNSUPPORTED_EXTENSION);
  }
  if (c->chain_fn != NULL) {
    result = c->chain_fn(c->chain_user, c, &cert, now);
  } else {
    result = gtls_verify_chain(NULL, c, &cert, now);
  }
  if (result != GTLS_OK) {
    return gtls_conn_fail(c, result, alert_for_certificate(result));
  }
  c->leaf = gcu_allocator_malloc(c->allocator, cert.der_len[0]);
  if (c->leaf == NULL) {
    return gtls_conn_fail(c, GTLS_ERR_OOM, GTLS_ALERT_INTERNAL_ERROR);
  }
  memcpy(c->leaf, cert.der[0], cert.der_len[0]);
  c->leaf_len = cert.der_len[0];
  result = gtls_transcript_update(&c->sec.transcript, msg, msg_len);
  if (result != GTLS_OK) {
    return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }
  c->state = GTLS_STATE_WAIT_CV;
  return GTLS_OK;
}

static GTLS_Result on_certificate_verify(GTLS_Conn * c,
    const unsigned char * msg, size_t msg_len) {
  GTLS_CertificateVerifyMsg cv;
  GCERT_X509 leaf;
  unsigned char content[GTLS_CV_CONTENT_MAX];
  unsigned char th[GTLS_HASH_MAX];
  size_t n = 0;
  size_t hlen = gtls_hash_len(gtls_suite_hash((uint32_t)c->suite));
  GTLS_Result result;
  GCERT_Result verdict;

  result = gtls_msg_parse_certificate_verify(msg + 4, msg_len - 4u, &c->limits,
      &cv);
  if (result != GTLS_OK) {
    return gtls_conn_fail_parse(c, result);
  }
  if (!gtls_cv_scheme_ok(cv.scheme) ||
      !offered_u16(c, GTLS_EXT_SIGNATURE_ALGORITHMS, cv.scheme)) {
    return gtls_conn_illegal(c);
  }
  if (gcert_x509_parse(c->leaf, c->leaf_len, &leaf) != GCERT_OK ||
      !gcert_key_scheme_fits((GCERT_SigScheme)cv.scheme, leaf.key)) {
    return gtls_conn_illegal(c);
  }
  /* RFC 8446 section 4.4.3: the transcript hash through Certificate. */
  result = gtls_transcript_snapshot(&c->sec.transcript,
      gtls_suite_hash((uint32_t)c->suite), th);
  if (result != GTLS_OK) {
    return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }
  n = gtls_cv_content(1, th, hlen, content);
  verdict = gcert_x509_verify_signature(&leaf, (GCERT_SigScheme)cv.scheme,
      content, n, cv.signature, cv.signature_len);
  if (verdict != GCERT_OK) {
    return gtls_conn_fail(c, GTLS_ERR_SIGNATURE, GTLS_ALERT_DECRYPT_ERROR);
  }
  result = gtls_transcript_update(&c->sec.transcript, msg, msg_len);
  if (result != GTLS_OK) {
    return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }
  c->state = GTLS_STATE_WAIT_FIN;
  return GTLS_OK;
}

static GTLS_Result on_finished(GTLS_Conn * c, const unsigned char * msg,
    size_t msg_len) {
  GTLS_Hash hash = gtls_suite_hash((uint32_t)c->suite);
  size_t hlen = gtls_hash_len(hash);
  unsigned char th[GTLS_HASH_MAX];
  unsigned char verify[GTLS_HASH_MAX];
  unsigned char fin[4 + GTLS_HASH_MAX];
  GTLS_Result result;

  result = gtls_transcript_snapshot(&c->sec.transcript, hash, th);
  if (result == GTLS_OK) {
    result = gtls_finished_check(hash, c->sec.schedule.s_hs, th, msg + 4,
        msg_len - 4u);
  }
  if (result != GTLS_OK) {
    (void)gsec_wipe(th, sizeof th);
    return gtls_conn_fail(c, result, result == GTLS_ERR_FINISHED
        ? GTLS_ALERT_DECRYPT_ERROR : GTLS_ALERT_INTERNAL_ERROR);
  }
  result = gtls_transcript_update(&c->sec.transcript, msg, msg_len);
  if (result == GTLS_OK) {
    result = gtls_transcript_snapshot(&c->sec.transcript, hash, th);
  }
  if (result == GTLS_OK) {
    result = gtls_schedule_master(&c->sec.schedule, th);
  }
  /* The client's Finished is over the transcript through the server's. */
  if (result == GTLS_OK) {
    result = gtls_finished_verify_data(hash, c->sec.schedule.c_hs, th, verify);
  }
  if (result == GTLS_OK) {
    fin[0] = GTLS_HS_FINISHED;
    fin[1] = 0;
    fin[2] = 0;
    fin[3] = (unsigned char)hlen;
    memcpy(fin + 4, verify, hlen);
    result = gtls_transcript_update(&c->sec.transcript, fin, 4u + hlen);
  }
  if (result == GTLS_OK) {
    result = gtls_conn_queue(c, GTLS_EPOCH_HANDSHAKE, fin, 4u + hlen);
    if (result != GTLS_OK) {
      (void)gsec_wipe(th, sizeof th);
      (void)gsec_wipe(verify, sizeof verify);
      return result; /* gtls_conn_queue() has already failed the connection */
    }
  }
  (void)gsec_wipe(th, sizeof th);
  (void)gsec_wipe(verify, sizeof verify);
  if (result != GTLS_OK) {
    return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }
  c->state = GTLS_STATE_CONNECTED;
  return GTLS_OK;
}

static GTLS_Result on_post_handshake(GTLS_Conn * c, unsigned type,
    const unsigned char * msg, size_t msg_len) {
  GTLS_NewSessionTicket t;
  GTLS_Result result;

  if (type == GTLS_HS_KEY_UPDATE) {
    if (c->mode == GTLS_MODE_STREAM) {
      return gtls_conn_on_key_update(c, msg, msg_len);
    }
    /* A caller that carries the messages itself (QUIC, RFC 9001 section 6)
     * has its own key update, and this one is not allowed. */
    return gtls_conn_fail(c, GTLS_ERR_UNSUPPORTED, GTLS_ALERT_UNEXPECTED_MESSAGE);
  }
  if (type != GTLS_HS_NEW_SESSION_TICKET || c->role != GTLS_ROLE_CLIENT) {
    return gtls_conn_unexpected(c);
  }
  if (c->tickets >= c->limits.max_tickets) {
    return gtls_conn_fail(c, GTLS_ERR_LIMIT, GTLS_ALERT_UNEXPECTED_MESSAGE);
  }
  result = gtls_msg_parse_new_session_ticket(msg + 4, msg_len - 4u,
      &c->limits, &t);
  if (result != GTLS_OK) {
    return gtls_conn_fail_parse(c, result);
  }
  /* Parsed, checked, and discarded: resumption is a later piece. */
  c->tickets++;
  return GTLS_OK;
}

static GTLS_Result on_message(GTLS_Conn * c, const unsigned char * msg,
    size_t msg_len, int64_t now) {
  unsigned type = msg[0];

  switch (c->state) {
    case GTLS_STATE_WAIT_SH:
    case GTLS_STATE_WAIT_SH2:
      if (type != GTLS_HS_SERVER_HELLO) {
        return gtls_conn_unexpected(c);
      }
      return on_server_hello(c, msg, msg_len);
    case GTLS_STATE_WAIT_EE:
      if (type != GTLS_HS_ENCRYPTED_EXTENSIONS) {
        return gtls_conn_unexpected(c);
      }
      return on_encrypted_extensions(c, msg, msg_len);
    case GTLS_STATE_WAIT_CERT:
      if (type == GTLS_HS_CERTIFICATE_REQUEST) {
        /* Client authentication is a later piece. Better to say so than to
         * answer with an empty Certificate and be refused for it later. */
        return gtls_conn_fail(c, GTLS_ERR_UNSUPPORTED, GTLS_ALERT_HANDSHAKE_FAILURE);
      }
      if (type != GTLS_HS_CERTIFICATE) {
        return gtls_conn_unexpected(c);
      }
      return on_certificate(c, msg, msg_len, now);
    case GTLS_STATE_WAIT_CV:
      if (type != GTLS_HS_CERTIFICATE_VERIFY) {
        return gtls_conn_unexpected(c);
      }
      return on_certificate_verify(c, msg, msg_len);
    case GTLS_STATE_WAIT_FIN:
      if (type != GTLS_HS_FINISHED) {
        return gtls_conn_unexpected(c);
      }
      return on_finished(c, msg, msg_len);
    case GTLS_STATE_CONNECTED:
      return on_post_handshake(c, type, msg, msg_len);
    case GTLS_STATE_S_WAIT_CH:
    case GTLS_STATE_S_WAIT_CH2:
    case GTLS_STATE_S_WAIT_FIN:
      return gtls_server_on_message(c, msg, msg_len, now);
    case GTLS_STATE_NEW:
    case GTLS_STATE_FAILED:
    case GTLS_STATE_COUNT:
      break;
  }
  return gtls_conn_fail(c, GTLS_ERR_INTERNAL, GTLS_ALERT_INTERNAL_ERROR);
}

GTLS_Epoch gtls_conn_expected_epoch(GTLS_State state) {
  switch (state) {
    case GTLS_STATE_WAIT_EE:
    case GTLS_STATE_WAIT_CERT:
    case GTLS_STATE_WAIT_CV:
    case GTLS_STATE_WAIT_FIN:
    case GTLS_STATE_S_WAIT_FIN:
      return GTLS_EPOCH_HANDSHAKE;
    case GTLS_STATE_CONNECTED:
      return GTLS_EPOCH_APPLICATION;
    default:
      return GTLS_EPOCH_INITIAL;
  }
}

static GTLS_Result conn_feed(GTLS_Conn * c, GTLS_Epoch epoch, const void * data,
    size_t len, int64_t unix_time) {
  const unsigned char * p = data;

  if (c == NULL || (data == NULL && len != 0) || (unsigned)epoch >= GTLS_EPOCH_COUNT) {
    return GTLS_ERR_INVALID;
  }
  if (c->state == GTLS_STATE_FAILED) {
    return GTLS_ERR_FAILED;
  }
  if (c->state == GTLS_STATE_NEW) {
    return GTLS_ERR_INVALID;
  }
  if (len == 0) {
    return GTLS_OK;
  }
  if (epoch != gtls_conn_expected_epoch(c->state)) {
    return gtls_conn_unexpected(c);
  }
  while (len > 0) {
    size_t body = 0;
    size_t need;
    size_t take;
    GTLS_Result result;
    GTLS_State before;
    int was_key_update;

    if (c->in.len >= 4u) {
      body = ((size_t)c->in.data[1] << 16) | ((size_t)c->in.data[2] << 8) |
          c->in.data[3];
    }
    need = c->in.len < 4u ? 4u - c->in.len : 4u + body - c->in.len;
    take = len < need ? len : need;
    result = gtls_buf_append(&c->in, p, take);
    if (result != GTLS_OK) {
      return gtls_conn_fail_parse(c, result);
    }
    p += take;
    len -= take;
    if (c->in.len < 4u) {
      continue;
    }
    body = ((size_t)c->in.data[1] << 16) | ((size_t)c->in.data[2] << 8) |
        c->in.data[3];
    if (body > c->limits.max_handshake_message ||
        ((c->state == GTLS_STATE_S_WAIT_CH || c->state == GTLS_STATE_S_WAIT_CH2) &&
            body > c->limits.max_client_hello)) {
      return gtls_conn_fail(c, GTLS_ERR_LIMIT, GTLS_ALERT_DECODE_ERROR);
    }
    if (c->in.len < 4u + body) {
      continue;
    }
    /* One whole message. */
    if (c->state != GTLS_STATE_CONNECTED) {
      c->hs_total += c->in.len;
      if (c->hs_total > c->limits.max_handshake_total) {
        return gtls_conn_fail(c, GTLS_ERR_LIMIT, GTLS_ALERT_DECODE_ERROR);
      }
    }
    before = c->state;
    was_key_update = c->in.data[0] == GTLS_HS_KEY_UPDATE;
    result = on_message(c, c->in.data, c->in.len, unix_time);
    c->in.len = 0;
    if (result != GTLS_OK) {
      return result;
    }
    /* A message that moves the keys on, or that ends the first flight,
     * must be the last of its epoch (RFC 8446 section 5.1 and RFC 9001
     * section 4.1.4). */
    if (len > 0 && (gtls_conn_expected_epoch(c->state) != gtls_conn_expected_epoch(before) ||
        before == GTLS_STATE_WAIT_SH || before == GTLS_STATE_WAIT_SH2 ||
        before == GTLS_STATE_S_WAIT_CH || before == GTLS_STATE_S_WAIT_CH2 ||
        (was_key_update && c->mode == GTLS_MODE_STREAM))) {
      return gtls_conn_unexpected(c);
    }
  }
  return GTLS_OK;
}

/** A feed that is not part of the stream interface: the one the callers of the message interface make. */
GTLS_Result gtls_conn_feed(GTLS_Conn * c, GTLS_Epoch epoch, const void * data,
    size_t len, int64_t unix_time) {
  if (c != NULL && c->mode == GTLS_MODE_STREAM) {
    return GTLS_ERR_INVALID;
  }
  if (c != NULL && c->mode == GTLS_MODE_NONE) {
    c->mode = GTLS_MODE_MESSAGE;
  }
  return conn_feed(c, epoch, data, len, unix_time);
}

/** The stream layer's way in: the same state machine, for a connection in stream mode. */
GTLS_Result gtls_conn_feed_stream(GTLS_Conn * c, GTLS_Epoch epoch,
    const void * data, size_t len, int64_t unix_time) {
  return conn_feed(c, epoch, data, len, unix_time);
}

/* ---------------------------------------------------------------- accessors */

GTLS_Result gtls_conn_pending_output(const GTLS_Conn * c, GTLS_Epoch epoch,
    const unsigned char ** data, size_t * len) {
  if (c == NULL || data == NULL || len == NULL || (unsigned)epoch >= GTLS_EPOCH_COUNT ||
      c->mode == GTLS_MODE_STREAM) {
    return GTLS_ERR_INVALID;
  }
  *data = c->out[epoch].data;
  *len = c->out[epoch].len;
  return GTLS_OK;
}

GTLS_Result gtls_conn_consume_output(GTLS_Conn * c, GTLS_Epoch epoch,
    size_t n) {
  if (c == NULL || (unsigned)epoch >= GTLS_EPOCH_COUNT ||
      n > c->out[epoch].len || c->mode == GTLS_MODE_STREAM) {
    return GTLS_ERR_INVALID;
  }
  if (c->mode == GTLS_MODE_NONE) {
    c->mode = GTLS_MODE_MESSAGE;
  }
  gtls_buf_consume(&c->out[epoch], n);
  return GTLS_OK;
}

int gtls_conn_is_connected(const GTLS_Conn * c) {
  return c != NULL && c->state == GTLS_STATE_CONNECTED;
}

int gtls_conn_is_failed(const GTLS_Conn * c) {
  return c != NULL && c->state == GTLS_STATE_FAILED;
}

GTLS_Result gtls_conn_failure(const GTLS_Conn * c) {
  return c == NULL ? GTLS_ERR_INVALID
                   : (c->state == GTLS_STATE_FAILED ? c->failure : GTLS_OK);
}

unsigned gtls_conn_alert(const GTLS_Conn * c) {
  return c != NULL && c->state == GTLS_STATE_FAILED ? c->alert : GTLS_ALERT_NONE;
}

GTLS_State gtls_conn_state(const GTLS_Conn * c) {
  return c == NULL ? GTLS_STATE_FAILED : c->state;
}

GTLS_Result gtls_conn_secret(const GTLS_Conn * c, GTLS_Epoch epoch,
    GTLS_Direction direction, void * out, size_t cap, size_t * len) {
  const unsigned char * secret;
  size_t hlen;

  if (c == NULL || len == NULL || (out == NULL && cap != 0) ||
      (direction != GTLS_DIR_WRITE && direction != GTLS_DIR_READ)) {
    return GTLS_ERR_INVALID;
  }
  if (c->state == GTLS_STATE_FAILED) {
    return GTLS_ERR_FAILED;
  }
  if (epoch == GTLS_EPOCH_EARLY) {
    return GTLS_ERR_UNSUPPORTED;
  }
  /* The direction is the local one: a client writes with the client's
   * secret and a server with the server's. */
  if (epoch == GTLS_EPOCH_HANDSHAKE && c->sec.schedule.stage >= 2) {
    secret = (direction == GTLS_DIR_WRITE) == (c->role == GTLS_ROLE_CLIENT)
        ? c->sec.schedule.c_hs : c->sec.schedule.s_hs;
  } else if (epoch == GTLS_EPOCH_APPLICATION && c->sec.schedule.stage >= 3) {
    secret = (direction == GTLS_DIR_WRITE) == (c->role == GTLS_ROLE_CLIENT)
        ? c->sec.schedule.c_ap : c->sec.schedule.s_ap;
  } else {
    return GTLS_ERR_INVALID;
  }
  hlen = c->sec.schedule.hlen;
  if (cap < hlen) {
    return GTLS_ERR_LIMIT;
  }
  memcpy(out, secret, hlen);
  *len = hlen;
  return GTLS_OK;
}

/** 1 once the suite and group are settled: ServerHello accepted, or sent. */
static int negotiated(const GTLS_Conn * c) {
  switch (c->state) {
    case GTLS_STATE_WAIT_EE:
    case GTLS_STATE_WAIT_CERT:
    case GTLS_STATE_WAIT_CV:
    case GTLS_STATE_WAIT_FIN:
    case GTLS_STATE_CONNECTED:
    case GTLS_STATE_S_WAIT_FIN:
      return 1;
    default:
      return 0;
  }
}

GTLS_Suite gtls_conn_suite(const GTLS_Conn * c) {
  return c != NULL && negotiated(c) ? c->suite : GTLS_SUITE_NONE;
}

GTLS_Group gtls_conn_group(const GTLS_Conn * c) {
  return c != NULL && negotiated(c) ? c->group : GTLS_GROUP_NONE;
}

GTLS_Result gtls_conn_alpn(const GTLS_Conn * c, const unsigned char ** protocol,
    size_t * len) {
  if (c == NULL || protocol == NULL || len == NULL) {
    return GTLS_ERR_INVALID;
  }
  if (c->state == GTLS_STATE_FAILED) {
    return GTLS_ERR_FAILED;
  }
  if (c->alpn_selected_len == 0) {
    *protocol = NULL;
    *len = 0;
  } else {
    *protocol = c->alpn_selected;
    *len = c->alpn_selected_len;
  }
  return GTLS_OK;
}

GTLS_Result gtls_conn_server_name_acknowledged(const GTLS_Conn * c, int * out) {
  if (c == NULL || out == NULL) {
    return GTLS_ERR_INVALID;
  }
  if (c->state == GTLS_STATE_FAILED) {
    return GTLS_ERR_FAILED;
  }
  *out = c->sni_acknowledged;
  return GTLS_OK;
}

int gtls_conn_retried(const GTLS_Conn * c) {
  return c != NULL && c->retried;
}

GTLS_Result gtls_conn_peer_certificate(const GTLS_Conn * c,
    const unsigned char ** der, size_t * len) {
  if (c == NULL || der == NULL || len == NULL) {
    return GTLS_ERR_INVALID;
  }
  if (c->state == GTLS_STATE_FAILED) {
    return GTLS_ERR_FAILED;
  }
  /* The certificate is trusted only once CertificateVerify and Finished have
   * both passed. */
  if (c->state != GTLS_STATE_CONNECTED) {
    *der = NULL;
    *len = 0;
    return GTLS_OK;
  }
  *der = c->leaf;
  *len = c->leaf_len;
  return GTLS_OK;
}

/* ------------------------------------------------------------------- tests */

GTLS_Result gtls_conn_debug_secret(const GTLS_Conn * c, GTLS_SecretId id,
    void * out, size_t cap, size_t * len) {
  const unsigned char * s;

  if (c == NULL || out == NULL || len == NULL) {
    return GTLS_ERR_INVALID;
  }
  switch (id) {
    case GTLS_SECRET_EARLY: s = c->sec.schedule.early; break;
    case GTLS_SECRET_HANDSHAKE: s = c->sec.schedule.handshake; break;
    case GTLS_SECRET_MASTER: s = c->sec.schedule.master; break;
    case GTLS_SECRET_CLIENT_HS: s = c->sec.schedule.c_hs; break;
    case GTLS_SECRET_SERVER_HS: s = c->sec.schedule.s_hs; break;
    case GTLS_SECRET_CLIENT_AP: s = c->sec.schedule.c_ap; break;
    case GTLS_SECRET_SERVER_AP: s = c->sec.schedule.s_ap; break;
    default: return GTLS_ERR_INVALID;
  }
  if (cap < c->sec.schedule.hlen || c->sec.schedule.hlen == 0) {
    return GTLS_ERR_LIMIT;
  }
  memcpy(out, s, c->sec.schedule.hlen);
  *len = c->sec.schedule.hlen;
  return GTLS_OK;
}

int gtls_conn_secrets_are_wiped(const GTLS_Conn * c) {
  const unsigned char * p;
  unsigned acc = 0;
  size_t i;

  if (c == NULL) {
    return 1;
  }
  p = (const unsigned char *)&c->sec;
  for (i = 0; i < sizeof c->sec; i++) {
    acc |= p[i];
  }
  return acc == 0;
}

GTLS_Result gtls_conn_debug_transcript(const GTLS_Conn * c, void * out,
    size_t cap, size_t * len) {
  GTLS_Hash hash;

  if (c == NULL || out == NULL || len == NULL) {
    return GTLS_ERR_INVALID;
  }
  hash = c->sec.transcript.hash;
  if (hash == GTLS_HASH_NONE) {
    hash = GTLS_HASH_SHA256;
  }
  if (cap < gtls_hash_len(hash)) {
    return GTLS_ERR_LIMIT;
  }
  *len = gtls_hash_len(hash);
  return gtls_transcript_snapshot(&c->sec.transcript, hash, out);
}
