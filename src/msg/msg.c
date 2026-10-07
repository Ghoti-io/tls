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
 * @file msg.c
 *
 * Handshake message encoding and decoding. RFC 8446 section 4, with
 * RFC 6066 (server_name), RFC 7301 (ALPN) and RFC 7685 (padding).
 */

#include <ghoti.io/tls/macros.h>

#include "msg_internal.h"

#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/security/secret.h>

#include <string.h>

/* ------------------------------------------------------------------ buffer */

void gtls_buf_init(GTLS_Buf * b, const GTLS_Allocator * allocator, size_t max) {
  memset(b, 0, sizeof *b);
  b->allocator = allocator != NULL ? allocator : gcu_allocator_default();
  b->max = max;
  b->err = GTLS_OK;
}

void gtls_buf_free(GTLS_Buf * b) {
  if (b != NULL && b->data != NULL) {
    gcu_allocator_free(b->allocator, b->data);
  }
  if (b != NULL) {
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
  }
}

GTLS_Result gtls_buf_append(GTLS_Buf * b, const void * data, size_t n) {
  if (b->err != GTLS_OK) {
    return b->err;
  }
  if (n == 0) {
    return GTLS_OK;
  }
  if (n > b->max - b->len) {
    b->err = GTLS_ERR_LIMIT;
    return b->err;
  }
  if (b->len + n > b->cap) {
    size_t want = b->cap == 0 ? 256u : b->cap;
    unsigned char * grown;

    while (want < b->len + n) {
      want *= 2u;
    }
    if (want > b->max) {
      want = b->max;
    }
    grown = gcu_allocator_realloc(b->allocator, b->data, want);
    if (grown == NULL) {
      b->err = GTLS_ERR_OOM;
      return b->err;
    }
    b->data = grown;
    b->cap = want;
  }
  memcpy(b->data + b->len, data, n);
  b->len += n;
  return GTLS_OK;
}

void gtls_buf_u8(GTLS_Buf * b, unsigned v) {
  unsigned char c = (unsigned char)v;
  (void)gtls_buf_append(b, &c, 1);
}

void gtls_buf_u16(GTLS_Buf * b, unsigned v) {
  unsigned char c[2];
  c[0] = (unsigned char)(v >> 8);
  c[1] = (unsigned char)v;
  (void)gtls_buf_append(b, c, 2);
}

void gtls_buf_u24(GTLS_Buf * b, unsigned v) {
  unsigned char c[3];
  c[0] = (unsigned char)(v >> 16);
  c[1] = (unsigned char)(v >> 8);
  c[2] = (unsigned char)v;
  (void)gtls_buf_append(b, c, 3);
}

void gtls_buf_consume(GTLS_Buf * b, size_t n) {
  if (n >= b->len) {
    b->len = 0;
    return;
  }
  memmove(b->data, b->data + n, b->len - n);
  b->len -= n;
}

size_t gtls_buf_begin(GTLS_Buf * b, unsigned width) {
  static const unsigned char zeros[3] = {0, 0, 0};
  size_t at = b->len;
  (void)gtls_buf_append(b, zeros, width);
  return at;
}

void gtls_buf_end(GTLS_Buf * b, size_t offset, unsigned width) {
  size_t n;
  size_t limit = width == 1u ? 0xffu : width == 2u ? 0xffffu : 0xffffffu;

  if (b->err != GTLS_OK) {
    return;
  }
  n = b->len - offset - width;
  if (n > limit) {
    b->err = GTLS_ERR_LIMIT;
    return;
  }
  if (width == 3u) {
    b->data[offset] = (unsigned char)(n >> 16);
    b->data[offset + 1] = (unsigned char)(n >> 8);
    b->data[offset + 2] = (unsigned char)n;
  } else if (width == 2u) {
    b->data[offset] = (unsigned char)(n >> 8);
    b->data[offset + 1] = (unsigned char)n;
  } else {
    b->data[offset] = (unsigned char)n;
  }
}

/* ------------------------------------------------------------------ reader */

void gtls_reader_init(GTLS_Reader * r, const void * data, size_t len) {
  r->p = data;
  r->len = len;
  r->pos = 0;
}

size_t gtls_reader_left(const GTLS_Reader * r) {
  return r->len - r->pos;
}

GTLS_Result gtls_reader_bytes(GTLS_Reader * r, size_t n,
    const unsigned char ** out) {
  if (n > r->len - r->pos) {
    return GTLS_ERR_CORRUPT;
  }
  *out = r->p + r->pos;
  r->pos += n;
  return GTLS_OK;
}

GTLS_Result gtls_reader_u8(GTLS_Reader * r, unsigned * v) {
  const unsigned char * p;
  GTLS_Result result = gtls_reader_bytes(r, 1, &p);

  if (result == GTLS_OK) {
    *v = p[0];
  }
  return result;
}

GTLS_Result gtls_reader_u16(GTLS_Reader * r, unsigned * v) {
  const unsigned char * p;
  GTLS_Result result = gtls_reader_bytes(r, 2, &p);

  if (result == GTLS_OK) {
    *v = ((unsigned)p[0] << 8) | p[1];
  }
  return result;
}

GTLS_Result gtls_reader_u24(GTLS_Reader * r, unsigned * v) {
  const unsigned char * p;
  GTLS_Result result = gtls_reader_bytes(r, 3, &p);

  if (result == GTLS_OK) {
    *v = ((unsigned)p[0] << 16) | ((unsigned)p[1] << 8) | p[2];
  }
  return result;
}

GTLS_Result gtls_reader_vector(GTLS_Reader * r, unsigned width, size_t min,
    size_t max, GTLS_Reader * sub) {
  unsigned n = 0;
  const unsigned char * p;
  GTLS_Result result;

  if (width == 1u) {
    result = gtls_reader_u8(r, &n);
  } else if (width == 2u) {
    result = gtls_reader_u16(r, &n);
  } else {
    result = gtls_reader_u24(r, &n);
  }
  if (result != GTLS_OK) {
    return result;
  }
  if (n < min || (max != 0 && n > max)) {
    return GTLS_ERR_CORRUPT;
  }
  result = gtls_reader_bytes(r, n, &p);
  if (result != GTLS_OK) {
    return result;
  }
  gtls_reader_init(sub, p, n);
  return GTLS_OK;
}

GTLS_Result gtls_reader_end(const GTLS_Reader * r) {
  return r->pos == r->len ? GTLS_OK : GTLS_ERR_CORRUPT;
}

/* -------------------------------------------------------------- extensions */

GTLS_Result gtls_msg_extensions(GTLS_Reader * r, uint32_t max_ext,
    GTLS_Ext * out, size_t * count) {
  GTLS_Reader block;
  size_t n = 0;
  size_t i;
  GTLS_Result result = gtls_reader_vector(r, 2, 0, 0, &block);

  if (result != GTLS_OK) {
    return result;
  }
  if (max_ext > GTLS_EXT_MAX) {
    max_ext = GTLS_EXT_MAX;
  }
  while (gtls_reader_left(&block) != 0) {
    unsigned type;
    GTLS_Reader body;

    result = gtls_reader_u16(&block, &type);
    if (result == GTLS_OK) {
      result = gtls_reader_vector(&block, 2, 0, 0, &body);
    }
    if (result != GTLS_OK) {
      return result;
    }
    if (n >= max_ext) {
      return GTLS_ERR_LIMIT;
    }
    for (i = 0; i < n; i++) {
      if (out[i].type == type) {
        return GTLS_ERR_PROTOCOL;
      }
    }
    out[n].type = (uint16_t)type;
    out[n].data = body.p;
    out[n].len = body.len;
    n++;
  }
  *count = n;
  return GTLS_OK;
}

const GTLS_Ext * gtls_msg_find_ext(const GTLS_Ext * exts, size_t count,
    unsigned type) {
  size_t i;

  for (i = 0; i < count; i++) {
    if (exts[i].type == type) {
      return &exts[i];
    }
  }
  return NULL;
}

/* ------------------------------------------------------------- ClientHello */

static void ext_begin(GTLS_Buf * b, unsigned type, size_t * at) {
  gtls_buf_u16(b, type);
  *at = gtls_buf_begin(b, 2);
}

/** RFC 7685: a ClientHello of 256 to 511 bytes upsets some servers. */
static void pad_hello(GTLS_Buf * b) {
  size_t total;
  size_t data;
  size_t at;
  unsigned char zeros[512];

  if (b->err != GTLS_OK) {
    return;
  }
  total = b->len;
  if (total < 256u || total > 511u) {
    return;
  }
  data = total <= 508u ? 512u - total - 4u : 0u;
  memset(zeros, 0, sizeof zeros);
  ext_begin(b, GTLS_EXT_PADDING, &at);
  (void)gtls_buf_append(b, zeros, data);
  gtls_buf_end(b, at, 2);
}

/** Fix the three header lengths of a ClientHello once its end is known. */
static void finish_hello(GTLS_Buf * b, size_t ext_at) {
  gtls_buf_end(b, ext_at, 2);
  pad_hello(b);
  /* The padding extension, when one was added, is inside the extension
   * block, so its length is written again. */
  if (b->err == GTLS_OK) {
    gtls_buf_end(b, ext_at, 2);
    if (b->err == GTLS_OK) {
      size_t body = b->len - 4u;
      b->data[1] = (unsigned char)(body >> 16);
      b->data[2] = (unsigned char)(body >> 8);
      b->data[3] = (unsigned char)body;
    }
  }
}

static void write_key_share(GTLS_Buf * b, const GTLS_KeyShare * share) {
  size_t at;
  size_t list;

  ext_begin(b, GTLS_EXT_KEY_SHARE, &at);
  list = gtls_buf_begin(b, 2);
  gtls_buf_u16(b, share->group);
  gtls_buf_u16(b, (unsigned)share->pub_len);
  (void)gtls_buf_append(b, share->pub, share->pub_len);
  gtls_buf_end(b, list, 2);
  gtls_buf_end(b, at, 2);
}

GTLS_Result gtls_msg_build_client_hello(const GTLS_HelloParams * p,
    GTLS_Buf * out) {
  size_t at;
  size_t list;
  size_t ext_at;
  size_t i;

  if (p == NULL || out == NULL || p->suites == NULL || p->suite_count == 0 ||
      p->groups == NULL || p->group_count == 0 || p->sig_algs == NULL ||
      p->sig_alg_count == 0 || (p->session_id_len != 0 && p->session_id_len != 32u) ||
      (p->host == NULL && p->host_len != 0)) {
    return GTLS_ERR_INVALID;
  }
  gtls_buf_u8(out, GTLS_HS_CLIENT_HELLO);
  gtls_buf_u24(out, 0);
  gtls_buf_u16(out, 0x0303);
  (void)gtls_buf_append(out, p->random, 32);
  gtls_buf_u8(out, (unsigned)p->session_id_len);
  (void)gtls_buf_append(out, p->session_id, p->session_id_len);
  gtls_buf_u16(out, (unsigned)(2u * p->suite_count));
  for (i = 0; i < p->suite_count; i++) {
    gtls_buf_u16(out, (unsigned)p->suites[i]);
  }
  gtls_buf_u8(out, 1);
  gtls_buf_u8(out, 0);
  ext_at = gtls_buf_begin(out, 2);

  if (p->host != NULL && p->host_len != 0) {
    ext_begin(out, GTLS_EXT_SERVER_NAME, &at);
    list = gtls_buf_begin(out, 2);
    gtls_buf_u8(out, 0); /* host_name */
    gtls_buf_u16(out, (unsigned)p->host_len);
    (void)gtls_buf_append(out, p->host, p->host_len);
    gtls_buf_end(out, list, 2);
    gtls_buf_end(out, at, 2);
  }
  ext_begin(out, GTLS_EXT_SUPPORTED_GROUPS, &at);
  list = gtls_buf_begin(out, 2);
  for (i = 0; i < p->group_count; i++) {
    gtls_buf_u16(out, (unsigned)p->groups[i]);
  }
  gtls_buf_end(out, list, 2);
  gtls_buf_end(out, at, 2);

  ext_begin(out, GTLS_EXT_SIGNATURE_ALGORITHMS, &at);
  list = gtls_buf_begin(out, 2);
  for (i = 0; i < p->sig_alg_count; i++) {
    gtls_buf_u16(out, (unsigned)p->sig_algs[i]);
  }
  gtls_buf_end(out, list, 2);
  gtls_buf_end(out, at, 2);

  if (p->alpn_len != 0) {
    ext_begin(out, GTLS_EXT_ALPN, &at);
    list = gtls_buf_begin(out, 2);
    (void)gtls_buf_append(out, p->alpn, p->alpn_len);
    gtls_buf_end(out, list, 2);
    gtls_buf_end(out, at, 2);
  }
  ext_begin(out, GTLS_EXT_SUPPORTED_VERSIONS, &at);
  gtls_buf_u8(out, 2);
  gtls_buf_u16(out, 0x0304);
  gtls_buf_end(out, at, 2);

  write_key_share(out, &p->share);
  finish_hello(out, ext_at);
  return out->err;
}

GTLS_Result gtls_msg_parse_client_hello(const void * body, size_t len,
    const GTLS_Limits * limits, GTLS_ClientHello * out) {
  GTLS_Reader r;
  GTLS_Reader v;
  GTLS_ClientHello h;
  unsigned n;
  const unsigned char * p;
  GTLS_Result result;

  memset(&h, 0, sizeof h);
  gtls_reader_init(&r, body, len);
  result = gtls_reader_u16(&r, &h.legacy_version);
  if (result == GTLS_OK) {
    result = gtls_reader_bytes(&r, 32, &h.random);
  }
  if (result == GTLS_OK) {
    result = gtls_reader_vector(&r, 1, 0, 32, &v);
    h.session_id = v.p;
    h.session_id_len = v.len;
  }
  if (result == GTLS_OK) {
    result = gtls_reader_vector(&r, 2, 2, 0, &v);
    h.suites = v.p;
    h.suites_len = v.len;
    if (result == GTLS_OK && (v.len & 1u) != 0) {
      result = GTLS_ERR_CORRUPT;
    }
  }
  if (result == GTLS_OK) {
    result = gtls_reader_u8(&r, &n);
  }
  if (result == GTLS_OK) {
    result = n == 0 ? GTLS_ERR_CORRUPT : gtls_reader_bytes(&r, n, &p);
    h.compression = p;
    h.compression_len = n;
  }
  if (result != GTLS_OK) {
    return result;
  }
  h.prefix_len = r.pos;
  result = gtls_msg_extensions(&r, limits->max_extensions, h.exts, &h.ext_count);
  if (result == GTLS_OK) {
    result = gtls_reader_end(&r);
  }
  if (result != GTLS_OK) {
    return result;
  }
  *out = h;
  return GTLS_OK;
}

GTLS_Result gtls_msg_retry_client_hello(const void * hello1, size_t hello1_len,
    const GTLS_KeyShare * share, const void * cookie, size_t cookie_len,
    const GTLS_Limits * limits, GTLS_Buf * out) {
  const unsigned char * m = hello1;
  GTLS_ClientHello h;
  size_t ext_at;
  size_t i;
  int cookie_done = cookie_len == 0;
  size_t at;
  GTLS_Result result;

  if (m == NULL || hello1_len < 4u || m[0] != GTLS_HS_CLIENT_HELLO ||
      (((size_t)m[1] << 16) | ((size_t)m[2] << 8) | m[3]) != hello1_len - 4u ||
      (cookie == NULL && cookie_len != 0) || out == NULL) {
    return GTLS_ERR_INVALID;
  }
  result = gtls_msg_parse_client_hello(m + 4, hello1_len - 4u, limits, &h);
  if (result != GTLS_OK) {
    return result;
  }
  gtls_buf_u8(out, GTLS_HS_CLIENT_HELLO);
  gtls_buf_u24(out, 0);
  (void)gtls_buf_append(out, m + 4, h.prefix_len);
  ext_at = gtls_buf_begin(out, 2);
  for (i = 0; i < h.ext_count; i++) {
    const GTLS_Ext * e = &h.exts[i];

    if (e->type == GTLS_EXT_PADDING) {
      continue;
    }
    if (e->type == GTLS_EXT_COOKIE) {
      continue; /* replaced below, or dropped */
    }
    if (e->type == GTLS_EXT_PSK_KEY_EXCHANGE_MODES && !cookie_done) {
      ext_begin(out, GTLS_EXT_COOKIE, &at);
      gtls_buf_u16(out, (unsigned)cookie_len);
      (void)gtls_buf_append(out, cookie, cookie_len);
      gtls_buf_end(out, at, 2);
      cookie_done = 1;
    }
    if (e->type == GTLS_EXT_KEY_SHARE && share != NULL) {
      write_key_share(out, share);
      continue;
    }
    ext_begin(out, e->type, &at);
    (void)gtls_buf_append(out, e->data, e->len);
    gtls_buf_end(out, at, 2);
  }
  if (!cookie_done) {
    ext_begin(out, GTLS_EXT_COOKIE, &at);
    gtls_buf_u16(out, (unsigned)cookie_len);
    (void)gtls_buf_append(out, cookie, cookie_len);
    gtls_buf_end(out, at, 2);
  }
  finish_hello(out, ext_at);
  return out->err;
}

/* ------------------------------------------------------------- ServerHello */

static const unsigned char hrr_random[32] = {
  0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c,
  0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb,
  0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c
};

int gtls_msg_is_hrr_random(const unsigned char * random) {
  return gsec_equal(random, hrr_random, sizeof hrr_random) == GSEC_OK;
}

int gtls_msg_downgrade_sentinel(const unsigned char * random) {
  static const unsigned char tail[7] = {0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44};

  if (gsec_equal(random + 24, tail, sizeof tail) != GSEC_OK) {
    return 0;
  }
  if (random[31] == 1u) {
    return 2;
  }
  if (random[31] == 0u) {
    return 3;
  }
  return 0;
}

GTLS_Result gtls_msg_parse_server_hello(const void * body, size_t len,
    const GTLS_Limits * limits, GTLS_ServerHello * out) {
  GTLS_Reader r;
  GTLS_Reader v;
  GTLS_ServerHello s;
  GTLS_Ext exts[GTLS_EXT_MAX];
  size_t count = 0;
  size_t i;
  GTLS_Result result;

  memset(&s, 0, sizeof s);
  memset(exts, 0, sizeof exts);
  gtls_reader_init(&r, body, len);
  result = gtls_reader_u16(&r, &s.legacy_version);
  if (result == GTLS_OK) {
    result = gtls_reader_bytes(&r, 32, &s.random);
  }
  if (result == GTLS_OK) {
    result = gtls_reader_vector(&r, 1, 0, 32, &v);
    s.session_id = v.p;
    s.session_id_len = v.len;
  }
  if (result == GTLS_OK) {
    result = gtls_reader_u16(&r, &s.suite);
  }
  if (result == GTLS_OK) {
    result = gtls_reader_u8(&r, &s.compression);
  }
  if (result != GTLS_OK) {
    return result;
  }
  s.is_hrr = gtls_msg_is_hrr_random(s.random);
  if (gtls_reader_left(&r) != 0) {
    result = gtls_msg_extensions(&r, limits->max_extensions, exts, &count);
    if (result == GTLS_OK) {
      result = gtls_reader_end(&r);
    }
    if (result != GTLS_OK) {
      return result;
    }
  }
  for (i = 0; i < count; i++) {
    GTLS_Reader e;

    gtls_reader_init(&e, exts[i].data, exts[i].len);
    switch (exts[i].type) {
      case GTLS_EXT_SUPPORTED_VERSIONS:
        result = gtls_reader_u16(&e, &s.selected_version);
        if (result == GTLS_OK) {
          result = gtls_reader_end(&e);
        }
        s.flags |= GTLS_SH_FLAG_VERSION;
        break;
      case GTLS_EXT_KEY_SHARE:
        result = gtls_reader_u16(&e, &s.group);
        if (result == GTLS_OK && !s.is_hrr) {
          result = gtls_reader_vector(&e, 2, 1, 0, &v);
          s.key_exchange = v.p;
          s.key_exchange_len = v.len;
        }
        if (result == GTLS_OK) {
          result = gtls_reader_end(&e);
        }
        s.flags |= GTLS_SH_FLAG_KEY_SHARE;
        break;
      case GTLS_EXT_COOKIE:
        result = gtls_reader_vector(&e, 2, 1, 0, &v);
        if (result == GTLS_OK) {
          result = gtls_reader_end(&e);
        }
        if (result == GTLS_OK && v.len > limits->max_cookie_bytes) {
          result = GTLS_ERR_LIMIT;
        }
        s.cookie = v.p;
        s.cookie_len = v.len;
        s.flags |= GTLS_SH_FLAG_COOKIE;
        break;
      case GTLS_EXT_PRE_SHARED_KEY:
        s.flags |= GTLS_SH_FLAG_PSK;
        result = GTLS_OK;
        break;
      default:
        if ((s.flags & GTLS_SH_FLAG_UNKNOWN) == 0) {
          s.unknown_ext = exts[i].type;
        }
        s.flags |= GTLS_SH_FLAG_UNKNOWN;
        result = GTLS_OK;
        break;
    }
    if (result != GTLS_OK) {
      return result;
    }
  }
  *out = s;
  return GTLS_OK;
}

/* -------------------------------------------------- EncryptedExtensions etc. */

GTLS_Result gtls_msg_parse_encrypted_extensions(const void * body, size_t len,
    const GTLS_Limits * limits, GTLS_EncryptedExtensions * out) {
  GTLS_Reader r;
  GTLS_EncryptedExtensions ee;
  const GTLS_Ext * e;
  GTLS_Result result;

  memset(&ee, 0, sizeof ee);
  gtls_reader_init(&r, body, len);
  result = gtls_msg_extensions(&r, limits->max_extensions, ee.exts,
      &ee.ext_count);
  if (result == GTLS_OK) {
    result = gtls_reader_end(&r);
  }
  if (result != GTLS_OK) {
    return result;
  }
  e = gtls_msg_find_ext(ee.exts, ee.ext_count, GTLS_EXT_ALPN);
  if (e != NULL) {
    GTLS_Reader list;
    GTLS_Reader name;
    GTLS_Reader whole;

    gtls_reader_init(&whole, e->data, e->len);
    result = gtls_reader_vector(&whole, 2, 2, 0, &list);
    if (result == GTLS_OK) {
      result = gtls_reader_end(&whole);
    }
    if (result == GTLS_OK) {
      result = gtls_reader_vector(&list, 1, 1, 0, &name);
    }
    if (result == GTLS_OK) {
      result = gtls_reader_end(&list); /* exactly one protocol */
    }
    if (result != GTLS_OK) {
      return result;
    }
    ee.has_alpn = 1;
    ee.alpn = name.p;
    ee.alpn_len = name.len;
  }
  e = gtls_msg_find_ext(ee.exts, ee.ext_count, GTLS_EXT_SERVER_NAME);
  if (e != NULL) {
    if (e->len != 0) {
      return GTLS_ERR_PROTOCOL;
    }
    ee.has_server_name = 1;
  }
  *out = ee;
  return GTLS_OK;
}

GTLS_Result gtls_msg_parse_certificate(const void * body, size_t len,
    const GTLS_Limits * limits, GTLS_CertificateMsg * out) {
  GTLS_Reader r;
  GTLS_Reader list;
  GTLS_Reader v;
  GTLS_CertificateMsg c;
  size_t max = limits->max_certificates;
  GTLS_Result result;

  memset(&c, 0, sizeof c);
  if (max > GTLS_CERT_MAX) {
    max = GTLS_CERT_MAX;
  }
  gtls_reader_init(&r, body, len);
  result = gtls_reader_vector(&r, 1, 0, 0, &v);
  if (result != GTLS_OK) {
    return result;
  }
  c.context = v.p;
  c.context_len = v.len;
  result = gtls_reader_vector(&r, 3, 0, 0, &list);
  if (result == GTLS_OK) {
    result = gtls_reader_end(&r);
  }
  if (result != GTLS_OK) {
    return result;
  }
  while (gtls_reader_left(&list) != 0) {
    unsigned n;
    const unsigned char * der;
    GTLS_Reader ext;

    result = gtls_reader_u24(&list, &n);
    if (result != GTLS_OK) {
      return result;
    }
    if (n == 0) {
      return GTLS_ERR_CORRUPT;
    }
    if (c.count >= max || n > limits->max_certificate_bytes) {
      return GTLS_ERR_LIMIT;
    }
    result = gtls_reader_bytes(&list, n, &der);
    if (result == GTLS_OK) {
      result = gtls_reader_vector(&list, 2, 0, 0, &ext);
    }
    if (result != GTLS_OK) {
      return result;
    }
    c.der[c.count] = der;
    c.der_len[c.count] = n;
    c.count++;
    if (ext.len != 0) {
      c.has_entry_extensions = 1;
    }
  }
  *out = c;
  return GTLS_OK;
}

GTLS_Result gtls_msg_parse_certificate_verify(const void * body, size_t len,
    const GTLS_Limits * limits, GTLS_CertificateVerifyMsg * out) {
  GTLS_Reader r;
  GTLS_Reader sig;
  GTLS_CertificateVerifyMsg cv;
  GTLS_Result result;

  gtls_reader_init(&r, body, len);
  result = gtls_reader_u16(&r, &cv.scheme);
  if (result == GTLS_OK) {
    result = gtls_reader_vector(&r, 2, 1, 0, &sig);
  }
  if (result == GTLS_OK) {
    result = gtls_reader_end(&r);
  }
  if (result != GTLS_OK) {
    return result;
  }
  if (sig.len > limits->max_signature_bytes) {
    return GTLS_ERR_LIMIT;
  }
  cv.signature = sig.p;
  cv.signature_len = sig.len;
  *out = cv;
  return GTLS_OK;
}

GTLS_Result gtls_msg_parse_new_session_ticket(const void * body, size_t len,
    const GTLS_Limits * limits, GTLS_NewSessionTicket * out) {
  GTLS_Reader r;
  GTLS_Reader v;
  GTLS_NewSessionTicket t;
  GTLS_Ext exts[GTLS_EXT_MAX];
  size_t count = 0;
  const unsigned char * p;
  GTLS_Result result;

  memset(&t, 0, sizeof t);
  memset(exts, 0, sizeof exts);
  gtls_reader_init(&r, body, len);
  result = gtls_reader_bytes(&r, 4, &p);
  if (result == GTLS_OK) {
    t.lifetime = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
        ((uint32_t)p[2] << 8) | p[3];
    result = gtls_reader_bytes(&r, 4, &p);
  }
  if (result == GTLS_OK) {
    t.age_add = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
        ((uint32_t)p[2] << 8) | p[3];
    result = gtls_reader_vector(&r, 1, 0, 0, &v);
    t.nonce = v.p;
    t.nonce_len = v.len;
  }
  if (result == GTLS_OK) {
    result = gtls_reader_vector(&r, 2, 1, 0, &v);
    t.ticket = v.p;
    t.ticket_len = v.len;
  }
  if (result != GTLS_OK) {
    return result;
  }
  if (t.ticket_len > limits->max_ticket_bytes) {
    return GTLS_ERR_LIMIT;
  }
  result = gtls_msg_extensions(&r, limits->max_extensions, exts, &count);
  if (result == GTLS_OK) {
    result = gtls_reader_end(&r);
  }
  if (result != GTLS_OK) {
    return result;
  }
  {
    const GTLS_Ext * e = gtls_msg_find_ext(exts, count, GTLS_EXT_EARLY_DATA);

    if (e != NULL) {
      GTLS_Reader er;

      gtls_reader_init(&er, e->data, e->len);
      result = gtls_reader_bytes(&er, 4, &p);
      if (result == GTLS_OK) {
        result = gtls_reader_end(&er);
      }
      if (result != GTLS_OK) {
        return result;
      }
      t.early_data = 1;
      t.max_early_data = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
          ((uint32_t)p[2] << 8) | p[3];
    }
  }
  *out = t;
  return GTLS_OK;
}

/* ------------------------------------------- ClientHello, as a server reads it */

GTLS_Result gtls_msg_parse_ch_versions(const GTLS_Ext * e, int * has_tls13) {
  GTLS_Reader r;
  GTLS_Reader list;
  GTLS_Result result;
  int found = 0;

  gtls_reader_init(&r, e->data, e->len);
  result = gtls_reader_vector(&r, 1, 2, 254, &list);
  if (result == GTLS_OK) {
    result = gtls_reader_end(&r);
  }
  if (result == GTLS_OK && (list.len & 1u) != 0) {
    result = GTLS_ERR_CORRUPT;
  }
  if (result != GTLS_OK) {
    return result;
  }
  while (gtls_reader_left(&list) != 0) {
    unsigned v = 0;

    (void)gtls_reader_u16(&list, &v);
    if (v == 0x0304u) {
      found = 1;
    }
  }
  *has_tls13 = found;
  return GTLS_OK;
}

GTLS_Result gtls_msg_parse_ch_u16_list(const GTLS_Ext * e, uint16_t * out,
    size_t cap, size_t * count) {
  GTLS_Reader r;
  GTLS_Reader list;
  GTLS_Result result;
  size_t n = 0;

  gtls_reader_init(&r, e->data, e->len);
  result = gtls_reader_vector(&r, 2, 2, 0, &list);
  if (result == GTLS_OK) {
    result = gtls_reader_end(&r);
  }
  if (result == GTLS_OK && (list.len & 1u) != 0) {
    result = GTLS_ERR_CORRUPT;
  }
  if (result != GTLS_OK) {
    return result;
  }
  if (list.len / 2u > GTLS_CH_LIST_MAX) {
    return GTLS_ERR_LIMIT;
  }
  while (gtls_reader_left(&list) != 0) {
    unsigned v = 0;

    (void)gtls_reader_u16(&list, &v);
    if (n < cap) {
      out[n] = (uint16_t)v;
    }
    n++;
  }
  *count = n < cap ? n : cap;
  return GTLS_OK;
}

GTLS_Result gtls_msg_parse_ch_key_shares(const GTLS_Ext * e,
    GTLS_ClientShare * out, size_t * count) {
  GTLS_Reader r;
  GTLS_Reader list;
  GTLS_Result result;
  size_t n = 0;
  size_t i;

  gtls_reader_init(&r, e->data, e->len);
  result = gtls_reader_vector(&r, 2, 0, 0, &list);
  if (result == GTLS_OK) {
    result = gtls_reader_end(&r);
  }
  if (result != GTLS_OK) {
    return result;
  }
  while (gtls_reader_left(&list) != 0) {
    unsigned group = 0;
    GTLS_Reader kx;

    result = gtls_reader_u16(&list, &group);
    if (result == GTLS_OK) {
      result = gtls_reader_vector(&list, 2, 1, 0, &kx);
    }
    if (result != GTLS_OK) {
      return result;
    }
    if (n >= GTLS_CH_SHARES_MAX) {
      return GTLS_ERR_LIMIT;
    }
    for (i = 0; i < n; i++) {
      if (out[i].group == group) {
        return GTLS_ERR_PROTOCOL;
      }
    }
    out[n].group = group;
    out[n].kx = kx.p;
    out[n].kx_len = kx.len;
    n++;
  }
  *count = n;
  return GTLS_OK;
}

GTLS_Result gtls_msg_parse_ch_alpn(const GTLS_Ext * e, GTLS_Name * out,
    size_t * count) {
  GTLS_Reader r;
  GTLS_Reader list;
  GTLS_Result result;
  size_t n = 0;

  gtls_reader_init(&r, e->data, e->len);
  result = gtls_reader_vector(&r, 2, 2, 0, &list);
  if (result == GTLS_OK) {
    result = gtls_reader_end(&r);
  }
  if (result != GTLS_OK) {
    return result;
  }
  while (gtls_reader_left(&list) != 0) {
    GTLS_Reader name;

    result = gtls_reader_vector(&list, 1, 1, 0, &name);
    if (result != GTLS_OK) {
      return result;
    }
    if (n >= GTLS_CH_NAMES_MAX) {
      return GTLS_ERR_LIMIT;
    }
    out[n].p = name.p;
    out[n].len = name.len;
    n++;
  }
  *count = n;
  return GTLS_OK;
}

GTLS_Result gtls_msg_parse_ch_server_name(const GTLS_Ext * e, GTLS_Name * host) {
  GTLS_Reader r;
  GTLS_Reader list;
  GTLS_Result result;
  int seen = 0;

  host->p = NULL;
  host->len = 0;
  gtls_reader_init(&r, e->data, e->len);
  result = gtls_reader_vector(&r, 2, 1, 0, &list);
  if (result == GTLS_OK) {
    result = gtls_reader_end(&r);
  }
  if (result != GTLS_OK) {
    return result;
  }
  while (gtls_reader_left(&list) != 0) {
    unsigned type = 0;
    GTLS_Reader name;

    result = gtls_reader_u8(&list, &type);
    if (result == GTLS_OK) {
      result = gtls_reader_vector(&list, 2, 1, 0, &name);
    }
    if (result != GTLS_OK) {
      return result;
    }
    if (type == 0) {
      if (seen) {
        return GTLS_ERR_PROTOCOL;
      }
      seen = 1;
      host->p = name.p;
      host->len = name.len;
    }
  }
  return GTLS_OK;
}

GTLS_Result gtls_msg_parse_ch_cookie(const GTLS_Ext * e, GTLS_Name * cookie) {
  GTLS_Reader r;
  GTLS_Reader v;
  GTLS_Result result;

  gtls_reader_init(&r, e->data, e->len);
  result = gtls_reader_vector(&r, 2, 1, 0, &v);
  if (result == GTLS_OK) {
    result = gtls_reader_end(&r);
  }
  if (result != GTLS_OK) {
    return result;
  }
  cookie->p = v.p;
  cookie->len = v.len;
  return GTLS_OK;
}

GTLS_Result gtls_msg_parse_ch_psk_modes(const GTLS_Ext * e, int * has_dhe_ke) {
  GTLS_Reader r;
  GTLS_Reader list;
  GTLS_Result result;
  int found = 0;

  gtls_reader_init(&r, e->data, e->len);
  result = gtls_reader_vector(&r, 1, 1, 0, &list);
  if (result == GTLS_OK) {
    result = gtls_reader_end(&r);
  }
  if (result != GTLS_OK) {
    return result;
  }
  while (gtls_reader_left(&list) != 0) {
    unsigned m = 0;

    (void)gtls_reader_u8(&list, &m);
    if (m == 1u) {
      found = 1;
    }
  }
  *has_dhe_ke = found;
  return GTLS_OK;
}

GTLS_Result gtls_msg_parse_ch_psk_offer(const GTLS_Ext * e,
    const GTLS_Limits * limits, size_t * count) {
  GTLS_Reader r;
  GTLS_Reader ids;
  GTLS_Reader binders;
  GTLS_Result result;
  size_t n_ids = 0;
  size_t n_binders = 0;

  gtls_reader_init(&r, e->data, e->len);
  result = gtls_reader_vector(&r, 2, 7, 0, &ids);
  if (result == GTLS_OK) {
    result = gtls_reader_vector(&r, 2, 33, 0, &binders);
  }
  if (result == GTLS_OK) {
    result = gtls_reader_end(&r);
  }
  if (result != GTLS_OK) {
    return result;
  }
  while (gtls_reader_left(&ids) != 0) {
    GTLS_Reader identity;
    const unsigned char * age;

    result = gtls_reader_vector(&ids, 2, 1, 0, &identity);
    if (result == GTLS_OK) {
      result = gtls_reader_bytes(&ids, 4, &age); /* obfuscated_ticket_age */
    }
    if (result != GTLS_OK) {
      return result;
    }
    if (identity.len > limits->max_ticket_bytes || ++n_ids > limits->max_tickets) {
      return GTLS_ERR_LIMIT;
    }
  }
  while (gtls_reader_left(&binders) != 0) {
    GTLS_Reader binder;

    result = gtls_reader_vector(&binders, 1, 32, 0, &binder);
    if (result != GTLS_OK) {
      return result;
    }
    if (++n_binders > limits->max_tickets) {
      return GTLS_ERR_LIMIT;
    }
  }
  if (n_ids != n_binders) {
    return GTLS_ERR_PROTOCOL;
  }
  *count = n_ids;
  return GTLS_OK;
}

GTLS_Result gtls_msg_parse_ch_early_data(const GTLS_Ext * e) {
  return e->len == 0 ? GTLS_OK : GTLS_ERR_CORRUPT;
}

/* ----------------------------------------------------- what a server sends */

/** Open a handshake message: the type, and a length written by finish_message. */
static void begin_message(GTLS_Buf * b, unsigned type) {
  gtls_buf_u8(b, type);
  gtls_buf_u24(b, 0);
}

static GTLS_Result finish_message(GTLS_Buf * b, size_t start) {
  if (b->err == GTLS_OK) {
    size_t body = b->len - start - 4u;

    if (body > 0xffffffu) {
      b->err = GTLS_ERR_LIMIT;
    } else {
      b->data[start + 1u] = (unsigned char)(body >> 16);
      b->data[start + 2u] = (unsigned char)(body >> 8);
      b->data[start + 3u] = (unsigned char)body;
    }
  }
  return b->err;
}

GTLS_Result gtls_msg_build_server_hello(const GTLS_ServerHelloParams * p,
    GTLS_Buf * out) {
  size_t start;
  size_t ext_at;
  size_t at;

  if (p == NULL || out == NULL || (p->session_id == NULL && p->session_id_len != 0) ||
      p->session_id_len > 32u || (p->cookie == NULL && p->cookie_len != 0) ||
      (!p->is_hrr && (p->key_exchange == NULL || p->key_exchange_len == 0))) {
    return GTLS_ERR_INVALID;
  }
  start = out->len;
  begin_message(out, GTLS_HS_SERVER_HELLO);
  gtls_buf_u16(out, 0x0303);
  if (p->is_hrr) {
    (void)gtls_buf_append(out, hrr_random, sizeof hrr_random);
  } else {
    (void)gtls_buf_append(out, p->random, 32);
  }
  gtls_buf_u8(out, (unsigned)p->session_id_len);
  (void)gtls_buf_append(out, p->session_id, p->session_id_len);
  gtls_buf_u16(out, p->suite);
  gtls_buf_u8(out, 0);
  ext_at = gtls_buf_begin(out, 2);
  if (p->group != 0) {
    ext_begin(out, GTLS_EXT_KEY_SHARE, &at);
    gtls_buf_u16(out, p->group);
    if (!p->is_hrr) {
      gtls_buf_u16(out, (unsigned)p->key_exchange_len);
      (void)gtls_buf_append(out, p->key_exchange, p->key_exchange_len);
    }
    gtls_buf_end(out, at, 2);
  }
  if (p->cookie_len != 0) {
    ext_begin(out, GTLS_EXT_COOKIE, &at);
    gtls_buf_u16(out, (unsigned)p->cookie_len);
    (void)gtls_buf_append(out, p->cookie, p->cookie_len);
    gtls_buf_end(out, at, 2);
  }
  ext_begin(out, GTLS_EXT_SUPPORTED_VERSIONS, &at);
  gtls_buf_u16(out, 0x0304);
  gtls_buf_end(out, at, 2);
  gtls_buf_end(out, ext_at, 2);
  return finish_message(out, start);
}

GTLS_Result gtls_msg_build_encrypted_extensions(const GTLS_EeParams * p,
    GTLS_Buf * out) {
  size_t start;
  size_t ext_at;
  size_t at;
  size_t list;

  if (p == NULL || out == NULL || (p->prefix == NULL && p->prefix_len != 0) ||
      (p->alpn == NULL && p->alpn_len != 0) || p->alpn_len > 255u) {
    return GTLS_ERR_INVALID;
  }
  start = out->len;
  begin_message(out, GTLS_HS_ENCRYPTED_EXTENSIONS);
  ext_at = gtls_buf_begin(out, 2);
  (void)gtls_buf_append(out, p->prefix, p->prefix_len);
  if (p->ack_server_name) {
    ext_begin(out, GTLS_EXT_SERVER_NAME, &at);
    gtls_buf_end(out, at, 2);
  }
  if (p->alpn_len != 0) {
    ext_begin(out, GTLS_EXT_ALPN, &at);
    list = gtls_buf_begin(out, 2);
    gtls_buf_u8(out, (unsigned)p->alpn_len);
    (void)gtls_buf_append(out, p->alpn, p->alpn_len);
    gtls_buf_end(out, list, 2);
    gtls_buf_end(out, at, 2);
  }
  gtls_buf_end(out, ext_at, 2);
  return finish_message(out, start);
}

GTLS_Result gtls_msg_build_certificate(const unsigned char * const * der,
    const size_t * der_len, size_t count, GTLS_Buf * out) {
  size_t start;
  size_t list;
  size_t i;

  if (der == NULL || der_len == NULL || out == NULL || count == 0) {
    return GTLS_ERR_INVALID;
  }
  start = out->len;
  begin_message(out, GTLS_HS_CERTIFICATE);
  gtls_buf_u8(out, 0); /* certificate_request_context: empty for a server */
  list = gtls_buf_begin(out, 3);
  for (i = 0; i < count; i++) {
    if (der[i] == NULL || der_len[i] == 0 || der_len[i] > 0xffffffu) {
      return GTLS_ERR_INVALID;
    }
    gtls_buf_u24(out, (unsigned)der_len[i]);
    (void)gtls_buf_append(out, der[i], der_len[i]);
    gtls_buf_u16(out, 0); /* no entry extensions */
  }
  gtls_buf_end(out, list, 3);
  return finish_message(out, start);
}

GTLS_Result gtls_msg_build_certificate_verify(unsigned scheme,
    const void * signature, size_t signature_len, GTLS_Buf * out) {
  size_t start;

  if (signature == NULL || signature_len == 0 || signature_len > 0xffffu ||
      out == NULL) {
    return GTLS_ERR_INVALID;
  }
  start = out->len;
  begin_message(out, GTLS_HS_CERTIFICATE_VERIFY);
  gtls_buf_u16(out, scheme);
  gtls_buf_u16(out, (unsigned)signature_len);
  (void)gtls_buf_append(out, signature, signature_len);
  return finish_message(out, start);
}

GTLS_Result gtls_msg_build_finished(const void * verify_data, size_t len,
    GTLS_Buf * out) {
  size_t start;

  if (verify_data == NULL || len == 0 || len > GTLS_HASH_MAX || out == NULL) {
    return GTLS_ERR_INVALID;
  }
  start = out->len;
  begin_message(out, GTLS_HS_FINISHED);
  (void)gtls_buf_append(out, verify_data, len);
  return finish_message(out, start);
}

GTLS_Result gtls_msg_build_key_update(unsigned request, GTLS_Buf * out) {
  size_t start;

  if (request > 1u || out == NULL) {
    return GTLS_ERR_INVALID;
  }
  start = out->len;
  begin_message(out, GTLS_HS_KEY_UPDATE);
  gtls_buf_u8(out, request);
  return finish_message(out, start);
}

GTLS_Result gtls_msg_parse_key_update(const void * body, size_t len,
    unsigned * request) {
  GTLS_Reader r;
  unsigned v = 0;
  GTLS_Result result;

  gtls_reader_init(&r, body, len);
  result = gtls_reader_u8(&r, &v);
  if (result == GTLS_OK) {
    result = gtls_reader_end(&r);
  }
  if (result != GTLS_OK) {
    return result;
  }
  if (v > 1u) {
    return GTLS_ERR_PROTOCOL;
  }
  *request = v;
  return GTLS_OK;
}

GTLS_Result gtls_msg_parse_finished(const void * body, size_t len,
    size_t hash_len, const unsigned char ** verify_data) {
  if (hash_len == 0 || len != hash_len || body == NULL) {
    return GTLS_ERR_CORRUPT;
  }
  *verify_data = body;
  return GTLS_OK;
}
