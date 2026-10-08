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
 * @file session.c
 *
 * The session a client holds for a ticket: its allocation, wiping, copying
 * and serialisation, and the connection's calls that hand sessions out and
 * take one in.
 */

#include <ghoti.io/tls/macros.h>

#include <ghoti.io/tls/conn.h>
#include <ghoti.io/tls/session.h>

#include "../core/core_internal.h"
#include "../client/client_internal.h"

#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/security/secret.h>
#include <ghoti.io/security/sha256.h>

#include <string.h>

#define SESSION_VERSION 1u

GTLS_Session * gtls_session_alloc(const GTLS_Allocator * allocator, size_t ticket_len) {
  GTLS_Session * s = gcu_allocator_calloc(allocator, 1, sizeof *s);

  if (s == NULL) {
    return NULL;
  }
  s->allocator = allocator;
  s->ticket = gcu_allocator_malloc(allocator, ticket_len == 0 ? 1u : ticket_len);
  if (s->ticket == NULL) {
    gcu_allocator_free(allocator, s);
    return NULL;
  }
  s->ticket_len = ticket_len;
  return s;
}

void gtls_session_free(GTLS_Session * s) {
  const GTLS_Allocator * allocator;
  unsigned char * ticket;

  if (s == NULL) {
    return;
  }
  allocator = s->allocator;
  ticket = s->ticket;
  if (ticket != NULL) {
    (void)gsec_wipe(ticket, s->ticket_len);
  }
  (void)gsec_wipe(s, sizeof *s);
  gcu_allocator_free(allocator, ticket);
  gcu_allocator_free(allocator, s);
}

GTLS_Session * gtls_session_copy(const GTLS_Allocator * allocator, const GTLS_Session * from) {
  GTLS_Session * s = gtls_session_alloc(allocator, from->ticket_len);

  if (s == NULL) {
    return NULL;
  }
  s->suite = from->suite;
  s->lifetime = from->lifetime;
  s->age_add = from->age_add;
  s->max_early_data = from->max_early_data;
  s->received = from->received;
  memcpy(s->host, from->host, from->host_len);
  s->host_len = from->host_len;
  memcpy(s->alpn, from->alpn, from->alpn_len);
  s->alpn_len = from->alpn_len;
  memcpy(s->psk, from->psk, from->psk_len);
  s->psk_len = from->psk_len;
  memcpy(s->ticket, from->ticket, from->ticket_len);
  return s;
}

GTLS_Result gtls_session_info(const GTLS_Session * s, GTLS_SessionInfo * info) {
  if (s == NULL || info == NULL) {
    return GTLS_ERR_INVALID;
  }
  info->suite = (GTLS_Suite)s->suite;
  info->host = s->host;
  info->host_len = s->host_len;
  info->alpn = s->alpn_len != 0 ? s->alpn : NULL;
  info->alpn_len = s->alpn_len;
  info->received = s->received;
  info->lifetime = s->lifetime;
  info->expires = s->received + (int64_t)s->lifetime;
  info->max_early_data = s->max_early_data;
  return GTLS_OK;
}

/* ------------------------------------------------------------ serialising */

/* version 1: u8 version, u16 suite, u32 lifetime, u32 age_add, u32 max_early_data,
 * i64 received, u8 host_len, host, u8 alpn_len, alpn, u8 psk_len, psk,
 * u16 ticket_len, ticket, then the SHA-256 of everything before it. */
#define FIXED_PREFIX (1u + 2u + 4u + 4u + 4u + 8u)

static size_t blob_len(const GTLS_Session * s) {
  return FIXED_PREFIX + 1u + s->host_len + 1u + s->alpn_len + 1u + s->psk_len +
      2u + s->ticket_len + GSEC_SHA256_DIGEST_LEN;
}

static unsigned char * w32(unsigned char * p, uint32_t v) {
  p[0] = (unsigned char)(v >> 24);
  p[1] = (unsigned char)(v >> 16);
  p[2] = (unsigned char)(v >> 8);
  p[3] = (unsigned char)v;
  return p + 4;
}

GTLS_Result gtls_session_serialize(const GTLS_Session * s, void * out, size_t cap,
    size_t * len) {
  unsigned char * p = out;
  unsigned char * q;
  uint64_t r;
  unsigned i;
  size_t total;

  if (s == NULL || len == NULL || (out == NULL && cap != 0)) {
    return GTLS_ERR_INVALID;
  }
  total = blob_len(s);
  *len = total;
  if (out == NULL || cap < total) {
    return GTLS_ERR_LIMIT;
  }
  q = p;
  *q++ = (unsigned char)SESSION_VERSION;
  *q++ = (unsigned char)(s->suite >> 8);
  *q++ = (unsigned char)s->suite;
  q = w32(q, s->lifetime);
  q = w32(q, s->age_add);
  q = w32(q, s->max_early_data);
  r = (uint64_t)s->received;
  for (i = 0; i < 8u; i++) {
    *q++ = (unsigned char)(r >> (56u - 8u * i));
  }
  *q++ = (unsigned char)s->host_len;
  memcpy(q, s->host, s->host_len);
  q += s->host_len;
  *q++ = (unsigned char)s->alpn_len;
  memcpy(q, s->alpn, s->alpn_len);
  q += s->alpn_len;
  *q++ = (unsigned char)s->psk_len;
  memcpy(q, s->psk, s->psk_len);
  q += s->psk_len;
  *q++ = (unsigned char)(s->ticket_len >> 8);
  *q++ = (unsigned char)s->ticket_len;
  memcpy(q, s->ticket, s->ticket_len);
  q += s->ticket_len;
  if (gsec_sha256(p, (size_t)(q - p), q) != GSEC_OK) {
    (void)gsec_wipe(p, total);
    return GTLS_ERR_INTERNAL;
  }
  return GTLS_OK;
}

static uint32_t r32(const unsigned char * p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

GTLS_Result gtls_session_parse(const GTLS_Allocator * allocator,
    const GTLS_Limits * limits, const void * data, size_t len, GTLS_Session ** out) {
  const unsigned char * p = data;
  GTLS_Limits l;
  GTLS_Session * s;
  GTLS_Hash hash;
  unsigned char digest[GSEC_SHA256_DIGEST_LEN];
  size_t host_len;
  size_t alpn_len;
  size_t psk_len;
  size_t ticket_len;
  size_t at;
  uint64_t r = 0;
  unsigned i;

  if (data == NULL || out == NULL) {
    return GTLS_ERR_INVALID;
  }
  if (allocator == NULL) {
    allocator = gtls_allocator_default();
  }
  gtls_limits_resolve(limits, &l);
  /* Even the largest blob this limit allows is bounded before it is read. */
  if (len > FIXED_PREFIX + 1u + 255u + 1u + 255u + 1u + GTLS_HASH_MAX + 2u +
          (size_t)l.max_ticket_bytes + GSEC_SHA256_DIGEST_LEN) {
    return GTLS_ERR_LIMIT;
  }
  if (len < FIXED_PREFIX + 1u + 1u + 1u + 2u + GSEC_SHA256_DIGEST_LEN) {
    return GTLS_ERR_CORRUPT;
  }
  if (p[0] != SESSION_VERSION) {
    return GTLS_ERR_UNSUPPORTED;
  }
  at = FIXED_PREFIX;
  host_len = p[at++];
  if (len - at < host_len + 1u) {
    return GTLS_ERR_CORRUPT;
  }
  at += host_len;
  alpn_len = p[at++];
  if (len - at < alpn_len + 1u) {
    return GTLS_ERR_CORRUPT;
  }
  at += alpn_len;
  psk_len = p[at++];
  if (len - at < psk_len + 2u) {
    return GTLS_ERR_CORRUPT;
  }
  at += psk_len;
  ticket_len = ((size_t)p[at] << 8) | p[at + 1u];
  at += 2;
  if (ticket_len > l.max_ticket_bytes) {
    return GTLS_ERR_LIMIT;
  }
  if (len - at != ticket_len + GSEC_SHA256_DIGEST_LEN) {
    return GTLS_ERR_CORRUPT;
  }
  if (gsec_sha256(p, at + ticket_len, digest) != GSEC_OK) {
    return GTLS_ERR_INTERNAL;
  }
  if (gsec_equal(digest, p + at + ticket_len, GSEC_SHA256_DIGEST_LEN) != GSEC_OK) {
    return GTLS_ERR_CORRUPT;
  }
  hash = gtls_suite_hash(((uint32_t)p[1] << 8) | p[2]);
  if (hash == GTLS_HASH_NONE || psk_len != gtls_hash_len(hash) || host_len == 0 ||
      ticket_len == 0 || r32(p + 3) > GTLS_TICKET_LIFETIME_MAX) {
    return GTLS_ERR_CORRUPT;
  }
  s = gtls_session_alloc(allocator, ticket_len);
  if (s == NULL) {
    return GTLS_ERR_OOM;
  }
  s->suite = ((uint32_t)p[1] << 8) | p[2];
  s->lifetime = r32(p + 3);
  s->age_add = r32(p + 7);
  s->max_early_data = r32(p + 11);
  for (i = 0; i < 8u; i++) {
    r = (r << 8) | p[15u + i];
  }
  s->received = (int64_t)r;
  at = FIXED_PREFIX + 1u;
  memcpy(s->host, p + at, host_len);
  s->host_len = host_len;
  at += host_len + 1u;
  memcpy(s->alpn, p + at, alpn_len);
  s->alpn_len = alpn_len;
  at += alpn_len + 1u;
  memcpy(s->psk, p + at, psk_len);
  s->psk_len = psk_len;
  at += psk_len + 2u;
  memcpy(s->ticket, p + at, ticket_len);
  *out = s;
  return GTLS_OK;
}

/* ------------------------------------------------- the connection's calls */

int gtls_conn_resumed(const GTLS_Conn * c) {
  return c != NULL && c->resumed;
}

size_t gtls_conn_session_count(const GTLS_Conn * c) {
  return c == NULL || c->state == GTLS_STATE_FAILED ? 0u : c->session_count;
}

GTLS_Result gtls_conn_session(const GTLS_Conn * c, size_t index, GTLS_Session ** out) {
  GTLS_Session * copy;

  if (c == NULL || out == NULL) {
    return GTLS_ERR_INVALID;
  }
  if (c->state == GTLS_STATE_FAILED) {
    return GTLS_ERR_FAILED;
  }
  if (c->role != GTLS_ROLE_CLIENT || index >= c->session_count) {
    return GTLS_ERR_INVALID;
  }
  copy = gtls_session_copy(c->allocator, c->sessions[index]);
  if (copy == NULL) {
    return GTLS_ERR_OOM;
  }
  *out = copy;
  return GTLS_OK;
}

static int names_match(const unsigned char * a, const unsigned char * b, size_t n) {
  size_t i;

  for (i = 0; i < n; i++) {
    unsigned char x = a[i];
    unsigned char y = b[i];

    if (x >= 'A' && x <= 'Z') {
      x = (unsigned char)(x + ('a' - 'A'));
    }
    if (y >= 'A' && y <= 'Z') {
      y = (unsigned char)(y + ('a' - 'A'));
    }
    if (x != y) {
      return 0;
    }
  }
  return 1;
}

GTLS_Result gtls_conn_set_session(GTLS_Conn * c, const GTLS_Session * session,
    int64_t unix_time) {
  size_t i;
  int offered = 0;

  if (c == NULL || session == NULL) {
    return GTLS_ERR_INVALID;
  }
  if (c->state == GTLS_STATE_FAILED) {
    return GTLS_ERR_FAILED;
  }
  if (c->role != GTLS_ROLE_CLIENT || c->state != GTLS_STATE_NEW || c->offer != NULL) {
    return GTLS_ERR_INVALID;
  }
  /* A session is for the name it was issued for and the hash of its suite;
   * the suite itself must be one this connection offers, or no server could
   * pick it. A name differing in case is the same name. */
  if (session->host_len != c->host_len ||
      !names_match(session->host, c->host, c->host_len)) {
    return GTLS_ERR_INVALID;
  }
  for (i = 0; i < c->context->suite_count; i++) {
    if ((uint32_t)c->context->suites[i] == session->suite) {
      offered = 1;
    }
  }
  if (!offered) {
    return GTLS_ERR_INVALID;
  }
  /* Not yet received, or run out: no use to offer. The difference is unsigned,
   * so a time before the arrival comes out enormous and one comparison refuses
   * both. */
  if ((uint64_t)unix_time - (uint64_t)session->received >= session->lifetime) {
    return GTLS_ERR_INVALID;
  }
  c->offer = gtls_session_copy(c->allocator, session);
  if (c->offer == NULL) {
    return GTLS_ERR_OOM;
  }
  c->offer_time = unix_time;
  return GTLS_OK;
}
