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
 * @file ticket.c
 *
 * Sealing and opening the ticket a server hands out. RFC 8446 section 4.6.1
 * leaves the ticket's contents to the server; RFC 5077 section 4 suggests the
 * shape this follows (a key name, an IV, the encrypted state, a MAC, here an
 * AEAD tag).
 */

#include <ghoti.io/tls/macros.h>

#include "../core/core_internal.h"
#include "session_internal.h"

#include <ghoti.io/security/aes_gcm.h>
#include <ghoti.io/security/secret.h>

#include <string.h>

/** The additional data begins with this label, so a ticket cannot be passed for another use of the key. */
static const char ticket_label[] = "ghoti.io tls ticket v1";

#define AAD_MAX (sizeof ticket_label - 1u + GTLS_TICKET_KEY_NAME_LEN + GTLS_TICKET_NONCE_LEN)

static size_t build_aad(unsigned char * aad, const unsigned char * name,
    const unsigned char * nonce) {
  size_t n = sizeof ticket_label - 1u;

  memcpy(aad, ticket_label, n);
  memcpy(aad + n, name, GTLS_TICKET_KEY_NAME_LEN);
  n += GTLS_TICKET_KEY_NAME_LEN;
  memcpy(aad + n, nonce, GTLS_TICKET_NONCE_LEN);
  return n + GTLS_TICKET_NONCE_LEN;
}

const GTLS_TicketKey * gtls_ticket_sealing_key(const GTLS_TicketKey * keys,
    size_t count, int64_t now) {
  const GTLS_TicketKey * best = NULL;
  size_t i;

  for (i = 0; keys != NULL && i < count; i++) {
    if (keys[i].not_before <= now && now < keys[i].not_after &&
        (best == NULL || keys[i].not_before > best->not_before)) {
      best = &keys[i];
    }
  }
  return best;
}

static void put64(unsigned char * p, int64_t v) {
  uint64_t u = (uint64_t)v;
  unsigned i;

  for (i = 0; i < 8u; i++) {
    p[i] = (unsigned char)(u >> (56u - 8u * i));
  }
}

static int64_t get64(const unsigned char * p) {
  uint64_t u = 0;
  unsigned i;

  for (i = 0; i < 8u; i++) {
    u = (u << 8) | p[i];
  }
  return (int64_t)u;
}

static void put32(unsigned char * p, uint32_t v) {
  p[0] = (unsigned char)(v >> 24);
  p[1] = (unsigned char)(v >> 16);
  p[2] = (unsigned char)(v >> 8);
  p[3] = (unsigned char)v;
}

static uint32_t get32(const unsigned char * p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

GTLS_Result gtls_ticket_seal(const GTLS_TicketKey * keys, size_t count,
    int64_t now, const unsigned char * nonce, const GTLS_TicketPlain * p,
    unsigned char * out, size_t cap, size_t * out_len) {
  const GTLS_TicketKey * key = gtls_ticket_sealing_key(keys, count, now);
  unsigned char plain[GTLS_TICKET_PLAIN_MAX];
  unsigned char aad[AAD_MAX];
  size_t n = 0;
  size_t total;
  size_t aad_len;
  GTLS_Result result;

  if (key == NULL || nonce == NULL || p == NULL || out == NULL || out_len == NULL ||
      gtls_suite_hash(p->suite) == GTLS_HASH_NONE ||
      p->psk_len != gtls_hash_len(gtls_suite_hash(p->suite)) ||
      p->alpn_len > sizeof p->alpn || p->sni_len > sizeof p->sni ||
      p->lifetime > GTLS_TICKET_LIFETIME_MAX) {
    return GTLS_ERR_INVALID;
  }
  plain[n++] = (unsigned char)GTLS_TICKET_STATE_VERSION;
  plain[n++] = (unsigned char)(p->suite >> 8);
  plain[n++] = (unsigned char)p->suite;
  plain[n++] = (unsigned char)p->psk_len;
  memcpy(plain + n, p->psk, p->psk_len);
  n += p->psk_len;
  put32(plain + n, p->age_add);
  n += 4;
  put64(plain + n, p->issued);
  n += 8;
  put32(plain + n, p->lifetime);
  n += 4;
  plain[n++] = (unsigned char)p->alpn_len;
  memcpy(plain + n, p->alpn, p->alpn_len);
  n += p->alpn_len;
  plain[n++] = (unsigned char)p->sni_len;
  memcpy(plain + n, p->sni, p->sni_len);
  n += p->sni_len;

  total = GTLS_TICKET_KEY_NAME_LEN + GTLS_TICKET_NONCE_LEN + n + GTLS_TICKET_TAG_LEN;
  if (cap < total) {
    (void)gsec_wipe(plain, sizeof plain);
    return GTLS_ERR_LIMIT;
  }
  memcpy(out, key->name, GTLS_TICKET_KEY_NAME_LEN);
  memcpy(out + GTLS_TICKET_KEY_NAME_LEN, nonce, GTLS_TICKET_NONCE_LEN);
  aad_len = build_aad(aad, key->name, nonce);
  result = gtls_from_gsec(gsec_aes_gcm_encrypt(key->key, GTLS_TICKET_KEY_LEN, nonce,
      GTLS_TICKET_NONCE_LEN, aad, aad_len, plain, n,
      out + GTLS_TICKET_KEY_NAME_LEN + GTLS_TICKET_NONCE_LEN,
      out + GTLS_TICKET_KEY_NAME_LEN + GTLS_TICKET_NONCE_LEN + n, GTLS_TICKET_TAG_LEN));
  (void)gsec_wipe(plain, sizeof plain);
  if (result != GTLS_OK) {
    (void)gsec_wipe(out, total);
    return result;
  }
  *out_len = total;
  return GTLS_OK;
}

GTLS_Result gtls_ticket_open(const GTLS_TicketKey * keys, size_t count,
    int64_t now, const unsigned char * ticket, size_t len, GTLS_TicketPlain * out) {
  const GTLS_TicketKey * key = NULL;
  unsigned char plain[GTLS_TICKET_PLAIN_MAX];
  unsigned char aad[AAD_MAX];
  GTLS_TicketPlain t;
  size_t i;
  size_t n;
  size_t at = 0;
  size_t aad_len;
  GSEC_Result opened;
  GTLS_Result result = GTLS_ERR_MISMATCH;

  if (ticket == NULL || out == NULL || len < GTLS_TICKET_MIN || len > GTLS_TICKET_MAX) {
    return GTLS_ERR_MISMATCH;
  }
  for (i = 0; keys != NULL && i < count; i++) {
    if (now < keys[i].not_after &&
        gsec_equal(keys[i].name, ticket, GTLS_TICKET_KEY_NAME_LEN) == GSEC_OK) {
      key = &keys[i];
      break;
    }
  }
  if (key == NULL) {
    return GTLS_ERR_MISMATCH;
  }
  n = len - GTLS_TICKET_KEY_NAME_LEN - GTLS_TICKET_NONCE_LEN - GTLS_TICKET_TAG_LEN;
  /* The name the ticket carries is authenticated, whichever key was found by it. */
  aad_len = build_aad(aad, ticket, ticket + GTLS_TICKET_KEY_NAME_LEN);
  opened = gsec_aes_gcm_decrypt(key->key, GTLS_TICKET_KEY_LEN,
      ticket + GTLS_TICKET_KEY_NAME_LEN, GTLS_TICKET_NONCE_LEN, aad, aad_len,
      ticket + GTLS_TICKET_KEY_NAME_LEN + GTLS_TICKET_NONCE_LEN, n, plain,
      ticket + GTLS_TICKET_KEY_NAME_LEN + GTLS_TICKET_NONCE_LEN + n, GTLS_TICKET_TAG_LEN);
  if (opened != GSEC_OK) {
    (void)gsec_wipe(plain, sizeof plain);
    return GTLS_ERR_MISMATCH;
  }
  /* Decode strictly: the sealer wrote it, but a key shared with another
   * version of this code, or another program, would still have to be read
   * with the bounds checked. */
  memset(&t, 0, sizeof t);
  if (n < 1u + 2u + 1u || plain[at++] != GTLS_TICKET_STATE_VERSION) {
    goto done;
  }
  t.suite = ((uint32_t)plain[at] << 8) | plain[at + 1u];
  at += 2;
  t.psk_len = plain[at++];
  if (gtls_suite_hash(t.suite) == GTLS_HASH_NONE ||
      t.psk_len != gtls_hash_len(gtls_suite_hash(t.suite)) ||
      n - at < t.psk_len + 4u + 8u + 4u + 1u) {
    goto done;
  }
  memcpy(t.psk, plain + at, t.psk_len);
  at += t.psk_len;
  t.age_add = get32(plain + at);
  at += 4;
  t.issued = get64(plain + at);
  at += 8;
  t.lifetime = get32(plain + at);
  at += 4;
  t.alpn_len = plain[at++];
  if (t.lifetime > GTLS_TICKET_LIFETIME_MAX || n - at < t.alpn_len + 1u) {
    goto done;
  }
  memcpy(t.alpn, plain + at, t.alpn_len);
  at += t.alpn_len;
  t.sni_len = plain[at++];
  if (n - at != t.sni_len) {
    goto done;
  }
  memcpy(t.sni, plain + at, t.sni_len);
  *out = t;
  result = GTLS_OK;
done:
  (void)gsec_wipe(plain, sizeof plain);
  (void)gsec_wipe(&t, sizeof t);
  return result;
}

int gtls_ticket_fresh(const GTLS_TicketPlain * p, int64_t now,
    uint32_t obfuscated_age, uint32_t window_ms) {
  uint64_t elapsed_s;
  int64_t server_ms;
  int64_t client_ms;
  int64_t diff;

  if (p->lifetime > GTLS_TICKET_LIFETIME_MAX) {
    return 0;
  }
  if (now >= p->issued) {
    /* Unsigned subtraction: exact when now >= issued, whatever the signs. */
    elapsed_s = (uint64_t)now - (uint64_t)p->issued;
    if (elapsed_s >= p->lifetime) {
      return 0; /* expired (the first second past the lifetime is already too late) */
    }
    server_ms = (int64_t)(elapsed_s * 1000u);
  } else {
    /* Issued in the future: a clock that moved back, or a forged ticket. Only
     * the window's worth of it is forgiven. */
    elapsed_s = (uint64_t)p->issued - (uint64_t)now;
    if (elapsed_s > GTLS_TICKET_AGE_WINDOW_MAX) {
      return 0;
    }
    server_ms = -(int64_t)(elapsed_s * 1000u);
  }
  /* The client's age is the obfuscated one minus the ticket's age_add,
   * modulo 2^32 (RFC 8446 section 4.2.11.1). */
  client_ms = (int64_t)(uint32_t)(obfuscated_age - p->age_add);
  diff = client_ms - server_ms;
  if (diff < 0) {
    diff = -diff;
  }
  return diff <= (int64_t)window_ms;
}
