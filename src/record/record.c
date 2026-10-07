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
 * @file record.c
 *
 * Record protection. RFC 8446 section 5: the TLSInnerPlaintext, the AEAD
 * with a nonce built from the sequence number, and the padding rules.
 */

#include <ghoti.io/tls/macros.h>

#include "record_internal.h"

#include "../core/core_internal.h"

#include <ghoti.io/security/aes_gcm.h>
#include <ghoti.io/security/chacha20_poly1305.h>
#include <ghoti.io/security/secret.h>

#include <string.h>

void gtls_record_keys_wipe(GTLS_RecordKeys * k) {
  if (k != NULL) {
    (void)gsec_wipe(k, sizeof *k);
  }
}

static uint64_t resolve_limit(uint64_t limit) {
  return limit == 0 || limit > UINT64_MAX - 1u ? UINT64_MAX - 1u : limit;
}

GTLS_Result gtls_record_keys_from_raw(GTLS_RecordKeys * k, uint32_t suite,
    const void * key, const void * iv, uint64_t limit) {
  size_t key_len = gtls_suite_key_len(suite);

  if (k == NULL || key == NULL || iv == NULL || key_len == 0) {
    return GTLS_ERR_INVALID;
  }
  memset(k, 0, sizeof *k);
  k->suite = suite;
  memcpy(k->key, key, key_len);
  memcpy(k->iv, iv, GTLS_IV_LEN);
  k->seq = 0;
  k->limit = resolve_limit(limit);
  k->active = 1;
  return GTLS_OK;
}

GTLS_Result gtls_record_keys_from_secret(GTLS_RecordKeys * k, uint32_t suite,
    const void * traffic_secret, uint64_t limit) {
  unsigned char key[GTLS_KEY_MAX];
  unsigned char iv[GTLS_IV_LEN];
  GTLS_Result result;

  if (k == NULL || traffic_secret == NULL) {
    return GTLS_ERR_INVALID;
  }
  result = gtls_traffic_keys(suite, traffic_secret, key, iv);
  if (result == GTLS_OK) {
    result = gtls_record_keys_from_raw(k, suite, key, iv, limit);
  }
  (void)gsec_wipe(key, sizeof key);
  (void)gsec_wipe(iv, sizeof iv);
  return result;
}

GTLS_Result gtls_record_next_secret(uint32_t suite, const void * secret,
    void * out) {
  GTLS_Hash hash = gtls_suite_hash(suite);
  unsigned char next[GTLS_HASH_MAX];
  GTLS_Result result;

  if (hash == GTLS_HASH_NONE || secret == NULL || out == NULL) {
    return GTLS_ERR_INVALID;
  }
  result = gtls_hkdf_expand_label(hash, secret, gtls_hash_len(hash),
      "traffic upd", NULL, 0, next, gtls_hash_len(hash));
  if (result == GTLS_OK) {
    memcpy(out, next, gtls_hash_len(hash));
  }
  (void)gsec_wipe(next, sizeof next);
  return result;
}

/**
 * The per-record nonce (RFC 8446 section 5.3): the 64-bit sequence number,
 * big-endian, left-padded with zeros to the IV's length, xor the static IV.
 */
static void build_nonce(const GTLS_RecordKeys * k, unsigned char * nonce) {
  unsigned i;

  memcpy(nonce, k->iv, GTLS_IV_LEN);
  for (i = 0; i < 8u; i++) {
    nonce[GTLS_IV_LEN - 1u - i] ^= (unsigned char)(k->seq >> (8u * i));
  }
}

static GTLS_Result aead_seal(const GTLS_RecordKeys * k, const unsigned char * nonce,
    const unsigned char * aad, const unsigned char * in, size_t n,
    unsigned char * ct, unsigned char * tag) {
  if (k->suite == GTLS_SUITE_CHACHA20_POLY1305_SHA256) {
    return gtls_from_gsec(gsec_chacha20_poly1305_encrypt(k->key, nonce, aad,
        GTLS_RECORD_HEADER, in, n, ct, tag));
  }
  return gtls_from_gsec(gsec_aes_gcm_encrypt(k->key, gtls_suite_key_len(k->suite),
      nonce, GTLS_IV_LEN, aad, GTLS_RECORD_HEADER, in, n, ct, tag,
      GTLS_RECORD_TAG));
}

static GTLS_Result aead_open(const GTLS_RecordKeys * k, const unsigned char * nonce,
    const unsigned char * aad, const unsigned char * ct, size_t n,
    unsigned char * pt, const unsigned char * tag) {
  if (k->suite == GTLS_SUITE_CHACHA20_POLY1305_SHA256) {
    return gtls_from_gsec(gsec_chacha20_poly1305_decrypt(k->key, nonce, aad,
        GTLS_RECORD_HEADER, ct, n, pt, tag));
  }
  return gtls_from_gsec(gsec_aes_gcm_decrypt(k->key, gtls_suite_key_len(k->suite),
      nonce, GTLS_IV_LEN, aad, GTLS_RECORD_HEADER, ct, n, pt, tag,
      GTLS_RECORD_TAG));
}

GTLS_Result gtls_record_plain(unsigned type, unsigned version, const void * pt,
    size_t pt_len, GTLS_Buf * out) {
  size_t mark;

  if (out == NULL || (pt == NULL && pt_len != 0)) {
    return GTLS_ERR_INVALID;
  }
  if (pt_len > GTLS_RECORD_PLAIN_MAX) {
    return GTLS_ERR_LIMIT;
  }
  if (out->err != GTLS_OK) {
    return out->err;
  }
  if (GTLS_RECORD_HEADER + pt_len > out->max - out->len) {
    return GTLS_ERR_LIMIT;
  }
  mark = out->len;
  gtls_buf_u8(out, type);
  gtls_buf_u16(out, version);
  gtls_buf_u16(out, (unsigned)pt_len);
  (void)gtls_buf_append(out, pt, pt_len);
  if (out->err != GTLS_OK) {
    GTLS_Result err = out->err;

    out->len = mark;
    out->err = GTLS_OK;
    return err;
  }
  return GTLS_OK;
}

GTLS_Result gtls_record_seal(GTLS_RecordKeys * k, unsigned inner_type,
    const void * pt, size_t pt_len, size_t padding, GTLS_Buf * out) {
  /* The inner plaintext, then the tag; the header is built beside them. */
  unsigned char inner[GTLS_RECORD_PLAIN_MAX + 256u];
  unsigned char nonce[GTLS_IV_LEN];
  unsigned char header[GTLS_RECORD_HEADER];
  unsigned char tag[GTLS_RECORD_TAG];
  size_t inner_len;
  size_t cipher_len;
  size_t mark;
  GTLS_Result result;

  if (k == NULL || out == NULL || !k->active || (pt == NULL && pt_len != 0) ||
      inner_type == 0 || inner_type > 255u) {
    return GTLS_ERR_INVALID;
  }
  if (pt_len > GTLS_RECORD_PLAIN_MAX ||
      pt_len + 1u + padding > GTLS_RECORD_PLAIN_MAX + 256u - GTLS_RECORD_TAG) {
    return GTLS_ERR_LIMIT;
  }
  if (k->seq >= k->limit) {
    return GTLS_ERR_LIMIT;
  }
  if (out->err != GTLS_OK) {
    return out->err;
  }
  inner_len = pt_len + 1u + padding;
  cipher_len = inner_len + GTLS_RECORD_TAG;
  if (GTLS_RECORD_HEADER + cipher_len > out->max - out->len) {
    return GTLS_ERR_LIMIT;
  }
  if (pt_len != 0) {
    memcpy(inner, pt, pt_len);
  }
  inner[pt_len] = (unsigned char)inner_type;
  memset(inner + pt_len + 1u, 0, padding);
  header[0] = GTLS_CT_APPLICATION_DATA;
  header[1] = 0x03;
  header[2] = 0x03;
  header[3] = (unsigned char)(cipher_len >> 8);
  header[4] = (unsigned char)cipher_len;
  build_nonce(k, nonce);
  result = aead_seal(k, nonce, header, inner, inner_len, inner, tag);
  if (result == GTLS_OK) {
    mark = out->len;
    (void)gtls_buf_append(out, header, sizeof header);
    (void)gtls_buf_append(out, inner, inner_len);
    (void)gtls_buf_append(out, tag, sizeof tag);
    if (out->err != GTLS_OK) {
      result = out->err;
      out->len = mark;
      out->err = GTLS_OK;
    } else {
      k->seq++;
    }
  }
  (void)gsec_wipe(inner, inner_len);
  (void)gsec_wipe(nonce, sizeof nonce);
  return result;
}

GTLS_Result gtls_record_open(GTLS_RecordKeys * k, const unsigned char * header,
    const unsigned char * ct, size_t ct_len, size_t max_padding,
    unsigned char * pt, size_t * pt_len, unsigned * inner_type) {
  unsigned char nonce[GTLS_IV_LEN];
  size_t body;
  size_t i;
  size_t pad;
  GTLS_Result result;

  if (k == NULL || header == NULL || ct == NULL || pt == NULL || pt_len == NULL ||
      inner_type == NULL || !k->active) {
    return GTLS_ERR_INVALID;
  }
  if (ct_len > GTLS_RECORD_CIPHER_MAX) {
    return GTLS_ERR_LIMIT;
  }
  if (ct_len < GTLS_RECORD_TAG) {
    /* No room for the tag: it cannot have been sealed. (A record of just a
     * tag opens, if it is genuine, to nothing, which has no content type.) */
    return GTLS_ERR_MISMATCH;
  }
  if (k->seq >= k->limit) {
    return GTLS_ERR_LIMIT;
  }
  body = ct_len - GTLS_RECORD_TAG;
  build_nonce(k, nonce);
  result = aead_open(k, nonce, header, ct, body, pt, ct + body);
  (void)gsec_wipe(nonce, sizeof nonce);
  if (result != GTLS_OK) {
    (void)gsec_wipe(pt, body);
    return result;
  }
  /* The record is authentic from here, so scanning it for the content type
   * reveals nothing an attacker chose: the last nonzero byte is the type
   * and the zeros after it are the padding (section 5.4). */
  for (i = body; i > 0 && pt[i - 1u] == 0; i--) {
  }
  if (i == 0) {
    (void)gsec_wipe(pt, body);
    return GTLS_ERR_PROTOCOL;
  }
  pad = body - i;
  if (pad > max_padding || i - 1u > GTLS_RECORD_PLAIN_MAX) {
    (void)gsec_wipe(pt, body);
    return GTLS_ERR_LIMIT;
  }
  *inner_type = pt[i - 1u];
  *pt_len = i - 1u;
  (void)gsec_wipe(pt + i - 1u, body - (i - 1u));
  k->seq++;
  return GTLS_OK;
}
