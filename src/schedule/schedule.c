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
 * @file schedule.c
 *
 * HKDF-Expand-Label, Derive-Secret, the chain of secrets, and the
 * transcript hash. RFC 8446 sections 4.4.1, 4.4.4 and 7.
 */

#include <ghoti.io/tls/macros.h>

#include <ghoti.io/tls/schedule.h>

#include "../core/core_internal.h"
#include "schedule_internal.h"

#include <ghoti.io/security/hkdf.h>
#include <ghoti.io/security/hmac.h>
#include <ghoti.io/security/secret.h>

#include <string.h>

#ifdef GTLS_CT_TEST
#include <valgrind/memcheck.h>
#endif

int gtls_suite_valid(uint32_t suite) {
  return suite == GTLS_SUITE_AES_128_GCM_SHA256 ||
      suite == GTLS_SUITE_AES_256_GCM_SHA384 ||
      suite == GTLS_SUITE_CHACHA20_POLY1305_SHA256;
}

GTLS_Hash gtls_suite_hash(uint32_t suite) {
  switch (suite) {
    case GTLS_SUITE_AES_128_GCM_SHA256:
    case GTLS_SUITE_CHACHA20_POLY1305_SHA256:
      return GTLS_HASH_SHA256;
    case GTLS_SUITE_AES_256_GCM_SHA384:
      return GTLS_HASH_SHA384;
    default:
      return GTLS_HASH_NONE;
  }
}

size_t gtls_suite_key_len(uint32_t suite) {
  switch (suite) {
    case GTLS_SUITE_AES_128_GCM_SHA256:
      return 16u;
    case GTLS_SUITE_AES_256_GCM_SHA384:
    case GTLS_SUITE_CHACHA20_POLY1305_SHA256:
      return 32u;
    default:
      return 0u;
  }
}

size_t gtls_hash_len(GTLS_Hash hash) {
  switch (hash) {
    case GTLS_HASH_SHA256:
      return GSEC_SHA256_DIGEST_LEN;
    case GTLS_HASH_SHA384:
      return GSEC_SHA384_DIGEST_LEN;
    case GTLS_HASH_NONE:
      break;
  }
  return 0u;
}

static uint32_t hkdf_id(GTLS_Hash hash) {
  return hash == GTLS_HASH_SHA384 ? GSEC_HKDF_SHA384 : GSEC_HKDF_SHA256;
}

GTLS_Result gtls_hkdf_expand_label(GTLS_Hash hash, const void * secret,
    size_t secret_len, const char * label, const void * context,
    size_t context_len, void * out, size_t out_len) {
  /* struct HkdfLabel { uint16 length; opaque label<7..255>;
   *                    opaque context<0..255>; } */
  unsigned char info[2 + 1 + 255 + 1 + 255];
  const char prefix[] = "tls13 ";
  size_t label_len;
  size_t full;
  size_t n = 0;
  GTLS_Result result;

  if (gtls_hash_len(hash) == 0 || secret == NULL || label == NULL ||
      (context == NULL && context_len != 0) || out == NULL) {
    return GTLS_ERR_INVALID;
  }
  label_len = strlen(label);
  full = sizeof prefix - 1u + label_len;
  if (full > 255u || context_len > 255u) {
    return GTLS_ERR_INVALID;
  }
  if (out_len > 0xffffu) {
    return GTLS_ERR_LIMIT;
  }
  info[n++] = (unsigned char)(out_len >> 8);
  info[n++] = (unsigned char)out_len;
  info[n++] = (unsigned char)full;
  memcpy(info + n, prefix, sizeof prefix - 1u);
  n += sizeof prefix - 1u;
  memcpy(info + n, label, label_len);
  n += label_len;
  info[n++] = (unsigned char)context_len;
  if (context_len != 0) {
    memcpy(info + n, context, context_len);
    n += context_len;
  }
  result = gtls_from_gsec(gsec_hkdf_expand(hkdf_id(hash), secret, secret_len,
      info, n, out, out_len));
  if (result != GTLS_OK) {
    (void)gsec_wipe(out, out_len);
  }
  return result;
}

GTLS_Result gtls_derive_secret(GTLS_Hash hash, const void * secret,
    size_t secret_len, const char * label, const void * transcript_hash,
    void * out) {
  if (transcript_hash == NULL) {
    return GTLS_ERR_INVALID;
  }
  return gtls_hkdf_expand_label(hash, secret, secret_len, label,
      transcript_hash, gtls_hash_len(hash), out, gtls_hash_len(hash));
}

GTLS_Result gtls_traffic_keys(uint32_t suite, const void * secret, void * key,
    void * iv) {
  GTLS_Hash hash = gtls_suite_hash(suite);
  size_t hlen = gtls_hash_len(hash);
  size_t klen = gtls_suite_key_len(suite);
  GTLS_Result result;

  if (hlen == 0 || secret == NULL || key == NULL || iv == NULL) {
    return GTLS_ERR_INVALID;
  }
  result = gtls_hkdf_expand_label(hash, secret, hlen, "key", NULL, 0, key,
      klen);
  if (result == GTLS_OK) {
    result = gtls_hkdf_expand_label(hash, secret, hlen, "iv", NULL, 0, iv,
        GTLS_IV_LEN);
  }
  if (result != GTLS_OK) {
    (void)gsec_wipe(key, klen);
    (void)gsec_wipe(iv, GTLS_IV_LEN);
  }
  return result;
}

/* ---------------------------------------------------------------- transcript */

GTLS_Result gtls_transcript_init(GTLS_Transcript * t) {
  GTLS_Result result;

  if (t == NULL) {
    return GTLS_ERR_INVALID;
  }
  memset(t, 0, sizeof *t);
  result = gtls_from_gsec(gsec_sha256_init(&t->s256));
  if (result == GTLS_OK) {
    t->live256 = 1;
    result = gtls_from_gsec(gsec_sha384_init(&t->s384));
  }
  if (result == GTLS_OK) {
    t->live384 = 1;
  } else {
    gtls_transcript_wipe(t);
  }
  return result;
}

GTLS_Result gtls_transcript_update(GTLS_Transcript * t, const void * data,
    size_t len) {
  GTLS_Result result = GTLS_OK;

  if (t == NULL || (data == NULL && len != 0)) {
    return GTLS_ERR_INVALID;
  }
  if (t->live256) {
    result = gtls_from_gsec(gsec_sha256_update(&t->s256, data, len));
  }
  if (result == GTLS_OK && t->live384) {
    result = gtls_from_gsec(gsec_sha384_update(&t->s384, data, len));
  }
  if (result != GTLS_OK) {
    gtls_transcript_wipe(t);
  }
  return result;
}

GTLS_Result gtls_transcript_select(GTLS_Transcript * t, GTLS_Hash hash) {
  if (t == NULL || t->hash != GTLS_HASH_NONE || !t->live256 || !t->live384) {
    return GTLS_ERR_INVALID;
  }
  if (hash == GTLS_HASH_SHA256) {
    (void)gsec_wipe(&t->s384, sizeof t->s384);
    t->live384 = 0;
  } else if (hash == GTLS_HASH_SHA384) {
    (void)gsec_wipe(&t->s256, sizeof t->s256);
    t->live256 = 0;
  } else {
    return GTLS_ERR_INVALID;
  }
  t->hash = hash;
  return GTLS_OK;
}

GTLS_Result gtls_transcript_snapshot(const GTLS_Transcript * t, GTLS_Hash hash,
    void * out) {
  GTLS_Result result;

  if (t == NULL || out == NULL) {
    return GTLS_ERR_INVALID;
  }
  if (hash == GTLS_HASH_SHA256 && t->live256) {
    GSEC_Sha256 copy = t->s256;
    result = gtls_from_gsec(gsec_sha256_final(&copy, out));
    (void)gsec_wipe(&copy, sizeof copy);
    return result;
  }
  if (hash == GTLS_HASH_SHA384 && t->live384) {
    GSEC_Sha384 copy = t->s384;
    result = gtls_from_gsec(gsec_sha384_final(&copy, out));
    (void)gsec_wipe(&copy, sizeof copy);
    return result;
  }
  return GTLS_ERR_INVALID;
}

GTLS_Result gtls_transcript_restart(GTLS_Transcript * t, GTLS_Hash hash) {
  unsigned char msg[4 + GTLS_HASH_MAX];
  size_t hlen = gtls_hash_len(hash);
  GTLS_Result result;

  if (t == NULL || hlen == 0) {
    return GTLS_ERR_INVALID;
  }
  /* The hash of ClientHello1 under the suite the server picked. */
  msg[0] = 254u; /* message_hash */
  msg[1] = 0;
  msg[2] = 0;
  msg[3] = (unsigned char)hlen;
  result = gtls_transcript_snapshot(t, hash, msg + 4);
  if (result != GTLS_OK) {
    gtls_transcript_wipe(t);
    return result;
  }
  gtls_transcript_wipe(t);
  if (hash == GTLS_HASH_SHA256) {
    result = gtls_from_gsec(gsec_sha256_init(&t->s256));
    t->live256 = result == GTLS_OK;
  } else {
    result = gtls_from_gsec(gsec_sha384_init(&t->s384));
    t->live384 = result == GTLS_OK;
  }
  if (result == GTLS_OK) {
    t->hash = hash;
    result = gtls_transcript_update(t, msg, 4u + hlen);
  }
  if (result != GTLS_OK) {
    gtls_transcript_wipe(t);
  }
  return result;
}

void gtls_transcript_wipe(GTLS_Transcript * t) {
  if (t != NULL) {
    (void)gsec_wipe(t, sizeof *t);
  }
}

/* ------------------------------------------------------------------ secrets */

static GTLS_Result empty_hash(GTLS_Hash hash, unsigned char * out) {
  return hash == GTLS_HASH_SHA384
      ? gtls_from_gsec(gsec_sha384(NULL, 0, out))
      : gtls_from_gsec(gsec_sha256(NULL, 0, out));
}

GTLS_Result gtls_schedule_early(GTLS_Schedule * s, GTLS_Hash hash) {
  unsigned char zeros[GTLS_HASH_MAX];
  GTLS_Result result;

  if (s == NULL || gtls_hash_len(hash) == 0) {
    return GTLS_ERR_INVALID;
  }
  memset(s, 0, sizeof *s);
  memset(zeros, 0, sizeof zeros);
  s->hash = hash;
  s->hlen = gtls_hash_len(hash);
  /* A salt of length zero is HashLen zero bytes: the RFC's "0". */
  result = gtls_from_gsec(gsec_hkdf_extract(hkdf_id(hash), NULL, 0, zeros,
      s->hlen, s->early));
  if (result != GTLS_OK) {
    gtls_schedule_wipe(s);
    return result;
  }
  s->stage = 1;
  return GTLS_OK;
}

GTLS_Result gtls_schedule_early_psk(GTLS_Schedule * s, GTLS_Hash hash,
    const void * psk, size_t psk_len) {
  GTLS_Result result;

  if (s == NULL || gtls_hash_len(hash) == 0 || psk == NULL ||
      psk_len != gtls_hash_len(hash)) {
    return GTLS_ERR_INVALID;
  }
  memset(s, 0, sizeof *s);
  s->hash = hash;
  s->hlen = gtls_hash_len(hash);
  /* A salt of length zero is HashLen zero bytes: the RFC's "0". */
  result = gtls_from_gsec(gsec_hkdf_extract(hkdf_id(hash), NULL, 0, psk,
      psk_len, s->early));
  if (result != GTLS_OK) {
    gtls_schedule_wipe(s);
    return result;
  }
  s->stage = 1;
  return GTLS_OK;
}

GTLS_Result gtls_schedule_early_traffic(GTLS_Schedule * s,
    const void * th_client_hello) {
  GTLS_Result result;

  if (s == NULL || s->stage != 1 || th_client_hello == NULL) {
    return GTLS_ERR_INVALID;
  }
  result = gtls_derive_secret(s->hash, s->early, s->hlen, "c e traffic",
      th_client_hello, s->c_e);
  if (result != GTLS_OK) {
    gtls_schedule_wipe(s);
    return result;
  }
  s->has_e = 1;
  return GTLS_OK;
}

GTLS_Result gtls_schedule_handshake(GTLS_Schedule * s, const void * ecdhe,
    size_t ecdhe_len, const void * th_server_hello) {
  unsigned char empty[GTLS_HASH_MAX]; /* the hash of nothing: public */
  GTLS_Result result;

  if (s == NULL || s->stage != 1 || ecdhe == NULL || ecdhe_len == 0 ||
      th_server_hello == NULL) {
    return GTLS_ERR_INVALID;
  }
  result = empty_hash(s->hash, empty);
  if (result == GTLS_OK) {
    result = gtls_derive_secret(s->hash, s->early, s->hlen, "derived", empty,
        s->derived);
  }
  if (result == GTLS_OK) {
    result = gtls_from_gsec(gsec_hkdf_extract(hkdf_id(s->hash), s->derived,
        s->hlen, ecdhe, ecdhe_len, s->handshake));
  }
  if (result == GTLS_OK) {
    result = gtls_derive_secret(s->hash, s->handshake, s->hlen, "c hs traffic",
        th_server_hello, s->c_hs);
  }
  if (result == GTLS_OK) {
    result = gtls_derive_secret(s->hash, s->handshake, s->hlen, "s hs traffic",
        th_server_hello, s->s_hs);
  }
  (void)gsec_wipe(s->derived, sizeof s->derived);
  if (result != GTLS_OK) {
    gtls_schedule_wipe(s);
    return result;
  }
  s->stage = 2;
  return GTLS_OK;
}

GTLS_Result gtls_schedule_master(GTLS_Schedule * s,
    const void * th_server_finished) {
  unsigned char empty[GTLS_HASH_MAX]; /* the hash of nothing: public */
  unsigned char zeros[GTLS_HASH_MAX]; /* the IKM of the Master Secret: all zero by definition */
  GTLS_Result result;

  if (s == NULL || s->stage != 2 || th_server_finished == NULL) {
    return GTLS_ERR_INVALID;
  }
  memset(zeros, 0, sizeof zeros);
  result = empty_hash(s->hash, empty);
  if (result == GTLS_OK) {
    result = gtls_derive_secret(s->hash, s->handshake, s->hlen, "derived",
        empty, s->derived);
  }
  if (result == GTLS_OK) {
    result = gtls_from_gsec(gsec_hkdf_extract(hkdf_id(s->hash), s->derived,
        s->hlen, zeros, s->hlen, s->master));
  }
  if (result == GTLS_OK) {
    result = gtls_derive_secret(s->hash, s->master, s->hlen, "c ap traffic",
        th_server_finished, s->c_ap);
  }
  if (result == GTLS_OK) {
    result = gtls_derive_secret(s->hash, s->master, s->hlen, "s ap traffic",
        th_server_finished, s->s_ap);
  }
  (void)gsec_wipe(s->derived, sizeof s->derived);
  if (result != GTLS_OK) {
    gtls_schedule_wipe(s);
    return result;
  }
  s->stage = 3;
  return GTLS_OK;
}

GTLS_Result gtls_schedule_exporter(const GTLS_Schedule * s,
    const void * th_server_finished, void * out) {
  if (s == NULL || s->stage != 3 || th_server_finished == NULL || out == NULL) {
    return GTLS_ERR_INVALID;
  }
  return gtls_derive_secret(s->hash, s->master, s->hlen, "exp master",
      th_server_finished, out);
}

GTLS_Result gtls_schedule_resumption(const GTLS_Schedule * s,
    const void * th_client_finished, void * out) {
  if (s == NULL || s->stage != 3 || th_client_finished == NULL || out == NULL) {
    return GTLS_ERR_INVALID;
  }
  return gtls_derive_secret(s->hash, s->master, s->hlen, "res master",
      th_client_finished, out);
}

GTLS_Result gtls_schedule_keep_resumption(GTLS_Schedule * s,
    const void * th_client_finished) {
  GTLS_Result result = gtls_schedule_resumption(s, th_client_finished, s == NULL ? NULL : s->res);

  if (s != NULL) {
    s->has_res = result == GTLS_OK;
  }
  return result;
}

GTLS_Result gtls_resumption_psk(GTLS_Hash hash, const void * res_master,
    const void * nonce, size_t nonce_len, void * out) {
  size_t hlen = gtls_hash_len(hash);

  if (hlen == 0 || res_master == NULL || out == NULL ||
      (nonce == NULL && nonce_len != 0)) {
    return GTLS_ERR_INVALID;
  }
  return gtls_hkdf_expand_label(hash, res_master, hlen, "resumption", nonce,
      nonce_len, out, hlen);
}

GTLS_Result gtls_schedule_binder_key(const GTLS_Schedule * s, void * out) {
  unsigned char empty[GTLS_HASH_MAX];
  GTLS_Result result;

  if (s == NULL || s->stage != 1 || out == NULL) {
    return GTLS_ERR_INVALID;
  }
  result = empty_hash(s->hash, empty);
  if (result == GTLS_OK) {
    result = gtls_derive_secret(s->hash, s->early, s->hlen, "res binder", empty,
        out);
  }
  return result;
}

GTLS_Result gtls_binder_compute(GTLS_Hash hash, const void * psk, size_t psk_len,
    const void * th, void * out, GTLS_MacScratch * m) {
  GTLS_Result result;

  if (th == NULL || out == NULL || m == NULL) {
    return GTLS_ERR_INVALID;
  }
  result = gtls_schedule_early_psk(&m->schedule, hash, psk, psk_len);
  if (result != GTLS_OK) {
    return result;
  }
  result = gtls_schedule_binder_key(&m->schedule, m->bkey);
  if (result == GTLS_OK) {
    result = gtls_finished_verify_data(hash, m->bkey, th, out, m);
  }
  gtls_schedule_wipe(&m->schedule);
  (void)gsec_wipe(m->bkey, sizeof m->bkey);
  return result;
}

GTLS_Result gtls_binder_check(GTLS_Hash hash, const void * psk, size_t psk_len,
    const void * th, const void * got, size_t got_len, GTLS_MacScratch * m) {
  size_t hlen = gtls_hash_len(hash);
  GSEC_Result same;
  GTLS_Result result;

  if (hlen == 0 || got == NULL || m == NULL) {
    return GTLS_ERR_INVALID;
  }
  if (got_len != hlen) {
    return GTLS_ERR_MISMATCH;
  }
  result = gtls_binder_compute(hash, psk, psk_len, th, m->want, m);
  if (result == GTLS_OK) {
#ifdef GTLS_CT_TEST
    /* As for Finished: tracking stops at the door of gsec_equal. */
    VALGRIND_MAKE_MEM_DEFINED(m->want, hlen);
#endif
    same = gsec_equal(m->want, got, hlen);
    result = same == GSEC_OK ? GTLS_OK
        : (same == GSEC_ERR_MISMATCH ? GTLS_ERR_MISMATCH : gtls_from_gsec(same));
  }
  (void)gsec_wipe(m->want, sizeof m->want);
  return result;
}

GTLS_Result gtls_binder_transcript(const GTLS_Transcript * t, const void * trunc,
    size_t trunc_len, void * out) {
  GTLS_Transcript copy;
  GTLS_Result result;

  if (t == NULL || trunc == NULL || out == NULL || t->hash == GTLS_HASH_NONE) {
    return GTLS_ERR_INVALID;
  }
  copy = *t;
  result = gtls_transcript_update(&copy, trunc, trunc_len);
  if (result == GTLS_OK) {
    result = gtls_transcript_snapshot(&copy, t->hash, out);
  }
  gtls_transcript_wipe(&copy);
  return result;
}

void gtls_schedule_wipe(GTLS_Schedule * s) {
  if (s != NULL) {
    (void)gsec_wipe(s, sizeof *s);
  }
}

GTLS_Result gtls_finished_verify_data(GTLS_Hash hash, const void * base_key,
    const void * th, void * out, GTLS_MacScratch * m) {
  size_t hlen = gtls_hash_len(hash);
  GTLS_Result result;

  if (hlen == 0 || base_key == NULL || th == NULL || out == NULL || m == NULL) {
    return GTLS_ERR_INVALID;
  }
  result = gtls_hkdf_expand_label(hash, base_key, hlen, "finished", NULL, 0,
      m->fkey, hlen);
  if (result == GTLS_OK) {
    result = gtls_from_gsec(gsec_hmac(hkdf_id(hash), m->fkey, hlen, th, hlen, out));
  }
  (void)gsec_wipe(m->fkey, sizeof m->fkey);
  return result;
}

GTLS_Result gtls_finished_check(GTLS_Hash hash, const void * base_key,
    const void * th, const void * got, size_t got_len, GTLS_MacScratch * m) {
  size_t hlen = gtls_hash_len(hash);
  GSEC_Result same;
  GTLS_Result result;

  if (hlen == 0 || got == NULL || m == NULL) {
    return GTLS_ERR_INVALID;
  }
  /* The length is public. The bytes are compared without branching on them. */
  if (got_len != hlen) {
    return GTLS_ERR_FINISHED;
  }
  result = gtls_finished_verify_data(hash, base_key, th, m->want, m);
  if (result == GTLS_OK) {
#ifdef GTLS_CT_TEST
    /* Tracking stops at the door of gsec_equal. Everything up to here, the
     * label encoding, the HKDF expansion and the HMAC under the poisoned key,
     * has been watched for a branch or an index that depends on the key. The
     * comparison itself is gsec_equal's, which security's own check-ct watches
     * with its own marks; here it would report its verdict branch, which is
     * the answer and is public. */
    VALGRIND_MAKE_MEM_DEFINED(m->want, hlen);
#endif
    same = gsec_equal(m->want, got, hlen);
    result = same == GSEC_OK ? GTLS_OK
        : (same == GSEC_ERR_MISMATCH ? GTLS_ERR_FINISHED : gtls_from_gsec(same));
  }
  (void)gsec_wipe(m->want, sizeof m->want);
  return result;
}
