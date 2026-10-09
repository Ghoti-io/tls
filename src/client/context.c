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
 * @file context.c
 *
 * Building the immutable configuration connections share.
 */

#include <ghoti.io/tls/macros.h>

#include <ghoti.io/tls/context.h>

#include "../core/core_internal.h"
#include "client_internal.h"

#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/security/secret.h>

#include <string.h>

static const GTLS_Suite default_suites[3] = {
  GTLS_SUITE_AES_128_GCM_SHA256,
  GTLS_SUITE_CHACHA20_POLY1305_SHA256,
  GTLS_SUITE_AES_256_GCM_SHA384
};

static const GTLS_Group default_groups[3] = {
  GTLS_GROUP_X25519, GTLS_GROUP_SECP256R1, GTLS_GROUP_SECP384R1
};

/* The RSA-PSS, ECDSA and Ed25519 schemes TLS 1.3 allows in CertificateVerify,
 * then the PKCS#1 ones, which a certificate signature may still use. */
static const GCERT_SigScheme default_sig_algs[9] = {
  GCERT_SIG_RSA_PSS_SHA256, GCERT_SIG_RSA_PSS_SHA384, GCERT_SIG_RSA_PSS_SHA512,
  GCERT_SIG_ECDSA_P256_SHA256, GCERT_SIG_ECDSA_P384_SHA384, GCERT_SIG_ED25519,
  GCERT_SIG_RSA_PKCS1_SHA256, GCERT_SIG_RSA_PKCS1_SHA384,
  GCERT_SIG_RSA_PKCS1_SHA512
};

void gtls_context_config_default(GTLS_ContextConfig * config) {
  if (config == NULL) {
    return;
  }
  memset(config, 0, sizeof *config);
  config->role = GTLS_ROLE_CLIENT;
  config->versions = GTLS_VERSION_TLS13;
  config->ticket_count = 1;
}

static int sig_scheme_known(unsigned v) {
  switch (v) {
    case GCERT_SIG_RSA_PKCS1_SHA256:
    case GCERT_SIG_ECDSA_P256_SHA256:
    case GCERT_SIG_RSA_PKCS1_SHA384:
    case GCERT_SIG_ECDSA_P384_SHA384:
    case GCERT_SIG_RSA_PKCS1_SHA512:
    case GCERT_SIG_RSA_PSS_SHA256:
    case GCERT_SIG_RSA_PSS_SHA384:
    case GCERT_SIG_RSA_PSS_SHA512:
    case GCERT_SIG_ED25519:
      return 1;
    default:
      return 0;
  }
}

static int group_known(unsigned v) {
  return v == GTLS_GROUP_X25519 || v == GTLS_GROUP_SECP256R1 ||
      v == GTLS_GROUP_SECP384R1;
}

static void free_identity(const GTLS_Allocator * allocator, GTLS_ServerIdentity * id) {
  gcu_allocator_free(allocator, id->chain);
  gcu_allocator_free(allocator, id->chain_len);
  gcu_allocator_free(allocator, id->names);
  gcu_allocator_free(allocator, id->name_len);
  memset(id, 0, sizeof *id);
}

/** Copy one identity into the context, checking what can be checked now. */
static GTLS_Result build_identity(const GTLS_Context * x, const GTLS_Identity * in,
    GTLS_ServerIdentity * out) {
  const GTLS_Allocator * allocator = x->allocator;
  GCERT_X509 leaf;
  size_t total = 0;
  size_t msg;
  size_t name_bytes = 0;
  size_t off = 0;
  size_t i;

  memset(out, 0, sizeof *out);
  if (in->chain == NULL || in->chain_lens == NULL || in->chain_count == 0 ||
      in->chain_count > GTLS_CERT_MAX || in->key == NULL ||
      (in->names == NULL && in->name_count != 0)) {
    return GTLS_ERR_INVALID;
  }
  for (i = 0; i < in->chain_count; i++) {
    if (in->chain[i] == NULL || in->chain_lens[i] == 0 ||
        in->chain_lens[i] > 0xffffffu - total) {
      return GTLS_ERR_INVALID;
    }
    total += in->chain_lens[i];
  }
  /* The Certificate message, and room beside it for the rest of the flight,
   * has to fit the queue a connection holds. */
  msg = 8u + 5u * in->chain_count + total;
  if (msg + 1024u > x->limits.max_output_bytes) {
    return GTLS_ERR_LIMIT;
  }
  for (i = 0; i < in->name_count; i++) {
    size_t n;
    size_t k;

    if (in->names[i] == NULL) {
      return GTLS_ERR_INVALID;
    }
    n = strlen(in->names[i]);
    if (n == 0 || n > 255u) {
      return GTLS_ERR_INVALID;
    }
    for (k = 0; k < n; k++) {
      if ((unsigned char)in->names[i][k] > 0x7fu) {
        return GTLS_ERR_INVALID;
      }
    }
    name_bytes += n;
  }
  out->chain = gcu_allocator_malloc(allocator, total);
  out->chain_len = gcu_allocator_malloc(allocator, in->chain_count * sizeof *out->chain_len);
  out->names = in->name_count != 0 ? gcu_allocator_malloc(allocator, name_bytes) : NULL;
  out->name_len = in->name_count != 0
      ? gcu_allocator_malloc(allocator, in->name_count * sizeof *out->name_len) : NULL;
  if (out->chain == NULL || out->chain_len == NULL ||
      (in->name_count != 0 && (out->names == NULL || out->name_len == NULL))) {
    free_identity(allocator, out);
    return GTLS_ERR_OOM;
  }
  for (i = 0; i < in->chain_count; i++) {
    memcpy(out->chain + off, in->chain[i], in->chain_lens[i]);
    out->chain_len[i] = in->chain_lens[i];
    off += in->chain_lens[i];
  }
  out->chain_count = in->chain_count;
  out->chain_bytes = total;
  off = 0;
  for (i = 0; i < in->name_count; i++) {
    size_t n = strlen(in->names[i]);
    size_t k;

    for (k = 0; k < n; k++) {
      unsigned char ch = (unsigned char)in->names[i][k];

      out->names[off + k] = ch >= 'A' && ch <= 'Z' ? (unsigned char)(ch + ('a' - 'A')) : ch;
    }
    out->name_len[i] = n;
    off += n;
  }
  out->name_count = in->name_count;
  out->key = in->key;
  out->key_kind = gcert_key_kind(in->key);
  if (gcert_x509_parse(out->chain, out->chain_len[0], &leaf) != GCERT_OK ||
      gcert_key_matches(in->key, &leaf) != GCERT_OK) {
    free_identity(allocator, out);
    return GTLS_ERR_INVALID;
  }
  return GTLS_OK;
}

static GTLS_Result build_identities(GTLS_Context * x, const GTLS_Identity * list,
    size_t count) {
  size_t i;
  GTLS_Result result = GTLS_OK;

  x->identities = gcu_allocator_calloc(x->allocator, count, sizeof *x->identities);
  if (x->identities == NULL) {
    return GTLS_ERR_OOM;
  }
  for (i = 0; i < count && result == GTLS_OK; i++) {
    result = build_identity(x, &list[i], &x->identities[i]);
    if (result == GTLS_OK) {
      x->identity_count = i + 1u;
    }
  }
  return result;
}

GTLS_Result gtls_context_new(const GTLS_Allocator * allocator,
    const GTLS_ContextConfig * config, GTLS_Context ** out) {
  GTLS_Context * c;
  size_t i;
  size_t j;

  if (config == NULL || out == NULL) {
    return GTLS_ERR_INVALID;
  }
  if (allocator == NULL) {
    allocator = gtls_allocator_default();
  }
  if (config->role != GTLS_ROLE_CLIENT && config->role != GTLS_ROLE_SERVER) {
    return GTLS_ERR_INVALID;
  }
  if (config->versions == 0 ||
      (config->versions & ~(GTLS_VERSION_TLS13 | GTLS_VERSION_TLS12)) != 0) {
    return GTLS_ERR_INVALID;
  }
  if (config->versions != GTLS_VERSION_TLS13) {
    return GTLS_ERR_UNSUPPORTED;
  }
  if (config->psk != NULL || config->psk_len != 0 || config->psk_identity != NULL ||
      config->psk_identity_len != 0) {
    return GTLS_ERR_UNSUPPORTED;
  }
  if (config->role == GTLS_ROLE_CLIENT) {
    /* A chain and key on a client are client authentication, which is not
     * built; identities are a server's. */
    if (config->chain != NULL || config->chain_lens != NULL ||
        config->chain_count != 0 || config->key != NULL) {
      return GTLS_ERR_UNSUPPORTED;
    }
    if (config->identities != NULL || config->identity_count != 0 ||
        config->default_identity != 0) {
      return GTLS_ERR_INVALID;
    }
    if (config->trust == NULL) {
      return GTLS_ERR_INVALID;
    }
  } else {
    int single = config->chain != NULL || config->chain_lens != NULL ||
        config->chain_count != 0 || config->key != NULL;

    if ((config->identities == NULL) != (config->identity_count == 0) ||
        (single && config->identity_count != 0) ||
        (!single && config->identity_count == 0)) {
      return GTLS_ERR_INVALID;
    }
    if (config->default_identity >= (single ? 1u : config->identity_count)) {
      return GTLS_ERR_INVALID;
    }
  }
  if ((config->alpn == NULL && config->alpn_count != 0) ||
      (config->suites == NULL && config->suite_count != 0) ||
      (config->groups == NULL && config->group_count != 0) ||
      (config->sig_algs == NULL && config->sig_alg_count != 0) ||
      config->suite_count > 3u || config->group_count > 3u ||
      config->sig_alg_count > GTLS_SIG_ALGS_MAX) {
    return GTLS_ERR_INVALID;
  }
  if (config->role == GTLS_ROLE_SERVER && config->limits != NULL &&
      config->limits->max_client_hello > GTLS_HELLO_MAX - 4u) {
    return GTLS_ERR_INVALID; /* a hello it accepted could not be kept for a retry */
  }
  if ((config->ticket_keys == NULL) != (config->ticket_key_count == 0) ||
      config->ticket_key_count > GTLS_TICKET_KEYS_MAX ||
      config->ticket_lifetime > GTLS_TICKET_LIFETIME_MAX ||
      config->ticket_age_window > GTLS_TICKET_AGE_WINDOW_MAX) {
    return GTLS_ERR_INVALID;
  }
  if (config->role == GTLS_ROLE_CLIENT &&
      (config->ticket_keys != NULL || config->ticket_lifetime != 0 ||
          config->ticket_age_window != 0)) {
    return GTLS_ERR_INVALID; /* tickets are a server's; a client holds the ones it is sent */
  }
  for (i = 0; i < config->ticket_key_count; i++) {
    if (config->ticket_keys[i].not_after <= config->ticket_keys[i].not_before) {
      return GTLS_ERR_INVALID;
    }
    for (j = 0; j < i; j++) {
      if (gsec_equal(config->ticket_keys[j].name, config->ticket_keys[i].name,
              GTLS_TICKET_KEY_NAME_LEN) == GSEC_OK) {
        return GTLS_ERR_INVALID;
      }
    }
  }
  c = gcu_allocator_calloc(allocator, 1, sizeof *c);
  if (c == NULL) {
    return GTLS_ERR_OOM;
  }
  c->allocator = allocator;
  c->default_identity = config->default_identity;
  c->role = config->role;
  c->versions = config->versions;
  c->trust = config->trust;
  c->middlebox_compat = config->middlebox_compat != 0;
  gtls_limits_resolve(config->limits, &c->limits);
  if (config->role == GTLS_ROLE_SERVER) {
    if (config->ticket_count > GTLS_TICKET_COUNT_MAX) {
      gcu_allocator_free(allocator, c);
      return GTLS_ERR_LIMIT; /* the nonce that tells the tickets apart is one byte */
    }
    if (config->ticket_count > c->limits.max_tickets) {
      gcu_allocator_free(allocator, c);
      return GTLS_ERR_INVALID;
    }
    if (config->ticket_key_count != 0 && c->limits.max_ticket_bytes < GTLS_TICKET_MAX) {
      gcu_allocator_free(allocator, c);
      return GTLS_ERR_LIMIT; /* a ticket it seals could be refused by the very caps it was given */
    }
    /* The count was checked above; the copy does not rely on it. */
    c->ticket_key_count = config->ticket_key_count < GTLS_TICKET_KEYS_MAX
        ? config->ticket_key_count : GTLS_TICKET_KEYS_MAX;
    if (c->ticket_key_count != 0) {
      memcpy(c->ticket_keys, config->ticket_keys,
          c->ticket_key_count * sizeof config->ticket_keys[0]);
    }
    c->ticket_count = config->ticket_count;
    c->ticket_lifetime = config->ticket_lifetime != 0 ? config->ticket_lifetime
                                                      : GTLS_TICKET_LIFETIME_DEFAULT;
    c->ticket_age_window = config->ticket_age_window != 0 ? config->ticket_age_window
                                                          : GTLS_TICKET_AGE_WINDOW_DEFAULT;
  }

  if (config->suite_count == 0) {
    memcpy(c->suites, default_suites, sizeof default_suites);
    c->suite_count = 3;
  } else {
    for (i = 0; i < config->suite_count; i++) {
      if (!gtls_suite_valid((uint32_t)config->suites[i])) {
        goto invalid;
      }
      for (j = 0; j < i; j++) {
        if (config->suites[j] == config->suites[i]) {
          goto invalid;
        }
      }
      c->suites[i] = config->suites[i];
    }
    c->suite_count = config->suite_count;
  }
  if (config->group_count == 0) {
    memcpy(c->groups, default_groups, sizeof default_groups);
    c->group_count = 3;
  } else {
    for (i = 0; i < config->group_count; i++) {
      if (!group_known((unsigned)config->groups[i])) {
        goto invalid;
      }
      for (j = 0; j < i; j++) {
        if (config->groups[j] == config->groups[i]) {
          goto invalid;
        }
      }
      c->groups[i] = config->groups[i];
    }
    c->group_count = config->group_count;
  }
  if (config->sig_alg_count == 0) {
    memcpy(c->sig_algs, default_sig_algs, sizeof default_sig_algs);
    c->sig_alg_count = 9;
  } else {
    for (i = 0; i < config->sig_alg_count; i++) {
      if (!sig_scheme_known((unsigned)config->sig_algs[i])) {
        goto invalid;
      }
      for (j = 0; j < i; j++) {
        if (config->sig_algs[j] == config->sig_algs[i]) {
          goto invalid;
        }
      }
      c->sig_algs[i] = config->sig_algs[i];
    }
    c->sig_alg_count = config->sig_alg_count;
  }
  {
    /* TLS 1.3 forbids PKCS#1 in CertificateVerify, so a list of nothing else
     * could never be satisfied: refuse it here, not at every handshake. */
    int usable = 0;

    for (i = 0; i < c->sig_alg_count; i++) {
      switch ((unsigned)c->sig_algs[i]) {
        case GCERT_SIG_RSA_PSS_SHA256:
        case GCERT_SIG_RSA_PSS_SHA384:
        case GCERT_SIG_RSA_PSS_SHA512:
        case GCERT_SIG_ECDSA_P256_SHA256:
        case GCERT_SIG_ECDSA_P384_SHA384:
        case GCERT_SIG_ED25519:
          usable = 1;
          break;
        default:
          break;
      }
    }
    if (!usable) {
      goto invalid;
    }
  }
  for (i = 0; i < config->alpn_count; i++) {
    size_t n;

    if (config->alpn[i] == NULL) {
      goto invalid;
    }
    n = strlen(config->alpn[i]);
    if (n == 0 || n > 255u) {
      goto invalid;
    }
    if (c->alpn_len + 1u + n > GTLS_ALPN_WIRE_MAX) {
      gcu_allocator_free(allocator, c);
      return GTLS_ERR_LIMIT;
    }
    c->alpn[c->alpn_len++] = (unsigned char)n;
    memcpy(c->alpn + c->alpn_len, config->alpn[i], n);
    c->alpn_len += n;
  }
  if (config->role == GTLS_ROLE_SERVER) {
    GTLS_Identity one;
    const GTLS_Identity * list = config->identities;
    size_t count = config->identity_count;
    GTLS_Result result;

    if (list == NULL) {
      memset(&one, 0, sizeof one);
      one.chain = config->chain;
      one.chain_lens = config->chain_lens;
      one.chain_count = config->chain_count;
      one.key = config->key;
      list = &one;
      count = 1;
    }
    result = build_identities(c, list, count);
    if (result != GTLS_OK) {
      gtls_context_free(c);
      return result;
    }
  }
  *out = c;
  return GTLS_OK;

invalid:
  gcu_allocator_free(allocator, c);
  return GTLS_ERR_INVALID;
}

void gtls_context_free(GTLS_Context * context) {
  if (context != NULL) {
    const GTLS_Allocator * allocator = context->allocator;
    size_t i;

    for (i = 0; i < context->identity_count; i++) {
      free_identity(allocator, &context->identities[i]);
    }
    gcu_allocator_free(allocator, context->identities);
    (void)gsec_wipe(context, sizeof *context);
    gcu_allocator_free(allocator, context);
  }
}
