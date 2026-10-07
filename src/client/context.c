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
  if (config->role == GTLS_ROLE_SERVER) {
    return GTLS_ERR_UNSUPPORTED;
  }
  if (config->role != GTLS_ROLE_CLIENT) {
    return GTLS_ERR_INVALID;
  }
  if (config->versions == 0 ||
      (config->versions & ~(GTLS_VERSION_TLS13 | GTLS_VERSION_TLS12)) != 0) {
    return GTLS_ERR_INVALID;
  }
  if (config->versions != GTLS_VERSION_TLS13) {
    return GTLS_ERR_UNSUPPORTED;
  }
  if (config->chain != NULL || config->chain_lens != NULL ||
      config->chain_count != 0 || config->key != NULL || config->psk != NULL ||
      config->psk_len != 0 || config->psk_identity != NULL ||
      config->psk_identity_len != 0) {
    return GTLS_ERR_UNSUPPORTED;
  }
  if (config->trust == NULL) {
    return GTLS_ERR_INVALID;
  }
  if ((config->alpn == NULL && config->alpn_count != 0) ||
      (config->suites == NULL && config->suite_count != 0) ||
      (config->groups == NULL && config->group_count != 0) ||
      (config->sig_algs == NULL && config->sig_alg_count != 0) ||
      config->suite_count > 3u || config->group_count > 3u ||
      config->sig_alg_count > GTLS_SIG_ALGS_MAX) {
    return GTLS_ERR_INVALID;
  }
  c = gcu_allocator_calloc(allocator, 1, sizeof *c);
  if (c == NULL) {
    return GTLS_ERR_OOM;
  }
  c->allocator = allocator;
  c->role = config->role;
  c->versions = config->versions;
  c->trust = config->trust;
  c->middlebox_compat = config->middlebox_compat != 0;
  gtls_limits_resolve(config->limits, &c->limits);

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
  *out = c;
  return GTLS_OK;

invalid:
  gcu_allocator_free(allocator, c);
  return GTLS_ERR_INVALID;
}

void gtls_context_free(GTLS_Context * context) {
  if (context != NULL) {
    const GTLS_Allocator * allocator = context->allocator;

    (void)gsec_wipe(context, sizeof *context);
    gcu_allocator_free(allocator, context);
  }
}
