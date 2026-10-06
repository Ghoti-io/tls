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
 * @file verify.c
 *
 * The server's chain and name, checked by `certificate`.
 *
 * This file adds no judgement of its own. It asks the questions in an order
 * that gives each failure its own answer, and maps the answers. The chain is
 * built and validated by gcert_chain_build, whose verdict is
 * gcert_x509_path's; the name is gcert_x509_verify_host's.
 */

#include <ghoti.io/tls/macros.h>

#include "../core/core_internal.h"
#include "client_internal.h"

GTLS_Result gtls_verify_chain(void * user, const GTLS_Conn * conn,
    const GTLS_CertificateMsg * certificate, int64_t unix_time) {
  GCERT_X509 leaf;
  GCERT_Chain chain;
  GCERT_Result verdict;
  const void * pool[GTLS_CERT_MAX];
  size_t i;

  (void)user;
  if (conn == NULL || certificate == NULL || certificate->count == 0) {
    return GTLS_ERR_INVALID;
  }
  verdict = gcert_x509_parse(certificate->der[0], certificate->der_len[0],
      &leaf);
  if (verdict == GCERT_ERR_LIMIT) {
    return GTLS_ERR_LIMIT;
  }
  if (verdict != GCERT_OK) {
    return GTLS_ERR_CERT_INVALID;
  }
  /* The purpose first, so that a certificate meant for something else is
   * said to be that rather than "no path". */
  if (gcert_x509_purpose(&leaf, GCERT_X509_EKU_SERVER_AUTH) != GCERT_OK) {
    return GTLS_ERR_CERT_PURPOSE;
  }
  /* Everything after the leaf is the pool. An array of void pointers, not a
   * cast of the parser's array: the two are not the same type to the
   * compiler. */
  for (i = 1; i < certificate->count; i++) {
    pool[i - 1u] = certificate->der[i];
  }
  verdict = gcert_chain_build(conn->context->trust, certificate->der[0],
      certificate->der_len[0], pool, &certificate->der_len[1],
      certificate->count - 1u, unix_time,
      GCERT_X509_EKU_SERVER_AUTH, NULL, &chain);
  switch (verdict) {
    case GCERT_OK:
      break;
    case GCERT_ERR_MISMATCH:
      switch (chain.failure) {
        case GCERT_CHAIN_EXPIRED:
          return GTLS_ERR_CERT_EXPIRED;
        case GCERT_CHAIN_NOT_YET_VALID:
          return GTLS_ERR_CERT_NOT_YET_VALID;
        case GCERT_CHAIN_UNKNOWN_ISSUER:
          return GTLS_ERR_CERT_ISSUER;
        default:
          return GTLS_ERR_CERT_INVALID;
      }
    case GCERT_ERR_LIMIT:
      return GTLS_ERR_LIMIT;
    case GCERT_ERR_OOM:
      return GTLS_ERR_OOM;
    case GCERT_ERR_CORRUPT:
    case GCERT_ERR_UNSUPPORTED:
      return GTLS_ERR_CERT_INVALID;
    default:
      return GTLS_ERR_INTERNAL;
  }
  if (gcert_x509_verify_host(&leaf, (const char *)conn->host, conn->host_len,
          NULL) != GCERT_OK) {
    return GTLS_ERR_CERT_HOST;
  }
  return GTLS_OK;
}
