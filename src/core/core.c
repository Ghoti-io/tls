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
 * @file core.c
 *
 * Result strings, default limits, and the limits a zero field resolves to.
 */

#include <ghoti.io/tls/macros.h>

#include <ghoti.io/tls/core.h>

#include "core_internal.h"

#include <string.h>

const char * gtls_result_string(GTLS_Result result) {
  switch (result) {
    case GTLS_OK:
      return "No error";
    case GTLS_ERR_IO:
      return "Input/output error";
    case GTLS_ERR_FORMAT:
      return "Format not recognised";
    case GTLS_ERR_UNSUPPORTED:
      return "Unsupported feature";
    case GTLS_ERR_LIMIT:
      return "Limit exceeded";
    case GTLS_ERR_CORRUPT:
      return "Corrupt input";
    case GTLS_ERR_OOM:
      return "Out of memory";
    case GTLS_ERR_INVALID:
      return "Invalid argument";
    case GTLS_ERR_INTERNAL:
      return "Internal error";
    case GTLS_ERR_MISMATCH:
      return "Verification failed";
    case GTLS_ERR_PROTOCOL:
      return "Protocol violation by the peer";
    case GTLS_ERR_DOWNGRADE:
      return "Downgrade sentinel in ServerHello.random";
    case GTLS_ERR_FINISHED:
      return "Finished did not verify";
    case GTLS_ERR_SIGNATURE:
      return "CertificateVerify did not verify";
    case GTLS_ERR_CERT_HOST:
      return "Certificate does not name the host";
    case GTLS_ERR_CERT_EXPIRED:
      return "Certificate has expired";
    case GTLS_ERR_CERT_NOT_YET_VALID:
      return "Certificate is not yet valid";
    case GTLS_ERR_CERT_ISSUER:
      return "No path to a trust anchor";
    case GTLS_ERR_CERT_PURPOSE:
      return "Certificate may not be used for server authentication";
    case GTLS_ERR_CERT_INVALID:
      return "Certificate chain refused";
    case GTLS_ERR_FAILED:
      return "Connection has failed";
    case GTLS_RESULT_COUNT:
      break;
  }
  return "Unknown error";
}

void gtls_limits_default(GTLS_Limits * limits) {
  if (!limits) {
    return;
  }
  memset(limits, 0, sizeof *limits);
  limits->max_handshake_message = GTLS_HANDSHAKE_MESSAGE_DEFAULT;
  limits->max_handshake_total = 1024u * 1024u;
  limits->max_certificates = 10u;
  limits->max_certificate_bytes = 16384u;
  limits->max_extensions = 32u;
  limits->max_signature_bytes = 1024u;
  limits->max_ticket_bytes = 16384u;
  limits->max_cookie_bytes = 1024u;
  limits->max_tickets = 16u;
  limits->max_output_bytes = 65536u;
}

void gtls_limits_resolve(const GTLS_Limits * in, GTLS_Limits * out) {
  GTLS_Limits defaults;

  gtls_limits_default(&defaults);
  if (in == NULL) {
    *out = defaults;
    return;
  }
  *out = *in;
#define GTLS_RESOLVE(field) \
  if (out->field == 0) { \
    out->field = defaults.field; \
  }
  GTLS_RESOLVE(max_handshake_message)
  GTLS_RESOLVE(max_handshake_total)
  GTLS_RESOLVE(max_certificates)
  GTLS_RESOLVE(max_certificate_bytes)
  GTLS_RESOLVE(max_extensions)
  GTLS_RESOLVE(max_signature_bytes)
  GTLS_RESOLVE(max_ticket_bytes)
  GTLS_RESOLVE(max_cookie_bytes)
  GTLS_RESOLVE(max_tickets)
  GTLS_RESOLVE(max_output_bytes)
#undef GTLS_RESOLVE
}
