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
 * @file selftest.c
 *
 * Power-on known answers, from RFC 8448 section 3.
 */

#include <ghoti.io/tls/macros.h>

#include <ghoti.io/tls/schedule.h>
#include <ghoti.io/tls/selftest.h>
#include <ghoti.io/security/secret.h>
#include <ghoti.io/security/sha256.h>

#include "../schedule/schedule_internal.h"
#include "core_internal.h"
#include "selftest_kat.h"

GTLS_Result gtls_selftest(void) {
  GTLS_Schedule schedule;
  unsigned char empty[GSEC_SHA256_DIGEST_LEN];
  unsigned char derived[GSEC_SHA256_DIGEST_LEN];
  GTLS_Result result;

  /* The Early Secret of a handshake with no PSK, then the "derived" secret
   * that feeds the Handshake Secret: HKDF-Extract, the label encoding of
   * HKDF-Expand-Label, SHA-256 and HMAC, in one chain. */
  result = gtls_schedule_early(&schedule, GTLS_HASH_SHA256);
  if (result != GTLS_OK) {
    return result;
  }
  if (gtls_from_gsec(gsec_equal(schedule.early, gtls_kat_early_secret,
          sizeof gtls_kat_early_secret)) != GTLS_OK) {
    gtls_schedule_wipe(&schedule);
    return GTLS_ERR_INTERNAL;
  }
  result = gtls_from_gsec(gsec_sha256(NULL, 0, empty));
  if (result == GTLS_OK) {
    result = gtls_derive_secret(GTLS_HASH_SHA256, schedule.early,
        schedule.hlen, "derived", empty, derived);
  }
  gtls_schedule_wipe(&schedule);
  if (result == GTLS_OK &&
      gtls_from_gsec(gsec_equal(derived, gtls_kat_derived_secret,
          sizeof gtls_kat_derived_secret)) != GTLS_OK) {
    result = GTLS_ERR_INTERNAL;
  }
  (void)gsec_wipe(derived, sizeof derived);
  return result;
}
