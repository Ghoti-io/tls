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
 * @file clean.c
 *
 * Constant-time gate, clean case.
 *
 * Built against this library compiled with GTLS_CT_TEST and run under
 * memcheck. The key Finished is checked under is marked undefined; a
 * conditional jump or a memory index that depends on it, anywhere between the
 * key and the verdict, is reported. The verdict itself is declassified inside
 * the library, because it is the answer. Refuses to run outside Valgrind:
 * without it the marks are invisible and a green exit would mean nothing.
 */

#include <ghoti.io/tls/macros.h>

#include "../../src/schedule/schedule_internal.h"

#include <string.h>
#include <valgrind/memcheck.h>

int main(void) {
  unsigned char key[GTLS_HASH_MAX];
  unsigned char th[GTLS_HASH_MAX];
  unsigned char good[GTLS_HASH_MAX];
  unsigned char bad[GTLS_HASH_MAX];
  GTLS_Result result;
  size_t hlen = 32;
  int pass;

  if (RUNNING_ON_VALGRIND == 0) {
    return 2;
  }
  memset(key, 0xA5, sizeof key);
  memset(th, 0x5A, sizeof th);
  for (pass = 0; pass < 2; pass++) {
    GTLS_Hash hash = pass == 0 ? GTLS_HASH_SHA256 : GTLS_HASH_SHA384;

    hlen = gtls_hash_len(hash);
    memset(key, 0xA5, sizeof key);
    if (gtls_finished_verify_data(hash, key, th, good) != GTLS_OK) {
      return 3;
    }
    memcpy(bad, good, hlen);
    bad[hlen - 1u] ^= 1u;

    VALGRIND_MAKE_MEM_UNDEFINED(key, hlen);
    result = gtls_finished_check(hash, key, th, good, hlen);
    if (result != GTLS_OK) {
      return 4;
    }
    VALGRIND_MAKE_MEM_UNDEFINED(key, hlen);
    result = gtls_finished_check(hash, key, th, bad, hlen);
    if (result != GTLS_ERR_FINISHED) {
      return 5;
    }
    /* The first byte differing, which is where an early-exit compare would
     * stop at once. */
    memcpy(bad, good, hlen);
    bad[0] ^= 1u;
    VALGRIND_MAKE_MEM_UNDEFINED(key, hlen);
    result = gtls_finished_check(hash, key, th, bad, hlen);
    if (result != GTLS_ERR_FINISHED) {
      return 6;
    }
  }
  return 0;
}
