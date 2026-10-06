/*
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * Copyright (C) 2026 Corey Pennycuff
 *
 * This file is part of Ghoti.io TLS.
 *
 * Constant-time gate, leak plant.
 *
 * The byte is initialised and then marked undefined, so the only
 * undefinedness memcheck can see is the one this file asked for. A branch on
 * it must be reported. If it is not, `make check-ct` fails: a gate that does
 * not fire on a planted leak is not a gate.
 *
 * Refuses to run outside Valgrind. A native run would take the branch on a
 * real 1 and exit 0, which is the green result this file must not be able to
 * produce on its own.
 */

#include <valgrind/memcheck.h>

int main(void) {
  unsigned char secret = 1;

  if (RUNNING_ON_VALGRIND == 0) {
    return 2;
  }
  VALGRIND_MAKE_MEM_UNDEFINED(&secret, sizeof secret);
  if (secret == 1) {
    return 0;
  }
  return 1;
}
