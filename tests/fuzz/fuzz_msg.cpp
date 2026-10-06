/**
 * @file
 *
 * Fuzz every handshake message parser, and the retry transform, with the
 * limits taken from the input. See fuzz_common.h.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "fuzz_common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  return gtlsfuzz::msg_one(data, size);
}
