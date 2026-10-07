#include "fuzz_common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  return gtlsfuzz::pump_one(data, size);
}
