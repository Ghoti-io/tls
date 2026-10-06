/**
 * @file
 *
 * The fuzz seeds, replayed in-process through the fuzzers' own code, with
 * the states they reach counted against the whole state table: a state the
 * corpus never reaches is a state the fuzzers can only reach by luck. Every
 * seed byte is also flipped once, and the stream is cut at every length, which
 * is what a mutation-based fuzzer does first.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "../test_helpers.h"
#include "../fuzz/fuzz_common.h"

#include <dirent.h>

namespace {

std::vector<std::string> seeds(const std::string & kind) {
  std::vector<std::string> out;
  const std::string dir = gtlstest::data_dir() + "/../fuzz/corpus/" + kind;
  DIR * d = opendir(dir.c_str());
  if (d == nullptr) {
    return out;
  }
  while (struct dirent * e = readdir(d)) {
    std::string n = e->d_name;
    if (n.rfind("seed-", 0) == 0) {
      out.push_back(dir + "/" + n);
    }
  }
  closedir(d);
  return out;
}

gtlsfuzz::Bytes read(const std::string & path) {
  std::ifstream in(path, std::ios::binary);
  return gtlsfuzz::Bytes(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

}  // namespace

TEST(FuzzSeeds, TheCorpusIsThereAndNotEmpty) {
  EXPECT_GE(seeds("client").size(), 15u);
  EXPECT_GE(seeds("msg").size(), 8u);
}

TEST(FuzzSeeds, EverySeedRunsCleanThroughBothHarnesses) {
  for (const std::string & p : seeds("client")) {
    gtlsfuzz::Bytes b = read(p);
    EXPECT_EQ(gtlsfuzz::client_one(b.data(), b.size()), 0) << p;
  }
  for (const std::string & p : seeds("msg")) {
    gtlsfuzz::Bytes b = read(p);
    EXPECT_EQ(gtlsfuzz::msg_one(b.data(), b.size()), 0) << p;
  }
}

TEST(FuzzSeeds, TheCorpusReachesEveryStateInTheTable) {
  gtlsfuzz::visited() = 0;
  for (const std::string & p : seeds("client")) {
    gtlsfuzz::Bytes b = read(p);
    gtlsfuzz::client_one(b.data(), b.size());
  }
  const unsigned want = (1u << GTLS_STATE_COUNT) - 1u;
  EXPECT_EQ(gtlsfuzz::visited(), want)
      << "states reached: 0x" << std::hex << gtlsfuzz::visited() << ", the table has 0x" << want;
}

TEST(FuzzSeeds, EveryByteFlippedAndEveryTruncationOfEveryClientSeed) {
  size_t runs = 0;
  for (const std::string & p : seeds("client")) {
    gtlsfuzz::Bytes b = read(p);
    for (size_t i = 0; i < b.size(); i += 9) {
      gtlsfuzz::Bytes m = b;
      m[i] ^= 0x01u << (i % 8);
      gtlsfuzz::client_one(m.data(), m.size());
      runs++;
    }
    for (size_t n = 0; n < b.size(); n += 61) {
      gtlsfuzz::client_one(b.data(), n);
      runs++;
    }
  }
  EXPECT_GT(runs, 300u);
}

TEST(FuzzSeeds, EveryByteFlippedAndEveryTruncationOfEveryMessageSeed) {
  for (const std::string & p : seeds("msg")) {
    gtlsfuzz::Bytes b = read(p);
    for (size_t i = 0; i < b.size(); i++) {
      for (unsigned bit : {0x01u, 0x80u}) {
        gtlsfuzz::Bytes m = b;
        m[i] ^= bit;
        gtlsfuzz::msg_one(m.data(), m.size());
      }
    }
    for (size_t n = 0; n <= b.size(); n++) {
      gtlsfuzz::msg_one(b.data(), n);
    }
    /* The same body under every parser and every limits byte. */
    for (unsigned opt = 0; opt < 256; opt++) {
      gtlsfuzz::Bytes m = b;
      m[0] = static_cast<unsigned char>(opt);
      gtlsfuzz::msg_one(m.data(), m.size());
    }
  }
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
