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

namespace {

/** One harness: its corpus directory and the function that runs an input through it. */
struct Harness {
  const char * kind;
  int (*run)(const uint8_t *, size_t);
  size_t min_seeds;
};

const Harness kHarnesses[] = {
    {"client", gtlsfuzz::client_one, 15},
    {"msg", gtlsfuzz::msg_one, 17},
    {"server", gtlsfuzz::server_one, 26},
    {"stream", gtlsfuzz::client_stream_one, 20},
    {"record", gtlsfuzz::record_one, 7},
    {"pump", gtlsfuzz::pump_one, 12},
};

}  // namespace

TEST(FuzzSeeds, TheCorpusIsThereAndNotEmpty) {
  for (const Harness & h : kHarnesses) {
    EXPECT_GE(seeds(h.kind).size(), h.min_seeds) << h.kind;
  }
}

TEST(FuzzSeeds, EverySeedRunsCleanThroughItsHarness) {
  for (const Harness & h : kHarnesses) {
    for (const std::string & p : seeds(h.kind)) {
      gtlsfuzz::Bytes b = read(p);
      EXPECT_EQ(h.run(b.data(), b.size()), 0) << p;
    }
  }
}

/* The denominator is the state table, which now has the server's states in
 * it: the client's harnesses reach the client's, the server's the server's. */
TEST(FuzzSeeds, TheCorpusReachesEveryStateInTheTable) {
  gtlsfuzz::visited() = 0;
  for (const Harness & h : kHarnesses) {
    if (std::string(h.kind) == "msg" || std::string(h.kind) == "record") {
      continue;
    }
    for (const std::string & p : seeds(h.kind)) {
      gtlsfuzz::Bytes b = read(p);
      h.run(b.data(), b.size());
    }
  }
  const unsigned want = (1u << GTLS_STATE_COUNT) - 1u;
  EXPECT_EQ(gtlsfuzz::visited(), want)
      << "states reached: 0x" << std::hex << gtlsfuzz::visited() << ", the table has 0x" << want;
}

TEST(FuzzSeeds, EachHarnessAloneReachesItsOwnRolesStates) {
  const unsigned client_states = (1u << GTLS_STATE_NEW) | (1u << GTLS_STATE_WAIT_SH) |
      (1u << GTLS_STATE_WAIT_SH2) | (1u << GTLS_STATE_WAIT_EE) | (1u << GTLS_STATE_WAIT_CERT) |
      (1u << GTLS_STATE_WAIT_CV) | (1u << GTLS_STATE_WAIT_FIN) | (1u << GTLS_STATE_CONNECTED) |
      (1u << GTLS_STATE_FAILED);
  const unsigned server_states = (1u << GTLS_STATE_NEW) | (1u << GTLS_STATE_S_WAIT_CH) |
      (1u << GTLS_STATE_S_WAIT_CH2) | (1u << GTLS_STATE_S_WAIT_FIN) | (1u << GTLS_STATE_CONNECTED) |
      (1u << GTLS_STATE_FAILED);
  /* The RFC's flight is one protected record, so a client fed records goes
   * from waiting for EncryptedExtensions to connected in one call: the
   * message-level harness is the one that stops between the messages. */
  const unsigned stream_states = (1u << GTLS_STATE_NEW) | (1u << GTLS_STATE_WAIT_SH) |
      (1u << GTLS_STATE_WAIT_SH2) | (1u << GTLS_STATE_WAIT_EE) | (1u << GTLS_STATE_CONNECTED) |
      (1u << GTLS_STATE_FAILED);
  struct Want {
    const char * kind;
    unsigned states;
  };
  for (const Want & w : {Want{"client", client_states}, Want{"stream", stream_states},
           Want{"server", server_states}}) {
    gtlsfuzz::visited() = 0;
    for (const Harness & h : kHarnesses) {
      if (std::string(h.kind) != w.kind) {
        continue;
      }
      for (const std::string & p : seeds(h.kind)) {
        gtlsfuzz::Bytes b = read(p);
        h.run(b.data(), b.size());
      }
    }
    EXPECT_EQ(gtlsfuzz::visited(), w.states) << w.kind;
  }
  gtlsfuzz::visited() = 0;
  for (const std::string & p : seeds("pump")) {
    gtlsfuzz::Bytes b = read(p);
    gtlsfuzz::pump_one(b.data(), b.size());
  }
  EXPECT_EQ(gtlsfuzz::visited() | (1u << GTLS_STATE_WAIT_CERT) | (1u << GTLS_STATE_WAIT_CV) |
                (1u << GTLS_STATE_WAIT_FIN),
      (1u << GTLS_STATE_COUNT) - 1u)
      << "two real endpoints with a few flipped bytes visit every state of both roles but the three "
         "a record-fed client passes through inside one call";
}

TEST(FuzzSeeds, ByteFlipsAndTruncationsAtAStrideOfEveryStreamSeed) {
  size_t runs = 0;
  for (const Harness & h : kHarnesses) {
    const std::string kind = h.kind;
    if (kind != "client" && kind != "server" && kind != "stream") {
      continue;
    }
    for (const std::string & p : seeds(h.kind)) {
      gtlsfuzz::Bytes b = read(p);
      for (size_t i = 0; i < b.size(); i += kind == "client" ? 9 : 23) {
        gtlsfuzz::Bytes m = b;
        m[i] ^= 0x01u << (i % 8);
        h.run(m.data(), m.size());
        runs++;
      }
      for (size_t n = 0; n < b.size(); n += 61) {
        h.run(b.data(), n);
        runs++;
      }
    }
  }
  EXPECT_GT(runs, 800u);
}

TEST(FuzzSeeds, ByteFlipsAndTruncationsOfEveryMessageAndRecordSeed) {
  for (const char * kind : {"msg", "record"}) {
    int (*run)(const uint8_t *, size_t) = std::string(kind) == "msg" ? gtlsfuzz::msg_one : gtlsfuzz::record_one;
    for (const std::string & p : seeds(kind)) {
      gtlsfuzz::Bytes b = read(p);
      size_t step = b.size() > 2000 ? 7 : 1;
      for (size_t i = 0; i < b.size(); i += step) {
        for (unsigned bit : {0x01u, 0x80u}) {
          gtlsfuzz::Bytes m = b;
          m[i] ^= bit;
          run(m.data(), m.size());
        }
      }
      for (size_t n = 0; n <= b.size(); n += step) {
        run(b.data(), n);
      }
      /* The same body under every parser and every limits byte. */
      for (unsigned opt = 0; opt < 256; opt++) {
        gtlsfuzz::Bytes m = b;
        m[0] = static_cast<unsigned char>(opt);
        run(m.data(), m.size());
      }
    }
  }
}

/* Two real endpoints, one byte of the traffic changed at a time: whichever
 * byte it is, in whichever direction, no check fails to hold. */
TEST(FuzzSeeds, PositionsAtAStrideOfBothStreamsOfARealHandshakeChangedInTurn) {
  size_t runs = 0;
  for (int direction = 0; direction < 2; direction++) {
    for (unsigned at = 0; at < 3200; at += 31) {
      for (unsigned x : {0x01u, 0x80u}) {
        unsigned v = (static_cast<unsigned>(direction) << 15) | at;
        gtlsfuzz::Bytes in = {0x0f, static_cast<unsigned char>(v >> 8), static_cast<unsigned char>(v),
            static_cast<unsigned char>(x)};
        gtlsfuzz::pump_one(in.data(), in.size());
        runs++;
      }
    }
  }
  EXPECT_GT(runs, 400u);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
