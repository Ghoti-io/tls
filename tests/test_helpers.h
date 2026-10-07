/**
 * @file
 *
 * Shared helpers for the Ghoti.io TLS unit tests: the vector loader for the
 * RFC 8448 files, a scripted random source, and the pieces that put a
 * connection through a flight.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#ifndef GHOTI_IO_GTLS_TEST_HELPERS_H
#define GHOTI_IO_GTLS_TEST_HELPERS_H

#include <gtest/gtest.h>

#include <ghoti.io/tls/tls.h>
#include <ghoti.io/security/security.h>

/* The internal headers are C and have no extern "C" of their own. */
extern "C" {
#include "../src/client/client_internal.h"
#include "../src/core/core_internal.h"
}

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace gtlstest {

typedef std::vector<unsigned char> Bytes;

/** Directory holding the checked-in data. The Makefile bakes in
 *  GTLS_TEST_DATA so the binaries can run from the build tree. */
inline std::string data_dir() {
  const char * env = std::getenv("GTLS_TEST_DATA");
  if (env != nullptr && env[0] != '\0') {
    return std::string(env);
  }
#ifdef GTLS_TEST_DATA
  return std::string(GTLS_TEST_DATA);
#else
  return std::string("tests/data");
#endif
}

inline Bytes from_hex(const std::string & text) {
  Bytes out;
  for (size_t i = 0; i + 1 < text.size(); i += 2) {
    out.push_back(static_cast<unsigned char>(std::stoi(text.substr(i, 2), nullptr, 16)));
  }
  return out;
}

inline std::string to_hex(const Bytes & b) {
  static const char digits[] = "0123456789abcdef";
  std::string out;
  for (unsigned char c : b) {
    out += digits[c >> 4];
    out += digits[c & 15];
  }
  return out;
}

/** One of the .vec files under tests/data/rfc8448, which tools/extract-rfc8448.py wrote. */
class Vec {
 public:
  explicit Vec(const std::string & name) {
    std::ifstream in(data_dir() + "/rfc8448/" + name + ".vec");
    EXPECT_TRUE(in.good()) << name;
    std::string line;
    while (std::getline(in, line)) {
      if (line.empty() || line[0] == '#') {
        continue;
      }
      size_t sp = line.find(' ');
      map_[line.substr(0, sp)] = from_hex(line.substr(sp + 1));
    }
  }
  const Bytes & operator[](const std::string & key) const {
    auto it = map_.find(key);
    EXPECT_TRUE(it != map_.end()) << "no vector " << key;
    static const Bytes empty;
    return it == map_.end() ? empty : it->second;
  }
  bool has(const std::string & key) const { return map_.count(key) != 0; }
  size_t size() const { return map_.size(); }

 private:
  std::map<std::string, Bytes> map_;
};

inline Bytes cat(const Bytes & a, const Bytes & b) {
  Bytes out = a;
  out.insert(out.end(), b.begin(), b.end());
  return out;
}

/** A random source that returns scripted chunks, then fails the test. */
struct ScriptedRandom {
  std::deque<Bytes> chunks;
  int draws = 0;
  static GTLS_Result fn(void * user, void * out, size_t n) {
    ScriptedRandom * self = static_cast<ScriptedRandom *>(user);
    self->draws++;
    if (self->chunks.empty()) {
      ADD_FAILURE() << "random drawn with nothing scripted";
      return GTLS_ERR_IO;
    }
    Bytes chunk = self->chunks.front();
    self->chunks.pop_front();
    EXPECT_EQ(chunk.size(), n);
    if (chunk.size() != n) {
      return GTLS_ERR_IO;
    }
    std::memcpy(out, chunk.data(), n);
    return GTLS_OK;
  }
};

/** A chain verdict that is whatever the test says, counted. */
struct FixedVerdict {
  GTLS_Result result = GTLS_OK;
  int calls = 0;
  static GTLS_Result fn(void * user, const GTLS_Conn *, const GTLS_CertificateMsg *,
      int64_t) {
    FixedVerdict * self = static_cast<FixedVerdict *>(user);
    self->calls++;
    return self->result;
  }
};

/** gtls_conn_server_name_acknowledged as a plain value, failing the test if it errs. */
inline int sni_ack(const GTLS_Conn * c) {
  int v = -1;
  EXPECT_EQ(gtls_conn_server_name_acknowledged(c, &v), GTLS_OK);
  return v;
}

/** An empty trust store, for the tests that supply their own verdict. */
struct EmptyTrust {
  GCERT_TrustStore * store = nullptr;
  EmptyTrust() { EXPECT_EQ(gcert_trust_new(nullptr, nullptr, &store), GCERT_OK); }
  ~EmptyTrust() { gcert_trust_free(store); }
};

} /* namespace gtlstest */

#endif /* GHOTI_IO_GTLS_TEST_HELPERS_H */
