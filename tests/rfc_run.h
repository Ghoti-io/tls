/**
 * @file
 *
 * Drive a connection through one of RFC 8448's traces. The ClientHello and
 * the ephemeral keys are the RFC's, handed over through the internal seam;
 * everything after that is the code that ships, except that the verdict on
 * the server's chain is the test's (the RFC's certificate is a 1024-bit
 * key in a certificate that says it is not a CA, which a real check refuses,
 * and a test below shows that it does).
 *
 * Copyright 2026 by Corey Pennycuff
 */

#ifndef GHOTI_IO_GTLS_TEST_RFC_RUN_H
#define GHOTI_IO_GTLS_TEST_RFC_RUN_H

#include "test_helpers.h"

namespace gtlstest {

struct Trace {
  const char * file;
  bool hrr;
  const char * ch1() const { return "client.construct-a-clienthello-handshake-message.clienthello"; }
  const char * ch2() const { return "client.construct-a-clienthello-handshake-message@2.clienthello"; }
  const char * x25519() const { return "client.create-an-ephemeral-x25519-key-pair.private-key"; }
  const char * p256() const { return "client.create-an-ephemeral-p-256-key-pair.private-key"; }
  const char * hrr_msg() const { return "server.construct-a-serverhello-handshake-message.serverhello"; }
  const char * sh() const {
    return hrr ? "server.construct-a-serverhello-handshake-message@2.serverhello"
               : "server.construct-a-serverhello-handshake-message.serverhello";
  }
  const char * flight() const {
    return hrr ? "server.send-handshake-record@3.payload"
               : "server.send-handshake-record@2.payload";
  }
  const char * client_finished() const {
    return "client.construct-a-finished-handshake-message.finished";
  }
};

inline Trace simple_trace() { return Trace{"simple-1rtt", false}; }
inline Trace hrr_trace() { return Trace{"hrr", true}; }

/** The RFC's server flight is EncryptedExtensions, Certificate,
 *  CertificateVerify and Finished, back to back. Split it. */
inline std::vector<Bytes> split_messages(const Bytes & flight) {
  std::vector<Bytes> out;
  size_t at = 0;
  while (at + 4 <= flight.size()) {
    size_t n = 4 + ((static_cast<size_t>(flight[at + 1]) << 16) |
                       (static_cast<size_t>(flight[at + 2]) << 8) | flight[at + 3]);
    out.push_back(Bytes(flight.begin() + at, flight.begin() + at + n));
    at += n;
  }
  EXPECT_EQ(at, flight.size());
  return out;
}

class Flow {
 public:
  Vec v;
  Trace t;
  EmptyTrust trust;
  GTLS_Context * ctx = nullptr;
  GTLS_Conn * conn = nullptr;
  ScriptedRandom rnd;
  FixedVerdict verdict;
  int64_t now = 1700000000;

  explicit Flow(const Trace & trace, unsigned alpn_count = 0) : v(trace.file), t(trace) {
    GTLS_ContextConfig cfg;
    gtls_context_config_default(&cfg);
    cfg.trust = trust.store;
    static const char * const alpn[] = {"h2", "http/1.1"};
    cfg.alpn = alpn;
    cfg.alpn_count = alpn_count;
    EXPECT_EQ(gtls_context_new(nullptr, &cfg, &ctx), GTLS_OK);
    EXPECT_EQ(gtls_conn_new(ctx, "server", 6, &conn), GTLS_OK);
    gtls_conn_set_hooks(conn, ScriptedRandom::fn, &rnd, FixedVerdict::fn, &verdict);
    if (t.hrr) {
      rnd.chunks.push_back(v[t.p256()]);
    }
  }
  ~Flow() {
    gtls_conn_free(conn);
    gtls_context_free(ctx);
  }

  void start() {
    ASSERT_EQ(gtls_conn_start_raw(conn, v[t.ch1()].data(), v[t.ch1()].size(),
                  v[t.x25519()].data()), GTLS_OK);
  }

  GTLS_Result feed(GTLS_Epoch e, const Bytes & b, size_t chunk = 0) {
    if (chunk == 0) {
      return gtls_conn_feed(conn, e, b.data(), b.size(), now);
    }
    for (size_t at = 0; at < b.size(); at += chunk) {
      size_t n = b.size() - at < chunk ? b.size() - at : chunk;
      GTLS_Result r = gtls_conn_feed(conn, e, b.data() + at, n, now);
      if (r != GTLS_OK) {
        return r;
      }
    }
    return GTLS_OK;
  }

  Bytes pending(GTLS_Epoch e) {
    const unsigned char * p = nullptr;
    size_t n = 0;
    EXPECT_EQ(gtls_conn_pending_output(conn, e, &p, &n), GTLS_OK);
    return n == 0 ? Bytes() : Bytes(p, p + n);
  }

  void take(GTLS_Epoch e) {
    Bytes b = pending(e);
    EXPECT_EQ(gtls_conn_consume_output(conn, e, b.size()), GTLS_OK);
  }

  Bytes secret(GTLS_SecretId id) {
    Bytes out(GTLS_HASH_MAX);
    size_t n = 0;
    EXPECT_EQ(gtls_conn_debug_secret(conn, id, out.data(), out.size(), &n), GTLS_OK);
    out.resize(n);
    return out;
  }

  Bytes transcript() {
    Bytes out(GTLS_HASH_MAX);
    size_t n = 0;
    EXPECT_EQ(gtls_conn_debug_transcript(conn, out.data(), out.size(), &n), GTLS_OK);
    out.resize(n);
    return out;
  }

  /** The whole handshake, HelloRetryRequest included, up to ServerHello. */
  GTLS_Result through_server_hello(size_t chunk = 0) {
    if (t.hrr) {
      GTLS_Result r = feed(GTLS_EPOCH_INITIAL, v[t.hrr_msg()], chunk);
      if (r != GTLS_OK) {
        return r;
      }
      take(GTLS_EPOCH_INITIAL);
    }
    return feed(GTLS_EPOCH_INITIAL, v[t.sh()], chunk);
  }
};

} /* namespace gtlstest */

#endif /* GHOTI_IO_GTLS_TEST_RFC_RUN_H */
