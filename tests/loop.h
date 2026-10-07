/**
 * @file
 *
 * A real client and a real server, joined by a loopback the test pumps: what
 * one side has to send is carried to the other in pieces of any size, and
 * what each side reads is kept. No simulated peer is involved; the
 * credentials are chains `certificate` really validates.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#ifndef GHOTI_IO_GTLS_TEST_LOOP_H
#define GHOTI_IO_GTLS_TEST_LOOP_H

#include "sim.h"

#include <ghoti.io/tls/record.h>

#include <algorithm>
#include <memory>

namespace gtlstest {

inline Bytes read_file(const std::string & path) {
  std::ifstream in(path, std::ios::binary);
  EXPECT_TRUE(in.good()) << path;
  return Bytes(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

/** A chain the server presents, its key, the anchor, and the name it carries. */
struct Cred {
  Bytes root;
  std::vector<Bytes> chain;   /* leaf first */
  Bytes pkcs8;
  std::string name;
  GCERT_Key * key = nullptr;

  Cred() = default;
  Cred(const Cred &) = delete;
  Cred & operator=(const Cred &) = delete;
  ~Cred() { gcert_key_free(key); }

  void load_key() {
    ASSERT_EQ(gcert_key_from_pkcs8(nullptr, pkcs8.data(), pkcs8.size(), &key), GCERT_OK);
  }
};

/** The in-memory Ed25519 chain: root, inter, a leaf naming example.test. */
inline std::unique_ptr<Cred> ed_cred(const std::string & name = "example.test") {
  std::unique_ptr<Cred> c(new Cred);
  Pki pki;
  CertSpec l;
  l.subject = "leaf";
  l.issuer = "inter";
  l.key_tag = 3;
  l.signer_tag = 2;
  l.dns = name;
  l.has_eku = true;
  l.eku_server = true;
  c->root = pki.root;
  c->chain = {make_cert(l), pki.inter};
  c->pkcs8 = ed_pkcs8(3);
  c->name = name;
  c->load_key();
  return c;
}

/** One of tests/data/pki: kind is rsa, p256, p384 or ed. */
inline std::unique_ptr<Cred> file_cred(const std::string & kind) {
  static const std::map<std::string, std::string> names = {
      {"rsa", "rsa.example.com"}, {"p256", "www.example.com"},
      {"p384", "p384.example.com"}, {"ed", "ed.example.com"}};
  std::unique_ptr<Cred> c(new Cred);
  const std::string dir = data_dir() + "/pki/";
  c->root = read_file(dir + kind + "-ca.der");
  c->chain = {read_file(dir + kind + "-leaf.der")};
  c->pkcs8 = read_file(dir + kind + "-leaf.pkcs8");
  c->name = names.at(kind);
  c->load_key();
  return c;
}

/** What one end has read, and why it stopped. */
struct Endpoint {
  GTLS_Context * ctx = nullptr;
  GTLS_Conn * conn = nullptr;
  Bytes got;
  GTLS_Result read_end = GTLS_OK;   /* the last result of gtls_conn_read */
  GTLS_Result feed_result = GTLS_OK; /* the first result of a feed that was not OK */
  size_t sent = 0;                  /* bytes this end handed to the wire */
  ~Endpoint() {
    gtls_conn_free(conn);
    gtls_context_free(ctx);
  }
};

inline Bytes stream_out(GTLS_Conn * c) {
  const unsigned char * p = nullptr;
  size_t n = 0;
  EXPECT_EQ(gtls_conn_stream_output(c, &p, &n), GTLS_OK);
  return n == 0 ? Bytes() : Bytes(p, p + n);
}

inline void drain_reads(Endpoint & e) {
  unsigned char buf[4096];
  for (;;) {
    size_t n = 0;
    e.read_end = gtls_conn_read(e.conn, buf, sizeof buf, &n);
    if (e.read_end != GTLS_OK || n == 0) {
      return;
    }
    e.got.insert(e.got.end(), buf, buf + n);
  }
}

struct Pair {
  std::vector<Cred *> creds;          /* the server's identities; the first is the default */
  std::unique_ptr<Trust> trust;
  GTLS_ContextConfig ccfg, scfg;
  std::vector<const char *> calpn, salpn;
  std::vector<std::vector<const char *>> names;   /* per identity */
  std::vector<std::vector<const void *>> chains;
  std::vector<std::vector<size_t>> chain_lens;
  std::vector<GTLS_Identity> ids;
  GTLS_Limits climits, slimits;
  const GTLS_Allocator * allocator = nullptr;
  std::string host;
  int64_t now = kNow;
  bool auto_read = true;   /* read what arrives into Endpoint::got as it comes */
  Endpoint c, s;

  explicit Pair(std::vector<Cred *> cs) : creds(cs) {
    std::vector<Bytes> roots;
    for (Cred * cr : creds) {
      roots.push_back(cr->root);
    }
    trust.reset(new Trust(roots));
    gtls_context_config_default(&ccfg);
    gtls_context_config_default(&scfg);
    gtls_limits_default(&climits);
    gtls_limits_default(&slimits);
    host = creds[0]->name;
    names.resize(creds.size());
    for (size_t i = 0; i < creds.size(); i++) {
      names[i].push_back(creds[i]->name.c_str());
    }
  }
  explicit Pair(Cred & cr) : Pair(std::vector<Cred *>{&cr}) {}

  /** Make both contexts, both connections, and start both. */
  GTLS_Result build() {
    ccfg.trust = trust->store;
    ccfg.limits = &climits;
    if (!calpn.empty()) {
      ccfg.alpn = calpn.data();
      ccfg.alpn_count = calpn.size();
    }
    scfg.role = GTLS_ROLE_SERVER;
    scfg.limits = &slimits;
    if (!salpn.empty()) {
      scfg.alpn = salpn.data();
      scfg.alpn_count = salpn.size();
    }
    chains.assign(creds.size(), {});
    chain_lens.assign(creds.size(), {});
    ids.assign(creds.size(), GTLS_Identity());
    for (size_t i = 0; i < creds.size(); i++) {
      for (const Bytes & d : creds[i]->chain) {
        chains[i].push_back(d.data());
        chain_lens[i].push_back(d.size());
      }
      ids[i].chain = chains[i].data();
      ids[i].chain_lens = chain_lens[i].data();
      ids[i].chain_count = chains[i].size();
      ids[i].key = creds[i]->key;
      ids[i].names = names[i].empty() ? nullptr : names[i].data();
      ids[i].name_count = names[i].size();
    }
    scfg.identities = ids.data();
    scfg.identity_count = ids.size();
    GTLS_Result r = gtls_context_new(allocator, &ccfg, &c.ctx);
    if (r != GTLS_OK) {
      return r;
    }
    r = gtls_context_new(allocator, &scfg, &s.ctx);
    if (r != GTLS_OK) {
      return r;
    }
    r = gtls_conn_new(c.ctx, host.data(), host.size(), &c.conn);
    if (r != GTLS_OK) {
      return r;
    }
    r = gtls_conn_new_server(s.ctx, &s.conn);
    if (r != GTLS_OK) {
      return r;
    }
    r = gtls_conn_start(c.conn);
    if (r != GTLS_OK) {
      return r;
    }
    return gtls_conn_start(s.conn);
  }

  /**
   * Carry what @p from has to send to @p to, in pieces of @p chunk bytes (0
   * for all at once). Returns the bytes carried.
   */
  size_t carry(Endpoint & from, Endpoint & to, size_t chunk) {
    Bytes out = stream_out(from.conn);
    size_t at = 0;
    while (at < out.size()) {
      size_t n = chunk == 0 ? out.size() - at : std::min(chunk, out.size() - at);
      size_t used = 0;
      GTLS_Result r = gtls_conn_stream_feed(to.conn, out.data() + at, n, now, &used);
      if (r != GTLS_OK && to.feed_result == GTLS_OK) {
        to.feed_result = r;
      }
      if (auto_read) {
        drain_reads(to);
      }
      at += used;
      if (r != GTLS_OK || (used == 0 && n != 0)) {
        break;
      }
    }
    EXPECT_EQ(gtls_conn_stream_consume(from.conn, out.size()), GTLS_OK);
    from.sent += out.size();
    return out.size();
  }

  /** Carry bytes both ways until neither side has any. */
  void run(size_t chunk = 0, int rounds = 400) {
    for (int i = 0; i < rounds; i++) {
      size_t moved = carry(c, s, chunk) + carry(s, c, chunk);
      if (moved == 0) {
        return;
      }
    }
    ADD_FAILURE() << "the two ends were still talking after " << rounds << " rounds";
  }

  bool connected() const {
    return gtls_conn_is_connected(c.conn) && gtls_conn_is_connected(s.conn);
  }

  /** Write all of @p data from @p from, draining the output as it goes. */
  void send_all(Endpoint & from, Endpoint & to, const Bytes & data, size_t chunk = 0) {
    size_t at = 0;
    for (int i = 0; i < 100000 && at < data.size(); i++) {
      size_t w = 0;
      ASSERT_EQ(gtls_conn_write(from.conn, data.data() + at, data.size() - at, &w), GTLS_OK);
      at += w;
      carry(from, to, chunk);
    }
    ASSERT_EQ(at, data.size());
  }
};

/**
 * The same two ends, driven through the message interface, as QUIC would:
 * handshake bytes carried by epoch, no records.
 */
struct MessagePair : Pair {
  using Pair::Pair;

  static Bytes pending(Endpoint & e, GTLS_Epoch ep) {
    const unsigned char * p = nullptr;
    size_t n = 0;
    EXPECT_EQ(gtls_conn_pending_output(e.conn, ep, &p, &n), GTLS_OK);
    Bytes out = n == 0 ? Bytes() : Bytes(p, p + n);
    EXPECT_EQ(gtls_conn_consume_output(e.conn, ep, n), GTLS_OK);
    return out;
  }

  /** Carry every epoch's bytes both ways until neither has any. */
  void run(size_t chunk = 0) {
    for (int round = 0; round < 50; round++) {
      size_t moved = 0;
      for (int dir = 0; dir < 2; dir++) {
        Endpoint & from = dir == 0 ? c : s;
        Endpoint & to = dir == 0 ? s : c;
        for (int e = 0; e < GTLS_EPOCH_COUNT; e++) {
          Bytes b = pending(from, static_cast<GTLS_Epoch>(e));
          moved += b.size();
          for (size_t at = 0; at < b.size(); at += chunk == 0 ? b.size() : chunk) {
            size_t n = chunk == 0 ? b.size() : std::min(chunk, b.size() - at);
            GTLS_Result r = gtls_conn_feed(to.conn, static_cast<GTLS_Epoch>(e), b.data() + at, n, now);
            if (r != GTLS_OK && to.feed_result == GTLS_OK) {
              to.feed_result = r;
            }
          }
        }
      }
      if (moved == 0) {
        return;
      }
    }
    ADD_FAILURE() << "the message pair did not settle";
  }
};

inline Bytes pattern(size_t n, unsigned seed = 1) {
  Bytes b(n);
  for (size_t i = 0; i < n; i++) {
    b[i] = static_cast<unsigned char>((i * 7 + seed * 31 + (i >> 8)) & 0xff);
  }
  return b;
}

inline std::string result_name(GTLS_Result r) { return gtls_result_string(r); }

} /* namespace gtlstest */

#endif /* GHOTI_IO_GTLS_TEST_LOOP_H */
