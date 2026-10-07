/**
 * @file
 *
 * ClientHellos of any shape, built byte by byte, for the server's tests: a
 * valid one by default, and a field at a time made wrong, missing or
 * repeated. Independent of the library's own ClientHello builder, which only
 * makes the one a client sends.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#ifndef GHOTI_IO_GTLS_TEST_HELLO_H
#define GHOTI_IO_GTLS_TEST_HELLO_H

#include "loop.h"

namespace gtlstest {

inline void put16(Bytes & b, unsigned v) { b.push_back(v >> 8); b.push_back(v & 255); }
inline Bytes ext_of(unsigned type, const Bytes & data) { return SimServer::ext(type, data); }
inline Bytes lp8(const Bytes & b) { Bytes o{static_cast<unsigned char>(b.size())}; o.insert(o.end(), b.begin(), b.end()); return o; }
inline Bytes lp16(const Bytes & b) { Bytes o; put16(o, b.size()); o.insert(o.end(), b.begin(), b.end()); return o; }

/** The client's key share in @p group, from a fixed private key. */
inline Bytes client_share(unsigned group) {
  if (group == GTLS_GROUP_X25519) {
    Bytes priv(32, 0x33), pub(32);
    EXPECT_EQ(gsec_x25519_public(priv.data(), pub.data()), GSEC_OK);
    return pub;
  }
  if (group == GTLS_GROUP_SECP256R1) {
    Bytes priv(32, 0x21), raw(64);
    EXPECT_EQ(gsec_ecdh_p256_public(priv.data(), raw.data()), GSEC_OK);
    Bytes pub{4};
    pub.insert(pub.end(), raw.begin(), raw.end());
    return pub;
  }
  Bytes priv(48, 0x21), raw(96);
  EXPECT_EQ(gsec_ecdh_p384_public(priv.data(), raw.data()), GSEC_OK);
  Bytes pub{4};
  pub.insert(pub.end(), raw.begin(), raw.end());
  return pub;
}

struct HelloSpec {
  unsigned legacy_version = 0x0303;
  Bytes random = Bytes(32, 0x42);
  Bytes session_id;
  std::vector<unsigned> suites = {0x1301, 0x1303, 0x1302};
  Bytes compression = Bytes{0};
  bool has_versions = true;
  std::vector<unsigned> versions = {0x0304};
  bool has_groups = true;
  std::vector<unsigned> groups = {GTLS_GROUP_X25519, GTLS_GROUP_SECP256R1, GTLS_GROUP_SECP384R1};
  bool has_sigs = true;
  std::vector<unsigned> sigs = {0x0804, 0x0805, 0x0806, 0x0403, 0x0503, 0x0807};
  bool has_key_share = true;
  std::vector<std::pair<unsigned, Bytes>> shares = {{GTLS_GROUP_X25519, client_share(GTLS_GROUP_X25519)}};
  std::string sni;
  bool has_sni = false;
  std::vector<std::string> alpn;
  bool psk_modes = true;
  std::vector<Bytes> extra;      /* whole extensions, appended */
  std::vector<Bytes> before;     /* whole extensions, put first */

  Bytes build() const {
    std::vector<Bytes> exts = before;
    if (has_sni) {
      Bytes name{0};
      Bytes h(sni.begin(), sni.end());
      Bytes entry = name;
      put16(entry, h.size());
      entry.insert(entry.end(), h.begin(), h.end());
      exts.push_back(ext_of(GTLS_EXT_SERVER_NAME, lp16(entry)));
    }
    if (has_groups) {
      Bytes l;
      for (unsigned g : groups) put16(l, g);
      exts.push_back(ext_of(GTLS_EXT_SUPPORTED_GROUPS, lp16(l)));
    }
    if (has_sigs) {
      Bytes l;
      for (unsigned s : sigs) put16(l, s);
      exts.push_back(ext_of(GTLS_EXT_SIGNATURE_ALGORITHMS, lp16(l)));
    }
    if (!alpn.empty()) {
      Bytes l;
      for (const std::string & a : alpn) {
        l.push_back(a.size());
        l.insert(l.end(), a.begin(), a.end());
      }
      exts.push_back(ext_of(GTLS_EXT_ALPN, lp16(l)));
    }
    if (has_versions) {
      Bytes l;
      for (unsigned v : versions) put16(l, v);
      exts.push_back(ext_of(GTLS_EXT_SUPPORTED_VERSIONS, lp8(l)));
    }
    if (has_key_share) {
      Bytes l;
      for (const auto & sh : shares) {
        put16(l, sh.first);
        put16(l, sh.second.size());
        l.insert(l.end(), sh.second.begin(), sh.second.end());
      }
      exts.push_back(ext_of(GTLS_EXT_KEY_SHARE, lp16(l)));
    }
    if (psk_modes) {
      exts.push_back(ext_of(GTLS_EXT_PSK_KEY_EXCHANGE_MODES, Bytes{1, 1}));
    }
    for (const Bytes & e : extra) exts.push_back(e);
    Bytes body;
    put16(body, legacy_version);
    body.insert(body.end(), random.begin(), random.end());
    body.push_back(session_id.size());
    body.insert(body.end(), session_id.begin(), session_id.end());
    Bytes s;
    for (unsigned x : suites) put16(s, x);
    put16(body, s.size());
    body.insert(body.end(), s.begin(), s.end());
    body.push_back(compression.size());
    body.insert(body.end(), compression.begin(), compression.end());
    Bytes block = SimServer::ext_block(exts);
    body.insert(body.end(), block.begin(), block.end());
    return SimServer::wrap(GTLS_HS_CLIENT_HELLO, body);
  }
};

/** A server connection fed ClientHellos at the message level. */
struct Srv {
  std::vector<Cred *> creds;
  GTLS_ContextConfig cfg;
  std::vector<const char *> alpn;
  std::vector<std::vector<const char *>> names;
  std::vector<std::vector<const void *>> chains;
  std::vector<std::vector<size_t>> chain_lens;
  std::vector<GTLS_Identity> ids;
  GTLS_Limits limits;
  const GTLS_Allocator * allocator = nullptr;
  GTLS_Context * ctx = nullptr;
  GTLS_Conn * conn = nullptr;
  int64_t now = kNow;

  explicit Srv(std::vector<Cred *> cs) : creds(cs) {
    gtls_context_config_default(&cfg);
    gtls_limits_default(&limits);
    cfg.role = GTLS_ROLE_SERVER;
    names.resize(creds.size());
    for (size_t i = 0; i < creds.size(); i++) names[i].push_back(creds[i]->name.c_str());
  }
  explicit Srv(Cred & c) : Srv(std::vector<Cred *>{&c}) {}
  ~Srv() {
    gtls_conn_free(conn);
    gtls_context_free(ctx);
  }
  GTLS_Result build() {
    cfg.limits = &limits;
    if (!alpn.empty()) {
      cfg.alpn = alpn.data();
      cfg.alpn_count = alpn.size();
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
    cfg.identities = ids.data();
    cfg.identity_count = ids.size();
    GTLS_Result r = gtls_context_new(allocator, &cfg, &ctx);
    if (r != GTLS_OK) return r;
    r = gtls_conn_new_server(ctx, &conn);
    if (r != GTLS_OK) return r;
    return gtls_conn_start(conn);
  }
  GTLS_Result hello(const Bytes & ch, GTLS_Epoch e = GTLS_EPOCH_INITIAL) {
    return gtls_conn_feed(conn, e, ch.data(), ch.size(), now);
  }
  Bytes out(GTLS_Epoch e) {
    const unsigned char * p = nullptr;
    size_t n = 0;
    EXPECT_EQ(gtls_conn_pending_output(conn, e, &p, &n), GTLS_OK);
    return n == 0 ? Bytes() : Bytes(p, p + n);
  }
  unsigned alert() const { return gtls_conn_alert(conn); }
  GTLS_State state() const { return gtls_conn_state(conn); }
};

} /* namespace gtlstest */

#endif /* GHOTI_IO_GTLS_TEST_HELLO_H */
