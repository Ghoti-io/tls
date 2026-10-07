/**
 * @file
 *
 * The context and connection API, and a whole handshake with real
 * certificates: a chain built in memory, checked by `certificate` against a
 * trust store, a CertificateVerify signed by the leaf's key, and a Finished
 * the simulated server checks in the other direction.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "sim.h"

#include <algorithm>

using namespace gtlstest;

/* ---------------------------------------------------------------- context */

TEST(Context, DefaultConfigAsksForTls13ClientOnly) {
  GTLS_ContextConfig c;
  std::memset(&c, 0xff, sizeof c);
  gtls_context_config_default(&c);
  EXPECT_EQ(c.role, GTLS_ROLE_CLIENT);
  EXPECT_EQ(c.versions, GTLS_VERSION_TLS13);
  EXPECT_EQ(c.trust, nullptr);
  EXPECT_EQ(c.alpn_count, 0u);
  EXPECT_EQ(c.chain_count, 0u);
  EXPECT_EQ(c.key, nullptr);
  EXPECT_EQ(c.psk, nullptr);
  EXPECT_EQ(c.middlebox_compat, 0);
  gtls_context_config_default(nullptr);
}

TEST(Context, NeedsATrustStore) {
  GTLS_ContextConfig c;
  GTLS_Context * ctx = nullptr;
  gtls_context_config_default(&c);
  EXPECT_EQ(gtls_context_new(nullptr, &c, &ctx), GTLS_ERR_INVALID)
      << "there is no mode that skips the chain check";
  EXPECT_EQ(ctx, nullptr);
  EXPECT_EQ(gtls_context_new(nullptr, nullptr, &ctx), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_context_new(nullptr, &c, nullptr), GTLS_ERR_INVALID);
}

TEST(Context, WhatIsNotBuiltIsRefusedNotIgnored) {
  EmptyTrust trust;
  GTLS_Context * ctx = nullptr;
  GTLS_ContextConfig c;
  gtls_context_config_default(&c);
  c.trust = trust.store;
  c.role = GTLS_ROLE_SERVER;
  EXPECT_EQ(gtls_context_new(nullptr, &c, &ctx), GTLS_ERR_INVALID)
      << "the server role is built; one with no identity has nothing to present";
  gtls_context_config_default(&c);
  c.trust = trust.store;
  c.versions = GTLS_VERSION_TLS13 | GTLS_VERSION_TLS12;
  EXPECT_EQ(gtls_context_new(nullptr, &c, &ctx), GTLS_ERR_UNSUPPORTED);
  c.versions = GTLS_VERSION_TLS12;
  EXPECT_EQ(gtls_context_new(nullptr, &c, &ctx), GTLS_ERR_UNSUPPORTED);
  c.versions = 0;
  EXPECT_EQ(gtls_context_new(nullptr, &c, &ctx), GTLS_ERR_INVALID);
  c.versions = 0x80;
  EXPECT_EQ(gtls_context_new(nullptr, &c, &ctx), GTLS_ERR_INVALID);

  gtls_context_config_default(&c);
  c.trust = trust.store;
  unsigned char der[1] = {0};
  const void * chain[1] = {der};
  size_t lens[1] = {1};
  c.chain = chain;
  c.chain_lens = lens;
  c.chain_count = 1;
  EXPECT_EQ(gtls_context_new(nullptr, &c, &ctx), GTLS_ERR_UNSUPPORTED) << "client authentication";
  gtls_context_config_default(&c);
  c.trust = trust.store;
  unsigned char psk[4] = {1, 2, 3, 4};
  c.psk = psk;
  c.psk_len = 4;
  EXPECT_EQ(gtls_context_new(nullptr, &c, &ctx), GTLS_ERR_UNSUPPORTED) << "a pre-shared key";
  EXPECT_EQ(ctx, nullptr);
}

TEST(Context, ValidatesLists) {
  EmptyTrust trust;
  GTLS_Context * ctx = nullptr;
  GTLS_ContextConfig c;
  gtls_context_config_default(&c);
  c.trust = trust.store;

  GTLS_Suite bad_suite[1] = {static_cast<GTLS_Suite>(0x1304)};
  c.suites = bad_suite;
  c.suite_count = 1;
  EXPECT_EQ(gtls_context_new(nullptr, &c, &ctx), GTLS_ERR_INVALID) << "CCM is never offered";
  GTLS_Suite dup[2] = {GTLS_SUITE_AES_128_GCM_SHA256, GTLS_SUITE_AES_128_GCM_SHA256};
  c.suites = dup;
  c.suite_count = 2;
  EXPECT_EQ(gtls_context_new(nullptr, &c, &ctx), GTLS_ERR_INVALID);
  c.suites = nullptr;
  c.suite_count = 1;
  EXPECT_EQ(gtls_context_new(nullptr, &c, &ctx), GTLS_ERR_INVALID) << "a count with no list";
  c.suite_count = 0;

  GTLS_Group bad_group[1] = {static_cast<GTLS_Group>(0x0100)};
  c.groups = bad_group;
  c.group_count = 1;
  EXPECT_EQ(gtls_context_new(nullptr, &c, &ctx), GTLS_ERR_INVALID) << "no FFDHE";
  c.groups = nullptr;
  c.group_count = 0;

  GCERT_SigScheme bad_sig[1] = {static_cast<GCERT_SigScheme>(0x0201)};
  c.sig_algs = bad_sig;
  c.sig_alg_count = 1;
  EXPECT_EQ(gtls_context_new(nullptr, &c, &ctx), GTLS_ERR_INVALID) << "no SHA-1";
  c.sig_algs = nullptr;
  c.sig_alg_count = 0;

  const char * empty_name[1] = {""};
  c.alpn = empty_name;
  c.alpn_count = 1;
  EXPECT_EQ(gtls_context_new(nullptr, &c, &ctx), GTLS_ERR_INVALID);
  std::string long_name(256, 'x');
  const char * too_long[1] = {long_name.c_str()};
  c.alpn = too_long;
  EXPECT_EQ(gtls_context_new(nullptr, &c, &ctx), GTLS_ERR_INVALID);
  std::string name255(255, 'x');
  const char * ok[5] = {name255.c_str(), name255.c_str(), name255.c_str(), name255.c_str(),
      name255.c_str()};
  c.alpn = ok;
  c.alpn_count = 3;
  EXPECT_EQ(gtls_context_new(nullptr, &c, &ctx), GTLS_OK) << "3 * 256 fits in 1024";
  gtls_context_free(ctx);
  ctx = nullptr;
  c.alpn_count = 4;
  EXPECT_EQ(gtls_context_new(nullptr, &c, &ctx), GTLS_OK) << "4 * 256 is exactly 1024";
  gtls_context_free(ctx);
  ctx = nullptr;
  c.alpn_count = 5;
  EXPECT_EQ(gtls_context_new(nullptr, &c, &ctx), GTLS_ERR_LIMIT) << "5 * 256 does not";
  EXPECT_EQ(ctx, nullptr);
}

TEST(Context, CopiesItsListsSoTheCallersMayGo) {
  EmptyTrust trust;
  GTLS_Context * ctx = nullptr;
  GTLS_ContextConfig c;
  gtls_context_config_default(&c);
  c.trust = trust.store;
  char name[3] = {'h', '2', 0};
  const char * alpn[1] = {name};
  c.alpn = alpn;
  c.alpn_count = 1;
  ASSERT_EQ(gtls_context_new(nullptr, &c, &ctx), GTLS_OK);
  name[0] = 'x';
  GTLS_Conn * conn = nullptr;
  ASSERT_EQ(gtls_conn_new(ctx, "example.test", 12, &conn), GTLS_OK);
  ASSERT_EQ(gtls_conn_start(conn), GTLS_OK);
  const unsigned char * p;
  size_t n;
  ASSERT_EQ(gtls_conn_pending_output(conn, GTLS_EPOCH_INITIAL, &p, &n), GTLS_OK);
  Bytes hello(p, p + n);
  const Bytes needle = {0, 16, 0, 5, 0, 3, 2, 'h', '2'};
  EXPECT_NE(std::search(hello.begin(), hello.end(), needle.begin(), needle.end()), hello.end());
  gtls_conn_free(conn);
  gtls_context_free(ctx);
}

/* ------------------------------------------------------------- connection */

TEST(Conn, NewRejectsBadArguments) {
  EmptyTrust trust;
  GTLS_Context * ctx = nullptr;
  GTLS_ContextConfig c;
  gtls_context_config_default(&c);
  c.trust = trust.store;
  ASSERT_EQ(gtls_context_new(nullptr, &c, &ctx), GTLS_OK);
  GTLS_Conn * conn = nullptr;
  EXPECT_EQ(gtls_conn_new(nullptr, "a", 1, &conn), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_new(ctx, nullptr, 1, &conn), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_new(ctx, "a", 0, &conn), GTLS_ERR_INVALID);
  std::string long_host(256, 'a');
  EXPECT_EQ(gtls_conn_new(ctx, long_host.data(), 256, &conn), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_new(ctx, "a", 1, nullptr), GTLS_ERR_INVALID);
  EXPECT_EQ(conn, nullptr);
  ASSERT_EQ(gtls_conn_new(ctx, long_host.data(), 255, &conn), GTLS_OK);
  gtls_conn_free(conn);
  gtls_context_free(ctx);
  gtls_conn_free(nullptr);
  gtls_context_free(nullptr);
}

TEST(Conn, CallsOutOfOrderAreInvalidAndChangeNothing) {
  World w;
  w.build();
  const Bytes b = {1, 2, 3};
  EXPECT_EQ(gtls_conn_feed(w.conn, GTLS_EPOCH_INITIAL, b.data(), b.size(), kNow), GTLS_ERR_INVALID)
      << "before start";
  EXPECT_FALSE(gtls_conn_is_failed(w.conn));
  ASSERT_EQ(gtls_conn_start(w.conn), GTLS_OK);
  EXPECT_EQ(gtls_conn_start(w.conn), GTLS_ERR_INVALID) << "twice";
  EXPECT_FALSE(gtls_conn_is_failed(w.conn));
  EXPECT_EQ(gtls_conn_feed(w.conn, static_cast<GTLS_Epoch>(9), b.data(), 1, kNow), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_feed(w.conn, GTLS_EPOCH_INITIAL, nullptr, 1, kNow), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_feed(w.conn, GTLS_EPOCH_INITIAL, nullptr, 0, kNow), GTLS_OK);
  const unsigned char * p;
  size_t n;
  EXPECT_EQ(gtls_conn_pending_output(w.conn, static_cast<GTLS_Epoch>(4), &p, &n), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_consume_output(w.conn, GTLS_EPOCH_INITIAL, 1u << 20), GTLS_ERR_INVALID);
  EXPECT_FALSE(gtls_conn_is_failed(w.conn));
}

TEST(Conn, NullConnectionIsSafeToAskAbout) {
  EXPECT_FALSE(gtls_conn_is_connected(nullptr));
  EXPECT_FALSE(gtls_conn_is_failed(nullptr));
  EXPECT_EQ(gtls_conn_failure(nullptr), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_alert(nullptr), GTLS_ALERT_NONE);
  EXPECT_EQ(gtls_conn_suite(nullptr), GTLS_SUITE_NONE);
  EXPECT_EQ(gtls_conn_group(nullptr), GTLS_GROUP_NONE);
  int ack = 0;
  EXPECT_EQ(gtls_conn_server_name_acknowledged(nullptr, &ack), GTLS_ERR_INVALID);
  EXPECT_FALSE(gtls_conn_retried(nullptr));
  size_t n;
  const unsigned char * p;
  EXPECT_EQ(gtls_conn_alpn(nullptr, &p, &n), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_peer_certificate(nullptr, &p, &n), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_secret(nullptr, GTLS_EPOCH_HANDSHAKE, GTLS_DIR_READ, nullptr, 0, &n),
      GTLS_ERR_INVALID);
}

TEST(Conn, TheClientHelloAsTheLibraryBuildsIt) {
  World w;
  w.alpn = {"h2", "http/1.1"};
  w.build();
  ASSERT_EQ(gtls_conn_start(w.conn), GTLS_OK);
  Bytes ch = w.out(GTLS_EPOCH_INITIAL);
  ASSERT_GT(ch.size(), 4u);
  GTLS_Limits lim;
  gtls_limits_default(&lim);
  GTLS_ClientHello h;
  ASSERT_EQ(gtls_msg_parse_client_hello(ch.data() + 4, ch.size() - 4, &lim, &h), GTLS_OK);
  EXPECT_EQ(h.session_id_len, 0u);
  EXPECT_EQ(h.suites_len, 6u);
  const GTLS_Ext * sn = gtls_msg_find_ext(h.exts, h.ext_count, GTLS_EXT_SERVER_NAME);
  ASSERT_NE(sn, nullptr);
  EXPECT_EQ(sn->len, 2u + 3u + 12u);
  EXPECT_NE(gtls_msg_find_ext(h.exts, h.ext_count, GTLS_EXT_ALPN), nullptr);
  /* One key share, X25519, 32 bytes. */
  const GTLS_Ext * ks = gtls_msg_find_ext(h.exts, h.ext_count, GTLS_EXT_KEY_SHARE);
  ASSERT_NE(ks, nullptr);
  EXPECT_EQ(Bytes(ks->data, ks->data + 6), (Bytes{0, 36, 0x00, 0x1d, 0, 32}));
  /* The random differs between two connections. */
  World w2;
  w2.build();
  ASSERT_EQ(gtls_conn_start(w2.conn), GTLS_OK);
  Bytes ch2 = w2.out(GTLS_EPOCH_INITIAL);
  EXPECT_NE(Bytes(ch.begin() + 6, ch.begin() + 38), Bytes(ch2.begin() + 6, ch2.begin() + 38));
  EXPECT_EQ(gtls_conn_state(w.conn), GTLS_STATE_WAIT_SH);
}

TEST(Conn, AnIpLiteralIsNeverSentAsServerName) {
  for (const char * host : {"192.0.2.7", "2001:db8::1"}) {
    World w;
    w.host = host;
    w.build();
    ASSERT_EQ(gtls_conn_start(w.conn), GTLS_OK);
    Bytes ch = w.out(GTLS_EPOCH_INITIAL);
    GTLS_Limits lim;
    gtls_limits_default(&lim);
    GTLS_ClientHello h;
    ASSERT_EQ(gtls_msg_parse_client_hello(ch.data() + 4, ch.size() - 4, &lim, &h), GTLS_OK);
    EXPECT_EQ(gtls_msg_find_ext(h.exts, h.ext_count, GTLS_EXT_SERVER_NAME), nullptr) << host;
  }
}

TEST(Conn, MiddleboxCompatibilitySendsAThirtyTwoByteSessionId) {
  World w;
  w.cfg.middlebox_compat = 1;
  w.build();
  ASSERT_EQ(gtls_conn_start(w.conn), GTLS_OK);
  Bytes ch = w.out(GTLS_EPOCH_INITIAL);
  EXPECT_EQ(ch[4 + 2 + 32], 32);
  /* ...and the server must echo it. A server that does not is refused. */
  SimOptions o = w.server_options();
  o.mut_sh = [](Bytes & m) {
    /* the session id echo sits after the 4-byte header, version and random */
    m[4 + 2 + 32] = 0;
    m.erase(m.begin() + 4 + 2 + 32 + 1, m.begin() + 4 + 2 + 32 + 1 + 32);
    m[1] = 0;
    m[2] = (m.size() - 4) >> 8;
    m[3] = (m.size() - 4) & 255;
  };
  SimServer s(o);
  World w2;
  w2.cfg.middlebox_compat = 1;
  w2.build();
  EXPECT_EQ(w2.run(s), GTLS_ERR_PROTOCOL);
  EXPECT_EQ(gtls_conn_alert(w2.conn), GTLS_ALERT_ILLEGAL_PARAMETER);
}

/* ------------------------------------------------- a whole real handshake */

class RealHandshake : public ::testing::TestWithParam<std::tuple<GTLS_Suite, GTLS_Group, size_t>> {};

TEST_P(RealHandshake, CompletesAndBothSidesAgreeOnEverySecret) {
  World w;
  w.build();
  SimOptions o = w.server_options();
  o.suite = std::get<0>(GetParam());
  o.group = std::get<1>(GetParam());
  /* The client sends a share for its first group only; any other is a retry. */
  o.hrr = o.group != GTLS_GROUP_X25519;
  o.hrr_group = o.group;
  SimServer s(o);
  ASSERT_EQ(w.run(s, std::get<2>(GetParam())), GTLS_OK);
  EXPECT_TRUE(gtls_conn_is_connected(w.conn));
  EXPECT_EQ(gtls_conn_suite(w.conn), o.suite);
  EXPECT_EQ(gtls_conn_group(w.conn), o.group);
  EXPECT_EQ(gtls_conn_retried(w.conn), o.hrr ? 1 : 0);

  /* The client's Finished is the one the server computed independently. */
  EXPECT_EQ(w.out(GTLS_EPOCH_HANDSHAKE), s.expected_client_finished);
  size_t hlen = gtls_hash_len(gtls_suite_hash(o.suite));
  Bytes buf(GTLS_HASH_MAX);
  size_t n = 0;
  ASSERT_EQ(gtls_conn_secret(w.conn, GTLS_EPOCH_APPLICATION, GTLS_DIR_WRITE, buf.data(), buf.size(), &n),
      GTLS_OK);
  ASSERT_EQ(n, hlen);
  EXPECT_EQ(Bytes(buf.begin(), buf.begin() + n), Bytes(s.sched.c_ap, s.sched.c_ap + hlen));
  ASSERT_EQ(gtls_conn_secret(w.conn, GTLS_EPOCH_APPLICATION, GTLS_DIR_READ, buf.data(), buf.size(), &n),
      GTLS_OK);
  EXPECT_EQ(Bytes(buf.begin(), buf.begin() + n), Bytes(s.sched.s_ap, s.sched.s_ap + hlen));
  ASSERT_EQ(gtls_conn_secret(w.conn, GTLS_EPOCH_HANDSHAKE, GTLS_DIR_READ, buf.data(), buf.size(), &n),
      GTLS_OK);
  EXPECT_EQ(Bytes(buf.begin(), buf.begin() + n), Bytes(s.sched.s_hs, s.sched.s_hs + hlen));
  /* A cap too small is a limit, not a truncation. */
  EXPECT_EQ(gtls_conn_secret(w.conn, GTLS_EPOCH_APPLICATION, GTLS_DIR_READ, buf.data(), hlen - 1, &n),
      GTLS_ERR_LIMIT);

  const unsigned char * der = nullptr;
  size_t der_len = 0;
  ASSERT_EQ(gtls_conn_peer_certificate(w.conn, &der, &der_len), GTLS_OK);
  EXPECT_EQ(Bytes(der, der + der_len), w.pki.leaf);
}

INSTANTIATE_TEST_SUITE_P(Suites, RealHandshake,
    ::testing::Combine(
        ::testing::Values(GTLS_SUITE_AES_128_GCM_SHA256, GTLS_SUITE_AES_256_GCM_SHA384,
            GTLS_SUITE_CHACHA20_POLY1305_SHA256),
        ::testing::Values(GTLS_GROUP_X25519, GTLS_GROUP_SECP256R1, GTLS_GROUP_SECP384R1),
        ::testing::Values<size_t>(0, 1)),
    [](const ::testing::TestParamInfo<std::tuple<GTLS_Suite, GTLS_Group, size_t>> & info) {
      return std::to_string(static_cast<int>(std::get<0>(info.param))) + "_" +
          std::to_string(static_cast<int>(std::get<1>(info.param))) + "_chunk" +
          std::to_string(std::get<2>(info.param));
    });

TEST(RealHandshakeVariants, ChainInAnyOrderWithExtrasStillVerifies) {
  World w;
  w.build();
  SimOptions o = w.server_options();
  CertSpec stray;
  stray.subject = "stray";
  stray.issuer = "nobody";
  stray.key_tag = 9;
  stray.signer_tag = 9;
  o.chain = {w.pki.leaf, make_cert(stray), w.pki.inter, w.pki.root};
  SimServer s(o);
  EXPECT_EQ(w.run(s), GTLS_OK);
  EXPECT_TRUE(gtls_conn_is_connected(w.conn));
}

TEST(RealHandshakeVariants, AlpnAndServerNameAreReported) {
  World w;
  w.alpn = {"h2", "http/1.1"};
  w.build();
  SimOptions o = w.server_options();
  o.alpn = Bytes{'h', '2'};
  SimServer s(o);
  ASSERT_EQ(w.run(s), GTLS_OK);
  const unsigned char * p = nullptr;
  size_t n = 0;
  ASSERT_EQ(gtls_conn_alpn(w.conn, &p, &n), GTLS_OK);
  EXPECT_EQ(Bytes(p, p + n), (Bytes{'h', '2'}));
  EXPECT_TRUE(sni_ack(w.conn));
}

TEST(RealHandshakeVariants, AServerThatAnswersNeitherIsStillAccepted) {
  World w;
  w.alpn = {"h2"};
  w.build();
  SimOptions o = w.server_options();
  o.ack_sni = false;
  SimServer s(o);
  ASSERT_EQ(w.run(s), GTLS_OK);
  const unsigned char * p = nullptr;
  size_t n = 99;
  ASSERT_EQ(gtls_conn_alpn(w.conn, &p, &n), GTLS_OK);
  EXPECT_EQ(n, 0u);
  EXPECT_FALSE(sni_ack(w.conn));
}

TEST(RealHandshakeVariants, CertificateVerifyByEcdsaAndEd25519SchemesBothWorkOrAreRefusedByFit) {
  /* The leaf in the test PKI is Ed25519, so 0x0807 verifies; ECDSA schemes do
   * not fit its key and are refused rather than tried. */
  World w;
  w.build();
  SimOptions o = w.server_options();
  o.cv_scheme = 0x0403;
  SimServer s(o);
  EXPECT_EQ(w.run(s), GTLS_ERR_PROTOCOL);
  EXPECT_EQ(gtls_conn_alert(w.conn), GTLS_ALERT_ILLEGAL_PARAMETER);
}

/* ---------------------------------------------- what is readable, and when */

TEST(Accessors, PeerCertificateWaitsForTheEndOfTheHandshake) {
  World w;
  w.build();
  SimServer s(w.server_options());
  ASSERT_EQ(gtls_conn_start(w.conn), GTLS_OK);
  Bytes ch = w.out(GTLS_EPOCH_INITIAL);
  w.drain(GTLS_EPOCH_INITIAL);
  s.accept_hello(ch);
  ASSERT_EQ(w.feed(GTLS_EPOCH_INITIAL, s.sh_msg), GTLS_OK);
  const unsigned char * der = reinterpret_cast<const unsigned char *>("x");
  size_t n = 7;
  for (const Bytes * m : {&s.ee_wire, &s.cert_msg, &s.cv_msg}) {
    ASSERT_EQ(w.feed(GTLS_EPOCH_HANDSHAKE, *m), GTLS_OK);
    der = reinterpret_cast<const unsigned char *>("x");
    n = 7;
    ASSERT_EQ(gtls_conn_peer_certificate(w.conn, &der, &n), GTLS_OK);
    EXPECT_EQ(der, nullptr) << "chain accepted is not yet trusted";
    EXPECT_EQ(n, 0u);
  }
  ASSERT_EQ(w.feed(GTLS_EPOCH_HANDSHAKE, s.fin_msg), GTLS_OK);
  ASSERT_EQ(gtls_conn_peer_certificate(w.conn, &der, &n), GTLS_OK);
  EXPECT_EQ(Bytes(der, der + n), w.pki.leaf);
}

TEST(Accessors, CertificateAlpnAndServerNameAreRefusedAfterAFailure) {
  World w;
  w.alpn = {"h2"};
  w.build();
  SimOptions o = w.server_options();
  o.alpn = Bytes{'h', '2'};
  o.bad_finished = true;
  SimServer s(o);
  ASSERT_EQ(w.run(s), GTLS_ERR_FINISHED);
  const unsigned char * p = nullptr;
  size_t n = 0;
  int ack = 5;
  EXPECT_EQ(gtls_conn_alpn(w.conn, &p, &n), GTLS_ERR_FAILED);
  EXPECT_EQ(gtls_conn_server_name_acknowledged(w.conn, &ack), GTLS_ERR_FAILED);
  EXPECT_EQ(gtls_conn_peer_certificate(w.conn, &p, &n), GTLS_ERR_FAILED);
}

TEST(Accessors, InternalAccessorsCheckTheirArguments) {
  unsigned char buf[GTLS_HASH_MAX];
  size_t n = 0;
  EXPECT_EQ(gtls_conn_state(nullptr), GTLS_STATE_FAILED);
  EXPECT_EQ(gtls_conn_debug_secret(nullptr, GTLS_SECRET_EARLY, buf, sizeof buf, &n), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_debug_transcript(nullptr, buf, sizeof buf, &n), GTLS_ERR_INVALID);
  EXPECT_TRUE(gtls_conn_secrets_are_wiped(nullptr));
  World w;
  w.build();
  EXPECT_EQ(gtls_conn_debug_secret(w.conn, GTLS_SECRET_EARLY, nullptr, 0, &n), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_debug_secret(w.conn, GTLS_SECRET_EARLY, buf, sizeof buf, nullptr), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_debug_transcript(w.conn, nullptr, 0, &n), GTLS_ERR_INVALID);
}

TEST(Conn, StartRawOnAFailedConnectionIsFailedLikeStart) {
  World w;
  w.limits.max_output_bytes = 16;
  w.build();
  ASSERT_EQ(gtls_conn_start(w.conn), GTLS_ERR_LIMIT);
  const Bytes hello(40, 1);
  const Bytes key(32, 2);
  EXPECT_EQ(gtls_conn_start_raw(w.conn, hello.data(), hello.size(), key.data()), GTLS_ERR_FAILED);
}

TEST(Conn, HostsThatCannotBeSentOrCheckedAreInvalid) {
  EmptyTrust trust;
  GTLS_Context * ctx = nullptr;
  GTLS_ContextConfig c;
  gtls_context_config_default(&c);
  c.trust = trust.store;
  ASSERT_EQ(gtls_context_new(nullptr, &c, &ctx), GTLS_OK);
  const std::string bad[] = {std::string("exa\0mple.test", 13), "caf\xc3\xa9.test", "example.test.",
      "a.\x80", "."};
  for (const std::string & h : bad) {
    GTLS_Conn * conn = nullptr;
    EXPECT_EQ(gtls_conn_new(ctx, h.data(), h.size(), &conn), GTLS_ERR_INVALID) << h;
    EXPECT_EQ(conn, nullptr);
  }
  GTLS_Conn * conn = nullptr;
  EXPECT_EQ(gtls_conn_new(ctx, "example.test", 12, &conn), GTLS_OK);
  gtls_conn_free(conn);
  gtls_context_free(ctx);
}

TEST(Context, SignatureSchemesNoServerCouldUseAreRefusedUpFront) {
  EmptyTrust trust;
  GTLS_Context * ctx = nullptr;
  GTLS_ContextConfig c;
  gtls_context_config_default(&c);
  c.trust = trust.store;
  static const GCERT_SigScheme pkcs1[2] = {GCERT_SIG_RSA_PKCS1_SHA256, GCERT_SIG_RSA_PKCS1_SHA384};
  c.sig_algs = pkcs1;
  c.sig_alg_count = 2;
  EXPECT_EQ(gtls_context_new(nullptr, &c, &ctx), GTLS_ERR_INVALID)
      << "TLS 1.3 forbids PKCS#1 in CertificateVerify";
  static const GCERT_SigScheme mixed[2] = {GCERT_SIG_RSA_PKCS1_SHA256, GCERT_SIG_ED25519};
  c.sig_algs = mixed;
  EXPECT_EQ(gtls_context_new(nullptr, &c, &ctx), GTLS_OK);
  gtls_context_free(ctx);
}

/* ------------------------------------------ ephemeral scalar rejection */

namespace {

const Bytes kP256Order = from_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
const Bytes kP384Order = from_hex(
    "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973");

/** The 04||x||y a P-256 or P-384 scalar yields. */
Bytes point_for(GTLS_Group g, const Bytes & scalar) {
  Bytes raw(g == GTLS_GROUP_SECP256R1 ? 64 : 96);
  GSEC_Result r = g == GTLS_GROUP_SECP256R1 ? gsec_ecdh_p256_public(scalar.data(), raw.data())
                                             : gsec_ecdh_p384_public(scalar.data(), raw.data());
  EXPECT_EQ(r, GSEC_OK);
  Bytes out{4};
  out.insert(out.end(), raw.begin(), raw.end());
  return out;
}

bool has(const Bytes & hay, const Bytes & needle) {
  return std::search(hay.begin(), hay.end(), needle.begin(), needle.end()) != hay.end();
}

}  // namespace

class ScalarRejection : public ::testing::TestWithParam<GTLS_Group> {};

TEST_P(ScalarRejection, ZeroTheOrderAndAllOnesAreSkippedAndTheValidOneIsUsedOnStart) {
  const GTLS_Group g = GetParam();
  const size_t len = g == GTLS_GROUP_SECP256R1 ? 32 : 48;
  const Bytes & order = g == GTLS_GROUP_SECP256R1 ? kP256Order : kP384Order;
  const Bytes good(len, 0x22);
  Bytes order_plus_one = order;
  order_plus_one.back() += 1;
  World w;
  GTLS_Group groups[1] = {g};
  w.cfg.groups = groups;
  w.cfg.group_count = 1;
  w.build();
  ScriptedRandom rnd;
  rnd.chunks = {Bytes(32, 0x61), Bytes(len, 0), order, order_plus_one, Bytes(len, 0xff), good};
  gtls_conn_set_hooks(w.conn, ScriptedRandom::fn, &rnd, nullptr, nullptr);
  ASSERT_EQ(gtls_conn_start(w.conn), GTLS_OK);
  EXPECT_EQ(rnd.draws, 6);
  EXPECT_TRUE(rnd.chunks.empty());
  EXPECT_TRUE(has(w.out(GTLS_EPOCH_INITIAL), point_for(g, good))) << "the valid scalar's share";
  EXPECT_TRUE(has(Bytes(w.conn->sec.p256, w.conn->sec.p256 + 32), Bytes(32, 0x22)) ||
              has(Bytes(w.conn->sec.p384, w.conn->sec.p384 + 48), Bytes(48, 0x22)));
}

TEST_P(ScalarRejection, TheSameOnAHelloRetryRequestRetry) {
  const GTLS_Group g = GetParam();
  const size_t len = g == GTLS_GROUP_SECP256R1 ? 32 : 48;
  const Bytes & order = g == GTLS_GROUP_SECP256R1 ? kP256Order : kP384Order;
  const Bytes good(len, 0x23);
  World w;
  w.build();
  ScriptedRandom rnd;
  rnd.chunks = {Bytes(32, 0x61), Bytes(32, 0x66), Bytes(len, 0), order, Bytes(len, 0xff), good};
  gtls_conn_set_hooks(w.conn, ScriptedRandom::fn, &rnd, nullptr, nullptr);
  SimOptions o = w.server_options();
  o.hrr = true;
  o.hrr_group = g;
  SimServer s(o);
  ASSERT_EQ(gtls_conn_start(w.conn), GTLS_OK);
  Bytes ch = w.out(GTLS_EPOCH_INITIAL);
  w.drain(GTLS_EPOCH_INITIAL);
  s.accept_hello(ch);
  ASSERT_EQ(w.feed(GTLS_EPOCH_INITIAL, s.hrr_msg), GTLS_OK);
  EXPECT_EQ(rnd.draws, 6);
  EXPECT_TRUE(has(w.out(GTLS_EPOCH_INITIAL), point_for(g, good)));
}

TEST_P(ScalarRejection, EightBadDrawsInARowIsAnInternalErrorAndAWipedConnection) {
  const GTLS_Group g = GetParam();
  const size_t len = g == GTLS_GROUP_SECP256R1 ? 32 : 48;
  World w;
  GTLS_Group groups[1] = {g};
  w.cfg.groups = groups;
  w.cfg.group_count = 1;
  w.build();
  ScriptedRandom rnd;
  rnd.chunks.push_back(Bytes(32, 0x61));
  for (int i = 0; i < 8; i++) {
    rnd.chunks.push_back(Bytes(len, 0));
  }
  gtls_conn_set_hooks(w.conn, ScriptedRandom::fn, &rnd, nullptr, nullptr);
  EXPECT_EQ(gtls_conn_start(w.conn), GTLS_ERR_INTERNAL);
  EXPECT_EQ(rnd.draws, 9) << "eight attempts, no more";
  EXPECT_TRUE(gtls_conn_is_failed(w.conn));
  EXPECT_TRUE(gtls_conn_secrets_are_wiped(w.conn));
  EXPECT_EQ(w.out(GTLS_EPOCH_INITIAL), Bytes()) << "no ClientHello was queued";
}

INSTANTIATE_TEST_SUITE_P(Curves, ScalarRejection,
    ::testing::Values(GTLS_GROUP_SECP256R1, GTLS_GROUP_SECP384R1),
    [](const ::testing::TestParamInfo<GTLS_Group> & info) {
      return info.param == GTLS_GROUP_SECP256R1 ? std::string("P256") : std::string("P384");
    });

/* --------------------------------------------- IP literals as hosts */

TEST(IpHost, AnIpSanIsAcceptedForAnAddressAndNoServerNameIsSent) {
  const struct {
    const char * host;
    Bytes ip;
  } cases[] = {{"192.0.2.7", Bytes{192, 0, 2, 7}},
      {"2001:db8::1", Bytes{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}};
  for (const auto & c : cases) {
    World w;
    w.host = c.host;
    CertSpec l;
    l.ip = c.ip;
    l.has_eku = true;
    l.eku_server = true;
    SimOptions o = w.server_options();
    o.chain = {make_cert(l), w.pki.inter};
    o.ack_sni = false;
    w.build();
    SimServer s(o);
    ASSERT_EQ(w.run(s), GTLS_OK) << c.host;
    EXPECT_TRUE(gtls_conn_is_connected(w.conn));
    EXPECT_EQ(sni_ack(w.conn), 0);
  }
}

TEST(IpHost, TheClientHelloForAnAddressHasNoServerNameAndAMismatchedSanIsRefused) {
  World w;
  w.host = "192.0.2.7";
  CertSpec l;
  l.ip = Bytes{192, 0, 2, 8};
  l.has_eku = true;
  l.eku_server = true;
  SimOptions o = w.server_options();
  o.chain = {make_cert(l), w.pki.inter};
  o.ack_sni = false;
  w.build();
  SimServer s(o);
  ASSERT_EQ(gtls_conn_start(w.conn), GTLS_OK);
  Bytes ch = w.out(GTLS_EPOCH_INITIAL);
  GTLS_Limits lim;
  gtls_limits_default(&lim);
  GTLS_ClientHello h;
  ASSERT_EQ(gtls_msg_parse_client_hello(ch.data() + 4, ch.size() - 4, &lim, &h), GTLS_OK);
  EXPECT_EQ(gtls_msg_find_ext(h.exts, h.ext_count, GTLS_EXT_SERVER_NAME), nullptr);
  w.drain(GTLS_EPOCH_INITIAL);
  s.accept_hello(ch);
  ASSERT_EQ(w.feed(GTLS_EPOCH_INITIAL, s.sh_msg), GTLS_OK);
  GTLS_Result r = GTLS_OK;
  for (const Bytes * m : {&s.ee_wire, &s.cert_msg}) {
    r = w.feed(GTLS_EPOCH_HANDSHAKE, *m);
  }
  EXPECT_EQ(r, GTLS_ERR_CERT_HOST);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
