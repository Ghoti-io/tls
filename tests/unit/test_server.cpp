/**
 * @file
 *
 * The server's handshake. The first tests drive it with RFC 8448's
 * ClientHello and ephemeral key and require its flight to be the RFC's byte
 * for byte; the rest give it ClientHellos of every shape a client can send
 * and require each to be answered with the specific result and alert, and
 * the choices (identity, suite, group, scheme, ALPN) to be the ones the
 * context's order and the client's offer call for.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "hello.h"
#include "rfc_run.h"
#include "rfc_server.h"

using namespace gtlstest;

TEST(Rfc8448Server, TheFlightIsTheRfcsByteForByte) {
  RfcServer r;
  const Bytes & ch = r.v["client.construct-a-clienthello-handshake-message.clienthello"];
  ASSERT_EQ(gtls_conn_feed(r.conn, GTLS_EPOCH_INITIAL, ch.data(), ch.size(), r.now), GTLS_OK);
  EXPECT_EQ(gtls_conn_state(r.conn), GTLS_STATE_S_WAIT_FIN);
  EXPECT_EQ(r.pending(GTLS_EPOCH_INITIAL),
      r.v["server.construct-a-serverhello-handshake-message.serverhello"]);
  EXPECT_EQ(r.pending(GTLS_EPOCH_HANDSHAKE),
      r.v["server.send-handshake-record@2.payload"])
      << "EncryptedExtensions, Certificate, CertificateVerify and Finished";
  EXPECT_EQ(r.signed_calls, 1);
  EXPECT_TRUE(r.signature_verified);
  EXPECT_EQ(r.pending(GTLS_EPOCH_APPLICATION), Bytes()) << "no NewSessionTicket, no CertificateRequest";
  EXPECT_EQ(r.rnd.draws, 2);
  EXPECT_TRUE(r.rnd.chunks.empty());

  EXPECT_EQ(r.secret(GTLS_SECRET_HANDSHAKE), r.v["server.extract-secret-handshake.secret"]);
  EXPECT_EQ(r.secret(GTLS_SECRET_CLIENT_HS), r.v["server.derive-secret-tls13-c-hs-traffic.expanded"]);
  EXPECT_EQ(r.secret(GTLS_SECRET_SERVER_HS), r.v["server.derive-secret-tls13-s-hs-traffic.expanded"]);
  EXPECT_EQ(r.secret(GTLS_SECRET_MASTER), r.v["server.extract-secret-master.secret"]);
  EXPECT_EQ(r.secret(GTLS_SECRET_CLIENT_AP), r.v["server.derive-secret-tls13-c-ap-traffic.expanded"]);
  EXPECT_EQ(r.secret(GTLS_SECRET_SERVER_AP), r.v["server.derive-secret-tls13-s-ap-traffic.expanded"]);
  EXPECT_EQ(gtls_conn_suite(r.conn), GTLS_SUITE_AES_128_GCM_SHA256);
  EXPECT_EQ(gtls_conn_group(r.conn), GTLS_GROUP_X25519);
  int ack = -1;
  ASSERT_EQ(gtls_conn_server_name_acknowledged(r.conn, &ack), GTLS_OK);
  EXPECT_EQ(ack, 1);
  const unsigned char * alpn = nullptr;
  size_t alpn_len = 1;
  ASSERT_EQ(gtls_conn_alpn(r.conn, &alpn, &alpn_len), GTLS_OK);
  EXPECT_EQ(alpn_len, 0u);

  const Bytes & fin = r.v["client.send-handshake-record@2.payload"];
  ASSERT_EQ(gtls_conn_feed(r.conn, GTLS_EPOCH_HANDSHAKE, fin.data(), fin.size(), r.now), GTLS_OK);
  EXPECT_TRUE(gtls_conn_is_connected(r.conn));
  /* The direction is the local one: a server writes with the server's secret. */
  Bytes w(GTLS_HASH_MAX);
  size_t n = 0;
  ASSERT_EQ(gtls_conn_secret(r.conn, GTLS_EPOCH_APPLICATION, GTLS_DIR_WRITE, w.data(), w.size(), &n),
      GTLS_OK);
  w.resize(n);
  EXPECT_EQ(w, r.v["server.derive-secret-tls13-s-ap-traffic.expanded"]);
  ASSERT_EQ(gtls_conn_secret(r.conn, GTLS_EPOCH_HANDSHAKE, GTLS_DIR_READ, w.data(), GTLS_HASH_MAX, &n),
      GTLS_OK);
  w.resize(n);
  EXPECT_EQ(w, r.v["server.derive-secret-tls13-c-hs-traffic.expanded"]);
}

TEST(Rfc8448Server, TheFlightIsTheSameAtEveryFeedSize) {
  for (size_t chunk : {1u, 2u, 3u, 7u, 64u}) {
    RfcServer r;
    const Bytes & ch = r.v["client.construct-a-clienthello-handshake-message.clienthello"];
    for (size_t at = 0; at < ch.size(); at += chunk) {
      size_t n = std::min(chunk, ch.size() - at);
      ASSERT_EQ(gtls_conn_feed(r.conn, GTLS_EPOCH_INITIAL, ch.data() + at, n, r.now), GTLS_OK)
          << "chunk " << chunk;
    }
    EXPECT_EQ(r.pending(GTLS_EPOCH_HANDSHAKE), r.v["server.send-handshake-record@2.payload"])
        << "chunk " << chunk;
    const Bytes & fin = r.v["client.send-handshake-record@2.payload"];
    for (size_t at = 0; at < fin.size(); at += chunk) {
      size_t n = std::min(chunk, fin.size() - at);
      ASSERT_EQ(gtls_conn_feed(r.conn, GTLS_EPOCH_HANDSHAKE, fin.data() + at, n, r.now), GTLS_OK);
    }
    EXPECT_TRUE(gtls_conn_is_connected(r.conn));
  }
}

TEST(Rfc8448Server, ABadClientFinishedIsRefusedAndWipes) {
  RfcServer r;
  const Bytes & ch = r.v["client.construct-a-clienthello-handshake-message.clienthello"];
  ASSERT_EQ(gtls_conn_feed(r.conn, GTLS_EPOCH_INITIAL, ch.data(), ch.size(), r.now), GTLS_OK);
  Bytes fin = r.v["client.send-handshake-record@2.payload"];
  fin[10] ^= 1;
  EXPECT_EQ(gtls_conn_feed(r.conn, GTLS_EPOCH_HANDSHAKE, fin.data(), fin.size(), r.now),
      GTLS_ERR_FINISHED);
  EXPECT_EQ(gtls_conn_alert(r.conn), GTLS_ALERT_DECRYPT_ERROR);
  EXPECT_TRUE(gtls_conn_secrets_are_wiped(r.conn));
  EXPECT_FALSE(gtls_conn_is_connected(r.conn));
}

TEST(Rfc8448Server, AClientFinishedOfTheWrongLengthIsADecodeError) {
  RfcServer r;
  const Bytes & ch = r.v["client.construct-a-clienthello-handshake-message.clienthello"];
  ASSERT_EQ(gtls_conn_feed(r.conn, GTLS_EPOCH_INITIAL, ch.data(), ch.size(), r.now), GTLS_OK);
  Bytes fin = r.v["client.send-handshake-record@2.payload"];
  fin.pop_back();
  fin[3] -= 1;
  EXPECT_EQ(gtls_conn_feed(r.conn, GTLS_EPOCH_HANDSHAKE, fin.data(), fin.size(), r.now),
      GTLS_ERR_CORRUPT);
  EXPECT_EQ(gtls_conn_alert(r.conn), GTLS_ALERT_DECODE_ERROR);
}

TEST(Rfc8448Server, TheWholeTraceAsRecordsInBothDirections) {
  RfcServer r;
  const Vec & v = r.v;
  gtls_conn_set_hooks(r.conn, ScriptedRandom::fn, &r.rnd, nullptr, nullptr);
  size_t used = 0;
  const Bytes & chrec = v["client.send-handshake-record.complete-record"];
  ASSERT_EQ(gtls_conn_stream_feed(r.conn, chrec.data(), chrec.size(), r.now, &used), GTLS_OK);
  EXPECT_EQ(used, chrec.size());
  const unsigned char * out = nullptr;
  size_t n = 0;
  ASSERT_EQ(gtls_conn_stream_output(r.conn, &out, &n), GTLS_OK);
  Bytes want = cat(v["server.send-handshake-record.complete-record"],
      v["server.send-handshake-record@2.complete-record"]);
  EXPECT_EQ(Bytes(out, out + n), want) << "ServerHello as a plain record, the flight as one protected one";
  ASSERT_EQ(gtls_conn_stream_consume(r.conn, n), GTLS_OK);

  const Bytes & finrec = v["client.send-handshake-record@2.complete-record"];
  ASSERT_EQ(gtls_conn_stream_feed(r.conn, finrec.data(), finrec.size(), r.now, &used), GTLS_OK);
  EXPECT_TRUE(gtls_conn_is_connected(r.conn));

  const Bytes & app = v["client.send-application-data-record.complete-record"];
  ASSERT_EQ(gtls_conn_stream_feed(r.conn, app.data(), app.size(), r.now, &used), GTLS_OK);
  Bytes got(200);
  size_t got_n = 0;
  ASSERT_EQ(gtls_conn_read(r.conn, got.data(), got.size(), &got_n), GTLS_OK);
  got.resize(got_n);
  EXPECT_EQ(got, v["client.send-application-data-record.payload"]);

  /* The trace's server sent a NewSessionTicket first, so its data record is
   * the second under the key; this server sends none, so move its counter
   * past the one the ticket took, and what it writes is the trace's. */
  size_t written = 0;
  ASSERT_EQ(gtls_conn_write(r.conn, nullptr, 0, &written), GTLS_OK) << "installs the application keys";
  r.conn->sec.wr.seq = 1;
  const Bytes & payload = v["server.send-application-data-record.payload"];
  ASSERT_EQ(gtls_conn_write(r.conn, payload.data(), payload.size(), &written), GTLS_OK);
  EXPECT_EQ(written, payload.size());
  ASSERT_EQ(gtls_conn_stream_output(r.conn, &out, &n), GTLS_OK);
  EXPECT_EQ(Bytes(out, out + n), v["server.send-application-data-record.complete-record"]);
  ASSERT_EQ(gtls_conn_stream_consume(r.conn, n), GTLS_OK);

  /* The client's close_notify (the trace's alert record, second under its key). */
  const Bytes & alert = v["client.send-alert-record.complete-record"];
  ASSERT_EQ(gtls_conn_stream_feed(r.conn, alert.data(), alert.size(), r.now, &used), GTLS_OK);
  EXPECT_TRUE(gtls_conn_peer_closed(r.conn));
  EXPECT_EQ(gtls_conn_read(r.conn, got.data(), got.size(), &got_n), GTLS_ERR_CLOSED);

  ASSERT_EQ(gtls_conn_close(r.conn), GTLS_OK);
  ASSERT_EQ(gtls_conn_stream_output(r.conn, &out, &n), GTLS_OK);
  EXPECT_EQ(Bytes(out, out + n), v["server.send-alert-record.complete-record"]);
  EXPECT_EQ(gtls_conn_write(r.conn, payload.data(), payload.size(), &written), GTLS_ERR_CLOSED);
}

/* ------------------------------------------------------------------ the context */

namespace {

struct Cfg {
  std::unique_ptr<Cred> cred = ed_cred();
  std::vector<const void *> chain;
  std::vector<size_t> lens;
  GTLS_ContextConfig cfg;
  Cfg() {
    gtls_context_config_default(&cfg);
    cfg.role = GTLS_ROLE_SERVER;
    for (const Bytes & d : cred->chain) {
      chain.push_back(d.data());
      lens.push_back(d.size());
    }
  }
  void shorthand() {
    cfg.chain = chain.data();
    cfg.chain_lens = lens.data();
    cfg.chain_count = chain.size();
    cfg.key = cred->key;
  }
};

}  // namespace

TEST(ServerContext, TheShorthandChainAndKeyIsOneIdentity) {
  Cfg c;
  c.shorthand();
  GTLS_Context * ctx = nullptr;
  ASSERT_EQ(gtls_context_new(nullptr, &c.cfg, &ctx), GTLS_OK) << "no trust store is needed";
  GTLS_Conn * conn = nullptr;
  ASSERT_EQ(gtls_conn_new_server(ctx, &conn), GTLS_OK);
  gtls_conn_free(conn);
  gtls_context_free(ctx);
}

TEST(ServerContext, WhatIsRefused) {
  GTLS_Context * ctx = nullptr;
  {
    Cfg c;
    EXPECT_EQ(gtls_context_new(nullptr, &c.cfg, &ctx), GTLS_ERR_INVALID) << "no identity";
  }
  {
    Cfg c;
    c.shorthand();
    GTLS_Identity id = {c.chain.data(), c.lens.data(), c.chain.size(), c.cred->key, nullptr, 0};
    c.cfg.identities = &id;
    c.cfg.identity_count = 1;
    EXPECT_EQ(gtls_context_new(nullptr, &c.cfg, &ctx), GTLS_ERR_INVALID) << "both forms";
  }
  {
    Cfg c;
    c.shorthand();
    std::unique_ptr<Cred> other = file_cred("p256");
    c.cfg.key = other->key;
    EXPECT_EQ(gtls_context_new(nullptr, &c.cfg, &ctx), GTLS_ERR_INVALID)
        << "a key that is not the leaf's";
  }
  {
    Cfg c;
    c.shorthand();
    c.cfg.chain_count = 0;
    EXPECT_EQ(gtls_context_new(nullptr, &c.cfg, &ctx), GTLS_ERR_INVALID);
  }
  {
    Cfg c;
    c.shorthand();
    c.cfg.default_identity = 1;
    EXPECT_EQ(gtls_context_new(nullptr, &c.cfg, &ctx), GTLS_ERR_INVALID);
  }
  {
    Cfg c;
    c.shorthand();
    c.cfg.key = nullptr;
    EXPECT_EQ(gtls_context_new(nullptr, &c.cfg, &ctx), GTLS_ERR_INVALID);
  }
  {
    Cfg c;
    const void * junk[1] = {"not a certificate"};
    size_t jl[1] = {17};
    c.cfg.chain = junk;
    c.cfg.chain_lens = jl;
    c.cfg.chain_count = 1;
    c.cfg.key = c.cred->key;
    EXPECT_EQ(gtls_context_new(nullptr, &c.cfg, &ctx), GTLS_ERR_INVALID) << "not DER";
  }
  for (const char * bad : {"", "caf\xc3\xa9.example"}) {
    Cfg c;
    const char * names[1] = {bad};
    GTLS_Identity id = {c.chain.data(), c.lens.data(), c.chain.size(), c.cred->key, names, 1};
    c.cfg.identities = &id;
    c.cfg.identity_count = 1;
    EXPECT_EQ(gtls_context_new(nullptr, &c.cfg, &ctx), GTLS_ERR_INVALID) << "name '" << bad << "'";
  }
  {
    Cfg c;
    std::string big(256, 'a');
    const char * names[1] = {big.c_str()};
    GTLS_Identity id = {c.chain.data(), c.lens.data(), c.chain.size(), c.cred->key, names, 1};
    c.cfg.identities = &id;
    c.cfg.identity_count = 1;
    EXPECT_EQ(gtls_context_new(nullptr, &c.cfg, &ctx), GTLS_ERR_INVALID);
  }
  {
    Cfg c;
    GTLS_Identity id = {c.chain.data(), c.lens.data(), c.chain.size(), c.cred->key, nullptr, 3};
    c.cfg.identities = &id;
    c.cfg.identity_count = 1;
    EXPECT_EQ(gtls_context_new(nullptr, &c.cfg, &ctx), GTLS_ERR_INVALID) << "names counted, none given";
  }
  {
    Cfg c;
    c.shorthand();
    GTLS_Limits lim;
    gtls_limits_default(&lim);
    lim.max_output_bytes = 1500;
    c.cfg.limits = &lim;
    EXPECT_EQ(gtls_context_new(nullptr, &c.cfg, &ctx), GTLS_ERR_LIMIT)
        << "the flight would not fit the queue";
  }
  {
    Cfg c;
    c.shorthand();
    c.cfg.psk = "x";
    c.cfg.psk_len = 1;
    EXPECT_EQ(gtls_context_new(nullptr, &c.cfg, &ctx), GTLS_ERR_UNSUPPORTED);
  }
  {
    /* a client takes identities from no one */
    EmptyTrust trust;
    Cfg c;
    c.cfg.role = GTLS_ROLE_CLIENT;
    c.cfg.trust = trust.store;
    GTLS_Identity id = {c.chain.data(), c.lens.data(), c.chain.size(), c.cred->key, nullptr, 0};
    c.cfg.identities = &id;
    c.cfg.identity_count = 1;
    EXPECT_EQ(gtls_context_new(nullptr, &c.cfg, &ctx), GTLS_ERR_INVALID);
    c.cfg.identities = nullptr;
    c.cfg.identity_count = 0;
    c.shorthand();
    EXPECT_EQ(gtls_context_new(nullptr, &c.cfg, &ctx), GTLS_ERR_UNSUPPORTED) << "client authentication";
  }
  EXPECT_EQ(ctx, nullptr);
}

TEST(ServerContext, TheChainIsCopiedAndTheNamesAreFoldedToLowerCase) {
  std::unique_ptr<Cred> cred = ed_cred("example.test");
  Cfg c;
  Bytes chain0 = c.cred->chain[0];
  const void * ch[1] = {chain0.data()};
  size_t cl[1] = {chain0.size()};
  std::string name = "WWW.Example.TEST";
  const char * names[1] = {name.c_str()};
  GTLS_Identity id = {ch, cl, 1, c.cred->key, names, 1};
  c.cfg.identities = &id;
  c.cfg.identity_count = 1;
  GTLS_Context * ctx = nullptr;
  ASSERT_EQ(gtls_context_new(nullptr, &c.cfg, &ctx), GTLS_OK);
  std::fill(chain0.begin(), chain0.end(), 0);
  name.assign(name.size(), 'z');
  GTLS_Conn * conn = nullptr;
  ASSERT_EQ(gtls_conn_new_server(ctx, &conn), GTLS_OK);
  ASSERT_EQ(gtls_conn_start(conn), GTLS_OK);
  HelloSpec h;
  h.has_sni = true;
  h.sni = "www.example.test";
  Bytes ch1 = h.build();
  ASSERT_EQ(gtls_conn_feed(conn, GTLS_EPOCH_INITIAL, ch1.data(), ch1.size(), kNow), GTLS_OK)
      << "the caller's buffers were wiped and the server still has its chain";
  size_t index = 99;
  ASSERT_EQ(gtls_conn_identity(conn, &index), GTLS_OK);
  EXPECT_EQ(index, 0u);
  int ack = 0;
  ASSERT_EQ(gtls_conn_server_name_acknowledged(conn, &ack), GTLS_OK);
  EXPECT_EQ(ack, 1) << "the name matched, so the server says it used it";
  gtls_conn_free(conn);
  gtls_context_free(ctx);
}

TEST(ServerContext, ANewServerConnectionNeedsAServerContext) {
  EmptyTrust trust;
  GTLS_ContextConfig cfg;
  gtls_context_config_default(&cfg);
  cfg.trust = trust.store;
  GTLS_Context * ctx = nullptr;
  ASSERT_EQ(gtls_context_new(nullptr, &cfg, &ctx), GTLS_OK);
  GTLS_Conn * conn = nullptr;
  EXPECT_EQ(gtls_conn_new_server(ctx, &conn), GTLS_ERR_INVALID);
  EXPECT_EQ(conn, nullptr);
  EXPECT_EQ(gtls_conn_new_server(nullptr, &conn), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_new_server(ctx, nullptr), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_new(ctx, "x", 1, &conn), GTLS_OK) << "and a client context makes a client";
  gtls_conn_free(conn);
  gtls_context_free(ctx);
  Cfg c;
  c.shorthand();
  ASSERT_EQ(gtls_context_new(nullptr, &c.cfg, &ctx), GTLS_OK);
  conn = nullptr;
  EXPECT_EQ(gtls_conn_new(ctx, "x", 1, &conn), GTLS_ERR_INVALID) << "a server context does not dial";
  gtls_context_free(ctx);
}

/* ------------------------------------------------------------------ the answers */

namespace {

/** Run one ClientHello against a fresh single-identity server. */
struct One {
  std::unique_ptr<Cred> cred = ed_cred();
  Srv srv;
  One() : srv(*cred) {}
};

GTLS_ServerHello parse_sh(const Bytes & msg, bool * ok) {
  GTLS_ServerHello sh;
  GTLS_Limits lim;
  gtls_limits_default(&lim);
  *ok = msg.size() > 4 &&
      gtls_msg_parse_server_hello(msg.data() + 4, msg.size() - 4, &lim, &sh) == GTLS_OK;
  return sh;
}

}  // namespace

TEST(ServerHello, AValidHelloIsAnsweredWithAFlightAndNothingMore) {
  One t;
  ASSERT_EQ(t.srv.build(), GTLS_OK);
  HelloSpec h;
  h.session_id = Bytes(32, 0x77);
  ASSERT_EQ(t.srv.hello(h.build()), GTLS_OK);
  EXPECT_EQ(t.srv.state(), GTLS_STATE_S_WAIT_FIN);
  bool ok = false;
  Bytes sh_msg = t.srv.out(GTLS_EPOCH_INITIAL);
  GTLS_ServerHello sh = parse_sh(sh_msg, &ok);
  ASSERT_TRUE(ok);
  EXPECT_FALSE(sh.is_hrr);
  EXPECT_EQ(sh.legacy_version, 0x0303u);
  EXPECT_EQ(sh.selected_version, 0x0304u);
  EXPECT_EQ(sh.compression, 0u);
  EXPECT_EQ(Bytes(sh.session_id, sh.session_id + sh.session_id_len), Bytes(32, 0x77))
      << "the session id is echoed";
  EXPECT_EQ(sh.suite, 0x1301u);
  EXPECT_EQ(sh.group, static_cast<unsigned>(GTLS_GROUP_X25519));
  EXPECT_EQ(sh.key_exchange_len, 32u);
  EXPECT_EQ(sh.flags, GTLS_SH_FLAG_VERSION | GTLS_SH_FLAG_KEY_SHARE) << "nothing else is in it";
  EXPECT_EQ(gtls_msg_downgrade_sentinel(sh.random), 0) << "a TLS 1.3 server sets no sentinel";
  /* The encrypted flight: exactly EE, Certificate, CertificateVerify, Finished. */
  std::vector<Bytes> msgs = split_messages(t.srv.out(GTLS_EPOCH_HANDSHAKE));
  ASSERT_EQ(msgs.size(), 4u);
  EXPECT_EQ(msgs[0][0], GTLS_HS_ENCRYPTED_EXTENSIONS);
  EXPECT_EQ(msgs[1][0], GTLS_HS_CERTIFICATE);
  EXPECT_EQ(msgs[2][0], GTLS_HS_CERTIFICATE_VERIFY);
  EXPECT_EQ(msgs[3][0], GTLS_HS_FINISHED);
  GTLS_Limits lim;
  gtls_limits_default(&lim);
  GTLS_CertificateMsg cert;
  ASSERT_EQ(gtls_msg_parse_certificate(msgs[1].data() + 4, msgs[1].size() - 4, &lim, &cert), GTLS_OK);
  EXPECT_EQ(cert.context_len, 0u);
  EXPECT_EQ(cert.count, 2u);
  EXPECT_FALSE(cert.has_entry_extensions);
  EXPECT_EQ(Bytes(cert.der[0], cert.der[0] + cert.der_len[0]), t.cred->chain[0]);
  EXPECT_EQ(Bytes(cert.der[1], cert.der[1] + cert.der_len[1]), t.cred->chain[1]);
  EXPECT_EQ(t.srv.out(GTLS_EPOCH_APPLICATION), Bytes());
  const unsigned char * der = &msgs[0][0];
  size_t der_len = 7;
  ASSERT_EQ(gtls_conn_peer_certificate(t.srv.conn, &der, &der_len), GTLS_OK);
  EXPECT_EQ(der, nullptr) << "a server has no peer certificate: it never asks";
  EXPECT_EQ(der_len, 0u);
}

TEST(ServerHello, AFlightAfterTheFirstHelloIsNotSentTwice) {
  One t;
  ASSERT_EQ(t.srv.build(), GTLS_OK);
  Bytes ch = HelloSpec().build();
  ASSERT_EQ(t.srv.hello(ch), GTLS_OK);
  EXPECT_EQ(t.srv.hello(ch), GTLS_ERR_PROTOCOL) << "a second ClientHello in S_WAIT_FIN";
  EXPECT_EQ(t.srv.alert(), GTLS_ALERT_UNEXPECTED_MESSAGE);
}

namespace {

struct Refusal {
  const char * what;
  std::function<void(HelloSpec &)> change;
  GTLS_Result result;
  unsigned alert;
};

}  // namespace

TEST(ServerHello, EveryRefusalHasItsOwnResultAndAlert) {
  const Refusal cases[] = {
      {"no supported_versions: a 1.2 client", [](HelloSpec & h) { h.has_versions = false; },
          GTLS_ERR_UNSUPPORTED, GTLS_ALERT_PROTOCOL_VERSION},
      {"supported_versions without 1.3", [](HelloSpec & h) { h.versions = {0x0303, 0x0302}; },
          GTLS_ERR_UNSUPPORTED, GTLS_ALERT_PROTOCOL_VERSION},
      {"supported_versions empty list", [](HelloSpec & h) { h.versions = {}; },
          GTLS_ERR_CORRUPT, GTLS_ALERT_DECODE_ERROR},
      {"no supported_groups", [](HelloSpec & h) { h.has_groups = false; },
          GTLS_ERR_PROTOCOL, GTLS_ALERT_MISSING_EXTENSION},
      {"no signature_algorithms", [](HelloSpec & h) { h.has_sigs = false; },
          GTLS_ERR_PROTOCOL, GTLS_ALERT_MISSING_EXTENSION},
      {"no key_share", [](HelloSpec & h) { h.has_key_share = false; },
          GTLS_ERR_PROTOCOL, GTLS_ALERT_MISSING_EXTENSION},
      {"compression other than null", [](HelloSpec & h) { h.compression = Bytes{1}; },
          GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER},
      {"two compression methods", [](HelloSpec & h) { h.compression = Bytes{0, 1}; },
          GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER},
      {"a share for a group not in supported_groups",
          [](HelloSpec & h) { h.groups = {GTLS_GROUP_SECP256R1}; },
          GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER},
      {"two shares for one group",
          [](HelloSpec & h) { h.shares.push_back(h.shares[0]); },
          GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER},
      {"a share of the wrong length",
          [](HelloSpec & h) { h.shares[0].second.pop_back(); },
          GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER},
      {"a P-256 share that is not a point",
          [](HelloSpec & h) {
            h.shares = {{GTLS_GROUP_SECP256R1, Bytes(65, 7)}};
            h.shares[0].second[0] = 4;
          },
          GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER},
      {"a P-256 share in compressed form",
          [](HelloSpec & h) {
            Bytes pub = client_share(GTLS_GROUP_SECP256R1);
            pub.resize(33);
            pub[0] = 2;
            h.shares = {{GTLS_GROUP_SECP256R1, pub}};
          },
          GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER},
      {"an X25519 share of small order (all zero)",
          [](HelloSpec & h) { h.shares = {{GTLS_GROUP_X25519, Bytes(32, 0)}}; },
          GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER},
      {"no suite in common", [](HelloSpec & h) { h.suites = {0x1304, 0x00ff, 0xc02f}; },
          GTLS_ERR_NO_COMMON, GTLS_ALERT_HANDSHAKE_FAILURE},
      {"no group in common", [](HelloSpec & h) { h.groups = {0x001e, 0x0100}; h.shares = {}; },
          GTLS_ERR_NO_COMMON, GTLS_ALERT_HANDSHAKE_FAILURE},
      {"no signature scheme in common", [](HelloSpec & h) { h.sigs = {0x0401, 0x0201, 0x0808}; },
          GTLS_ERR_NO_COMMON, GTLS_ALERT_HANDSHAKE_FAILURE},
      {"only PKCS#1 offered, which CertificateVerify may not use",
          [](HelloSpec & h) { h.sigs = {0x0401, 0x0501, 0x0601}; },
          GTLS_ERR_NO_COMMON, GTLS_ALERT_HANDSHAKE_FAILURE},
      {"a PSK offer with no psk_key_exchange_modes", [](HelloSpec & h) {
            h.psk_modes = false;
            h.extra.push_back(ext_of(GTLS_EXT_PRE_SHARED_KEY, Bytes(50, 1)));
          },
          GTLS_ERR_PROTOCOL, GTLS_ALERT_MISSING_EXTENSION},
      {"a PSK that is not the last extension", [](HelloSpec & h) {
            h.extra.push_back(ext_of(GTLS_EXT_PRE_SHARED_KEY, Bytes(50, 1)));
            h.extra.push_back(ext_of(GTLS_EXT_PADDING, Bytes(4, 0)));
          },
          GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER},
      {"a cookie the server never issued", [](HelloSpec & h) {
            h.extra.push_back(ext_of(GTLS_EXT_COOKIE, lp16(Bytes(8, 1))));
          },
          GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER},
      {"the same extension twice", [](HelloSpec & h) {
            h.extra.push_back(ext_of(GTLS_EXT_PADDING, Bytes(4, 0)));
            h.extra.push_back(ext_of(GTLS_EXT_PADDING, Bytes(4, 0)));
          },
          GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER},
      {"a server_name with a NUL", [](HelloSpec & h) {
            h.has_sni = true;
            h.sni = std::string("a\0b.test", 8);
          },
          GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER},
      {"a server_name that is not ASCII", [](HelloSpec & h) {
            h.has_sni = true;
            h.sni = "caf\xc3\xa9.test";
          },
          GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER},
      {"an empty ALPN name", [](HelloSpec & h) {
            h.extra.push_back(ext_of(GTLS_EXT_ALPN, lp16(Bytes{0})));
          },
          GTLS_ERR_PROTOCOL /* a duplicate of none: replaced below */, 0},
  };
  for (const Refusal & k : cases) {
    if (std::string(k.what) == "an empty ALPN name") {
      continue; /* built by hand in EmptyAlpn below */
    }
    One t;
    ASSERT_EQ(t.srv.build(), GTLS_OK);
    HelloSpec h;
    k.change(h);
    GTLS_Result r = t.srv.hello(h.build());
    EXPECT_EQ(r, k.result) << k.what << ": got " << result_name(r);
    EXPECT_EQ(t.srv.alert(), k.alert) << k.what;
    EXPECT_TRUE(gtls_conn_is_failed(t.srv.conn)) << k.what;
    EXPECT_TRUE(gtls_conn_secrets_are_wiped(t.srv.conn)) << k.what;
    EXPECT_EQ(t.srv.out(GTLS_EPOCH_HANDSHAKE), Bytes()) << k.what << ": nothing was sent past the alert";
  }
}

TEST(ServerHello, MalformedBytesAreDecodeErrors) {
  {
    One t;
    ASSERT_EQ(t.srv.build(), GTLS_OK);
    Bytes ch = HelloSpec().build();
    ch.push_back(0);
    ch[3] += 1; /* a byte after the extensions */
    EXPECT_EQ(t.srv.hello(ch), GTLS_ERR_CORRUPT);
    EXPECT_EQ(t.srv.alert(), GTLS_ALERT_DECODE_ERROR);
  }
  {
    One t;
    ASSERT_EQ(t.srv.build(), GTLS_OK);
    HelloSpec h;
    h.extra.push_back(ext_of(GTLS_EXT_ALPN, lp16(Bytes{0})));
    EXPECT_EQ(t.srv.hello(h.build()), GTLS_ERR_CORRUPT) << "an empty ALPN name";
    EXPECT_EQ(t.srv.alert(), GTLS_ALERT_DECODE_ERROR);
  }
  {
    One t;
    ASSERT_EQ(t.srv.build(), GTLS_OK);
    HelloSpec h;
    h.versions = {0x0304};
    Bytes ch = h.build();
    ch.resize(ch.size() - 7); /* cut inside the last extension */
    ch[3] = static_cast<unsigned char>(ch.size() - 4);
    ch[2] = (ch.size() - 4) >> 8;
    EXPECT_EQ(t.srv.hello(ch), GTLS_ERR_CORRUPT);
  }
  {
    One t;
    ASSERT_EQ(t.srv.build(), GTLS_OK);
    HelloSpec h;
    h.suites = {};
    EXPECT_EQ(t.srv.hello(h.build()), GTLS_ERR_CORRUPT) << "no suites at all";
  }
  {
    One t;
    ASSERT_EQ(t.srv.build(), GTLS_OK);
    HelloSpec h;
    h.session_id = Bytes(33, 1);
    EXPECT_EQ(t.srv.hello(h.build()), GTLS_ERR_CORRUPT) << "a session id past 32 bytes";
  }
}

TEST(ServerHello, ALegacyClientHelloIsAnswered) {
  /* An old-looking hello that still offers 1.3: a legacy version of 0x0301
   * is not a reason to refuse, supported_versions decides. */
  One t;
  ASSERT_EQ(t.srv.build(), GTLS_OK);
  HelloSpec h;
  h.legacy_version = 0x0301;
  h.suites = {0xc02f, 0x1301, 0x00ff};
  EXPECT_EQ(t.srv.hello(h.build()), GTLS_OK);
}

TEST(ServerHello, TheSizeCapsAreTheLimits) {
  {
    One t;
    t.srv.limits.max_client_hello = 100;
    ASSERT_EQ(t.srv.build(), GTLS_OK);
    EXPECT_EQ(t.srv.hello(HelloSpec().build()), GTLS_ERR_LIMIT);
    EXPECT_EQ(t.srv.alert(), GTLS_ALERT_DECODE_ERROR);
  }
  {
    One t;
    t.srv.limits.max_extensions = 3;
    ASSERT_EQ(t.srv.build(), GTLS_OK);
    EXPECT_EQ(t.srv.hello(HelloSpec().build()), GTLS_ERR_LIMIT);
    EXPECT_EQ(t.srv.alert(), GTLS_ALERT_DECODE_ERROR);
  }
  {
    One t;
    ASSERT_EQ(t.srv.build(), GTLS_OK);
    Bytes ch = HelloSpec().build();
    /* A header that announces more than the cap allows is refused before
     * the bytes are read. */
    ch[1] = 0x7f;
    EXPECT_EQ(t.srv.hello(Bytes(ch.begin(), ch.begin() + 4)), GTLS_ERR_LIMIT);
  }
  {
    One t;
    ASSERT_EQ(t.srv.build(), GTLS_OK);
    HelloSpec h;
    for (unsigned i = 0; i < 200; i++) h.groups.push_back(0x2a00 + i);
    EXPECT_EQ(t.srv.hello(h.build()), GTLS_ERR_LIMIT) << "a list longer than any real client's";
  }
  {
    One t;
    ASSERT_EQ(t.srv.build(), GTLS_OK);
    HelloSpec h;
    for (unsigned i = 0; i < 20; i++) h.shares.push_back({0x2a00 + i, Bytes(1, 1)});
    EXPECT_EQ(t.srv.hello(h.build()), GTLS_ERR_LIMIT) << "more shares than the cap";
  }
}

TEST(ServerHello, OnlyAClientHelloAtTheInitialEpochIsAccepted) {
  {
    One t;
    ASSERT_EQ(t.srv.build(), GTLS_OK);
    EXPECT_EQ(t.srv.hello(HelloSpec().build(), GTLS_EPOCH_HANDSHAKE), GTLS_ERR_PROTOCOL);
    EXPECT_EQ(t.srv.alert(), GTLS_ALERT_UNEXPECTED_MESSAGE);
  }
  for (unsigned type : {2u, 4u, 8u, 11u, 13u, 15u, 20u, 24u}) {
    One t;
    ASSERT_EQ(t.srv.build(), GTLS_OK);
    Bytes m{static_cast<unsigned char>(type), 0, 0, 0};
    EXPECT_EQ(t.srv.hello(m), GTLS_ERR_PROTOCOL) << "type " << type;
    EXPECT_EQ(t.srv.alert(), GTLS_ALERT_UNEXPECTED_MESSAGE) << "type " << type;
  }
  {
    One t;
    ASSERT_EQ(t.srv.build(), GTLS_OK);
    Bytes ch = HelloSpec().build();
    ch.push_back(GTLS_HS_FINISHED); /* a second message in the ClientHello's own epoch */
    ch.push_back(0);
    ch.push_back(0);
    ch.push_back(0);
    EXPECT_EQ(t.srv.hello(ch), GTLS_ERR_PROTOCOL);
  }
  {
    One t;
    EXPECT_EQ(gtls_conn_feed(t.srv.conn, GTLS_EPOCH_INITIAL, "x", 1, 0), GTLS_ERR_INVALID)
        << "before the connection was built and started";
  }
}

/* ------------------------------------------------------------------ the choices */

TEST(ServerChoice, TheServersSuiteOrderWins) {
  One t;
  GTLS_Suite order[3] = {GTLS_SUITE_CHACHA20_POLY1305_SHA256, GTLS_SUITE_AES_256_GCM_SHA384,
      GTLS_SUITE_AES_128_GCM_SHA256};
  t.srv.cfg.suites = order;
  t.srv.cfg.suite_count = 3;
  ASSERT_EQ(t.srv.build(), GTLS_OK);
  HelloSpec h;
  h.suites = {0x1301, 0x1302, 0x1303};
  ASSERT_EQ(t.srv.hello(h.build()), GTLS_OK);
  EXPECT_EQ(gtls_conn_suite(t.srv.conn), GTLS_SUITE_CHACHA20_POLY1305_SHA256);
  EXPECT_EQ(gtls_conn_suite(t.srv.conn) == GTLS_SUITE_NONE, false);
}

TEST(ServerChoice, ASuiteTheServerDoesNotOfferIsNotChosen) {
  One t;
  GTLS_Suite only[1] = {GTLS_SUITE_AES_256_GCM_SHA384};
  t.srv.cfg.suites = only;
  t.srv.cfg.suite_count = 1;
  ASSERT_EQ(t.srv.build(), GTLS_OK);
  HelloSpec h;
  h.suites = {0x1301, 0x1303};
  EXPECT_EQ(t.srv.hello(h.build()), GTLS_ERR_NO_COMMON);
  EXPECT_EQ(t.srv.alert(), GTLS_ALERT_HANDSHAKE_FAILURE);
}

TEST(ServerChoice, AGroupWithAShareIsChosenOverAMorePreferredOneWithout) {
  One t;
  GTLS_Group order[2] = {GTLS_GROUP_SECP384R1, GTLS_GROUP_X25519};
  t.srv.cfg.groups = order;
  t.srv.cfg.group_count = 2;
  ASSERT_EQ(t.srv.build(), GTLS_OK);
  ASSERT_EQ(t.srv.hello(HelloSpec().build()), GTLS_OK) << "the client sent an X25519 share only";
  EXPECT_EQ(gtls_conn_group(t.srv.conn), GTLS_GROUP_X25519);
  EXPECT_FALSE(gtls_conn_retried(t.srv.conn));
}

TEST(ServerChoice, TheServersGroupOrderWinsAmongSharesTheClientSent) {
  One t;
  GTLS_Group order[3] = {GTLS_GROUP_SECP384R1, GTLS_GROUP_SECP256R1, GTLS_GROUP_X25519};
  t.srv.cfg.groups = order;
  t.srv.cfg.group_count = 3;
  ASSERT_EQ(t.srv.build(), GTLS_OK);
  HelloSpec h;
  h.shares = {{GTLS_GROUP_X25519, client_share(GTLS_GROUP_X25519)},
      {GTLS_GROUP_SECP256R1, client_share(GTLS_GROUP_SECP256R1)}};
  ASSERT_EQ(t.srv.hello(h.build()), GTLS_OK);
  EXPECT_EQ(gtls_conn_group(t.srv.conn), GTLS_GROUP_SECP256R1);
}

TEST(ServerChoice, ShareForAGroupTheServerDoesNotHaveIsIgnored) {
  One t;
  ASSERT_EQ(t.srv.build(), GTLS_OK);
  HelloSpec h;
  h.groups = {0x11ec /* a hybrid the server lacks */, GTLS_GROUP_X25519};
  h.shares = {{0x11ec, Bytes(1216, 9)}, {GTLS_GROUP_X25519, client_share(GTLS_GROUP_X25519)}};
  ASSERT_EQ(t.srv.hello(h.build()), GTLS_OK);
  EXPECT_EQ(gtls_conn_group(t.srv.conn), GTLS_GROUP_X25519);
}

TEST(ServerChoice, TheSchemeIsTheFirstOfTheServersThatTheClientListedAndTheKeyFits) {
  /* An Ed25519 key signs only with Ed25519, whatever else is listed. */
  One t;
  ASSERT_EQ(t.srv.build(), GTLS_OK);
  HelloSpec h;
  h.sigs = {0x0804, 0x0403, 0x0807};
  ASSERT_EQ(t.srv.hello(h.build()), GTLS_OK);
  std::vector<Bytes> msgs = split_messages(t.srv.out(GTLS_EPOCH_HANDSHAKE));
  ASSERT_EQ(msgs.size(), 4u);
  EXPECT_EQ((static_cast<unsigned>(msgs[2][4]) << 8) | msgs[2][5], 0x0807u);
}

TEST(ServerChoice, AnRsaKeyUsesTheFirstPssSchemeInTheServersOrder) {
  std::unique_ptr<Cred> rsa = file_cred("rsa");
  Srv srv(*rsa);
  GCERT_SigScheme order[2] = {GCERT_SIG_RSA_PSS_SHA384, GCERT_SIG_RSA_PSS_SHA256};
  srv.cfg.sig_algs = order;
  srv.cfg.sig_alg_count = 2;
  ASSERT_EQ(srv.build(), GTLS_OK);
  HelloSpec h;
  h.sigs = {0x0804, 0x0805};
  ASSERT_EQ(srv.hello(h.build()), GTLS_OK);
  std::vector<Bytes> msgs = split_messages(srv.out(GTLS_EPOCH_HANDSHAKE));
  ASSERT_EQ(msgs.size(), 4u);
  EXPECT_EQ((static_cast<unsigned>(msgs[2][4]) << 8) | msgs[2][5], 0x0805u);
}

/* ------------------------------------------------------------------------ ALPN */

TEST(ServerAlpn, TheFirstOfTheServersListThatTheClientOffered) {
  One t;
  t.srv.alpn = {"h2", "http/1.1"};
  ASSERT_EQ(t.srv.build(), GTLS_OK);
  HelloSpec h;
  h.alpn = {"http/1.1", "spdy/3", "h2"};
  ASSERT_EQ(t.srv.hello(h.build()), GTLS_OK);
  const unsigned char * p = nullptr;
  size_t n = 0;
  ASSERT_EQ(gtls_conn_alpn(t.srv.conn, &p, &n), GTLS_OK);
  EXPECT_EQ(std::string(reinterpret_cast<const char *>(p), n), "h2")
      << "the server's preference, not the client's";
  /* and it is sent, once, in EncryptedExtensions */
  std::vector<Bytes> msgs = split_messages(t.srv.out(GTLS_EPOCH_HANDSHAKE));
  GTLS_Limits lim;
  gtls_limits_default(&lim);
  GTLS_EncryptedExtensions ee;
  ASSERT_EQ(gtls_msg_parse_encrypted_extensions(msgs[0].data() + 4, msgs[0].size() - 4, &lim, &ee), GTLS_OK);
  ASSERT_TRUE(ee.has_alpn);
  EXPECT_EQ(std::string(reinterpret_cast<const char *>(ee.alpn), ee.alpn_len), "h2");
}

TEST(ServerAlpn, BothListsAndNoOverlapIsFatal) {
  One t;
  t.srv.alpn = {"h2"};
  ASSERT_EQ(t.srv.build(), GTLS_OK);
  HelloSpec h;
  h.alpn = {"http/1.1", "spdy/3"};
  EXPECT_EQ(t.srv.hello(h.build()), GTLS_ERR_ALPN);
  EXPECT_EQ(t.srv.alert(), GTLS_ALERT_NO_APPLICATION_PROTOCOL);
  EXPECT_TRUE(gtls_conn_secrets_are_wiped(t.srv.conn));
  const unsigned char * p = nullptr;
  size_t n = 0;
  EXPECT_EQ(gtls_conn_alpn(t.srv.conn, &p, &n), GTLS_ERR_FAILED);
}

TEST(ServerAlpn, AClientThatOfferedNoneGetsNone) {
  One t;
  t.srv.alpn = {"h2", "http/1.1"};
  ASSERT_EQ(t.srv.build(), GTLS_OK);
  ASSERT_EQ(t.srv.hello(HelloSpec().build()), GTLS_OK);
  const unsigned char * p = reinterpret_cast<const unsigned char *>(&t);
  size_t n = 5;
  ASSERT_EQ(gtls_conn_alpn(t.srv.conn, &p, &n), GTLS_OK);
  EXPECT_EQ(p, nullptr);
  EXPECT_EQ(n, 0u);
  std::vector<Bytes> msgs = split_messages(t.srv.out(GTLS_EPOCH_HANDSHAKE));
  GTLS_Limits lim;
  gtls_limits_default(&lim);
  GTLS_EncryptedExtensions ee;
  ASSERT_EQ(gtls_msg_parse_encrypted_extensions(msgs[0].data() + 4, msgs[0].size() - 4, &lim, &ee), GTLS_OK);
  EXPECT_FALSE(ee.has_alpn);
}

TEST(ServerAlpn, AServerWithNoListSelectsNothingWhateverTheClientOffers) {
  One t;
  ASSERT_EQ(t.srv.build(), GTLS_OK);
  HelloSpec h;
  h.alpn = {"h2"};
  ASSERT_EQ(t.srv.hello(h.build()), GTLS_OK);
  const unsigned char * p = nullptr;
  size_t n = 5;
  ASSERT_EQ(gtls_conn_alpn(t.srv.conn, &p, &n), GTLS_OK);
  EXPECT_EQ(n, 0u);
}

/* ------------------------------------------------------------------------- SNI */

TEST(ServerSni, TheIdentityIsChosenByNameWithTheFirstAsDefault) {
  std::unique_ptr<Cred> a = ed_cred("a.test");
  std::unique_ptr<Cred> b = ed_cred("b.test");
  std::unique_ptr<Cred> w = ed_cred("wild.test");
  struct Case {
    bool has_sni;
    const char * sni;
    size_t index;
    int ack;
  };
  const Case cases[] = {
      {true, "a.test", 0, 1},      {true, "b.test", 1, 1},     {true, "B.TEST", 1, 1},
      {true, "unknown.test", 0, 0}, {false, "", 0, 0},         {true, "x.wild.test", 2, 1},
      {true, "wild.test", 0, 0},    {true, "x.y.wild.test", 0, 0}, {true, ".wild.test", 0, 0},
  };
  for (const Case & k : cases) {
    Srv srv(std::vector<Cred *>{a.get(), b.get(), w.get()});
    srv.names[2] = {"*.wild.test"};
    ASSERT_EQ(srv.build(), GTLS_OK);
    HelloSpec h;
    h.has_sni = k.has_sni;
    h.sni = k.sni;
    ASSERT_EQ(srv.hello(h.build()), GTLS_OK) << k.sni;
    size_t index = 99;
    ASSERT_EQ(gtls_conn_identity(srv.conn, &index), GTLS_OK);
    EXPECT_EQ(index, k.index) << "'" << k.sni << "'";
    int ack = -1;
    ASSERT_EQ(gtls_conn_server_name_acknowledged(srv.conn, &ack), GTLS_OK);
    EXPECT_EQ(ack, k.ack) << "'" << k.sni << "'";
    const unsigned char * name = nullptr;
    size_t len = 0;
    ASSERT_EQ(gtls_conn_server_name(srv.conn, &name, &len), GTLS_OK);
    EXPECT_EQ(std::string(reinterpret_cast<const char *>(name), len), k.has_sni ? k.sni : "");
    /* the chain sent is that identity's */
    std::vector<Bytes> msgs = split_messages(srv.out(GTLS_EPOCH_HANDSHAKE));
    GTLS_Limits lim;
    gtls_limits_default(&lim);
    GTLS_CertificateMsg cert;
    ASSERT_EQ(gtls_msg_parse_certificate(msgs[1].data() + 4, msgs[1].size() - 4, &lim, &cert), GTLS_OK);
    Cred * want = srv.creds[k.index];
    EXPECT_EQ(Bytes(cert.der[0], cert.der[0] + cert.der_len[0]), want->chain[0]) << k.sni;
  }
}

TEST(ServerSni, TheDefaultIsTheOneTheConfigNames) {
  std::unique_ptr<Cred> a = ed_cred("a.test");
  std::unique_ptr<Cred> b = ed_cred("b.test");
  Srv srv(std::vector<Cred *>{a.get(), b.get()});
  srv.cfg.default_identity = 1;
  ASSERT_EQ(srv.build(), GTLS_OK);
  HelloSpec h;
  h.has_sni = true;
  h.sni = "nobody.test";
  ASSERT_EQ(srv.hello(h.build()), GTLS_OK);
  size_t index = 99;
  ASSERT_EQ(gtls_conn_identity(srv.conn, &index), GTLS_OK);
  EXPECT_EQ(index, 1u);
}

TEST(ServerSni, AccessorsRefuseWhatTheyCannotAnswer) {
  One t;
  ASSERT_EQ(t.srv.build(), GTLS_OK);
  size_t index = 0;
  EXPECT_EQ(gtls_conn_identity(t.srv.conn, &index), GTLS_ERR_INVALID) << "nothing chosen yet";
  const unsigned char * name = nullptr;
  size_t len = 9;
  ASSERT_EQ(gtls_conn_server_name(t.srv.conn, &name, &len), GTLS_OK);
  EXPECT_EQ(len, 0u);
  EXPECT_EQ(gtls_conn_identity(nullptr, &index), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_identity(t.srv.conn, nullptr), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_server_name(nullptr, &name, &len), GTLS_ERR_INVALID);
  EmptyTrust trust;
  GTLS_ContextConfig cfg;
  gtls_context_config_default(&cfg);
  cfg.trust = trust.store;
  GTLS_Context * ctx = nullptr;
  GTLS_Conn * conn = nullptr;
  ASSERT_EQ(gtls_context_new(nullptr, &cfg, &ctx), GTLS_OK);
  ASSERT_EQ(gtls_conn_new(ctx, "x", 1, &conn), GTLS_OK);
  EXPECT_EQ(gtls_conn_identity(conn, &index), GTLS_ERR_INVALID) << "a client has no identity";
  EXPECT_EQ(gtls_conn_server_name(conn, &name, &len), GTLS_ERR_INVALID);
  gtls_conn_free(conn);
  gtls_context_free(ctx);
}

/* -------------------------------------------------------- HelloRetryRequest */

namespace {

/** A server that wants P-256 only, and a client that offered an X25519 share. */
struct Retry {
  std::unique_ptr<Cred> cred = ed_cred();
  Srv srv;
  GTLS_Group order[1] = {GTLS_GROUP_SECP256R1};
  Retry() : srv(*cred) {
    srv.cfg.groups = order;
    srv.cfg.group_count = 1;
  }
  HelloSpec first() {
    HelloSpec h;
    h.session_id = Bytes(32, 5);
    return h;
  }
  HelloSpec second() {
    HelloSpec h = first();
    h.shares = {{GTLS_GROUP_SECP256R1, client_share(GTLS_GROUP_SECP256R1)}};
    return h;
  }
};

}  // namespace

TEST(ServerRetry, ASupportedGroupWithoutAShareIsAHelloRetryRequest) {
  Retry r;
  ASSERT_EQ(r.srv.build(), GTLS_OK);
  ASSERT_EQ(r.srv.hello(r.first().build()), GTLS_OK);
  EXPECT_EQ(r.srv.state(), GTLS_STATE_S_WAIT_CH2);
  EXPECT_TRUE(gtls_conn_retried(r.srv.conn));
  bool ok = false;
  Bytes msg = r.srv.out(GTLS_EPOCH_INITIAL);
  GTLS_ServerHello sh = parse_sh(msg, &ok);
  ASSERT_TRUE(ok);
  EXPECT_TRUE(sh.is_hrr);
  EXPECT_EQ(sh.suite, 0x1301u);
  EXPECT_EQ(sh.group, static_cast<unsigned>(GTLS_GROUP_SECP256R1));
  EXPECT_EQ(sh.flags, GTLS_SH_FLAG_VERSION | GTLS_SH_FLAG_KEY_SHARE) << "no cookie: the server is not stateless";
  EXPECT_EQ(Bytes(sh.session_id, sh.session_id + sh.session_id_len), Bytes(32, 5));
  EXPECT_EQ(r.srv.out(GTLS_EPOCH_HANDSHAKE), Bytes()) << "nothing else is sent yet";
  /* the second hello completes it */
  r.srv.hello(Bytes());
  Bytes ch2 = r.second().build();
  ASSERT_EQ(r.srv.hello(ch2), GTLS_OK);
  EXPECT_EQ(r.srv.state(), GTLS_STATE_S_WAIT_FIN);
  EXPECT_EQ(gtls_conn_group(r.srv.conn), GTLS_GROUP_SECP256R1);
  EXPECT_EQ(split_messages(r.srv.out(GTLS_EPOCH_HANDSHAKE)).size(), 4u);
}

TEST(ServerRetry, ASecondRetryIsNotAllowed) {
  Retry r;
  ASSERT_EQ(r.srv.build(), GTLS_OK);
  ASSERT_EQ(r.srv.hello(r.first().build()), GTLS_OK);
  /* The second hello still has no share for the group asked for. */
  HelloSpec again = r.first();
  again.shares = {};
  EXPECT_EQ(r.srv.hello(again.build()), GTLS_ERR_PROTOCOL);
  EXPECT_EQ(r.srv.alert(), GTLS_ALERT_UNEXPECTED_MESSAGE);
  EXPECT_TRUE(gtls_conn_secrets_are_wiped(r.srv.conn));
}

TEST(ServerRetry, TheSecondHelloMustCarryTheGroupAskedFor) {
  Retry r;
  ASSERT_EQ(r.srv.build(), GTLS_OK);
  ASSERT_EQ(r.srv.hello(r.first().build()), GTLS_OK);
  EXPECT_EQ(r.srv.hello(r.first().build()), GTLS_ERR_PROTOCOL)
      << "the same X25519 share again: not the group that was asked for";
  EXPECT_EQ(r.srv.alert(), GTLS_ALERT_ILLEGAL_PARAMETER);
}

TEST(ServerRetry, TheSecondHelloMayChangeNothingElse) {
  const std::function<void(HelloSpec &)> changes[] = {
      [](HelloSpec & h) { h.random[0] ^= 1; },
      [](HelloSpec & h) { h.session_id = Bytes(32, 6); },
      [](HelloSpec & h) { h.suites = {0x1302, 0x1301}; },
      [](HelloSpec & h) { h.sigs = {0x0807}; },
      [](HelloSpec & h) { h.groups = {GTLS_GROUP_SECP256R1}; },
      [](HelloSpec & h) { h.alpn = {"h2"}; },
      [](HelloSpec & h) { h.has_sni = true; h.sni = "new.test"; },
      [](HelloSpec & h) { h.versions = {0x0304, 0x0303}; },
      [](HelloSpec & h) { h.psk_modes = false; },
      [](HelloSpec & h) { h.extra.push_back(ext_of(0x7777, Bytes(3, 1))); },
      [](HelloSpec & h) { h.legacy_version = 0x0301; },
  };
  int i = 0;
  for (const auto & change : changes) {
    Retry r;
    ASSERT_EQ(r.srv.build(), GTLS_OK);
    ASSERT_EQ(r.srv.hello(r.first().build()), GTLS_OK);
    HelloSpec second = r.second();
    change(second);
    EXPECT_EQ(r.srv.hello(second.build()), GTLS_ERR_PROTOCOL) << "change " << i;
    EXPECT_EQ(r.srv.alert(), GTLS_ALERT_ILLEGAL_PARAMETER) << "change " << i;
    i++;
  }
}

TEST(ServerRetry, PaddingMayChangeBetweenTheTwoHellos) {
  Retry r;
  ASSERT_EQ(r.srv.build(), GTLS_OK);
  HelloSpec a = r.first();
  a.extra.push_back(ext_of(GTLS_EXT_PADDING, Bytes(40, 0)));
  ASSERT_EQ(r.srv.hello(a.build()), GTLS_OK);
  HelloSpec b = r.second();
  b.extra.push_back(ext_of(GTLS_EXT_PADDING, Bytes(7, 0)));
  EXPECT_EQ(r.srv.hello(b.build()), GTLS_OK);
}

TEST(ServerRetry, ARetryNeedsOnlyOneShareAndNoMore) {
  Retry r;
  ASSERT_EQ(r.srv.build(), GTLS_OK);
  ASSERT_EQ(r.srv.hello(r.first().build()), GTLS_OK);
  HelloSpec two = r.second();
  two.shares.push_back({GTLS_GROUP_X25519, client_share(GTLS_GROUP_X25519)});
  EXPECT_EQ(r.srv.hello(two.build()), GTLS_ERR_PROTOCOL);
  EXPECT_EQ(r.srv.alert(), GTLS_ALERT_ILLEGAL_PARAMETER);
}

TEST(ServerRetry, ARetryWithTheSameSuiteLaterIsStillTheServersChoice) {
  Retry r;
  GTLS_Suite order[1] = {GTLS_SUITE_AES_256_GCM_SHA384};
  r.srv.cfg.suites = order;
  r.srv.cfg.suite_count = 1;
  ASSERT_EQ(r.srv.build(), GTLS_OK);
  HelloSpec first = r.first();
  first.suites = {0x1301, 0x1302};
  ASSERT_EQ(r.srv.hello(first.build()), GTLS_OK);
  bool ok = false;
  GTLS_ServerHello sh = parse_sh(r.srv.out(GTLS_EPOCH_INITIAL), &ok);
  ASSERT_TRUE(ok);
  EXPECT_EQ(sh.suite, 0x1302u) << "a retry names the suite, and it is a SHA-384 one";
  HelloSpec second = r.second();
  second.suites = {0x1301, 0x1302};
  ASSERT_EQ(r.srv.hello(second.build()), GTLS_OK);
  EXPECT_EQ(gtls_conn_suite(r.srv.conn), GTLS_SUITE_AES_256_GCM_SHA384);
}

/* --------------------------------------------------------------- state table */

TEST(ServerState, EveryMessageTypeInEveryWaitingStateAtEveryEpoch) {
  const unsigned types[] = {0, GTLS_HS_CLIENT_HELLO, GTLS_HS_SERVER_HELLO, 3,
      GTLS_HS_NEW_SESSION_TICKET, GTLS_HS_END_OF_EARLY_DATA, GTLS_HS_ENCRYPTED_EXTENSIONS,
      GTLS_HS_CERTIFICATE, GTLS_HS_CERTIFICATE_REQUEST, GTLS_HS_CERTIFICATE_VERIFY,
      GTLS_HS_FINISHED, GTLS_HS_KEY_UPDATE, GTLS_HS_MESSAGE_HASH, 255};
  const GTLS_State states[] = {GTLS_STATE_S_WAIT_CH, GTLS_STATE_S_WAIT_CH2, GTLS_STATE_S_WAIT_FIN,
      GTLS_STATE_CONNECTED};
  for (GTLS_State state : states) {
    for (int e = 0; e < GTLS_EPOCH_COUNT; e++) {
      for (unsigned type : types) {
        Retry r;
        ASSERT_EQ(r.srv.build(), GTLS_OK);
        if (state == GTLS_STATE_S_WAIT_CH2) {
          ASSERT_EQ(r.srv.hello(r.first().build()), GTLS_OK);
        } else if (state != GTLS_STATE_S_WAIT_CH) {
          ASSERT_EQ(r.srv.hello(r.first().build()), GTLS_OK);
          ASSERT_EQ(r.srv.hello(r.second().build()), GTLS_OK);
          if (state == GTLS_STATE_CONNECTED) {
            /* complete it with the real client's Finished: needs a real peer */
            continue;
          }
        }
        ASSERT_EQ(r.srv.state(), state);
        Bytes m = {static_cast<unsigned char>(type), 0, 0, 0};
        GTLS_Epoch want = gtls_conn_expected_epoch(state);
        GTLS_Result res = r.srv.hello(m, static_cast<GTLS_Epoch>(e));
        EXPECT_NE(res, GTLS_OK);
        EXPECT_TRUE(gtls_conn_is_failed(r.srv.conn));
        EXPECT_TRUE(gtls_conn_secrets_are_wiped(r.srv.conn));
        unsigned wanted_type = state == GTLS_STATE_S_WAIT_FIN ? GTLS_HS_FINISHED : GTLS_HS_CLIENT_HELLO;
        if (static_cast<GTLS_Epoch>(e) != want || type != wanted_type) {
          EXPECT_EQ(res, GTLS_ERR_PROTOCOL) << "state " << state << " epoch " << e << " type " << type;
          EXPECT_EQ(r.srv.alert(), GTLS_ALERT_UNEXPECTED_MESSAGE);
        } else {
          EXPECT_NE(r.srv.alert(), GTLS_ALERT_UNEXPECTED_MESSAGE) << "the wanted message reached its parser";
        }
      }
    }
  }
}

TEST(ServerState, ANewServerIsNotYetListening) {
  One t;
  Bytes ch = HelloSpec().build();
  EXPECT_EQ(gtls_conn_new_server(t.srv.ctx, &t.srv.conn), GTLS_ERR_INVALID);
  ASSERT_EQ(t.srv.build(), GTLS_OK);
  EXPECT_EQ(gtls_conn_start(t.srv.conn), GTLS_ERR_INVALID) << "started twice";
  EXPECT_EQ(gtls_conn_state(t.srv.conn), GTLS_STATE_S_WAIT_CH);
}

TEST(ServerState, TheSecretsAreRefusedUntilTheyExistAndAfterAFailure) {
  One t;
  ASSERT_EQ(t.srv.build(), GTLS_OK);
  Bytes out(GTLS_HASH_MAX);
  size_t n = 0;
  EXPECT_EQ(gtls_conn_secret(t.srv.conn, GTLS_EPOCH_HANDSHAKE, GTLS_DIR_WRITE, out.data(), out.size(), &n),
      GTLS_ERR_INVALID);
  ASSERT_EQ(t.srv.hello(HelloSpec().build()), GTLS_OK);
  EXPECT_EQ(gtls_conn_secret(t.srv.conn, GTLS_EPOCH_HANDSHAKE, GTLS_DIR_WRITE, out.data(), out.size(), &n),
      GTLS_OK);
  Bytes bad{GTLS_HS_FINISHED, 0, 0, 1, 0};
  EXPECT_NE(t.srv.hello(bad, GTLS_EPOCH_HANDSHAKE), GTLS_OK);
  EXPECT_EQ(gtls_conn_secret(t.srv.conn, GTLS_EPOCH_HANDSHAKE, GTLS_DIR_WRITE, out.data(), out.size(), &n),
      GTLS_ERR_FAILED);
  EXPECT_EQ(gtls_conn_suite(t.srv.conn), GTLS_SUITE_NONE);
  EXPECT_EQ(gtls_conn_group(t.srv.conn), GTLS_GROUP_NONE);
}

TEST(ServerState, ASettledServerTakesNoHandshakeMessageAtAnyEpoch) {
  const unsigned types[] = {0, GTLS_HS_CLIENT_HELLO, GTLS_HS_SERVER_HELLO, 3,
      GTLS_HS_NEW_SESSION_TICKET, GTLS_HS_END_OF_EARLY_DATA, GTLS_HS_ENCRYPTED_EXTENSIONS,
      GTLS_HS_CERTIFICATE, GTLS_HS_CERTIFICATE_REQUEST, GTLS_HS_CERTIFICATE_VERIFY,
      GTLS_HS_FINISHED, GTLS_HS_KEY_UPDATE, GTLS_HS_MESSAGE_HASH, 255};
  std::unique_ptr<Cred> cred = ed_cred();
  for (int e = 0; e < GTLS_EPOCH_COUNT; e++) {
    for (unsigned type : types) {
      MessagePair m(*cred);
      ASSERT_EQ(m.build(), GTLS_OK);
      m.run();
      ASSERT_TRUE(gtls_conn_is_connected(m.s.conn));
      ASSERT_EQ(gtls_conn_state(m.s.conn), GTLS_STATE_CONNECTED);
      Bytes msg = {static_cast<unsigned char>(type), 0, 0, 0};
      GTLS_Result r = gtls_conn_feed(m.s.conn, static_cast<GTLS_Epoch>(e), msg.data(), msg.size(), kNow);
      EXPECT_NE(r, GTLS_OK) << "epoch " << e << " type " << type;
      if (e == GTLS_EPOCH_APPLICATION && type == GTLS_HS_KEY_UPDATE) {
        EXPECT_EQ(r, GTLS_ERR_UNSUPPORTED) << "the message interface has no key update";
      } else {
        EXPECT_EQ(r, GTLS_ERR_PROTOCOL) << "epoch " << e << " type " << type;
      }
      EXPECT_EQ(gtls_conn_alert(m.s.conn), GTLS_ALERT_UNEXPECTED_MESSAGE) << "epoch " << e << " type " << type;
      EXPECT_TRUE(gtls_conn_secrets_are_wiped(m.s.conn));
    }
  }
}

TEST(ServerState, TheMessageInterfaceOfARealPairLeavesNoRecordLayerBehind) {
  /* QUIC's use: handshake bytes by epoch and the secrets, nothing framed. */
  std::unique_ptr<Cred> cred = ed_cred();
  MessagePair m(*cred);
  m.calpn = {"h3"};
  m.salpn = {"h3"};
  ASSERT_EQ(m.build(), GTLS_OK);
  m.run(7);
  ASSERT_TRUE(gtls_conn_is_connected(m.c.conn));
  ASSERT_TRUE(gtls_conn_is_connected(m.s.conn));
  for (GTLS_Epoch e : {GTLS_EPOCH_HANDSHAKE, GTLS_EPOCH_APPLICATION}) {
    Bytes cw(48), sr(48), sw(48), cr(48);
    size_t a = 0, b = 0, c2 = 0, d = 0;
    ASSERT_EQ(gtls_conn_secret(m.c.conn, e, GTLS_DIR_WRITE, cw.data(), 48, &a), GTLS_OK);
    ASSERT_EQ(gtls_conn_secret(m.s.conn, e, GTLS_DIR_READ, sr.data(), 48, &b), GTLS_OK);
    ASSERT_EQ(gtls_conn_secret(m.s.conn, e, GTLS_DIR_WRITE, sw.data(), 48, &c2), GTLS_OK);
    ASSERT_EQ(gtls_conn_secret(m.c.conn, e, GTLS_DIR_READ, cr.data(), 48, &d), GTLS_OK);
    cw.resize(a); sr.resize(b); sw.resize(c2); cr.resize(d);
    EXPECT_EQ(cw, sr) << "what the client writes with, the server reads with, at epoch " << e;
    EXPECT_EQ(sw, cr);
    EXPECT_NE(cw, sw);
  }
  EXPECT_EQ(m.c.conn->wire.len, 0u);
  EXPECT_EQ(m.s.conn->wire.len, 0u);
  EXPECT_FALSE(m.c.conn->sec.wr.active) << "no record key was derived: QUIC derives its own";
  EXPECT_FALSE(m.s.conn->sec.rd.active);
  const unsigned char * a = nullptr;
  size_t n = 0;
  ASSERT_EQ(gtls_conn_alpn(m.c.conn, &a, &n), GTLS_OK);
  EXPECT_EQ(std::string(reinterpret_cast<const char *>(a), n), "h3");
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
