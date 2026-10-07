/**
 * @file
 *
 * What review found the other tests did not pin: each test here fails when
 * one named line of the library is weakened (tools/controls.sh carries the
 * mutation for each, and runs it). Plaintext alerts and what they may and may
 * not do, handshake fragments and the records that may not interrupt them, a
 * KeyUpdate that must end its record, the answers to KeyUpdate and when there
 * are none, which identity a name picks, ALPN names of one length, a retry
 * that changes a byte, and what a context refuses.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "hello.h"
#include "rfc_run.h"

using namespace gtlstest;

namespace {

Bytes take(GTLS_Conn * c) {
  Bytes out = stream_out(c);
  EXPECT_EQ(gtls_conn_stream_consume(c, out.size()), GTLS_OK);
  return out;
}

GTLS_Result give(GTLS_Conn * c, const Bytes & b, size_t * used = nullptr) {
  size_t u = 0;
  GTLS_Result r = gtls_conn_stream_feed(c, b.data(), b.size(), kNow, &u);
  if (used != nullptr) {
    *used = u;
  }
  return r;
}

/** A record sealed under @p from's write key, as if it had sent it. */
Bytes craft(GTLS_Conn * from, unsigned type, const Bytes & pt) {
  GTLS_Buf b;
  gtls_buf_init(&b, nullptr, 1 << 16);
  EXPECT_EQ(gtls_record_seal(&from->sec.wr, type, pt.data(), pt.size(), 0, &b), GTLS_OK);
  Bytes out(b.data, b.data + b.len);
  gtls_buf_free(&b);
  return out;
}

void connect(Pair & p) {
  ASSERT_EQ(p.build(), GTLS_OK);
  p.run();
  ASSERT_TRUE(p.connected());
}

Bytes read_all_bytes(GTLS_Conn * c) {
  Bytes got;
  unsigned char buf[1000];
  for (;;) {
    size_t n = 0;
    if (gtls_conn_read(c, buf, sizeof buf, &n) != GTLS_OK || n == 0) {
      return got;
    }
    got.insert(got.end(), buf, buf + n);
  }
}

const Bytes kPlainCloseNotify = {21, 3, 3, 0, 2, 1, 0};

}  // namespace

/* ------------------------------------------------------------ plaintext alerts */

TEST(PlaintextAlert, ACloseNotifyInTheClearNeverEndsAHandshakeCleanly) {
  std::unique_ptr<Cred> cred = ed_cred();
  /* a client waiting for ServerHello */
  {
    Pair p(*cred);
    ASSERT_EQ(p.build(), GTLS_OK);
    take(p.c.conn);
    EXPECT_EQ(give(p.c.conn, kPlainCloseNotify), GTLS_ERR_ALERT);
    EXPECT_FALSE(gtls_conn_peer_closed(p.c.conn));
    EXPECT_TRUE(gtls_conn_is_failed(p.c.conn));
    EXPECT_EQ(gtls_conn_peer_alert(p.c.conn), 0u);
    EXPECT_EQ(gtls_conn_stream_eof(p.c.conn), GTLS_ERR_FAILED) << "not a clean end";
    EXPECT_EQ(gtls_conn_failure(p.c.conn), GTLS_ERR_ALERT);
  }
  /* a server waiting for the client's Finished, an end that reads under keys */
  {
    Pair p(*cred);
    ASSERT_EQ(p.build(), GTLS_OK);
    ASSERT_EQ(give(p.s.conn, take(p.c.conn)), GTLS_OK);
    take(p.s.conn);
    EXPECT_EQ(give(p.s.conn, kPlainCloseNotify), GTLS_ERR_ALERT);
    EXPECT_FALSE(gtls_conn_peer_closed(p.s.conn));
    EXPECT_EQ(gtls_conn_stream_eof(p.s.conn), GTLS_ERR_FAILED);
    EXPECT_EQ(gtls_conn_failure(p.s.conn), GTLS_ERR_ALERT);
  }
}

TEST(PlaintextAlert, AnyAlertInTheClearIsFatalAndNamed) {
  std::unique_ptr<Cred> cred = ed_cred();
  for (unsigned desc : {0u, 40u, 90u, 120u}) {
    Pair p(*cred);
    ASSERT_EQ(p.build(), GTLS_OK);
    ASSERT_EQ(give(p.s.conn, take(p.c.conn)), GTLS_OK);
    take(p.s.conn);
    EXPECT_EQ(give(p.s.conn, Bytes{21, 3, 3, 0, 2, 1, static_cast<unsigned char>(desc)}), GTLS_ERR_ALERT) << desc;
    EXPECT_EQ(gtls_conn_peer_alert(p.s.conn), desc);
    EXPECT_FALSE(gtls_conn_peer_closed(p.s.conn));
  }
}

TEST(PlaintextAlert, ARecordOfTheWrongSizeIsNotAnAlertUnderKeys) {
  std::unique_ptr<Cred> cred = ed_cred();
  for (const Bytes & rec : {Bytes{21, 3, 3, 0, 3, 1, 0, 0}, Bytes{21, 3, 3, 0, 1, 1}, Bytes{21, 3, 3, 0, 0}}) {
    Pair p(*cred);
    ASSERT_EQ(p.build(), GTLS_OK);
    ASSERT_EQ(give(p.s.conn, take(p.c.conn)), GTLS_OK);
    take(p.s.conn);
    EXPECT_EQ(give(p.s.conn, rec), GTLS_ERR_PROTOCOL) << rec.size();
    EXPECT_EQ(gtls_conn_alert(p.s.conn), GTLS_ALERT_UNEXPECTED_MESSAGE);
  }
}

TEST(PlaintextAlert, ACloseNotifyInTheClearToAnEstablishedConnectionIsRefused) {
  std::unique_ptr<Cred> cred = ed_cred();
  for (int who = 0; who < 2; who++) {
    Pair p(*cred);
    connect(p);
    GTLS_Conn * c = who == 0 ? p.c.conn : p.s.conn;
    EXPECT_EQ(give(c, kPlainCloseNotify), GTLS_ERR_PROTOCOL);
    EXPECT_EQ(gtls_conn_alert(c), GTLS_ALERT_UNEXPECTED_MESSAGE);
    EXPECT_FALSE(gtls_conn_peer_closed(c)) << "an attacker cannot close an established connection";
  }
}

TEST(PlaintextAlert, AnAuthenticatedCloseNotifyStillClosesCleanly) {
  std::unique_ptr<Cred> cred = ed_cred();
  Pair p(*cred);
  connect(p);
  ASSERT_EQ(gtls_conn_close(p.c.conn), GTLS_OK);
  p.run();
  EXPECT_TRUE(gtls_conn_peer_closed(p.s.conn));
  EXPECT_EQ(gtls_conn_stream_eof(p.s.conn), GTLS_OK);
}

/* ---------------------------------------------- the fragments of a handshake message */

TEST(Fragments, NothingMayComeBetweenThePiecesOfAHandshakeMessage) {
  std::unique_ptr<Cred> cred = ed_cred();
  /* a KeyUpdate header cut short, protected, and then each other kind of record */
  struct Case {
    const char * what;
    std::function<Bytes(Pair &)> interrupt;
  };
  const Case cases[] = {
      {"application data", [](Pair & p) { return craft(p.c.conn, GTLS_CT_APPLICATION_DATA, Bytes{'h', 'i'}); }},
      {"an alert", [](Pair & p) { return craft(p.c.conn, GTLS_CT_ALERT, Bytes{1, 0}); }},
      {"a dummy change_cipher_spec", [](Pair &) { return Bytes{20, 3, 3, 0, 1, 1}; }},
      {"an empty application record", [](Pair & p) { return craft(p.c.conn, GTLS_CT_APPLICATION_DATA, Bytes()); }},
  };
  for (const Case & k : cases) {
    Pair p(*cred);
    connect(p);
    ASSERT_EQ(give(p.s.conn, craft(p.c.conn, GTLS_CT_HANDSHAKE, Bytes{24, 0, 0})), GTLS_OK) << k.what;
    EXPECT_EQ(give(p.s.conn, k.interrupt(p)), GTLS_ERR_PROTOCOL) << k.what;
    EXPECT_EQ(gtls_conn_alert(p.s.conn), GTLS_ALERT_UNEXPECTED_MESSAGE) << k.what;
    EXPECT_EQ(read_all_bytes(p.s.conn), Bytes()) << k.what;
  }
}

TEST(Fragments, ACompatibilityRecordBetweenTheHalvesOfAServerHelloIsRefused) {
  std::unique_ptr<Cred> cred = ed_cred();
  Pair p(*cred);
  ASSERT_EQ(p.build(), GTLS_OK);
  ASSERT_EQ(give(p.s.conn, take(p.c.conn)), GTLS_OK);
  Bytes out = take(p.s.conn);
  size_t n = 5 + ((static_cast<size_t>(out[3]) << 8) | out[4]);
  Bytes sh(out.begin() + 5, out.begin() + n);
  size_t half = sh.size() / 2;
  auto record = [](const Bytes & body) {
    Bytes r = {22, 3, 3, static_cast<unsigned char>(body.size() >> 8), static_cast<unsigned char>(body.size())};
    r.insert(r.end(), body.begin(), body.end());
    return r;
  };
  ASSERT_EQ(give(p.c.conn, record(Bytes(sh.begin(), sh.begin() + half))), GTLS_OK);
  EXPECT_EQ(give(p.c.conn, Bytes{20, 3, 3, 0, 1, 1}), GTLS_ERR_PROTOCOL);
  EXPECT_EQ(gtls_conn_alert(p.c.conn), GTLS_ALERT_UNEXPECTED_MESSAGE);
}

TEST(Fragments, TheNextPieceOfTheMessageIsAcceptedAsBefore) {
  std::unique_ptr<Cred> cred = ed_cred();
  Pair p(*cred);
  connect(p);
  ASSERT_EQ(give(p.s.conn, craft(p.c.conn, GTLS_CT_HANDSHAKE, Bytes{24, 0, 0})), GTLS_OK);
  ASSERT_EQ(give(p.s.conn, craft(p.c.conn, GTLS_CT_HANDSHAKE, Bytes{1, 0})), GTLS_OK);
  EXPECT_EQ(p.s.conn->key_updates, 1u);
}

/* ------------------------------------------------------------ KeyUpdate ends its record */

TEST(KeyUpdateRecord, ItMustBeTheLastMessageOfItsRecord) {
  std::unique_ptr<Cred> cred = ed_cred();
  for (const Bytes & msgs : {Bytes{24, 0, 0, 1, 0, 24, 0, 0, 1, 0}, Bytes{24, 0, 0, 1, 0, 4, 0, 0, 0},
           Bytes{24, 0, 0, 1, 1, 0}}) {
    Pair p(*cred);
    connect(p);
    EXPECT_EQ(give(p.s.conn, craft(p.c.conn, GTLS_CT_HANDSHAKE, msgs)), GTLS_ERR_PROTOCOL) << msgs.size();
    EXPECT_EQ(gtls_conn_alert(p.s.conn), GTLS_ALERT_UNEXPECTED_MESSAGE);
    EXPECT_TRUE(gtls_conn_secrets_are_wiped(p.s.conn));
  }
  Pair p(*cred);
  connect(p);
  EXPECT_EQ(give(p.s.conn, craft(p.c.conn, GTLS_CT_HANDSHAKE, Bytes{24, 0, 0, 1, 0})), GTLS_OK) << "alone is fine";
}

/* ------------------------------------------------------------ answering KeyUpdate */

TEST(KeyUpdateAnswers, EveryRequestIsAnsweredOnce) {
  std::unique_ptr<Cred> cred = ed_cred();
  Pair p(*cred);
  connect(p);
  for (unsigned i = 1; i <= 5; i++) {
    ASSERT_EQ(gtls_conn_key_update(p.c.conn, 1), GTLS_OK);
    p.run();
    EXPECT_EQ(p.c.conn->key_updates, i) << "the server answered request " << i;
    EXPECT_EQ(p.s.conn->key_updates, i);
    EXPECT_EQ(p.s.conn->ku_queued, 0u);
    EXPECT_EQ(p.c.conn->ku_queued, 0u);
  }
}

TEST(KeyUpdateAnswers, TwoRequestsBeforeTheAnswerAreAnsweredOnce) {
  std::unique_ptr<Cred> cred = ed_cred();
  Pair p(*cred);
  connect(p);
  ASSERT_EQ(gtls_conn_key_update(p.c.conn, 1), GTLS_OK);
  ASSERT_EQ(gtls_conn_key_update(p.c.conn, 1), GTLS_OK);
  p.run();
  EXPECT_EQ(p.s.conn->key_updates, 2u);
  EXPECT_EQ(p.c.conn->key_updates, 1u) << "one answer covers both";
}

TEST(KeyUpdateAnswers, NoneAfterThisEndHasClosed) {
  std::unique_ptr<Cred> cred = ed_cred();
  Pair p(*cred);
  connect(p);
  ASSERT_EQ(gtls_conn_close(p.s.conn), GTLS_OK);
  take(p.s.conn);
  ASSERT_EQ(gtls_conn_key_update(p.c.conn, 1), GTLS_OK);
  Bytes ku = take(p.c.conn);
  ASSERT_EQ(give(p.s.conn, ku), GTLS_OK);
  EXPECT_EQ(stream_out(p.s.conn), Bytes()) << "nothing is sent after close_notify";
  EXPECT_EQ(p.s.conn->ku_queued, 0u);
  EXPECT_EQ(p.s.conn->key_updates, 1u) << "the update itself is still taken";
}

TEST(KeyUpdateAnswers, TheCapCountsUpdatesWithNoDataBetweenThem) {
  std::unique_ptr<Cred> cred = ed_cred();
  Pair p(*cred);
  p.slimits.max_key_updates = 3;
  connect(p);
  for (int i = 0; i < 12; i++) {
    ASSERT_EQ(gtls_conn_key_update(p.c.conn, 0), GTLS_OK);
    size_t w = 0;
    ASSERT_EQ(gtls_conn_write(p.c.conn, "x", 1, &w), GTLS_OK);
    p.run();
    ASSERT_FALSE(gtls_conn_is_failed(p.s.conn)) << "update " << i << ": a long life is not a flood";
  }
  EXPECT_EQ(p.s.conn->key_updates, 12u);
  for (int i = 0; i < 4; i++) {
    ASSERT_EQ(gtls_conn_key_update(p.c.conn, 0), GTLS_OK);
  }
  p.run();
  EXPECT_TRUE(gtls_conn_is_failed(p.s.conn));
  EXPECT_EQ(gtls_conn_failure(p.s.conn), GTLS_ERR_LIMIT);
}

/* ----------------------------------------------------------------- the keys of alerts */

TEST(AlertKeys, AServerBetweenItsFlightAndTheClientsFinishedAlertsUnderTheApplicationKey) {
  std::unique_ptr<Cred> cred = ed_cred();
  Pair p(*cred);
  ASSERT_EQ(p.build(), GTLS_OK);
  ASSERT_EQ(give(p.s.conn, take(p.c.conn)), GTLS_OK);
  Bytes flight = take(p.s.conn);
  ASSERT_EQ(gtls_conn_state(p.s.conn), GTLS_STATE_S_WAIT_FIN);
  ASSERT_EQ(give(p.c.conn, flight), GTLS_OK);
  ASSERT_EQ(gtls_conn_state(p.c.conn), GTLS_STATE_CONNECTED);
  /* the server fails before the Finished has come */
  Bytes junk = {23, 3, 3, 0, 20};
  junk.resize(25, 0x77);
  EXPECT_EQ(give(p.s.conn, junk), GTLS_ERR_MISMATCH);
  Bytes alert = take(p.s.conn);
  ASSERT_EQ(alert.size(), 5u + 2 + 1 + 16);
  /* the client has switched to the application key, and reads it as an alert */
  EXPECT_EQ(give(p.c.conn, alert), GTLS_ERR_ALERT);
  EXPECT_EQ(gtls_conn_peer_alert(p.c.conn), GTLS_ALERT_BAD_RECORD_MAC);
}

TEST(AlertKeys, ACompatibilityClientSendsItsDummyRecordBeforeItsFinished) {
  std::unique_ptr<Cred> cred = ed_cred();
  Pair p(*cred);
  p.ccfg.middlebox_compat = 1;
  ASSERT_EQ(p.build(), GTLS_OK);
  ASSERT_EQ(give(p.s.conn, take(p.c.conn)), GTLS_OK);
  ASSERT_EQ(give(p.c.conn, take(p.s.conn)), GTLS_OK);
  Bytes out = take(p.c.conn);
  ASSERT_GE(out.size(), 6u);
  EXPECT_EQ(Bytes(out.begin(), out.begin() + 6), (Bytes{20, 3, 3, 0, 1, 1})) << "the dummy record comes first";
  EXPECT_EQ(out[6], 23) << "then the protected Finished";
  /* and only once */
  p.run();
  EXPECT_EQ(p.c.conn->ccs_sent, 1);
  Bytes more;
  size_t w = 0;
  ASSERT_EQ(gtls_conn_write(p.c.conn, "x", 1, &w), GTLS_OK);
  more = take(p.c.conn);
  EXPECT_EQ(more[0], 23);
  /* without the setting there is none */
  Pair q(*cred);
  ASSERT_EQ(q.build(), GTLS_OK);
  ASSERT_EQ(give(q.s.conn, take(q.c.conn)), GTLS_OK);
  ASSERT_EQ(give(q.c.conn, take(q.s.conn)), GTLS_OK);
  Bytes plain = take(q.c.conn);
  EXPECT_EQ(plain[0], 23);
}

/* ------------------------------------------------------------------- SNI and identity */

namespace {

struct Two {
  std::unique_ptr<Cred> ed = ed_cred("one.test");
  std::unique_ptr<Cred> rsa = file_cred("rsa");
  Srv srv;
  Two() : srv(std::vector<Cred *>{ed.get(), rsa.get()}) {}
  size_t index() {
    size_t i = 99;
    EXPECT_EQ(gtls_conn_identity(srv.conn, &i), GTLS_OK);
    return i;
  }
};

}  // namespace

TEST(IdentityChoice, AnExactNameBeatsAWildcardWhicheverComesFirst) {
  for (int order = 0; order < 2; order++) {
    Two t;
    t.srv.names[0] = order == 0 ? std::vector<const char *>{"*.example.test"} : std::vector<const char *>{"www.example.test"};
    t.srv.names[1] = order == 0 ? std::vector<const char *>{"www.example.test"} : std::vector<const char *>{"*.example.test"};
    ASSERT_EQ(t.srv.build(), GTLS_OK);
    HelloSpec h;
    h.has_sni = true;
    h.sni = "www.example.test";
    ASSERT_EQ(t.srv.hello(h.build()), GTLS_OK);
    EXPECT_EQ(t.index(), order == 0 ? 1u : 0u) << "the identity with the exact name, wherever it is listed";
  }
}

TEST(IdentityChoice, TheFirstOfTwoExactMatchesStays) {
  Two t;
  t.srv.names[0] = {"dup.test"};
  t.srv.names[1] = {"dup.test"};
  ASSERT_EQ(t.srv.build(), GTLS_OK);
  HelloSpec h;
  h.has_sni = true;
  h.sni = "dup.test";
  ASSERT_EQ(t.srv.hello(h.build()), GTLS_OK);
  EXPECT_EQ(t.index(), 0u) << "a later identity does not override an earlier match";
}

TEST(IdentityChoice, AMatchThatCannotSignGivesWayToAnotherMatchThatCan) {
  Two t;
  t.srv.names[0] = {"x.test"};   /* Ed25519: signs only with Ed25519 */
  t.srv.names[1] = {"*.test"};   /* RSA */
  ASSERT_EQ(t.srv.build(), GTLS_OK);
  HelloSpec h;
  h.has_sni = true;
  h.sni = "x.test";
  h.sigs = {0x0804};            /* RSA-PSS only */
  ASSERT_EQ(t.srv.hello(h.build()), GTLS_OK);
  EXPECT_EQ(t.index(), 1u);
  int ack = 0;
  ASSERT_EQ(gtls_conn_server_name_acknowledged(t.srv.conn, &ack), GTLS_OK);
  EXPECT_EQ(ack, 1);
}

TEST(IdentityChoice, WhenNoMatchCanSignTheDefaultIsTriedAndMayFailToo) {
  {
    Two t;
    t.srv.names[0] = {"x.test"};
    t.srv.names[1] = {"other.test"};
    t.srv.cfg.default_identity = 1;
    ASSERT_EQ(t.srv.build(), GTLS_OK);
    HelloSpec h;
    h.has_sni = true;
    h.sni = "x.test";
    h.sigs = {0x0804};
    ASSERT_EQ(t.srv.hello(h.build()), GTLS_OK);
    EXPECT_EQ(t.index(), 1u);
    int ack = 1;
    ASSERT_EQ(gtls_conn_server_name_acknowledged(t.srv.conn, &ack), GTLS_OK);
    EXPECT_EQ(ack, 0) << "the name was not what was used";
  }
  {
    Two t;
    t.srv.names[0] = {"x.test"};
    ASSERT_EQ(t.srv.build(), GTLS_OK);
    HelloSpec h;
    h.has_sni = true;
    h.sni = "y.other";
    h.sigs = {0x0804};
    EXPECT_EQ(t.srv.hello(h.build()), GTLS_ERR_NO_COMMON) << "the default is the Ed25519 one";
    EXPECT_EQ(t.srv.alert(), GTLS_ALERT_HANDSHAKE_FAILURE);
  }
}

TEST(IdentityChoice, AHostNameOfMoreThan255BytesIsRefused) {
  Two t;
  ASSERT_EQ(t.srv.build(), GTLS_OK);
  HelloSpec h;
  h.has_sni = true;
  h.sni = std::string(256, 'a');
  EXPECT_EQ(t.srv.hello(h.build()), GTLS_ERR_PROTOCOL);
  EXPECT_EQ(t.srv.alert(), GTLS_ALERT_ILLEGAL_PARAMETER);
  Two u;
  ASSERT_EQ(u.srv.build(), GTLS_OK);
  h.sni = std::string(255, 'a');
  EXPECT_EQ(u.srv.hello(h.build()), GTLS_OK) << "255 is the most a host name is";
}

/* ----------------------------------------------------------------------------- ALPN */

TEST(AlpnNames, NamesOfOneLengthAreComparedByTheirBytes) {
  {
    std::unique_ptr<Cred> cred = ed_cred();
    Srv srv(*cred);
    srv.alpn = {"h2"};
    ASSERT_EQ(srv.build(), GTLS_OK);
    HelloSpec h;
    h.alpn = {"h3"};
    EXPECT_EQ(srv.hello(h.build()), GTLS_ERR_ALPN);
    EXPECT_EQ(srv.alert(), GTLS_ALERT_NO_APPLICATION_PROTOCOL);
  }
  {
    std::unique_ptr<Cred> cred = ed_cred();
    Srv srv(*cred);
    srv.alpn = {"h2"};
    ASSERT_EQ(srv.build(), GTLS_OK);
    HelloSpec h;
    h.alpn = {"h3", "h2", "hq"};
    ASSERT_EQ(srv.hello(h.build()), GTLS_OK);
    const unsigned char * a = nullptr;
    size_t n = 0;
    ASSERT_EQ(gtls_conn_alpn(srv.conn, &a, &n), GTLS_OK);
    EXPECT_EQ(std::string(reinterpret_cast<const char *>(a), n), "h2");
  }
  {
    /* a longer name that starts like a shorter one */
    std::unique_ptr<Cred> cred = ed_cred();
    Srv srv(*cred);
    srv.alpn = {"h2"};
    ASSERT_EQ(srv.build(), GTLS_OK);
    HelloSpec h;
    h.alpn = {"h2c"};
    EXPECT_EQ(srv.hello(h.build()), GTLS_ERR_ALPN);
  }
}

/* ---------------------------------------------------------- the second ClientHello */

namespace {

struct Retried {
  std::unique_ptr<Cred> cred = ed_cred();
  Srv srv;
  GTLS_Group order[1] = {GTLS_GROUP_SECP256R1};
  Retried() : srv(*cred) {
    srv.cfg.groups = order;
    srv.cfg.group_count = 1;
  }
  HelloSpec first() {
    HelloSpec h;
    h.session_id = Bytes(32, 5);
    return h;
  }
  HelloSpec second(HelloSpec h) {
    h.shares = {{GTLS_GROUP_SECP256R1, client_share(GTLS_GROUP_SECP256R1)}};
    return h;
  }
  GTLS_Result run(HelloSpec a, HelloSpec b) {
    EXPECT_EQ(srv.build(), GTLS_OK);
    EXPECT_EQ(srv.hello(a.build()), GTLS_OK);
    return srv.hello(second(b).build());
  }
};

}  // namespace

TEST(RetryConsistency, ASameLengthChangeIsStillAChange) {
  const std::function<void(HelloSpec &)> changes[] = {
      [](HelloSpec & h) { h.suites = {0x1302, 0x1303, 0x1301}; },
      [](HelloSpec & h) { h.suites = {0x1301, 0x1303, 0x1303}; },
      [](HelloSpec & h) { h.sigs = {0x0805, 0x0804, 0x0806, 0x0403, 0x0503, 0x0807}; },
      [](HelloSpec & h) { h.sigs = {0x0804, 0x0805, 0x0806, 0x0403, 0x0503, 0x0808}; },
      [](HelloSpec & h) { h.random[31] ^= 1; },
      [](HelloSpec & h) { h.session_id[31] ^= 1; },
      [](HelloSpec & h) { h.versions = {0x0304}; h.extra.push_back(ext_of(0x7777, Bytes{1, 2, 3})); },
  };
  int i = 0;
  for (const auto & change : changes) {
    Retried r;
    HelloSpec a = r.first();
    HelloSpec b = r.first();
    if (i == 6) {
      /* the same extension in both, with different bytes */
      a.extra.push_back(ext_of(0x7777, Bytes{1, 2, 4}));
    }
    change(b);
    EXPECT_EQ(r.run(a, b), GTLS_ERR_PROTOCOL) << "change " << i;
    EXPECT_EQ(r.srv.alert(), GTLS_ALERT_ILLEGAL_PARAMETER) << "change " << i;
    i++;
  }
}

TEST(RetryConsistency, AnExtensionThatGrewKeepingItsPrefixIsAChange) {
  Retried r;
  HelloSpec a = r.first();
  HelloSpec b = r.first();
  a.extra.push_back(ext_of(0x7777, Bytes{1, 2, 3}));
  b.extra.push_back(ext_of(0x7777, Bytes{1, 2, 3, 4}));
  EXPECT_EQ(r.run(a, b), GTLS_ERR_PROTOCOL);
  Retried q;
  HelloSpec c = q.first();
  HelloSpec d = q.first();
  c.extra.push_back(ext_of(0x7777, Bytes{1, 2, 3, 4}));
  d.extra.push_back(ext_of(0x7777, Bytes{1, 2, 3}));
  EXPECT_EQ(q.run(c, d), GTLS_ERR_PROTOCOL) << "and one that shrank";
  Retried same;
  HelloSpec e = same.first();
  e.extra.push_back(ext_of(0x7777, Bytes{1, 2, 3}));
  EXPECT_EQ(same.run(e, e), GTLS_OK) << "the control: the same extension is no change";
}

/* ------------------------------------------------------------------------ contexts */

TEST(ContextChecks, AChainIsHeldToTheCapsOfTheMessageItIsSentIn) {
  std::unique_ptr<Cred> cred = ed_cred();
  GTLS_ContextConfig cfg;
  gtls_context_config_default(&cfg);
  cfg.role = GTLS_ROLE_SERVER;
  GTLS_Context * ctx = nullptr;
  {
    std::vector<const void *> chain(33, cred->chain[0].data());
    std::vector<size_t> lens(33, 1);
    lens[0] = cred->chain[0].size();   /* a good leaf, so only the count can refuse it */
    GTLS_Identity id = {chain.data(), lens.data(), 33, cred->key, nullptr, 0};
    cfg.identities = &id;
    cfg.identity_count = 1;
    EXPECT_EQ(gtls_context_new(nullptr, &cfg, &ctx), GTLS_ERR_INVALID) << "more than 32 certificates";
    chain.resize(32);
    lens.assign(32, cred->chain[0].size());
    id.chain_count = 32;
    EXPECT_EQ(gtls_context_new(nullptr, &cfg, &ctx), GTLS_OK) << "32 is allowed";
    gtls_context_free(ctx);
    GTLS_Limits small;
    gtls_limits_default(&small);
    small.max_output_bytes = 8192;
    cfg.limits = &small;
    ctx = nullptr;
    EXPECT_EQ(gtls_context_new(nullptr, &cfg, &ctx), GTLS_ERR_LIMIT) << "and then it does not fit the queue";
    cfg.limits = nullptr;
  }
  {
    const void * chain[2] = {cred->chain[0].data(), cred->chain[1].data()};
    size_t lens[2] = {cred->chain[0].size(), 0};
    GTLS_Identity id = {chain, lens, 2, cred->key, nullptr, 0};
    cfg.identities = &id;
    EXPECT_EQ(gtls_context_new(nullptr, &cfg, &ctx), GTLS_ERR_INVALID) << "an empty certificate";
  }
  {
    const void * chain[2] = {cred->chain[0].data(), cred->chain[1].data()};
    size_t lens[2] = {cred->chain[0].size(), 0x1000000u};
    GTLS_Identity id = {chain, lens, 2, cred->key, nullptr, 0};
    cfg.identities = &id;
    EXPECT_EQ(gtls_context_new(nullptr, &cfg, &ctx), GTLS_ERR_INVALID) << "lengths that do not fit 24 bits together";
  }
  {
    const void * chain[1] = {cred->chain[0].data()};
    size_t lens[1] = {0x1000000u};
    GTLS_Identity id = {chain, lens, 1, cred->key, nullptr, 0};
    cfg.identities = &id;
    EXPECT_EQ(gtls_context_new(nullptr, &cfg, &ctx), GTLS_ERR_INVALID) << "one that does not";
  }
  {
    const void * chain[1] = {cred->chain[0].data()};
    size_t lens[1] = {cred->chain[0].size()};
    GTLS_Identity id = {chain, lens, 1, cred->key, nullptr, 0};
    cfg.identities = &id;
    EXPECT_EQ(gtls_context_new(nullptr, &cfg, &ctx), GTLS_OK);
    gtls_context_free(ctx);
    GTLS_Limits lim;
    gtls_limits_default(&lim);
    lim.max_client_hello = 65537;
    cfg.limits = &lim;
    ctx = nullptr;
    EXPECT_EQ(gtls_context_new(nullptr, &cfg, &ctx), GTLS_ERR_INVALID) << "a hello that could not be kept for a retry";
    lim.max_client_hello = 65536;
    EXPECT_EQ(gtls_context_new(nullptr, &cfg, &ctx), GTLS_OK);
    gtls_context_free(ctx);
  }
}

TEST(ContextChecks, ASmallOutputOrKeyLimitStillCompletesAHandshakeAndWrites) {
  std::unique_ptr<Cred> cred = ed_cred();
  Pair p(*cred);
  p.climits.max_output_bytes = 2048;
  p.climits.max_records_per_key = 2;
  p.slimits.max_records_per_key = 2;
  ASSERT_EQ(p.build(), GTLS_OK);
  p.run();
  ASSERT_TRUE(p.connected()) << "handshake records are not counted against the key limit";
  size_t w = 0;
  Bytes data = pattern(40000, 4);
  ASSERT_EQ(gtls_conn_write(p.c.conn, data.data(), data.size(), &w), GTLS_OK);
  EXPECT_GE(w, 16384u) << "a write into an empty output always fits one whole record";
  p.run();
  EXPECT_EQ(p.s.got, Bytes(data.begin(), data.begin() + w));
}

TEST(ContextChecks, HandshakeRecordsAreNotCountedAgainstTheKeyLimit) {
  /* A flight of two records under a key that may protect one: the limit is
   * the application key's. */
  std::unique_ptr<Cred> cred = file_cred("rsa");
  Bytes leaf = cred->chain[0];
  cred->chain.assign(32, leaf);
  Pair p(*cred);
  p.slimits.max_records_per_key = 1;
  p.climits.max_certificates = 32;
  p.slimits.max_output_bytes = 200000;
  p.climits.max_handshake_message = 1u << 20;
  ASSERT_EQ(p.build(), GTLS_OK);
  p.run();
  ASSERT_TRUE(p.connected()) << result_name(gtls_conn_failure(p.s.conn)) << " / "
                             << result_name(gtls_conn_failure(p.c.conn));
  EXPECT_GT(p.s.sent, 16384u) << "the flight really was more than one record";
}

TEST(ContextChecks, TheSealRefusesPaddingThatWouldWrapItsSize) {
  Bytes secret(32, 7);
  GTLS_RecordKeys k;
  ASSERT_EQ(gtls_record_keys_from_secret(&k, GTLS_SUITE_AES_128_GCM_SHA256, secret.data(), 0), GTLS_OK);
  GTLS_Buf b;
  gtls_buf_init(&b, nullptr, 1 << 16);
  EXPECT_EQ(gtls_record_seal(&k, GTLS_CT_APPLICATION_DATA, "0123456789", 10, SIZE_MAX - 10, &b), GTLS_ERR_LIMIT);
  EXPECT_EQ(gtls_record_seal(&k, GTLS_CT_APPLICATION_DATA, "0123456789", 10, SIZE_MAX, &b), GTLS_ERR_LIMIT);
  EXPECT_EQ(b.len, 0u);
  EXPECT_EQ(k.seq, 0u);
  gtls_buf_free(&b);
}

TEST(ContextChecks, ASignerThatClaimsMoreThanItWasGivenRoomForFailsTheHandshake) {
  std::unique_ptr<Cred> cred = ed_cred();
  struct Liar {
    size_t claim;
    static GTLS_Result fn(void * user, const GTLS_Conn *, unsigned, const unsigned char *, size_t,
        unsigned char * out, size_t cap, size_t * len) {
      Liar * self = static_cast<Liar *>(user);
      std::memset(out, 1, cap);
      *len = self->claim;
      return GTLS_OK;
    }
  };
  for (size_t claim : {size_t(GCERT_SIG_MAX + 1), size_t(1) << 40, size_t(0)}) {
    Srv srv(*cred);
    ASSERT_EQ(srv.build(), GTLS_OK);
    Liar liar = {claim};
    gtls_conn_set_server_hooks(srv.conn, Liar::fn, &liar, nullptr, nullptr, 0, 0, nullptr, 0);
    EXPECT_EQ(srv.hello(HelloSpec().build()), GTLS_ERR_INTERNAL) << claim;
    EXPECT_EQ(srv.alert(), GTLS_ALERT_INTERNAL_ERROR);
    EXPECT_TRUE(gtls_conn_secrets_are_wiped(srv.conn));
  }
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
