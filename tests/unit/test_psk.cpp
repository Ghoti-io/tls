/**
 * @file
 *
 * A server that issues no tickets still has to answer a ClientHello that
 * offers a pre-shared key or early data (RFC 8446 sections 4.2.9 to 4.2.11):
 * the offer is checked for shape and ignored, a full certificate handshake
 * follows, and the client's early-data records, which were encrypted under a
 * key this server never had, are skipped up to a cap. Each negative is a
 * test: a malformed offer is refused with the alert it calls for, skipping is
 * not active unless early data was offered, it ends at the first record that
 * opens, and it is capped.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "hello.h"
#include "rfc_run.h"

using namespace gtlstest;

namespace {

struct One {
  std::unique_ptr<Cred> cred = ed_cred();
  Srv srv;
  One() : srv(*cred) {}
};

/** A server that will answer a first hello with a HelloRetryRequest. */
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

GTLS_ServerHello parse_sh(const Bytes & msg, bool * ok) {
  GTLS_ServerHello sh;
  GTLS_Limits lim;
  gtls_limits_default(&lim);
  *ok = msg.size() > 4 &&
      gtls_msg_parse_server_hello(msg.data() + 4, msg.size() - 4, &lim, &sh) == GTLS_OK;
  return sh;
}

/** The extension types an EncryptedExtensions message carries. */
std::vector<unsigned> ee_types(const Bytes & msg) {
  std::vector<unsigned> out;
  size_t at = 6; /* header, then the block's length */
  while (at + 4 <= msg.size()) {
    out.push_back((static_cast<unsigned>(msg[at]) << 8) | msg[at + 1]);
    at += 4 + ((static_cast<size_t>(msg[at + 2]) << 8) | msg[at + 3]);
  }
  EXPECT_EQ(at, msg.size());
  return out;
}

/** A handshake message as one plaintext record. */
Bytes hs_record(const Bytes & msg) {
  Bytes r{22, 3, 3};
  put16(r, msg.size());
  r.insert(r.end(), msg.begin(), msg.end());
  return r;
}

/** A record that says application data and holds bytes nobody can open: early data. */
Bytes early_record(size_t body_len, unsigned char fill = 0xa5) {
  Bytes r{23, 3, 3};
  put16(r, body_len);
  r.insert(r.end(), body_len, fill);
  return r;
}

GTLS_Result stream(GTLS_Conn * c, const Bytes & b, int64_t now = kNow, size_t * used = nullptr) {
  size_t u = 0;
  GTLS_Result r = gtls_conn_stream_feed(c, b.data(), b.size(), now, &u);
  if (used != nullptr) {
    *used = u;
  }
  return r;
}

Bytes take(GTLS_Conn * c) {
  Bytes out = stream_out(c);
  EXPECT_EQ(gtls_conn_stream_consume(c, out.size()), GTLS_OK);
  return out;
}

Bytes read_all(GTLS_Conn * c) {
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

/**
 * A real client started from a ClientHello that offers a PSK and/or early
 * data, against the real server: the client's own Finished is the first
 * record that opens.
 */
struct Offering {
  std::unique_ptr<Cred> cred = ed_cred();
  Pair p;
  Offering(bool early, bool psk, std::function<void(Pair &)> tweak = nullptr) : p(*cred) {
    HelloSpec h;
    h.early_data = early;
    if (psk) {
      h.psk_identities = 1;
      h.psk_binders = 1;
    }
    p.raw_hello = h.build();
    if (tweak) {
      tweak(p);
    }
    EXPECT_EQ(p.build(), GTLS_OK);
  }
  /** The client's hello to the server, then @p garbage, in one feed or two. */
  GTLS_Result hello_then(const Bytes & garbage) {
    Bytes ch = take(p.c.conn);
    EXPECT_FALSE(ch.empty());
    GTLS_Result r = stream(p.s.conn, ch);
    if (r != GTLS_OK) {
      return r;
    }
    return garbage.empty() ? GTLS_OK : stream(p.s.conn, garbage);
  }
};

}  // namespace

/* ---------------------------------------------------------------- the offer */

TEST(PskOffer, AValidOfferIsIgnoredAndAFullHandshakeFollows) {
  for (int ids : {1, 2, 5}) {
    One t;
    ASSERT_EQ(t.srv.build(), GTLS_OK);
    HelloSpec h;
    h.session_id = Bytes(32, 0x77);
    h.psk_identities = ids;
    h.psk_binders = ids;
    ASSERT_EQ(t.srv.hello(h.build()), GTLS_OK) << ids << " identities";
    EXPECT_EQ(t.srv.state(), GTLS_STATE_S_WAIT_FIN);
    bool ok = false;
    GTLS_ServerHello sh = parse_sh(t.srv.out(GTLS_EPOCH_INITIAL), &ok);
    ASSERT_TRUE(ok);
    EXPECT_EQ(sh.flags, GTLS_SH_FLAG_VERSION | GTLS_SH_FLAG_KEY_SHARE)
        << "no pre_shared_key is selected";
    std::vector<Bytes> msgs = split_messages(t.srv.out(GTLS_EPOCH_HANDSHAKE));
    ASSERT_EQ(msgs.size(), 4u) << "the certificate flight, not a resumption";
    EXPECT_EQ(msgs[1][0], GTLS_HS_CERTIFICATE);
    EXPECT_EQ(msgs[2][0], GTLS_HS_CERTIFICATE_VERIFY);
  }
}

TEST(PskOffer, TheBindersAreNotCheckedBecauseNothingIsAccepted) {
  /* Every binder byte is wrong by construction (0x60...), and the offer is
   * still answered: the binder is what would vouch for a PSK that is used. */
  One t;
  ASSERT_EQ(t.srv.build(), GTLS_OK);
  HelloSpec h;
  h.psk_identities = 1;
  h.psk_binders = 1;
  h.psk_binder_len = 255;
  ASSERT_EQ(t.srv.hello(h.build()), GTLS_OK);
}

TEST(PskOffer, EveryMalformedOfferHasItsResultAndAlert) {
  struct Case {
    const char * what;
    std::function<void(HelloSpec &, GTLS_Limits &)> change;
    GTLS_Result result;
    unsigned alert;
  };
  const Case cases[] = {
      {"a PSK with another extension after it",
          [](HelloSpec & h, GTLS_Limits &) {
            HelloSpec p;
            p.psk_identities = p.psk_binders = 1;
            h.extra.push_back(ext_of(GTLS_EXT_PRE_SHARED_KEY, p.psk_body()));
            h.extra.push_back(ext_of(GTLS_EXT_PADDING, Bytes(4, 0)));
          },
          GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER},
      {"a PSK followed by early_data",
          [](HelloSpec & h, GTLS_Limits &) {
            HelloSpec p;
            p.psk_identities = p.psk_binders = 1;
            h.extra.push_back(ext_of(GTLS_EXT_PRE_SHARED_KEY, p.psk_body()));
            h.extra.push_back(ext_of(GTLS_EXT_EARLY_DATA, Bytes()));
          },
          GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER},
      {"a PSK and no psk_key_exchange_modes",
          [](HelloSpec & h, GTLS_Limits &) {
            h.psk_modes = false;
            h.psk_identities = h.psk_binders = 1;
          },
          GTLS_ERR_PROTOCOL, GTLS_ALERT_MISSING_EXTENSION},
      {"an identity with no binder",
          [](HelloSpec & h, GTLS_Limits &) { h.psk_identities = 1; h.psk_binders = 0; },
          GTLS_ERR_CORRUPT, GTLS_ALERT_DECODE_ERROR},
      {"two identities and one binder",
          [](HelloSpec & h, GTLS_Limits &) { h.psk_identities = 2; h.psk_binders = 1; },
          GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER},
      {"one identity and two binders",
          [](HelloSpec & h, GTLS_Limits &) { h.psk_identities = 1; h.psk_binders = 2; },
          GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER},
      {"a binder shorter than a hash",
          [](HelloSpec & h, GTLS_Limits &) {
            h.psk_identities = h.psk_binders = 1;
            h.psk_binder_len = 31;
          },
          GTLS_ERR_CORRUPT, GTLS_ALERT_DECODE_ERROR},
      {"a short binder beside a good one (the list as a whole is long enough)",
          [](HelloSpec & h, GTLS_Limits &) {
            h.psk_identities = h.psk_binders = 2;
            h.psk_first_binder_len = 8;
          },
          GTLS_ERR_CORRUPT, GTLS_ALERT_DECODE_ERROR},
      {"an empty identity",
          [](HelloSpec & h, GTLS_Limits &) {
            h.psk_identities = h.psk_binders = 1;
            h.psk_identity_len = 0;
          },
          GTLS_ERR_CORRUPT, GTLS_ALERT_DECODE_ERROR},
      {"more identities than the limit",
          [](HelloSpec & h, GTLS_Limits & l) {
            l.max_tickets = 2;
            h.psk_identities = h.psk_binders = 3;
          },
          GTLS_ERR_LIMIT, GTLS_ALERT_DECODE_ERROR},
  };
  for (const Case & k : cases) {
    One t;
    HelloSpec h;
    k.change(h, t.srv.limits);
    ASSERT_EQ(t.srv.build(), GTLS_OK) << k.what;
    EXPECT_EQ(t.srv.hello(h.build()), k.result) << k.what;
    EXPECT_EQ(t.srv.alert(), k.alert) << k.what;
    EXPECT_EQ(t.srv.state(), GTLS_STATE_FAILED) << k.what;
  }
}

TEST(PskOffer, ABodyThatDoesNotParseIsADecodeError) {
  const Bytes bodies[] = {
      Bytes(),                                  /* nothing */
      Bytes{0, 0},                              /* identities below their minimum */
      Bytes(50, 1),                             /* a length that overruns */
      [] { HelloSpec p; p.psk_identities = p.psk_binders = 1; Bytes b = p.psk_body(); b.push_back(0); return b; }(),
  };
  for (const Bytes & body : bodies) {
    One t;
    ASSERT_EQ(t.srv.build(), GTLS_OK);
    HelloSpec h;
    h.extra.push_back(ext_of(GTLS_EXT_PRE_SHARED_KEY, body));
    EXPECT_EQ(t.srv.hello(h.build()), GTLS_ERR_CORRUPT);
    EXPECT_EQ(t.srv.alert(), GTLS_ALERT_DECODE_ERROR);
  }
}

TEST(EarlyDataOffer, IsRejectedByNotEchoingItAndTheFlightIsTheFullOne) {
  for (bool psk : {false, true}) {
    One t;
    ASSERT_EQ(t.srv.build(), GTLS_OK);
    HelloSpec h;
    h.early_data = true;
    if (psk) {
      h.psk_identities = h.psk_binders = 1;
    }
    ASSERT_EQ(t.srv.hello(h.build()), GTLS_OK) << "psk " << psk;
    std::vector<Bytes> msgs = split_messages(t.srv.out(GTLS_EPOCH_HANDSHAKE));
    ASSERT_EQ(msgs.size(), 4u);
    EXPECT_EQ(msgs[0][0], GTLS_HS_ENCRYPTED_EXTENSIONS);
    for (unsigned type : ee_types(msgs[0])) {
      EXPECT_NE(type, static_cast<unsigned>(GTLS_EXT_EARLY_DATA)) << "early data is not accepted";
    }
    EXPECT_EQ(msgs[1][0], GTLS_HS_CERTIFICATE);
  }
}

TEST(EarlyDataOffer, MustHaveAnEmptyBody) {
  for (const Bytes & body : {Bytes{0}, Bytes{0, 0, 0, 0}}) {
    One t;
    ASSERT_EQ(t.srv.build(), GTLS_OK);
    HelloSpec h;
    h.extra.push_back(ext_of(GTLS_EXT_EARLY_DATA, body));
    EXPECT_EQ(t.srv.hello(h.build()), GTLS_ERR_CORRUPT);
    EXPECT_EQ(t.srv.alert(), GTLS_ALERT_DECODE_ERROR);
  }
}

TEST(EarlyDataOffer, TheLimitsAreResolvedLikeTheOthers) {
  GTLS_Limits l;
  gtls_limits_default(&l);
  EXPECT_EQ(l.max_early_skip_bytes, 16384u + 256u + 5u);
  GTLS_Limits zero, out;
  std::memset(&zero, 0, sizeof zero);
  gtls_limits_resolve(&zero, &out);
  EXPECT_EQ(out.max_early_skip_bytes, l.max_early_skip_bytes);
  zero.max_early_skip_bytes = 7;
  gtls_limits_resolve(&zero, &out);
  EXPECT_EQ(out.max_early_skip_bytes, 7u);
}

/* -------------------------------------------------------------- the retry */

TEST(PskRetry, TheSecondHelloMayDropEarlyDataAndRefreshThePsk) {
  Retry r;
  ASSERT_EQ(r.srv.build(), GTLS_OK);
  HelloSpec first = r.first();
  first.early_data = true;
  first.psk_identities = first.psk_binders = 1;
  ASSERT_EQ(r.srv.hello(first.build()), GTLS_OK);
  EXPECT_EQ(r.srv.state(), GTLS_STATE_S_WAIT_CH2) << "a HelloRetryRequest";
  HelloSpec second = r.second();
  second.psk_identities = second.psk_binders = 1;
  second.psk_binder_len = 48;   /* the binders change with the transcript */
  ASSERT_EQ(r.srv.hello(second.build()), GTLS_OK);
  EXPECT_EQ(r.srv.state(), GTLS_STATE_S_WAIT_FIN);
}

TEST(PskRetry, TheSecondHelloMustNotOfferEarlyData) {
  for (bool first_had : {true, false}) {
    Retry r;
    ASSERT_EQ(r.srv.build(), GTLS_OK);
    HelloSpec first = r.first();
    first.early_data = first_had;
    ASSERT_EQ(r.srv.hello(first.build()), GTLS_OK);
    HelloSpec second = r.second();
    second.early_data = true;
    EXPECT_EQ(r.srv.hello(second.build()), GTLS_ERR_PROTOCOL) << first_had;
    EXPECT_EQ(r.srv.alert(), GTLS_ALERT_ILLEGAL_PARAMETER);
  }
}

TEST(PskRetry, TheSecondHelloMayNotAddAPsk) {
  Retry r;
  ASSERT_EQ(r.srv.build(), GTLS_OK);
  ASSERT_EQ(r.srv.hello(r.first().build()), GTLS_OK);
  HelloSpec second = r.second();
  second.psk_identities = second.psk_binders = 1;
  EXPECT_EQ(r.srv.hello(second.build()), GTLS_ERR_PROTOCOL);
  EXPECT_EQ(r.srv.alert(), GTLS_ALERT_ILLEGAL_PARAMETER);
}

TEST(PskRetry, TheSecondHelloIsStillCheckedForShape) {
  Retry r;
  ASSERT_EQ(r.srv.build(), GTLS_OK);
  HelloSpec first = r.first();
  first.psk_identities = first.psk_binders = 1;
  ASSERT_EQ(r.srv.hello(first.build()), GTLS_OK);
  HelloSpec second = r.second();
  second.psk_identities = 2;
  second.psk_binders = 1;
  EXPECT_EQ(r.srv.hello(second.build()), GTLS_ERR_PROTOCOL);
  EXPECT_EQ(r.srv.alert(), GTLS_ALERT_ILLEGAL_PARAMETER);
}

/* ---------------------------------------------------------- skipping, live */

TEST(EarlySkip, RecordsThatDoNotOpenAreSkippedAndTheHandshakeCompletes) {
  for (int round = 0; round < 2; round++) {
    bool psk = true;
    Offering o(true, psk);
    Bytes garbage = cat(early_record(300), early_record(40));
    ASSERT_EQ(o.hello_then(garbage), GTLS_OK) << "psk " << psk;
    o.p.run();
    ASSERT_TRUE(o.p.connected()) << "client: " << result_name(gtls_conn_failure(o.p.c.conn))
                                 << ", server: " << result_name(gtls_conn_failure(o.p.s.conn));
    EXPECT_TRUE(o.p.s.got.empty()) << "skipped bytes never reach the application";
    /* The counter did not move for the skipped records: the client's Finished
     * was at sequence 0 and opened, and so does the first data record. */
    Bytes data = pattern(100, 9);
    o.p.send_all(o.p.c, o.p.s, data);
    EXPECT_EQ(o.p.s.got, data);
  }
}

TEST(EarlySkip, AMaximumSizeRecordIsSkipped) {
  Offering o(true, true);
  ASSERT_EQ(o.hello_then(early_record(16384 + 256)), GTLS_OK);
  o.p.run();
  EXPECT_TRUE(o.p.connected());
}

TEST(EarlySkip, AnyFeedSizeGivesTheSameResult) {
  for (size_t chunk : {1u, 7u, 100u}) {
    Offering o(true, true);
    Bytes ch = take(o.p.c.conn);
    Bytes all = cat(ch, cat(early_record(100), early_record(17)));
    for (size_t at = 0; at < all.size(); at += chunk) {
      Bytes piece(all.begin() + at, all.begin() + std::min(all.size(), at + chunk));
      ASSERT_EQ(stream(o.p.s.conn, piece), GTLS_OK) << "chunk " << chunk << " at " << at;
    }
    o.p.run();
    EXPECT_TRUE(o.p.connected()) << chunk;
  }
}

TEST(EarlySkip, TheCapIsInPlaintextBytesAndExceedingItIsFatal) {
  /* Cap 100: a record costs its body less the 17 bytes of inner type and tag,
   * so a body of 117 costs exactly 100. */
  {
    Offering o(true, true, [](Pair & p) { p.slimits.max_early_skip_bytes = 100; });
    EXPECT_EQ(o.hello_then(early_record(117)), GTLS_OK) << "exactly the cap";
    o.p.run();
    EXPECT_TRUE(o.p.connected());
  }
  {
    Offering o(true, true, [](Pair & p) { p.slimits.max_early_skip_bytes = 100; });
    EXPECT_EQ(o.hello_then(early_record(118)), GTLS_ERR_LIMIT) << "one byte over";
    EXPECT_EQ(gtls_conn_alert(o.p.s.conn), GTLS_ALERT_UNEXPECTED_MESSAGE);
    EXPECT_TRUE(gtls_conn_secrets_are_wiped(o.p.s.conn));
  }
  {
    Offering o(true, true, [](Pair & p) { p.slimits.max_early_skip_bytes = 100; });
    EXPECT_EQ(o.hello_then(cat(early_record(67), early_record(67))), GTLS_OK) << "two records, 100 in all";
    EXPECT_EQ(stream(o.p.s.conn, early_record(18)), GTLS_ERR_LIMIT) << "and a third, of one byte";
    EXPECT_EQ(gtls_conn_alert(o.p.s.conn), GTLS_ALERT_UNEXPECTED_MESSAGE);
  }
  {
    /* The header is not part of the cost, and a body too short to hold a
     * plaintext (an empty record is 17 bytes) costs one. */
    Offering o(true, true, [](Pair & p) { p.slimits.max_early_skip_bytes = 3; });
    EXPECT_EQ(o.hello_then(cat(early_record(17), cat(early_record(1), early_record(17)))), GTLS_OK)
        << "three records, one byte each";
    EXPECT_EQ(stream(o.p.s.conn, early_record(17)), GTLS_ERR_LIMIT) << "the fourth";
  }
}

TEST(EarlySkip, IsNotActiveForEarlyDataWithoutAPsk) {
  /* The extension is checked and ignored; nothing was sent under a key this
   * server could be expected to skip, so a bad record stays fatal. */
  Offering o(true, false);
  EXPECT_EQ(o.hello_then(early_record(50)), GTLS_ERR_MISMATCH);
  EXPECT_EQ(gtls_conn_alert(o.p.s.conn), GTLS_ALERT_BAD_RECORD_MAC);
  EXPECT_TRUE(gtls_conn_secrets_are_wiped(o.p.s.conn));
}

TEST(EarlySkip, AfterARetryEarlyDataWithoutAPskSkipsNothing) {
  Retry r;
  ASSERT_EQ(r.srv.build(), GTLS_OK);
  HelloSpec first = r.first();
  first.early_data = true;
  ASSERT_EQ(stream(r.srv.conn, hs_record(first.build())), GTLS_OK);
  EXPECT_EQ(stream(r.srv.conn, early_record(50)), GTLS_ERR_PROTOCOL);
  EXPECT_EQ(r.srv.alert(), GTLS_ALERT_UNEXPECTED_MESSAGE);
}

TEST(EarlySkip, IsNotActiveWhenEarlyDataWasNotOffered) {
  for (bool psk : {false, true}) {
    Offering o(false, psk);
    EXPECT_EQ(o.hello_then(early_record(50)), GTLS_ERR_MISMATCH) << "psk " << psk;
    EXPECT_EQ(gtls_conn_alert(o.p.s.conn), GTLS_ALERT_BAD_RECORD_MAC);
    EXPECT_TRUE(gtls_conn_secrets_are_wiped(o.p.s.conn));
  }
}

TEST(EarlySkip, EndsAtTheFirstRecordThatOpens) {
  Offering o(true, true);
  ASSERT_EQ(o.hello_then(early_record(60)), GTLS_OK);
  /* The server's flight to the client, the client's Finished back. */
  ASSERT_EQ(stream(o.p.c.conn, take(o.p.s.conn)), GTLS_OK);
  Bytes fin = take(o.p.c.conn);
  ASSERT_FALSE(fin.empty());
  ASSERT_EQ(stream(o.p.s.conn, fin), GTLS_OK);
  ASSERT_TRUE(gtls_conn_is_connected(o.p.s.conn));
  EXPECT_EQ(stream(o.p.s.conn, early_record(60)), GTLS_ERR_MISMATCH)
      << "after the Finished opened, a record that does not is fatal";
  EXPECT_EQ(gtls_conn_alert(o.p.s.conn), GTLS_ALERT_BAD_RECORD_MAC);
}

TEST(EarlySkip, GarbageAfterTheSkipWindowIsFatalInTheSameFeedToo) {
  Offering o(true, true);
  ASSERT_EQ(o.hello_then(early_record(60)), GTLS_OK);
  ASSERT_EQ(stream(o.p.c.conn, take(o.p.s.conn)), GTLS_OK);
  Bytes fin = take(o.p.c.conn);
  EXPECT_EQ(stream(o.p.s.conn, cat(fin, early_record(30))), GTLS_ERR_MISMATCH);
  EXPECT_EQ(gtls_conn_alert(o.p.s.conn), GTLS_ALERT_BAD_RECORD_MAC);
}

TEST(EarlySkip, AfterARetryTheRecordsBeforeTheSecondHelloAreSkipped) {
  Retry r;
  ASSERT_EQ(r.srv.build(), GTLS_OK);
  HelloSpec first = r.first();
  first.early_data = true;
  first.psk_identities = first.psk_binders = 1;
  ASSERT_EQ(stream(r.srv.conn, hs_record(first.build())), GTLS_OK);
  EXPECT_EQ(r.srv.state(), GTLS_STATE_S_WAIT_CH2);
  /* the client has not seen the retry yet: its early records are still coming */
  ASSERT_EQ(stream(r.srv.conn, early_record(16384 + 256)), GTLS_OK);
  EXPECT_EQ(r.srv.state(), GTLS_STATE_S_WAIT_CH2);
  ASSERT_EQ(stream(r.srv.conn, hs_record(r.second().build())), GTLS_OK) << "the second hello is read";
  EXPECT_EQ(r.srv.state(), GTLS_STATE_S_WAIT_FIN);
  EXPECT_EQ(read_all(r.srv.conn), Bytes());
}

TEST(EarlySkip, AfterARetryNothingIsSkippedOnceTheSecondHelloIsIn) {
  Retry r;
  ASSERT_EQ(r.srv.build(), GTLS_OK);
  HelloSpec first = r.first();
  first.early_data = true;
  first.psk_identities = first.psk_binders = 1;
  ASSERT_EQ(stream(r.srv.conn, hs_record(first.build())), GTLS_OK);
  ASSERT_EQ(stream(r.srv.conn, hs_record(r.second().build())), GTLS_OK);
  EXPECT_EQ(stream(r.srv.conn, early_record(50)), GTLS_ERR_MISMATCH)
      << "early data cannot follow the second hello (section 4.2.10)";
  EXPECT_EQ(r.srv.alert(), GTLS_ALERT_BAD_RECORD_MAC);
}

TEST(EarlySkip, AfterARetryWithoutEarlyDataAnApplicationRecordIsUnexpected) {
  Retry r;
  ASSERT_EQ(r.srv.build(), GTLS_OK);
  ASSERT_EQ(stream(r.srv.conn, hs_record(r.first().build())), GTLS_OK);
  EXPECT_EQ(stream(r.srv.conn, early_record(50)), GTLS_ERR_PROTOCOL);
  EXPECT_EQ(r.srv.alert(), GTLS_ALERT_UNEXPECTED_MESSAGE);
}

TEST(EarlySkip, AnOversizeRecordBeforeAnyKeyIsStillAnOverflowWithoutEarlyData) {
  Retry r;
  ASSERT_EQ(r.srv.build(), GTLS_OK);
  ASSERT_EQ(stream(r.srv.conn, hs_record(r.first().build())), GTLS_OK);
  Bytes big = early_record(16384 + 100);
  EXPECT_EQ(stream(r.srv.conn, big), GTLS_ERR_LIMIT);
  EXPECT_EQ(r.srv.alert(), GTLS_ALERT_RECORD_OVERFLOW);
}

TEST(EarlySkip, OnlyApplicationDataRecordsAreSkipped) {
  /* An alert, a handshake record or a bad record of another kind is not early data. */
  Offering o(true, true);
  ASSERT_EQ(o.hello_then(Bytes()), GTLS_OK);
  Bytes junk{22, 3, 3, 0, 20};
  junk.insert(junk.end(), 20, 0x11);
  EXPECT_NE(stream(o.p.s.conn, junk), GTLS_OK) << "a handshake-typed record in the clear under keys";
}


/* ------------------------------------------- the review's surviving mutants */

TEST(PskLists, TheCapsPassExactlyAtTheLimitAndFailOneOver) {
  struct Case {
    const char * what;
    std::function<void(HelloSpec &, GTLS_Limits &)> change;
    GTLS_Result result;
  };
  const Case cases[] = {
      {"as many identities and binders as the limit",
          [](HelloSpec & h, GTLS_Limits & l) { l.max_tickets = 3; h.psk_identities = h.psk_binders = 3; },
          GTLS_OK},
      {"one identity over the limit",
          [](HelloSpec & h, GTLS_Limits & l) { l.max_tickets = 3; h.psk_identities = h.psk_binders = 4; },
          GTLS_ERR_LIMIT},
      {"the identities at the limit and one binder over it (the binder cap, not the mismatch)",
          [](HelloSpec & h, GTLS_Limits & l) { l.max_tickets = 3; h.psk_identities = 3; h.psk_binders = 4; },
          GTLS_ERR_LIMIT},
      {"an identity exactly as long as the limit",
          [](HelloSpec & h, GTLS_Limits & l) {
            l.max_ticket_bytes = 20; h.psk_identities = h.psk_binders = 1; h.psk_identity_len = 20; },
          GTLS_OK},
      {"an identity one byte over the ticket limit (not ours, and not an error)",
          [](HelloSpec & h, GTLS_Limits & l) {
            l.max_ticket_bytes = 20; h.psk_identities = h.psk_binders = 1; h.psk_identity_len = 21; },
          GTLS_OK},
      {"the shortest identity there is (the identities list is exactly its minimum)",
          [](HelloSpec & h, GTLS_Limits &) { h.psk_identities = h.psk_binders = 1; h.psk_identity_len = 1; },
          GTLS_OK},
      {"binders and no identities",
          [](HelloSpec & h, GTLS_Limits &) { h.psk_identities = 0; h.psk_binders = 1; },
          GTLS_ERR_CORRUPT},
      {"a good identity and an empty one",
          [](HelloSpec & h, GTLS_Limits &) {
            h.psk_identities = h.psk_binders = 2; h.psk_last_identity_len = 0; },
          GTLS_ERR_CORRUPT},
      {"a binder of 31 bytes beside one of 32",
          [](HelloSpec & h, GTLS_Limits &) {
            h.psk_identities = h.psk_binders = 2; h.psk_first_binder_len = 31; },
          GTLS_ERR_CORRUPT},
      {"a binder of 32 bytes beside one of 32",
          [](HelloSpec & h, GTLS_Limits &) {
            h.psk_identities = h.psk_binders = 2; h.psk_first_binder_len = 32; },
          GTLS_OK},
  };
  for (const Case & k : cases) {
    One t;
    HelloSpec h;
    k.change(h, t.srv.limits);
    ASSERT_EQ(t.srv.build(), GTLS_OK) << k.what;
    EXPECT_EQ(t.srv.hello(h.build()), k.result) << k.what;
  }
}

TEST(PskOffer, AServerWithKeysPassesOverAnIdentityTooLongToBeItsAndStillRefusesTooManyOfThem) {
  GTLS_TicketKey key;
  std::memset(&key, 0, sizeof key);
  std::memset(key.name, 7, sizeof key.name);
  std::memset(key.key, 9, sizeof key.key);
  key.not_before = kNow - 100;
  key.not_after = kNow + 100000;

  auto serve = [&](const HelloSpec & h, uint32_t max_tickets, bool * resumed, unsigned * alert) {
    One t;
    t.srv.cfg.ticket_keys = &key;
    t.srv.cfg.ticket_key_count = 1;
    t.srv.limits.max_client_hello = 65536;
    t.srv.limits.max_tickets = max_tickets;
    EXPECT_EQ(t.srv.build(), GTLS_OK);
    GTLS_Result r = t.srv.hello(h.build());
    *resumed = gtls_conn_resumed(t.srv.conn) != 0;
    *alert = t.srv.alert();
    if (r == GTLS_OK) {
      EXPECT_EQ(t.srv.state(), GTLS_STATE_S_WAIT_FIN) << "the full flight is out";
      EXPECT_GT(t.srv.out(GTLS_EPOCH_HANDSHAKE).size(), 100u);
    }
    return r;
  };
  bool resumed = true;
  unsigned alert = 0;
  HelloSpec h;

  /* One identity, any length up to what a hello can hold: not a ticket this server sealed. */
  for (size_t len : {static_cast<size_t>(1), static_cast<size_t>(624), static_cast<size_t>(625),
           static_cast<size_t>(16384), static_cast<size_t>(16385), static_cast<size_t>(30000)}) {
    h.psk_identities = h.psk_binders = 1;
    h.psk_identity_len = len;
    EXPECT_EQ(serve(h, 16, &resumed, &alert), GTLS_OK) << len;
    EXPECT_FALSE(resumed) << len;
  }
  /* The identities are counted all the same: more than the limit is the error. */
  h.psk_identity_len = 16385;
  h.psk_identities = h.psk_binders = 2;
  EXPECT_EQ(serve(h, 2, &resumed, &alert), GTLS_OK) << "two within a limit of two";
  EXPECT_EQ(serve(h, 1, &resumed, &alert), GTLS_ERR_LIMIT) << "two over a limit of one";
  EXPECT_EQ(alert, GTLS_ALERT_DECODE_ERROR);
  h.psk_identity_len = 16;
  h.psk_identities = h.psk_binders = 17;
  EXPECT_EQ(serve(h, 16, &resumed, &alert), GTLS_ERR_LIMIT) << "seventeen over the default sixteen";
  EXPECT_EQ(alert, GTLS_ALERT_DECODE_ERROR);
  h.psk_identities = h.psk_binders = 16;
  EXPECT_EQ(serve(h, 16, &resumed, &alert), GTLS_OK);
}

TEST(PskOffer, AMalformedKeyExchangeModesBesideAPskIsADecodeError) {
  const Bytes bodies[] = {Bytes{0}, Bytes{5, 1}, Bytes{1, 1, 0}, Bytes()};
  for (const Bytes & body : bodies) {
    One t;
    ASSERT_EQ(t.srv.build(), GTLS_OK);
    HelloSpec h;
    h.psk_modes = false;
    h.extra.push_back(ext_of(GTLS_EXT_PSK_KEY_EXCHANGE_MODES, body));
    h.psk_identities = h.psk_binders = 1;
    EXPECT_EQ(t.srv.hello(h.build()), GTLS_ERR_CORRUPT) << body.size();
    EXPECT_EQ(t.srv.alert(), GTLS_ALERT_DECODE_ERROR);
  }
}

TEST(EarlySkip, AHandshakeFragmentInFlightRefusesEarlyData) {
  Retry r;
  ASSERT_EQ(r.srv.build(), GTLS_OK);
  HelloSpec first = r.first();
  first.early_data = true;
  first.psk_identities = first.psk_binders = 1;
  ASSERT_EQ(stream(r.srv.conn, hs_record(first.build())), GTLS_OK);
  Bytes second = r.second().build();
  Bytes head(second.begin(), second.begin() + 50);
  ASSERT_EQ(stream(r.srv.conn, hs_record(head)), GTLS_OK) << "the first piece of the second hello";
  EXPECT_EQ(stream(r.srv.conn, early_record(40)), GTLS_ERR_PROTOCOL)
      << "a message in pieces: only its next piece may follow";
  EXPECT_EQ(r.srv.alert(), GTLS_ALERT_UNEXPECTED_MESSAGE);
}

TEST(EarlySkip, ARecordThatIsNotHandshakeSizedIsRefusedWhileTheWindowIsOpen) {
  Retry r;
  ASSERT_EQ(r.srv.build(), GTLS_OK);
  HelloSpec first = r.first();
  first.early_data = true;
  first.psk_identities = first.psk_binders = 1;
  ASSERT_EQ(stream(r.srv.conn, hs_record(first.build())), GTLS_OK);
  Bytes big{22, 3, 3};
  put16(big, 16384 + 100);
  EXPECT_EQ(stream(r.srv.conn, big), GTLS_ERR_LIMIT) << "only application_data may be that large";
  EXPECT_EQ(r.srv.alert(), GTLS_ALERT_RECORD_OVERFLOW);
}

namespace {

/** Early-data window open, the server's flight sent, and the client handshake key in hand. */
struct Window {
  std::unique_ptr<Cred> cred = ed_cred();
  Pair p;
  GTLS_Suite suite = GTLS_SUITE_AES_128_GCM_SHA256;
  GTLS_RecordKeys keys;
  Window() : p(*cred) {
    HelloSpec h;
    h.early_data = true;
    h.psk_identities = h.psk_binders = 1;
    p.raw_hello = h.build();
    p.scfg.suites = &suite;
    p.scfg.suite_count = 1;
    p.slimits.max_record_padding = 10;
    EXPECT_EQ(p.build(), GTLS_OK);
    Bytes ch = take(p.c.conn);
    EXPECT_EQ(stream(p.s.conn, ch), GTLS_OK);
    EXPECT_EQ(gtls_record_keys_from_secret(&keys, suite, p.s.conn->sec.schedule.c_hs, 0), GTLS_OK);
  }
};

}  // namespace

TEST(EarlySkip, OnlyARecordThatDoesNotAuthenticateIsSkipped) {
  {
    /* sealed under the right key with more padding than is accepted */
    Window w;
    GTLS_Buf b;
    gtls_buf_init(&b, nullptr, 4096);
    Bytes pt(10, 7);
    ASSERT_EQ(gtls_record_seal(&w.keys, 23, pt.data(), pt.size(), 11, &b), GTLS_OK);
    EXPECT_EQ(stream(w.p.s.conn, Bytes(b.data, b.data + b.len)), GTLS_ERR_LIMIT);
    EXPECT_EQ(gtls_conn_alert(w.p.s.conn), GTLS_ALERT_RECORD_OVERFLOW);
    gtls_buf_free(&b);
  }
  {
    /* sealed under the right key, and nothing inside it but zeros: no content type */
    Window w;
    Bytes zeros(20, 0), ct(20), tag(16);
    Bytes hdr{23, 3, 3, 0, 36};
    unsigned char nonce[GTLS_IV_LEN];
    std::memcpy(nonce, w.keys.iv, sizeof nonce);   /* sequence number 0 */
    ASSERT_EQ(gsec_aes_gcm_encrypt(w.keys.key, 16, nonce, GTLS_IV_LEN, hdr.data(), 5, zeros.data(),
                  zeros.size(), ct.data(), tag.data(), 16), GSEC_OK);
    Bytes rec = cat(hdr, cat(ct, tag));
    EXPECT_EQ(stream(w.p.s.conn, rec), GTLS_ERR_PROTOCOL);
    EXPECT_EQ(gtls_conn_alert(w.p.s.conn), GTLS_ALERT_UNEXPECTED_MESSAGE);
  }
  {
    /* and a record that does authenticate, with the right padding, is read as what it is */
    Window w;
    GTLS_Buf b;
    gtls_buf_init(&b, nullptr, 4096);
    Bytes pt(10, 7);
    ASSERT_EQ(gtls_record_seal(&w.keys, 23, pt.data(), pt.size(), 10, &b), GTLS_OK);
    EXPECT_EQ(stream(w.p.s.conn, Bytes(b.data, b.data + b.len)), GTLS_ERR_PROTOCOL)
        << "application data before the handshake is done";
    EXPECT_EQ(gtls_conn_alert(w.p.s.conn), GTLS_ALERT_UNEXPECTED_MESSAGE);
    gtls_buf_free(&b);
  }
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
