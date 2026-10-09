/**
 * @file
 *
 * The real client against the real server over a loopback: every suite,
 * group and signature scheme, ALPN and SNI choices, HelloRetryRequest, the
 * stream split at every size, application data both ways, key update,
 * close_notify and the truncation check. Nothing here is simulated.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "hello.h"
#include "rfc_run.h"
#include "rfc_server.h"

using namespace gtlstest;

namespace {

const GTLS_Suite kSuites[] = {GTLS_SUITE_AES_128_GCM_SHA256, GTLS_SUITE_AES_256_GCM_SHA384,
    GTLS_SUITE_CHACHA20_POLY1305_SHA256};
const GTLS_Group kGroups[] = {GTLS_GROUP_X25519, GTLS_GROUP_SECP256R1, GTLS_GROUP_SECP384R1};

/** Complete the handshake and a round of data each way, and close cleanly. */
void talk(Pair & p, size_t chunk) {
  p.run(chunk);
  ASSERT_TRUE(p.connected()) << "client: " << result_name(gtls_conn_failure(p.c.conn))
                             << ", server: " << result_name(gtls_conn_failure(p.s.conn));
  Bytes up = pattern(5000, 1);
  Bytes down = pattern(40000, 2);
  p.send_all(p.c, p.s, up, chunk);
  p.send_all(p.s, p.c, down, chunk);
  p.run(chunk);
  EXPECT_EQ(p.s.got, up);
  EXPECT_EQ(p.c.got, down);
  ASSERT_EQ(gtls_conn_close(p.c.conn), GTLS_OK);
  p.run(chunk);
  EXPECT_TRUE(gtls_conn_peer_closed(p.s.conn));
  drain_reads(p.s);
  EXPECT_EQ(p.s.read_end, GTLS_ERR_CLOSED) << "later reads return end of stream";
  ASSERT_EQ(gtls_conn_close(p.s.conn), GTLS_OK);
  p.run(chunk);
  drain_reads(p.c);
  EXPECT_EQ(p.c.read_end, GTLS_ERR_CLOSED);
  EXPECT_EQ(gtls_conn_stream_eof(p.c.conn), GTLS_OK) << "a clean close is not a truncation";
  EXPECT_EQ(gtls_conn_stream_eof(p.s.conn), GTLS_OK);
}

}  // namespace

TEST(Loopback, EverySuiteAndGroupWithTheStreamSplitAtEveryByte) {
  std::unique_ptr<Cred> cred = ed_cred();
  for (GTLS_Suite suite : kSuites) {
    for (GTLS_Group group : kGroups) {
      for (size_t chunk : {static_cast<size_t>(0), static_cast<size_t>(1), static_cast<size_t>(7)}) {
        Pair p(*cred);
        p.scfg.suites = &suite;
        p.scfg.suite_count = 1;
        p.ccfg.groups = &group;
        p.ccfg.group_count = 1;
        ASSERT_EQ(p.build(), GTLS_OK);
        talk(p, chunk);
        EXPECT_EQ(gtls_conn_suite(p.c.conn), suite);
        EXPECT_EQ(gtls_conn_suite(p.s.conn), suite);
        EXPECT_EQ(gtls_conn_group(p.c.conn), group);
        EXPECT_EQ(gtls_conn_group(p.s.conn), group);
        EXPECT_FALSE(gtls_conn_retried(p.c.conn)) << "the client's first share was in the group";
        if (::testing::Test::HasFailure()) {
          return;
        }
      }
    }
  }
}

TEST(Loopback, EveryKindOfKeyAndEverySignatureScheme) {
  struct Case {
    const char * kind;
    GCERT_SigScheme scheme;
  };
  const Case cases[] = {
      {"rsa", GCERT_SIG_RSA_PSS_SHA256}, {"rsa", GCERT_SIG_RSA_PSS_SHA384},
      {"rsa", GCERT_SIG_RSA_PSS_SHA512}, {"p256", GCERT_SIG_ECDSA_P256_SHA256},
      {"p384", GCERT_SIG_ECDSA_P384_SHA384}, {"ed", GCERT_SIG_ED25519}};
  for (const Case & k : cases) {
    std::unique_ptr<Cred> cred = file_cred(k.kind);
    for (size_t chunk : {static_cast<size_t>(0), static_cast<size_t>(5)}) {
      Pair p(*cred);
      GCERT_SigScheme only = k.scheme;
      p.scfg.sig_algs = &only;
      p.scfg.sig_alg_count = 1;
      ASSERT_EQ(p.build(), GTLS_OK);
      talk(p, chunk);
      if (::testing::Test::HasFailure()) {
        ADD_FAILURE() << k.kind << " scheme " << std::hex << static_cast<unsigned>(k.scheme);
        return;
      }
    }
  }
}

TEST(Loopback, ADefaultServerSignsWithWhatItsKeyFits) {
  for (const char * kind : {"rsa", "p256", "p384", "ed"}) {
    std::unique_ptr<Cred> cred = file_cred(kind);
    Pair p(*cred);
    ASSERT_EQ(p.build(), GTLS_OK);
    talk(p, 0);
  }
}

namespace {

/** Bytes a connection has to send, taken off its output. */
Bytes take(GTLS_Conn * c) {
  Bytes out = stream_out(c);
  EXPECT_EQ(gtls_conn_stream_consume(c, out.size()), GTLS_OK);
  return out;
}

GTLS_Result give(GTLS_Conn * c, const Bytes & b, size_t * used = nullptr, int64_t now = kNow) {
  size_t u = 0;
  GTLS_Result r = gtls_conn_stream_feed(c, b.data(), b.size(), now, &u);
  EXPECT_SCRATCH_WIPED(c);
  if (used != nullptr) {
    *used = u;
  }
  return r;
}

std::vector<Bytes> records_of(const Bytes & wire) {
  std::vector<Bytes> out;
  size_t at = 0;
  while (at + 5 <= wire.size()) {
    size_t n = 5 + ((static_cast<size_t>(wire[at + 3]) << 8) | wire[at + 4]);
    EXPECT_LE(at + n, wire.size());
    out.push_back(Bytes(wire.begin() + at, wire.begin() + std::min(at + n, wire.size())));
    at += n;
  }
  EXPECT_EQ(at, wire.size());
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

/** The RFC 8448 client, in stream mode, ready to be given the server's records. */
struct RfcClient {
  Vec v;
  EmptyTrust trust;
  GTLS_Context * ctx = nullptr;
  GTLS_Conn * conn = nullptr;
  ScriptedRandom rnd;
  FixedVerdict verdict;
  explicit RfcClient(const char * trace = "simple-1rtt") : v(trace) {
    GTLS_ContextConfig cfg;
    gtls_context_config_default(&cfg);
    cfg.trust = trust.store;
    EXPECT_EQ(gtls_context_new(nullptr, &cfg, &ctx), GTLS_OK);
    EXPECT_EQ(gtls_conn_new(ctx, "server", 6, &conn), GTLS_OK);
    gtls_conn_set_hooks(conn, ScriptedRandom::fn, &rnd, FixedVerdict::fn, &verdict);
    if (std::string(trace) == "hrr") {
      rnd.chunks.push_back(v["client.create-an-ephemeral-p-256-key-pair.private-key"]);
    }
    EXPECT_EQ(gtls_conn_start_raw(conn, v["client.construct-a-clienthello-handshake-message.clienthello"].data(),
                  v["client.construct-a-clienthello-handshake-message.clienthello"].size(),
                  v["client.create-an-ephemeral-x25519-key-pair.private-key"].data()),
        GTLS_OK);
  }
  ~RfcClient() {
    gtls_conn_free(conn);
    gtls_context_free(ctx);
  }
};

}  // namespace

TEST(Rfc8448Client, TheWholeTraceAsRecordsInBothDirections) {
  RfcClient r;
  const Vec & v = r.v;
  EXPECT_EQ(stream_out(r.conn), v["client.send-handshake-record.complete-record"])
      << "the ClientHello record, with the 1.0 record version of a first hello";
  EXPECT_EQ(gtls_conn_stream_consume(r.conn, stream_out(r.conn).size()), GTLS_OK);
  size_t used = 0;
  Bytes flight = cat(v["server.send-handshake-record.complete-record"],
      v["server.send-handshake-record@2.complete-record"]);
  ASSERT_EQ(give(r.conn, flight, &used, 1700000000), GTLS_OK);
  EXPECT_EQ(used, flight.size());
  EXPECT_TRUE(gtls_conn_is_connected(r.conn));
  EXPECT_EQ(stream_out(r.conn), v["client.send-handshake-record@2.complete-record"])
      << "the client's Finished, protected under its handshake key";
  take(r.conn);
  const Bytes & payload = v["client.send-application-data-record.payload"];
  size_t written = 0;
  ASSERT_EQ(gtls_conn_write(r.conn, payload.data(), payload.size(), &written), GTLS_OK);
  EXPECT_EQ(stream_out(r.conn), v["client.send-application-data-record.complete-record"]);
  take(r.conn);
  /* the NewSessionTicket is taken and dropped, then the data, then close_notify */
  ASSERT_EQ(give(r.conn, v["server.send-handshake-record@3.complete-record"]), GTLS_OK);
  ASSERT_EQ(give(r.conn, v["server.send-application-data-record.complete-record"]), GTLS_OK);
  EXPECT_EQ(read_all(r.conn), v["server.send-application-data-record.payload"]);
  ASSERT_EQ(give(r.conn, v["server.send-alert-record.complete-record"]), GTLS_OK);
  EXPECT_TRUE(gtls_conn_peer_closed(r.conn));
  Bytes b(8);
  size_t n = 1;
  EXPECT_EQ(gtls_conn_read(r.conn, b.data(), b.size(), &n), GTLS_ERR_CLOSED);
  ASSERT_EQ(gtls_conn_close(r.conn), GTLS_OK);
  EXPECT_EQ(stream_out(r.conn), v["client.send-alert-record.complete-record"]);
}

TEST(Rfc8448Client, TheRetryTraceAsRecords) {
  RfcClient r("hrr");
  const Vec & v = r.v;
  EXPECT_EQ(take(r.conn), v["client.send-handshake-record.complete-record"]);
  ASSERT_EQ(give(r.conn, v["server.send-handshake-record.complete-record"]), GTLS_OK);
  EXPECT_EQ(take(r.conn), v["client.send-handshake-record@2.complete-record"])
      << "the second ClientHello, whose record says 1.2";
  ASSERT_EQ(give(r.conn, cat(v["server.send-handshake-record@2.complete-record"],
                             v["server.send-handshake-record@3.complete-record"])),
      GTLS_OK);
  EXPECT_TRUE(gtls_conn_is_connected(r.conn));
  EXPECT_EQ(take(r.conn), v["client.send-handshake-record@3.complete-record"]);
  ASSERT_EQ(give(r.conn, v["server.send-alert-record.complete-record"]), GTLS_OK);
  EXPECT_TRUE(gtls_conn_peer_closed(r.conn));
  ASSERT_EQ(gtls_conn_close(r.conn), GTLS_OK);
  EXPECT_EQ(take(r.conn), v["client.send-alert-record.complete-record"]);
}

TEST(Rfc8448Client, TheTraceAtEveryFeedSize) {
  for (size_t chunk : {1u, 2u, 3u, 5u, 17u, 100u, 1000u}) {
    RfcClient r;
    const Vec & v = r.v;
    take(r.conn);
    Bytes all = cat(cat(v["server.send-handshake-record.complete-record"],
                        v["server.send-handshake-record@2.complete-record"]),
        cat(v["server.send-handshake-record@3.complete-record"],
            v["server.send-application-data-record.complete-record"]));
    for (size_t at = 0; at < all.size(); at += chunk) {
      size_t n = std::min(chunk, all.size() - at);
      size_t used = 0;
      ASSERT_EQ(gtls_conn_stream_feed(r.conn, all.data() + at, n, 1700000000, &used), GTLS_OK);
      ASSERT_EQ(used, n) << "chunk " << chunk;
    }
    EXPECT_TRUE(gtls_conn_is_connected(r.conn));
    EXPECT_EQ(read_all(r.conn), v["server.send-application-data-record.payload"]);
    EXPECT_EQ(take(r.conn), v["client.send-handshake-record@2.complete-record"]);
  }
}

TEST(Rfc8448Client, EveryByteOfTheProtectedFlightFlippedIsRefused) {
  RfcClient probe;
  const Bytes flight = probe.v["server.send-handshake-record@2.complete-record"];
  const Bytes sh = probe.v["server.send-handshake-record.complete-record"];
  size_t checked = 0;
  for (size_t i = 0; i < flight.size(); i++) {
    for (unsigned bit : {0x01u, 0x80u}) {
      RfcClient r;
      take(r.conn);
      ASSERT_EQ(give(r.conn, sh), GTLS_OK);
      Bytes bad = flight;
      bad[i] ^= static_cast<unsigned char>(bit);
      GTLS_Result res = give(r.conn, bad, nullptr, 1700000000);
      EXPECT_FALSE(gtls_conn_is_connected(r.conn)) << "byte " << i;
      if (i >= 5) {
        EXPECT_EQ(res, GTLS_ERR_MISMATCH) << "byte " << i << " bit " << bit;
        EXPECT_EQ(gtls_conn_alert(r.conn), GTLS_ALERT_BAD_RECORD_MAC);
        EXPECT_TRUE(gtls_conn_is_failed(r.conn));
        EXPECT_TRUE(gtls_conn_secrets_are_wiped(r.conn)) << "a record that does not authenticate wipes";
      } else if (res != GTLS_OK) {
        EXPECT_TRUE(res == GTLS_ERR_MISMATCH || res == GTLS_ERR_PROTOCOL || res == GTLS_ERR_LIMIT)
            << "header byte " << i << ": " << result_name(res);
        EXPECT_TRUE(gtls_conn_secrets_are_wiped(r.conn));
      }
      checked++;
    }
  }
  EXPECT_EQ(checked, flight.size() * 2);
}

TEST(Rfc8448Client, EveryByteOfAnApplicationRecordFlippedIsRefused) {
  RfcClient probe;
  const Bytes rec = probe.v["server.send-application-data-record.complete-record"];
  for (size_t i = 5; i < rec.size(); i++) {
    RfcClient r;
    take(r.conn);
    ASSERT_EQ(give(r.conn, cat(r.v["server.send-handshake-record.complete-record"],
                               r.v["server.send-handshake-record@2.complete-record"]),
                  nullptr, 1700000000),
        GTLS_OK);
    ASSERT_EQ(give(r.conn, r.v["server.send-handshake-record@3.complete-record"]), GTLS_OK);
    Bytes bad = rec;
    bad[i] ^= 0x04;
    EXPECT_EQ(give(r.conn, bad), GTLS_ERR_MISMATCH) << "byte " << i;
    EXPECT_EQ(gtls_conn_alert(r.conn), GTLS_ALERT_BAD_RECORD_MAC);
    EXPECT_TRUE(gtls_conn_secrets_are_wiped(r.conn));
    EXPECT_EQ(read_all(r.conn), Bytes()) << "nothing from a record that did not authenticate";
  }
}

TEST(Rfc8448Client, ARecordAfterAFailureIsNeverAccepted) {
  RfcClient r;
  take(r.conn);
  Bytes bad = r.v["server.send-handshake-record.complete-record"];
  bad[0] = 99;
  EXPECT_EQ(give(r.conn, bad), GTLS_ERR_PROTOCOL);
  EXPECT_EQ(gtls_conn_alert(r.conn), GTLS_ALERT_UNEXPECTED_MESSAGE);
  size_t used = 7;
  EXPECT_EQ(give(r.conn, r.v["server.send-handshake-record.complete-record"], &used), GTLS_ERR_FAILED);
  EXPECT_EQ(used, 0u);
  EXPECT_FALSE(gtls_conn_is_connected(r.conn));
  /* the alert is waiting to be sent, as a plain record */
  Bytes out = take(r.conn);
  EXPECT_EQ(out, (Bytes{21, 3, 3, 0, 2, 2, 10}));
  EXPECT_EQ(stream_out(r.conn), Bytes());
}

TEST(Rfc8448Server, EveryByteOfTheClientFinishedFlippedIsRefused) {
  RfcServer probe;
  const Bytes fin = probe.v["client.send-handshake-record@2.complete-record"];
  for (size_t i = 5; i < fin.size(); i++) {
    RfcServer r;
    size_t used = 0;
    const Bytes & ch = r.v["client.send-handshake-record.complete-record"];
    ASSERT_EQ(gtls_conn_stream_feed(r.conn, ch.data(), ch.size(), r.now, &used), GTLS_OK);
    take(r.conn);
    Bytes bad = fin;
    bad[i] ^= 0x10;
    EXPECT_EQ(give(r.conn, bad), GTLS_ERR_MISMATCH) << "byte " << i;
    EXPECT_EQ(gtls_conn_alert(r.conn), GTLS_ALERT_BAD_RECORD_MAC);
    EXPECT_TRUE(gtls_conn_secrets_are_wiped(r.conn));
    EXPECT_FALSE(gtls_conn_is_connected(r.conn));
  }
}

TEST(Rfc8448Server, TheTraceAtEveryFeedSize) {
  for (size_t chunk : {1u, 2u, 3u, 5u, 17u, 100u}) {
    RfcServer r;
    Bytes all = cat(r.v["client.send-handshake-record.complete-record"],
        r.v["client.send-handshake-record@2.complete-record"]);
    all = cat(all, r.v["client.send-application-data-record.complete-record"]);
    for (size_t at = 0; at < all.size(); at += chunk) {
      size_t n = std::min(chunk, all.size() - at);
      size_t used = 0;
      ASSERT_EQ(gtls_conn_stream_feed(r.conn, all.data() + at, n, r.now, &used), GTLS_OK);
      ASSERT_EQ(used, n);
    }
    EXPECT_TRUE(gtls_conn_is_connected(r.conn));
    EXPECT_EQ(read_all(r.conn), r.v["client.send-application-data-record.payload"]);
  }
}

/* ------------------------------------------------------------------ the live loop */

TEST(Stream, RecordsTooBigAreRefusedAtTheHeader) {
  {
    /* a protected-epoch record that claims more than 2^14 + 256 bytes */
    std::unique_ptr<Cred> cred = ed_cred();
    Pair p(*cred);
    ASSERT_EQ(p.build(), GTLS_OK);
    p.run();
    ASSERT_TRUE(p.connected());
    Bytes h = {23, 3, 3, 0x41, 0x01};
    size_t used = 0;
    EXPECT_EQ(give(p.s.conn, h, &used), GTLS_ERR_LIMIT) << "refused before the body arrives";
    EXPECT_EQ(used, 5u);
    EXPECT_EQ(gtls_conn_alert(p.s.conn), GTLS_ALERT_RECORD_OVERFLOW);
    EXPECT_TRUE(gtls_conn_secrets_are_wiped(p.s.conn));
  }
  {
    /* a plaintext record over 2^14 */
    std::unique_ptr<Cred> cred = ed_cred();
    Pair p(*cred);
    ASSERT_EQ(p.build(), GTLS_OK);
    Bytes h = {22, 3, 1, 0x40, 0x01};
    EXPECT_EQ(give(p.s.conn, h), GTLS_ERR_LIMIT);
    EXPECT_EQ(gtls_conn_alert(p.s.conn), GTLS_ALERT_RECORD_OVERFLOW);
  }
  {
    /* the biggest a record may be is not refused */
    std::unique_ptr<Cred> cred = ed_cred();
    Pair p(*cred);
    ASSERT_EQ(p.build(), GTLS_OK);
    p.run();
    ASSERT_TRUE(p.connected());
    Bytes big = pattern(100000, 3);
    p.send_all(p.c, p.s, big);
    p.run();
    EXPECT_EQ(p.s.got, big);
  }
}

TEST(Stream, WhatIsNotARecordIsRefusedAtOnce) {
  struct Case {
    Bytes header;
    GTLS_Result result;
    unsigned alert;
    const char * what;
  };
  const Case cases[] = {
      {{0x47, 0x45, 0x54, 0x20, 0x2f}, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNEXPECTED_MESSAGE, "an HTTP request"},
      {{0, 3, 3, 0, 1}, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNEXPECTED_MESSAGE, "type 0"},
      {{24, 3, 3, 0, 1}, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNEXPECTED_MESSAGE, "type 24 (heartbeat)"},
      {{22, 2, 0, 0, 5}, GTLS_ERR_PROTOCOL, GTLS_ALERT_PROTOCOL_VERSION, "SSL 2 style"},
      {{20, 3, 3, 0, 2}, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNEXPECTED_MESSAGE, "a change_cipher_spec of 2 bytes"},
  };
  for (const Case & k : cases) {
    std::unique_ptr<Cred> cred = ed_cred();
    Pair p(*cred);
    ASSERT_EQ(p.build(), GTLS_OK);
    EXPECT_EQ(give(p.s.conn, k.header), k.result) << k.what;
    EXPECT_EQ(gtls_conn_alert(p.s.conn), k.alert) << k.what;
  }
}

TEST(Stream, TheKeysAreUsedOnlyForWhatTheyProtect) {
  std::unique_ptr<Cred> cred = ed_cred();
  /* application data, plaintext, before any keys */
  {
    Pair p(*cred);
    ASSERT_EQ(p.build(), GTLS_OK);
    EXPECT_EQ(give(p.s.conn, Bytes{23, 3, 3, 0, 1, 7}), GTLS_ERR_PROTOCOL);
    EXPECT_EQ(gtls_conn_alert(p.s.conn), GTLS_ALERT_UNEXPECTED_MESSAGE);
  }
  /* a plaintext handshake record once the handshake keys are in use */
  {
    Pair p(*cred);
    ASSERT_EQ(p.build(), GTLS_OK);
    ASSERT_EQ(give(p.s.conn, take(p.c.conn)), GTLS_OK);
    take(p.s.conn);
    EXPECT_EQ(give(p.s.conn, Bytes{22, 3, 3, 0, 4, 20, 0, 0, 0}), GTLS_ERR_PROTOCOL)
        << "the server waits for a protected Finished";
    EXPECT_EQ(gtls_conn_alert(p.s.conn), GTLS_ALERT_UNEXPECTED_MESSAGE);
  }
  /* application data inside a handshake-epoch record */
  {
    Pair p(*cred);
    ASSERT_EQ(p.build(), GTLS_OK);
    ASSERT_EQ(give(p.s.conn, take(p.c.conn)), GTLS_OK);
    take(p.s.conn);
    GTLS_Buf b;
    gtls_buf_init(&b, nullptr, 1 << 16);
    /* the client's handshake write key is not installed yet: borrow the server's read key */
    GTLS_RecordKeys k;
    Bytes sec(32);
    size_t n = 0;
    ASSERT_EQ(gtls_conn_secret(p.s.conn, GTLS_EPOCH_HANDSHAKE, GTLS_DIR_READ, sec.data(), sec.size(), &n), GTLS_OK);
    ASSERT_EQ(gtls_record_keys_from_secret(&k, gtls_conn_suite(p.s.conn), sec.data(), 0), GTLS_OK);
    ASSERT_EQ(gtls_record_seal(&k, GTLS_CT_APPLICATION_DATA, "hi", 2, 0, &b), GTLS_OK);
    EXPECT_EQ(give(p.s.conn, Bytes(b.data, b.data + b.len)), GTLS_ERR_PROTOCOL);
    EXPECT_EQ(gtls_conn_alert(p.s.conn), GTLS_ALERT_UNEXPECTED_MESSAGE);
    gtls_buf_free(&b);
  }
}

TEST(Stream, AnEmptyHandshakeRecordAndAnAlertOfTheWrongSizeAreRefused) {
  std::unique_ptr<Cred> cred = ed_cred();
  auto connected = [&](Pair & p) {
    ASSERT_EQ(p.build(), GTLS_OK);
    p.run();
    ASSERT_TRUE(p.connected());
  };
  auto craft = [](GTLS_Conn * from, unsigned type, const Bytes & pt) {
    GTLS_Buf b;
    gtls_buf_init(&b, nullptr, 1 << 16);
    EXPECT_EQ(gtls_record_seal(&from->sec.wr, type, pt.data(), pt.size(), 0, &b), GTLS_OK);
    Bytes out(b.data, b.data + b.len);
    gtls_buf_free(&b);
    return out;
  };
  {
    Pair p(*cred);
    connected(p);
    EXPECT_EQ(give(p.s.conn, craft(p.c.conn, GTLS_CT_HANDSHAKE, Bytes())), GTLS_ERR_PROTOCOL);
    EXPECT_EQ(gtls_conn_alert(p.s.conn), GTLS_ALERT_UNEXPECTED_MESSAGE);
  }
  for (const Bytes & a : {Bytes(), Bytes{1}, Bytes{1, 0, 0}}) {
    Pair p(*cred);
    connected(p);
    EXPECT_EQ(give(p.s.conn, craft(p.c.conn, GTLS_CT_ALERT, a)), GTLS_ERR_CORRUPT) << a.size();
    EXPECT_EQ(gtls_conn_alert(p.s.conn), GTLS_ALERT_DECODE_ERROR);
  }
  {
    Pair p(*cred);
    connected(p);
    EXPECT_EQ(give(p.s.conn, craft(p.c.conn, 99, Bytes{1})), GTLS_ERR_PROTOCOL) << "an unknown inner type";
    EXPECT_EQ(gtls_conn_alert(p.s.conn), GTLS_ALERT_UNEXPECTED_MESSAGE);
  }
  {
    Pair p(*cred);
    connected(p);
    EXPECT_EQ(give(p.s.conn, craft(p.c.conn, GTLS_CT_CHANGE_CIPHER_SPEC, Bytes{1})), GTLS_ERR_PROTOCOL)
        << "a change_cipher_spec inside a protected record";
  }
  {
    Pair p(*cred);
    connected(p);
    /* an empty application record is allowed, and leaves nothing to read */
    EXPECT_EQ(give(p.s.conn, craft(p.c.conn, GTLS_CT_APPLICATION_DATA, Bytes())), GTLS_OK);
    EXPECT_EQ(read_all(p.s.conn), Bytes());
    EXPECT_EQ(give(p.s.conn, craft(p.c.conn, GTLS_CT_APPLICATION_DATA, Bytes{9, 8})), GTLS_OK);
    EXPECT_EQ(read_all(p.s.conn), (Bytes{9, 8}));
  }
}

TEST(Stream, PaddingInAReceivedRecordIsAcceptedAndCapped) {
  std::unique_ptr<Cred> cred = ed_cred();
  for (size_t pad : {size_t(1), size_t(100), size_t(5000)}) {
    Pair p(*cred);
    p.slimits.max_record_padding = 5000;
    ASSERT_EQ(p.build(), GTLS_OK);
    p.run();
    ASSERT_TRUE(p.connected());
    GTLS_Buf b;
    gtls_buf_init(&b, nullptr, 1 << 16);
    Bytes data = pattern(70, 4);
    ASSERT_EQ(gtls_record_seal(&p.c.conn->sec.wr, GTLS_CT_APPLICATION_DATA, data.data(), data.size(), pad, &b),
        GTLS_OK);
    ASSERT_EQ(give(p.s.conn, Bytes(b.data, b.data + b.len)), GTLS_OK) << pad;
    EXPECT_EQ(read_all(p.s.conn), data);
    gtls_buf_free(&b);
  }
  Pair p(*cred);
  p.slimits.max_record_padding = 99;
  ASSERT_EQ(p.build(), GTLS_OK);
  p.run();
  GTLS_Buf b;
  gtls_buf_init(&b, nullptr, 1 << 16);
  ASSERT_EQ(gtls_record_seal(&p.c.conn->sec.wr, GTLS_CT_APPLICATION_DATA, "x", 1, 100, &b), GTLS_OK);
  EXPECT_EQ(give(p.s.conn, Bytes(b.data, b.data + b.len)), GTLS_ERR_LIMIT);
  EXPECT_EQ(gtls_conn_alert(p.s.conn), GTLS_ALERT_RECORD_OVERFLOW);
  gtls_buf_free(&b);
}

TEST(Stream, AZeroPaddingCapAcceptsNoPaddingAtAll) {
  std::unique_ptr<Cred> cred = ed_cred();
  for (bool zero : {false, true}) {
    /* Without the constant, 0 is the default: padding is accepted. */
    Pair p(*cred);
    p.slimits.max_record_padding = zero ? GTLS_LIMIT_ZERO : 0;
    ASSERT_EQ(p.build(), GTLS_OK);
    p.run();
    ASSERT_TRUE(p.connected());
    GTLS_Buf b;
    gtls_buf_init(&b, nullptr, 1 << 16);
    ASSERT_EQ(gtls_record_seal(&p.c.conn->sec.wr, GTLS_CT_APPLICATION_DATA, "ab", 2, 0, &b), GTLS_OK);
    ASSERT_EQ(give(p.s.conn, Bytes(b.data, b.data + b.len)), GTLS_OK) << "a record with no padding is fine";
    EXPECT_EQ(read_all(p.s.conn), (Bytes{'a', 'b'}));
    b.len = 0;
    ASSERT_EQ(gtls_record_seal(&p.c.conn->sec.wr, GTLS_CT_APPLICATION_DATA, "cd", 2, 1, &b), GTLS_OK);
    GTLS_Result r = give(p.s.conn, Bytes(b.data, b.data + b.len));
    if (zero) {
      EXPECT_EQ(r, GTLS_ERR_LIMIT) << "one byte of padding is past a cap of zero";
      EXPECT_EQ(gtls_conn_alert(p.s.conn), GTLS_ALERT_RECORD_OVERFLOW);
    } else {
      EXPECT_EQ(r, GTLS_OK) << "the default accepts it";
      EXPECT_EQ(read_all(p.s.conn), (Bytes{'c', 'd'}));
    }
    gtls_buf_free(&b);
  }
}

TEST(Stream, ARecordOfNothingButPaddingIsRefused) {
  std::unique_ptr<Cred> cred = ed_cred();
  Pair p(*cred);
  ASSERT_EQ(p.build(), GTLS_OK);
  p.run();
  ASSERT_TRUE(p.connected());
  /* sealed by hand: the key and IV are the client's, the nonce written out */
  GTLS_RecordKeys & k = p.c.conn->sec.wr;
  ASSERT_EQ(k.suite, static_cast<uint32_t>(GTLS_SUITE_AES_128_GCM_SHA256));
  Bytes nonce(k.iv, k.iv + 12);
  for (int i = 0; i < 8; i++) nonce[11 - i] ^= static_cast<unsigned char>(k.seq >> (8 * i));
  Bytes inner(20, 0);
  Bytes header = {23, 3, 3, 0, 36};
  Bytes ct(20), tag(16);
  ASSERT_EQ(gsec_aes_gcm_encrypt(k.key, 16, nonce.data(), 12, header.data(), 5, inner.data(), 20, ct.data(),
                tag.data(), 16),
      GSEC_OK);
  Bytes rec = cat(header, cat(ct, tag));
  EXPECT_EQ(give(p.s.conn, rec), GTLS_ERR_PROTOCOL);
  EXPECT_EQ(gtls_conn_alert(p.s.conn), GTLS_ALERT_UNEXPECTED_MESSAGE);
}

TEST(Stream, AnApplicationRecordBeforeTheHandshakeIsDoneIsRefused) {
  std::unique_ptr<Cred> cred = ed_cred();
  Pair p(*cred);
  ASSERT_EQ(p.build(), GTLS_OK);
  /* run the client through the server's flight but not the client's Finished */
  ASSERT_EQ(give(p.s.conn, take(p.c.conn)), GTLS_OK);
  ASSERT_EQ(give(p.c.conn, take(p.s.conn)), GTLS_OK);
  ASSERT_TRUE(gtls_conn_is_connected(p.c.conn));
  /* the client's Finished is still in its output; the server has not seen it */
  size_t w = 0;
  EXPECT_EQ(gtls_conn_write(p.s.conn, "hi", 2, &w), GTLS_ERR_INVALID) << "a server writes after the client's Finished";
  EXPECT_EQ(w, 0u);
  EXPECT_EQ(gtls_conn_write(p.c.conn, "hi", 2, &w), GTLS_OK);
  Bytes out = take(p.c.conn);
  std::vector<Bytes> recs = records_of(out);
  ASSERT_GE(recs.size(), 2u);
  /* the data record first, then the Finished: the server will not take that order */
  EXPECT_EQ(give(p.s.conn, recs.back()), GTLS_ERR_MISMATCH)
      << "data sealed under the application key, read under the handshake key";
}

/* ----------------------------------------------------------------- close and EOF */

TEST(Close, ATruncationIsNotACleanClose) {
  std::unique_ptr<Cred> cred = ed_cred();
  Pair p(*cred);
  ASSERT_EQ(p.build(), GTLS_OK);
  p.run();
  ASSERT_TRUE(p.connected());
  p.send_all(p.c, p.s, Bytes(10, 1));
  p.run();
  EXPECT_EQ(p.s.got, Bytes(10, 1));
  EXPECT_EQ(gtls_conn_stream_eof(p.s.conn), GTLS_ERR_TRUNCATED);
  EXPECT_TRUE(gtls_conn_is_failed(p.s.conn));
  EXPECT_EQ(gtls_conn_failure(p.s.conn), GTLS_ERR_TRUNCATED);
  EXPECT_EQ(gtls_conn_alert(p.s.conn), GTLS_ALERT_NONE) << "no one is left to send an alert to";
  EXPECT_TRUE(gtls_conn_secrets_are_wiped(p.s.conn));
  EXPECT_EQ(stream_out(p.s.conn), Bytes()) << "and none is sent";
  size_t n = 5;
  unsigned char b[4];
  EXPECT_EQ(gtls_conn_read(p.s.conn, b, 4, &n), GTLS_ERR_FAILED);
  EXPECT_EQ(gtls_conn_stream_eof(p.s.conn), GTLS_ERR_FAILED);
  EXPECT_NE(GTLS_ERR_TRUNCATED, GTLS_ERR_CLOSED);
}

TEST(Close, ACleanCloseThenEndOfFileIsClean) {
  std::unique_ptr<Cred> cred = ed_cred();
  Pair p(*cred);
  ASSERT_EQ(p.build(), GTLS_OK);
  p.run();
  p.auto_read = false;
  p.send_all(p.c, p.s, Bytes(10, 1));
  ASSERT_EQ(gtls_conn_close(p.c.conn), GTLS_OK);
  EXPECT_EQ(gtls_conn_close(p.c.conn), GTLS_OK) << "twice is fine";
  p.run();
  EXPECT_TRUE(gtls_conn_peer_closed(p.s.conn));
  EXPECT_EQ(gtls_conn_stream_eof(p.s.conn), GTLS_OK);
  EXPECT_FALSE(gtls_conn_is_failed(p.s.conn));
  /* what was sent before the close is still there to read, and then the end */
  unsigned char buf[100];
  size_t n = 0;
  ASSERT_EQ(gtls_conn_read(p.s.conn, buf, sizeof buf, &n), GTLS_OK);
  EXPECT_EQ(n, 10u);
  EXPECT_EQ(gtls_conn_read(p.s.conn, buf, sizeof buf, &n), GTLS_ERR_CLOSED);
  EXPECT_EQ(n, 0u);
  size_t w = 0;
  EXPECT_EQ(gtls_conn_write(p.c.conn, "x", 1, &w), GTLS_ERR_CLOSED);
  EXPECT_EQ(gtls_conn_key_update(p.c.conn, 0), GTLS_ERR_CLOSED);
  /* the server can still write to the client, which has closed only its own end */
  EXPECT_EQ(gtls_conn_write(p.s.conn, "yes", 3, &w), GTLS_OK);
  p.run();
  EXPECT_EQ(read_all(p.c.conn), (Bytes{'y', 'e', 's'}));
}

TEST(Close, DataAfterCloseNotifyIsIgnored) {
  std::unique_ptr<Cred> cred = ed_cred();
  Pair p(*cred);
  ASSERT_EQ(p.build(), GTLS_OK);
  p.run();
  ASSERT_EQ(gtls_conn_close(p.c.conn), GTLS_OK);
  Bytes closing = take(p.c.conn);
  /* a record the client "sends" after its close_notify, sealed by the library
   * under the next number: it must be ignored, not read */
  size_t w = 0;
  p.c.conn->local_closed = 0;
  ASSERT_EQ(gtls_conn_write(p.c.conn, "late", 4, &w), GTLS_OK);
  Bytes late = take(p.c.conn);
  size_t used = 0;
  ASSERT_EQ(give(p.s.conn, cat(closing, late), &used), GTLS_OK);
  EXPECT_EQ(used, closing.size() + late.size()) << "counted as consumed";
  EXPECT_EQ(read_all(p.s.conn), Bytes());
  EXPECT_TRUE(gtls_conn_peer_closed(p.s.conn));
  EXPECT_EQ(give(p.s.conn, Bytes{1, 2, 3}, &used), GTLS_OK);
  EXPECT_EQ(used, 3u);
}

TEST(Close, APeersFatalAlertIsReportedAndFatal) {
  std::unique_ptr<Cred> cred = ed_cred();
  /* at the initial epoch: the server's own refusal, as the client reads it */
  {
    Pair p(*cred);
    p.salpn = {"h2"};
    p.calpn = {"http/1.1"};
    ASSERT_EQ(p.build(), GTLS_OK);
    ASSERT_EQ(give(p.s.conn, take(p.c.conn)), GTLS_ERR_ALPN);
    EXPECT_EQ(gtls_conn_alert(p.s.conn), GTLS_ALERT_NO_APPLICATION_PROTOCOL);
    Bytes alert = take(p.s.conn);
    EXPECT_EQ(alert, (Bytes{21, 3, 3, 0, 2, 2, 120})) << "a fatal no_application_protocol, in the clear";
    EXPECT_EQ(give(p.c.conn, alert), GTLS_ERR_ALERT);
    EXPECT_EQ(gtls_conn_peer_alert(p.c.conn), GTLS_ALERT_NO_APPLICATION_PROTOCOL);
    EXPECT_EQ(gtls_conn_alert(p.c.conn), GTLS_ALERT_NONE) << "an alert is not answered with another";
    EXPECT_TRUE(gtls_conn_secrets_are_wiped(p.c.conn));
    EXPECT_EQ(stream_out(p.c.conn), Bytes());
  }
  /* under the keys: an internal_error after the handshake */
  {
    Pair p(*cred);
    ASSERT_EQ(p.build(), GTLS_OK);
    p.run();
    ASSERT_TRUE(p.connected());
    GTLS_Buf b;
    gtls_buf_init(&b, nullptr, 1000);
    Bytes a = {2, 80};
    ASSERT_EQ(gtls_record_seal(&p.c.conn->sec.wr, GTLS_CT_ALERT, a.data(), 2, 0, &b), GTLS_OK);
    EXPECT_EQ(give(p.s.conn, Bytes(b.data, b.data + b.len)), GTLS_ERR_ALERT);
    EXPECT_EQ(gtls_conn_peer_alert(p.s.conn), 80u);
    gtls_buf_free(&b);
  }
  /* a warning-level alert that is not a closure is fatal too (RFC 8446 section 6) */
  {
    Pair p(*cred);
    ASSERT_EQ(p.build(), GTLS_OK);
    p.run();
    GTLS_Buf b;
    gtls_buf_init(&b, nullptr, 1000);
    Bytes a = {1, 46};
    ASSERT_EQ(gtls_record_seal(&p.c.conn->sec.wr, GTLS_CT_ALERT, a.data(), 2, 0, &b), GTLS_OK);
    EXPECT_EQ(give(p.s.conn, Bytes(b.data, b.data + b.len)), GTLS_ERR_ALERT);
    EXPECT_EQ(gtls_conn_peer_alert(p.s.conn), 46u);
    gtls_buf_free(&b);
  }
  /* user_canceled is a warning that closure follows, and is not fatal */
  {
    Pair p(*cred);
    ASSERT_EQ(p.build(), GTLS_OK);
    p.run();
    GTLS_Buf b;
    gtls_buf_init(&b, nullptr, 1000);
    Bytes a = {1, 90};
    ASSERT_EQ(gtls_record_seal(&p.c.conn->sec.wr, GTLS_CT_ALERT, a.data(), 2, 0, &b), GTLS_OK);
    EXPECT_EQ(give(p.s.conn, Bytes(b.data, b.data + b.len)), GTLS_OK);
    EXPECT_FALSE(gtls_conn_is_failed(p.s.conn));
    EXPECT_FALSE(gtls_conn_peer_closed(p.s.conn));
    gtls_buf_free(&b);
  }
}

TEST(Close, EveryLocalFailureSendsItsAlertUnderTheKeysInUse) {
  std::unique_ptr<Cred> cred = ed_cred();
  /* after the handshake: a record that does not authenticate; the alert comes
   * back protected, and the other side reads it */
  Pair p(*cred);
  ASSERT_EQ(p.build(), GTLS_OK);
  p.run();
  ASSERT_TRUE(p.connected());
  Bytes junk = {23, 3, 3, 0, 20};
  junk.resize(25, 0x77);
  EXPECT_EQ(give(p.s.conn, junk), GTLS_ERR_MISMATCH);
  EXPECT_EQ(gtls_conn_alert(p.s.conn), GTLS_ALERT_BAD_RECORD_MAC);
  Bytes alert = take(p.s.conn);
  ASSERT_EQ(alert.size(), 5u + 2 + 1 + 16);
  EXPECT_EQ(alert[0], 23) << "protected, so it looks like application data";
  EXPECT_EQ(give(p.c.conn, alert), GTLS_ERR_ALERT);
  EXPECT_EQ(gtls_conn_peer_alert(p.c.conn), GTLS_ALERT_BAD_RECORD_MAC);
}

TEST(Close, AFailureDuringTheHandshakeIsAnAlertTheOtherEndReads) {
  /* the client's certificate check refuses the server's chain: the client
   * sends bad_certificate-class alert protected by its handshake key, and the
   * server reports it */
  std::unique_ptr<Cred> cred = ed_cred();
  Pair p(*cred);
  p.host = "someone-else.test";
  ASSERT_EQ(p.build(), GTLS_OK);
  p.run();
  EXPECT_TRUE(gtls_conn_is_failed(p.c.conn));
  EXPECT_EQ(gtls_conn_failure(p.c.conn), GTLS_ERR_CERT_HOST);
  EXPECT_EQ(gtls_conn_alert(p.c.conn), GTLS_ALERT_BAD_CERTIFICATE);
  EXPECT_EQ(p.s.feed_result, GTLS_ERR_ALERT);
  EXPECT_EQ(gtls_conn_peer_alert(p.s.conn), GTLS_ALERT_BAD_CERTIFICATE);
  EXPECT_TRUE(gtls_conn_secrets_are_wiped(p.c.conn));
  EXPECT_TRUE(gtls_conn_secrets_are_wiped(p.s.conn));
}

/* ---------------------------------------------------------------------------- ALPN */

TEST(StreamAlpn, EveryCaseEndToEnd) {
  struct Case {
    std::vector<const char *> client, server;
    const char * want;     /* "" for none */
    bool fails;
  };
  const Case cases[] = {
      {{"h2", "http/1.1"}, {"h2", "http/1.1"}, "h2", false},
      {{"http/1.1", "h2"}, {"h2", "http/1.1"}, "h2", false},
      {{"http/1.1"}, {"h2", "http/1.1"}, "http/1.1", false},
      {{"h2"}, {"http/1.1"}, "", true},
      {{}, {"h2"}, "", false},
      {{"h2"}, {}, "", false},
      {{}, {}, "", false},
  };
  for (const Case & k : cases) {
    std::unique_ptr<Cred> cred = ed_cred();
    Pair p(*cred);
    p.calpn = k.client;
    p.salpn = k.server;
    ASSERT_EQ(p.build(), GTLS_OK);
    p.run();
    if (k.fails) {
      EXPECT_TRUE(gtls_conn_is_failed(p.s.conn));
      EXPECT_EQ(gtls_conn_failure(p.s.conn), GTLS_ERR_ALPN);
      EXPECT_EQ(gtls_conn_alert(p.s.conn), GTLS_ALERT_NO_APPLICATION_PROTOCOL);
      EXPECT_EQ(p.c.feed_result, GTLS_ERR_ALERT);
      EXPECT_EQ(gtls_conn_peer_alert(p.c.conn), GTLS_ALERT_NO_APPLICATION_PROTOCOL);
      continue;
    }
    ASSERT_TRUE(p.connected());
    for (GTLS_Conn * conn : {p.c.conn, p.s.conn}) {
      const unsigned char * a = nullptr;
      size_t n = 0;
      ASSERT_EQ(gtls_conn_alpn(conn, &a, &n), GTLS_OK);
      EXPECT_EQ(std::string(reinterpret_cast<const char *>(a), n), k.want);
    }
  }
}

/* ------------------------------------------------------------------ SNI end to end */

TEST(StreamSni, TheClientGetsTheIdentityItAskedFor) {
  std::unique_ptr<Cred> a = ed_cred("a.test");
  std::unique_ptr<Cred> b = ed_cred("b.test");
  for (const char * name : {"a.test", "b.test"}) {
    Pair p(std::vector<Cred *>{a.get(), b.get()});
    p.host = name;
    ASSERT_EQ(p.build(), GTLS_OK);
    p.run();
    ASSERT_TRUE(p.connected()) << name;
    size_t index = 9;
    ASSERT_EQ(gtls_conn_identity(p.s.conn, &index), GTLS_OK);
    EXPECT_EQ(index, std::string(name) == "a.test" ? 0u : 1u);
    int ack = 0;
    ASSERT_EQ(gtls_conn_server_name_acknowledged(p.c.conn, &ack), GTLS_OK);
    EXPECT_EQ(ack, 1);
  }
  /* an unknown name gets the default, whose certificate the client then refuses */
  Pair p(std::vector<Cred *>{a.get(), b.get()});
  p.host = "unknown.test";
  ASSERT_EQ(p.build(), GTLS_OK);
  p.run();
  EXPECT_EQ(gtls_conn_failure(p.c.conn), GTLS_ERR_CERT_HOST);
}

/* ----------------------------------------------------------------- HelloRetryRequest */

TEST(StreamRetry, TheClientRetriesAndBothSidesAgree) {
  std::unique_ptr<Cred> cred = ed_cred();
  for (GTLS_Group want : {GTLS_GROUP_SECP256R1, GTLS_GROUP_SECP384R1}) {
    for (size_t chunk : {size_t(0), size_t(1), size_t(13)}) {
      Pair p(*cred);
      p.scfg.groups = &want;
      p.scfg.group_count = 1;
      ASSERT_EQ(p.build(), GTLS_OK);
      talk(p, chunk);
      EXPECT_TRUE(gtls_conn_retried(p.c.conn));
      EXPECT_TRUE(gtls_conn_retried(p.s.conn));
      EXPECT_EQ(gtls_conn_group(p.c.conn), want);
      EXPECT_EQ(gtls_conn_group(p.s.conn), want);
    }
  }
}

TEST(StreamRetry, EverySuiteSurvivesARetry) {
  std::unique_ptr<Cred> cred = ed_cred();
  for (GTLS_Suite suite : kSuites) {
    Pair p(*cred);
    GTLS_Group want = GTLS_GROUP_SECP256R1;
    p.scfg.groups = &want;
    p.scfg.group_count = 1;
    p.scfg.suites = &suite;
    p.scfg.suite_count = 1;
    ASSERT_EQ(p.build(), GTLS_OK);
    talk(p, 0);
    EXPECT_TRUE(gtls_conn_retried(p.s.conn));
  }
}

TEST(StreamRetry, ACompatibilityClientAndServerExchangeTheDummyRecordOnce) {
  std::unique_ptr<Cred> cred = ed_cred();
  for (bool retry : {false, true}) {
    Pair p(*cred);
    p.ccfg.middlebox_compat = 1;
    GTLS_Group want = GTLS_GROUP_SECP256R1;
    if (retry) {
      p.scfg.groups = &want;
      p.scfg.group_count = 1;
    }
    ASSERT_EQ(p.build(), GTLS_OK);
    Bytes ch = take(p.c.conn);
    ASSERT_EQ(give(p.s.conn, ch), GTLS_OK);
    Bytes first = take(p.s.conn);
    std::vector<Bytes> recs = records_of(first);
    /* the dummy change_cipher_spec follows the server's first message */
    ASSERT_GE(recs.size(), 2u);
    EXPECT_EQ(recs[0][0], GTLS_CT_HANDSHAKE);
    EXPECT_EQ(recs[1], (Bytes{20, 3, 3, 0, 1, 1})) << (retry ? "after the HelloRetryRequest" : "after the ServerHello");
    ASSERT_EQ(give(p.c.conn, first), GTLS_OK);
    p.run();
    ASSERT_TRUE(p.connected()) << (retry ? "retry" : "plain");
  }
}

TEST(StreamRetry, ADummyRecordIsRefusedWhereTheRfcRefusesIt) {
  std::unique_ptr<Cred> cred = ed_cred();
  const Bytes ccs = {20, 3, 3, 0, 1, 1};
  {
    Pair p(*cred);
    ASSERT_EQ(p.build(), GTLS_OK);
    EXPECT_EQ(give(p.s.conn, ccs), GTLS_ERR_PROTOCOL) << "before the first ClientHello";
    EXPECT_EQ(gtls_conn_alert(p.s.conn), GTLS_ALERT_UNEXPECTED_MESSAGE);
  }
  {
    Pair p(*cred);
    ASSERT_EQ(p.build(), GTLS_OK);
    ASSERT_EQ(give(p.s.conn, take(p.c.conn)), GTLS_OK);
    ASSERT_EQ(give(p.s.conn, ccs), GTLS_OK) << "between the hello and the Finished";
    ASSERT_EQ(give(p.s.conn, ccs), GTLS_OK) << "twice";
    EXPECT_EQ(give(p.s.conn, ccs), GTLS_ERR_PROTOCOL) << "a third is not the dummy of RFC 8446";
  }
  {
    Pair p(*cred);
    ASSERT_EQ(p.build(), GTLS_OK);
    p.run();
    ASSERT_TRUE(p.connected());
    EXPECT_EQ(give(p.s.conn, ccs), GTLS_ERR_PROTOCOL) << "after the peer's Finished";
    EXPECT_EQ(give(p.c.conn, ccs), GTLS_ERR_PROTOCOL) << "the same for the client, which is connected too";
  }
  {
    Pair p(*cred);
    ASSERT_EQ(p.build(), GTLS_OK);
    ASSERT_EQ(give(p.s.conn, take(p.c.conn)), GTLS_OK);
    EXPECT_EQ(give(p.s.conn, Bytes{20, 3, 3, 0, 1, 2}), GTLS_ERR_PROTOCOL) << "not the byte 1";
  }
  {
    /* the client, before it has sent a hello */
    EmptyTrust trust;
    GTLS_ContextConfig cfg;
    gtls_context_config_default(&cfg);
    cfg.trust = trust.store;
    GTLS_Context * ctx = nullptr;
    GTLS_Conn * conn = nullptr;
    ASSERT_EQ(gtls_context_new(nullptr, &cfg, &ctx), GTLS_OK);
    ASSERT_EQ(gtls_conn_new(ctx, "x", 1, &conn), GTLS_OK);
    ASSERT_EQ(gtls_conn_start(conn), GTLS_OK);
    EXPECT_EQ(give(conn, ccs), GTLS_OK) << "after its hello";
    gtls_conn_free(conn);
    gtls_context_free(ctx);
  }
}

/* ------------------------------------------------------------------------ key update */

TEST(KeyUpdate, EitherEndMayUpdateAndDataKeepsFlowing) {
  std::unique_ptr<Cred> cred = ed_cred();
  for (bool request : {false, true}) {
    for (bool from_client : {true, false}) {
      Pair p(*cred);
      ASSERT_EQ(p.build(), GTLS_OK);
      p.run();
      ASSERT_TRUE(p.connected());
      Endpoint & a = from_client ? p.c : p.s;
      Endpoint & b = from_client ? p.s : p.c;
      Bytes before = pattern(300, 1), after = pattern(300, 2), reply = pattern(100, 3);
      /* data sealed before the update, delivered after it was sent */
      size_t w = 0;
      ASSERT_EQ(gtls_conn_write(a.conn, before.data(), before.size(), &w), GTLS_OK);
      ASSERT_EQ(gtls_conn_key_update(a.conn, request), GTLS_OK);
      ASSERT_EQ(gtls_conn_write(a.conn, after.data(), after.size(), &w), GTLS_OK);
      EXPECT_EQ(a.conn->sec.wr.seq, 1u) << "the counter starts again under the new key, one record in";
      p.run();
      EXPECT_EQ(b.got, cat(before, after)) << "the old key still opens the old data";
      EXPECT_EQ(b.conn->key_updates, 1u);
      if (request) {
        /* the peer answered with its own update, and its data is under its new key */
        ASSERT_EQ(gtls_conn_write(b.conn, reply.data(), reply.size(), &w), GTLS_OK);
        p.run();
        EXPECT_EQ(a.got, reply);
        EXPECT_EQ(a.conn->key_updates, 1u) << "the answer is not itself answered";
        EXPECT_EQ(b.conn->sec.wr.seq, 1u);
      } else {
        EXPECT_EQ(a.conn->key_updates, 0u);
        ASSERT_EQ(gtls_conn_write(b.conn, reply.data(), reply.size(), &w), GTLS_OK);
        p.run();
        EXPECT_EQ(a.got, reply) << "the other direction was never touched";
        EXPECT_EQ(b.conn->sec.wr.seq, 1u);
      }
      EXPECT_FALSE(gtls_conn_is_failed(a.conn));
      EXPECT_FALSE(gtls_conn_is_failed(b.conn));
    }
  }
}

TEST(KeyUpdate, TheKeyReallyChangesAndTheOldOneIsGone) {
  std::unique_ptr<Cred> cred = ed_cred();
  Pair p(*cred);
  ASSERT_EQ(p.build(), GTLS_OK);
  p.run();
  Bytes old_key(p.c.conn->sec.wr.key, p.c.conn->sec.wr.key + 16);
  Bytes old_secret(p.c.conn->sec.wr_secret, p.c.conn->sec.wr_secret + 32);
  ASSERT_EQ(gtls_conn_key_update(p.c.conn, 0), GTLS_OK);
  p.run();
  Bytes new_key(p.c.conn->sec.wr.key, p.c.conn->sec.wr.key + 16);
  Bytes new_secret(p.c.conn->sec.wr_secret, p.c.conn->sec.wr_secret + 32);
  EXPECT_NE(old_key, new_key);
  EXPECT_NE(old_secret, new_secret);
  Bytes next(32);
  ASSERT_EQ(t_record_next_secret(gtls_conn_suite(p.c.conn), old_secret.data(), next.data()), GTLS_OK);
  EXPECT_EQ(new_secret, next);
  EXPECT_EQ(Bytes(p.s.conn->sec.rd_secret, p.s.conn->sec.rd_secret + 32), next)
      << "the server's read side followed";
  /* a record sealed under the old key is refused now */
  GTLS_RecordKeys stale;
  ASSERT_EQ(gtls_record_keys_from_secret(&stale, gtls_conn_suite(p.c.conn), old_secret.data(), 0), GTLS_OK);
  stale.seq = 5;
  GTLS_Buf b;
  gtls_buf_init(&b, nullptr, 1000);
  ASSERT_EQ(gtls_record_seal(&stale, GTLS_CT_APPLICATION_DATA, "x", 1, 0, &b), GTLS_OK);
  EXPECT_EQ(give(p.s.conn, Bytes(b.data, b.data + b.len)), GTLS_ERR_MISMATCH);
  gtls_buf_free(&b);
}

TEST(KeyUpdate, TheSecretsAccessorKeepsTheInitialApplicationSecrets) {
  std::unique_ptr<Cred> cred = ed_cred();
  Pair p(*cred);
  ASSERT_EQ(p.build(), GTLS_OK);
  p.run();
  Bytes before(48), after(48);
  size_t n1 = 0, n2 = 0;
  ASSERT_EQ(gtls_conn_secret(p.c.conn, GTLS_EPOCH_APPLICATION, GTLS_DIR_WRITE, before.data(), 48, &n1), GTLS_OK);
  ASSERT_EQ(gtls_conn_key_update(p.c.conn, 1), GTLS_OK);
  p.run();
  ASSERT_EQ(gtls_conn_secret(p.c.conn, GTLS_EPOCH_APPLICATION, GTLS_DIR_WRITE, after.data(), 48, &n2), GTLS_OK);
  before.resize(n1);
  after.resize(n2);
  EXPECT_EQ(before, after) << "that is the epoch's secret; the rotating one is the connection's own";
}

TEST(KeyUpdate, TheRecordLimitForcesAnUpdateBeforeTheCounterRunsOut) {
  std::unique_ptr<Cred> cred = ed_cred();
  Pair p(*cred);
  p.climits.max_records_per_key = 5;
  ASSERT_EQ(p.build(), GTLS_OK);
  p.run();
  ASSERT_TRUE(p.connected());
  Bytes all;
  for (int i = 0; i < 60; i++) {
    Bytes one = pattern(10 + i, i);
    all = cat(all, one);
    size_t w = 0;
    ASSERT_EQ(gtls_conn_write(p.c.conn, one.data(), one.size(), &w), GTLS_OK);
    ASSERT_EQ(w, one.size());
    EXPECT_LT(p.c.conn->sec.wr.seq, 5u) << "the counter never reaches the limit";
    p.run();
  }
  EXPECT_EQ(p.s.got, all);
  EXPECT_GE(p.s.conn->key_updates, 60u / 4u - 1u) << "one update every four records of data";
  EXPECT_FALSE(gtls_conn_is_failed(p.c.conn));
  EXPECT_FALSE(gtls_conn_is_failed(p.s.conn));
  /* and a limit that leaves no room for the replacement is refused, not wrapped */
  Pair q(*cred);
  q.climits.max_records_per_key = 1;
  ASSERT_EQ(q.build(), GTLS_OK);
  q.run();
  size_t w = 0;
  EXPECT_EQ(gtls_conn_write(q.c.conn, "x", 1, &w), GTLS_ERR_LIMIT);
}

TEST(KeyUpdate, OneRequestIsAnsweredOnceAndAFloodIsCapped) {
  std::unique_ptr<Cred> cred = ed_cred();
  Pair p(*cred);
  p.slimits.max_key_updates = 3;
  ASSERT_EQ(p.build(), GTLS_OK);
  p.run();
  ASSERT_TRUE(p.connected());
  for (int i = 0; i < 3; i++) {
    ASSERT_EQ(gtls_conn_key_update(p.c.conn, 1), GTLS_OK);
    p.run();
    EXPECT_FALSE(gtls_conn_is_failed(p.s.conn)) << i;
  }
  ASSERT_EQ(gtls_conn_key_update(p.c.conn, 1), GTLS_OK);
  p.run();
  EXPECT_TRUE(gtls_conn_is_failed(p.s.conn));
  EXPECT_EQ(gtls_conn_failure(p.s.conn), GTLS_ERR_LIMIT);
  EXPECT_EQ(gtls_conn_alert(p.s.conn), GTLS_ALERT_UNEXPECTED_MESSAGE);
}

TEST(KeyUpdate, AZeroCapRefusesTheFirstOneReceived) {
  std::unique_ptr<Cred> cred = ed_cred();
  for (bool zero : {false, true}) {
    Pair p(*cred);
    p.slimits.max_key_updates = zero ? GTLS_LIMIT_ZERO : 0;
    ASSERT_EQ(p.build(), GTLS_OK);
    p.run();
    ASSERT_TRUE(p.connected());
    ASSERT_EQ(gtls_conn_key_update(p.c.conn, 1), GTLS_OK);
    p.run();
    if (zero) {
      EXPECT_TRUE(gtls_conn_is_failed(p.s.conn));
      EXPECT_EQ(gtls_conn_failure(p.s.conn), GTLS_ERR_LIMIT);
      EXPECT_EQ(gtls_conn_alert(p.s.conn), GTLS_ALERT_UNEXPECTED_MESSAGE);
    } else {
      EXPECT_FALSE(gtls_conn_is_failed(p.s.conn)) << "without the constant 0 is the default, 65536";
    }
  }
}

TEST(KeyUpdate, MalformedAndMisplacedUpdatesAreRefused) {
  std::unique_ptr<Cred> cred = ed_cred();
  auto craft = [](GTLS_Conn * from, const Bytes & msg) {
    GTLS_Buf b;
    gtls_buf_init(&b, nullptr, 1 << 16);
    EXPECT_EQ(gtls_record_seal(&from->sec.wr, GTLS_CT_HANDSHAKE, msg.data(), msg.size(), 0, &b), GTLS_OK);
    Bytes out(b.data, b.data + b.len);
    gtls_buf_free(&b);
    return out;
  };
  struct Case {
    Bytes msg;
    GTLS_Result result;
    unsigned alert;
    const char * what;
  };
  const Case cases[] = {
      {{24, 0, 0, 1, 2}, GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER, "request_update 2"},
      {{24, 0, 0, 1, 255}, GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER, "request_update 255"},
      {{24, 0, 0, 0}, GTLS_ERR_CORRUPT, GTLS_ALERT_DECODE_ERROR, "empty"},
      {{24, 0, 0, 2, 0, 0}, GTLS_ERR_CORRUPT, GTLS_ALERT_DECODE_ERROR, "two bytes"},
      {{4, 0, 0, 0}, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNEXPECTED_MESSAGE, "a NewSessionTicket sent to a server"},
      {{13, 0, 0, 0}, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNEXPECTED_MESSAGE, "a CertificateRequest after the handshake"},
      {{1, 0, 0, 0}, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNEXPECTED_MESSAGE, "a ClientHello after the handshake"},
  };
  for (const Case & k : cases) {
    Pair p(*cred);
    ASSERT_EQ(p.build(), GTLS_OK);
    p.run();
    ASSERT_TRUE(p.connected());
    EXPECT_EQ(give(p.s.conn, craft(p.c.conn, k.msg)), k.result) << k.what;
    EXPECT_EQ(gtls_conn_alert(p.s.conn), k.alert) << k.what;
  }
  /* before the handshake is done: the server has not got its Finished yet */
  Pair p(*cred);
  ASSERT_EQ(p.build(), GTLS_OK);
  size_t w = 0;
  EXPECT_EQ(gtls_conn_key_update(p.c.conn, 0), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_write(p.c.conn, "x", 1, &w), GTLS_ERR_INVALID);
  p.run();
  EXPECT_EQ(gtls_conn_key_update(p.c.conn, 0), GTLS_OK);
}

TEST(KeyUpdate, AKeyUpdateAtTheMessageInterfaceIsStillRefused) {
  /* QUIC carries its own key update (RFC 9001 section 6) and a TLS one is
   * not allowed: the message interface keeps refusing it, in both roles. */
  std::unique_ptr<Cred> cred = ed_cred();
  for (int role = 0; role < 2; role++) {
    MessagePair m(*cred);
    ASSERT_EQ(m.build(), GTLS_OK);
    m.run();
    ASSERT_TRUE(gtls_conn_is_connected(m.c.conn));
    ASSERT_TRUE(gtls_conn_is_connected(m.s.conn));
    GTLS_Conn * conn = role == 0 ? m.c.conn : m.s.conn;
    Bytes ku = {24, 0, 0, 1, 0};
    EXPECT_EQ(gtls_conn_feed(conn, GTLS_EPOCH_APPLICATION, ku.data(), ku.size(), kNow), GTLS_ERR_UNSUPPORTED);
    EXPECT_EQ(gtls_conn_alert(conn), GTLS_ALERT_UNEXPECTED_MESSAGE);
    EXPECT_TRUE(gtls_conn_secrets_are_wiped(conn));
  }
}

/* ------------------------------------------------------------- the one interface at a time */

TEST(Interfaces, OneConnectionIsDrivenThroughOneInterface) {
  std::unique_ptr<Cred> cred = ed_cred();
  {
    Pair p(*cred);
    ASSERT_EQ(p.build(), GTLS_OK);
    const unsigned char * d = nullptr;
    size_t n = 0;
    ASSERT_EQ(gtls_conn_pending_output(p.c.conn, GTLS_EPOCH_INITIAL, &d, &n), GTLS_OK);
    EXPECT_GT(n, 0u);
    ASSERT_EQ(gtls_conn_consume_output(p.c.conn, GTLS_EPOCH_INITIAL, n), GTLS_OK);
    EXPECT_EQ(gtls_conn_stream_output(p.c.conn, &d, &n), GTLS_ERR_INVALID) << "message mode was chosen";
    size_t used = 0;
    EXPECT_EQ(gtls_conn_stream_feed(p.c.conn, "x", 1, 0, &used), GTLS_ERR_INVALID);
    size_t w = 0;
    EXPECT_EQ(gtls_conn_write(p.c.conn, "x", 1, &w), GTLS_ERR_INVALID);
    EXPECT_EQ(gtls_conn_read(p.c.conn, &w, 1, &used), GTLS_ERR_INVALID);
    EXPECT_EQ(gtls_conn_close(p.c.conn), GTLS_ERR_INVALID);
    EXPECT_EQ(gtls_conn_key_update(p.c.conn, 0), GTLS_ERR_INVALID);
    EXPECT_EQ(gtls_conn_stream_eof(p.c.conn), GTLS_ERR_INVALID);
    EXPECT_EQ(gtls_conn_stream_consume(p.c.conn, 0), GTLS_ERR_INVALID);
  }
  {
    Pair p(*cred);
    ASSERT_EQ(p.build(), GTLS_OK);
    const unsigned char * d = nullptr;
    size_t n = 0;
    ASSERT_EQ(gtls_conn_stream_output(p.c.conn, &d, &n), GTLS_OK);
    EXPECT_GT(n, 0u);
    EXPECT_EQ(gtls_conn_pending_output(p.c.conn, GTLS_EPOCH_INITIAL, &d, &n), GTLS_ERR_INVALID) << "stream mode was chosen";
    EXPECT_EQ(gtls_conn_feed(p.c.conn, GTLS_EPOCH_INITIAL, "x", 1, 0), GTLS_ERR_INVALID);
    EXPECT_EQ(gtls_conn_consume_output(p.c.conn, GTLS_EPOCH_INITIAL, 0), GTLS_ERR_INVALID);
    /* the accessors that report state work in either */
    EXPECT_FALSE(gtls_conn_is_connected(p.c.conn));
    Bytes sec(48);
    size_t len = 0;
    EXPECT_EQ(gtls_conn_secret(p.c.conn, GTLS_EPOCH_HANDSHAKE, GTLS_DIR_WRITE, sec.data(), 48, &len), GTLS_ERR_INVALID);
  }
}

TEST(Interfaces, ArgumentsAreChecked) {
  std::unique_ptr<Cred> cred = ed_cred();
  Pair p(*cred);
  ASSERT_EQ(p.build(), GTLS_OK);
  size_t used = 0;
  const unsigned char * d = nullptr;
  size_t n = 0;
  unsigned char buf[4];
  EXPECT_EQ(gtls_conn_stream_feed(nullptr, "x", 1, 0, &used), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_stream_feed(p.s.conn, nullptr, 1, 0, &used), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_stream_feed(p.s.conn, "x", 1, 0, nullptr), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_stream_feed(p.s.conn, nullptr, 0, 0, &used), GTLS_OK);
  EXPECT_EQ(gtls_conn_stream_output(nullptr, &d, &n), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_stream_output(p.s.conn, nullptr, &n), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_stream_output(p.s.conn, &d, nullptr), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_stream_consume(nullptr, 0), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_stream_consume(p.s.conn, 1), GTLS_ERR_INVALID) << "more than is waiting";
  EXPECT_EQ(gtls_conn_write(nullptr, "x", 1, &n), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_write(p.s.conn, nullptr, 3, &n), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_write(p.s.conn, "x", 1, nullptr), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_read(nullptr, buf, 4, &n), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_read(p.s.conn, buf, 4, nullptr), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_read(p.s.conn, nullptr, 4, &n), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_read(p.s.conn, nullptr, 0, &n), GTLS_OK);
  EXPECT_EQ(gtls_conn_close(nullptr), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_key_update(nullptr, 0), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_stream_eof(nullptr), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_peer_closed(nullptr), 0);
  EXPECT_EQ(gtls_conn_peer_alert(nullptr), 0u);
  /* a connection that was made but not started is not ready for bytes */
  GTLS_Conn * fresh = nullptr;
  ASSERT_EQ(gtls_conn_new_server(p.s.ctx, &fresh), GTLS_OK);
  EXPECT_EQ(gtls_conn_stream_feed(fresh, "x", 1, 0, &used), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_close(fresh), GTLS_ERR_INVALID);
  gtls_conn_free(fresh);
}

TEST(Interfaces, OutputIsDrainedInAnyAmount) {
  std::unique_ptr<Cred> cred = ed_cred();
  Pair p(*cred);
  ASSERT_EQ(p.build(), GTLS_OK);
  /* the socket takes 3 bytes at a time */
  for (int i = 0; i < 20000; i++) {
    for (Endpoint * from : {&p.c, &p.s}) {
      Endpoint & to = from == &p.c ? p.s : p.c;
      const unsigned char * d = nullptr;
      size_t n = 0;
      ASSERT_EQ(gtls_conn_stream_output(from->conn, &d, &n), GTLS_OK);
      if (n == 0) {
        continue;
      }
      size_t k = n < 3 ? n : 3;
      Bytes piece(d, d + k);
      ASSERT_EQ(gtls_conn_stream_consume(from->conn, k), GTLS_OK);
      size_t used = 0;
      GTLS_Result r = gtls_conn_stream_feed(to.conn, piece.data(), k, kNow, &used);
      ASSERT_EQ(r, GTLS_OK);
    }
    if (p.connected()) {
      break;
    }
  }
  ASSERT_TRUE(p.connected());
  size_t w = 0;
  Bytes data = pattern(20000, 9);
  ASSERT_EQ(gtls_conn_write(p.c.conn, data.data(), data.size(), &w), GTLS_OK);
  EXPECT_EQ(w, data.size());
  Bytes got;
  for (;;) {
    const unsigned char * d = nullptr;
    size_t n = 0;
    ASSERT_EQ(gtls_conn_stream_output(p.c.conn, &d, &n), GTLS_OK);
    if (n == 0) {
      break;
    }
    size_t k = n < 11 ? n : 11;
    Bytes piece(d, d + k);
    ASSERT_EQ(gtls_conn_stream_consume(p.c.conn, k), GTLS_OK);
    size_t used = 0;
    ASSERT_EQ(gtls_conn_stream_feed(p.s.conn, piece.data(), k, kNow, &used), GTLS_OK);
    Bytes r = read_all(p.s.conn);
    got.insert(got.end(), r.begin(), r.end());
  }
  EXPECT_EQ(got, data);
}

TEST(Interfaces, AWriteTakesWhatTheOutputHasRoomForAndNoMore) {
  std::unique_ptr<Cred> cred = ed_cred();
  Pair p(*cred);
  p.climits.max_output_bytes = 40000;
  ASSERT_EQ(p.build(), GTLS_OK);
  p.run();
  ASSERT_TRUE(p.connected());
  Bytes data = pattern(300000, 5);
  size_t w = 0;
  ASSERT_EQ(gtls_conn_write(p.c.conn, data.data(), data.size(), &w), GTLS_OK);
  EXPECT_GT(w, 0u);
  EXPECT_LT(w, data.size());
  EXPECT_LE(stream_out(p.c.conn).size(), 40000u + 2 * (5 + 16 + 1) + 16384 + 100) << "bounded by the cap and one record";
  /* the rest goes when the output has been drained */
  size_t at = w;
  p.run();
  while (at < data.size()) {
    ASSERT_EQ(gtls_conn_write(p.c.conn, data.data() + at, data.size() - at, &w), GTLS_OK);
    ASSERT_GT(w, 0u);
    at += w;
    p.run();
  }
  EXPECT_EQ(p.s.got, data);
  EXPECT_EQ(gtls_conn_write(p.c.conn, nullptr, 0, &w), GTLS_OK);
  EXPECT_EQ(w, 0u);
}

TEST(Interfaces, UnreadDataHoldsBackTheStreamAndNothingIsLost) {
  std::unique_ptr<Cred> cred = ed_cred();
  Pair p(*cred);
  p.slimits.max_app_buffer = 20000;
  ASSERT_EQ(p.build(), GTLS_OK);
  p.run();
  ASSERT_TRUE(p.connected());
  Bytes data = pattern(100000, 6);
  size_t w = 0, at = 0;
  Bytes wire;
  while (at < data.size()) {
    ASSERT_EQ(gtls_conn_write(p.c.conn, data.data() + at, data.size() - at, &w), GTLS_OK);
    at += w;
    wire = cat(wire, take(p.c.conn));
  }
  size_t used = 0, offered = 0;
  Bytes got;
  int stalls = 0;
  while (offered < wire.size()) {
    ASSERT_EQ(gtls_conn_stream_feed(p.s.conn, wire.data() + offered, wire.size() - offered, kNow, &used), GTLS_OK);
    offered += used;
    if (used == 0 || offered < wire.size()) {
      stalls++;
      EXPECT_LE(p.s.conn->app_in.len, 20000u) << "never past the cap";
      Bytes r = read_all(p.s.conn);
      got.insert(got.end(), r.begin(), r.end());
    }
  }
  Bytes r = read_all(p.s.conn);
  got.insert(got.end(), r.begin(), r.end());
  EXPECT_GT(stalls, 0) << "the cap was reached";
  EXPECT_EQ(got, data);
}

TEST(Interfaces, TheEndPointsReportTheirStateWhateverTheOrderOfCalls) {
  std::unique_ptr<Cred> cred = ed_cred();
  Pair p(*cred);
  ASSERT_EQ(p.build(), GTLS_OK);
  EXPECT_FALSE(gtls_conn_is_connected(p.c.conn));
  EXPECT_FALSE(gtls_conn_is_connected(p.s.conn));
  p.run();
  EXPECT_TRUE(gtls_conn_is_connected(p.c.conn));
  EXPECT_TRUE(gtls_conn_is_connected(p.s.conn));
  const unsigned char * der = nullptr;
  size_t len = 0;
  ASSERT_EQ(gtls_conn_peer_certificate(p.c.conn, &der, &len), GTLS_OK);
  ASSERT_NE(der, nullptr);
  EXPECT_EQ(Bytes(der, der + len), cred->chain[0]) << "the client sees the server's leaf";
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
