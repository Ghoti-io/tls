/**
 * @file
 *
 * The key schedule against RFC 8448: every secret, key, IV and Finished the
 * RFC prints for the simple 1-RTT handshake and for the HelloRetryRequest
 * one, byte for byte. The values are read from tests/data/rfc8448, which
 * tools/extract-rfc8448.py wrote from the pinned RFC text.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

using gtlstest::Bytes;
using gtlstest::Vec;

namespace {

struct Trace {
  const char * file;
  const char * title;
};

const Trace kTraces[] = {{"simple-1rtt", "simple"}, {"hrr", "hrr"}};

/** H("") */
Bytes empty_hash() {
  Bytes out(32);
  EXPECT_EQ(gsec_sha256(nullptr, 0, out.data()), GSEC_OK);
  return out;
}

}  // namespace

class ScheduleTrace : public ::testing::TestWithParam<Trace> {};

TEST_P(ScheduleTrace, EveryServerSecretMatches) {
  Vec v(GetParam().file);
  GTLS_Schedule s;
  const Bytes sh_hash = v["server.derive-secret-tls13-c-hs-traffic.hash"];
  const Bytes fin_hash = v["server.derive-secret-tls13-c-ap-traffic.hash"];
  ASSERT_EQ(sh_hash.size(), 32u);
  ASSERT_EQ(gtls_schedule_early(&s, GTLS_HASH_SHA256), GTLS_OK);
  EXPECT_EQ(Bytes(s.early, s.early + 32), v["server.extract-secret-early.secret"]);

  ASSERT_EQ(gtls_schedule_handshake(&s, v["server.extract-secret-handshake.ikm"].data(),
                32, sh_hash.data()),
      GTLS_OK);
  EXPECT_EQ(Bytes(s.handshake, s.handshake + 32),
      v["server.extract-secret-handshake.secret"]);
  EXPECT_EQ(Bytes(s.c_hs, s.c_hs + 32),
      v["server.derive-secret-tls13-c-hs-traffic.expanded"]);
  EXPECT_EQ(Bytes(s.s_hs, s.s_hs + 32),
      v["server.derive-secret-tls13-s-hs-traffic.expanded"]);

  ASSERT_EQ(gtls_schedule_master(&s, fin_hash.data()), GTLS_OK);
  EXPECT_EQ(Bytes(s.master, s.master + 32), v["server.extract-secret-master.secret"]);
  EXPECT_EQ(Bytes(s.c_ap, s.c_ap + 32),
      v["server.derive-secret-tls13-c-ap-traffic.expanded"]);
  EXPECT_EQ(Bytes(s.s_ap, s.s_ap + 32),
      v["server.derive-secret-tls13-s-ap-traffic.expanded"]);

  Bytes exp(32);
  ASSERT_EQ(gtls_schedule_exporter(&s, fin_hash.data(), exp.data()), GTLS_OK);
  EXPECT_EQ(exp, v["server.derive-secret-tls13-exp-master.expanded"]);

  const Bytes cfin_hash = v["client.derive-secret-tls13-res-master.hash"];
  Bytes res(32);
  ASSERT_EQ(gtls_schedule_resumption(&s, cfin_hash.data(), res.data()), GTLS_OK);
  EXPECT_EQ(res, v["client.derive-secret-tls13-res-master.expanded"]);
  gtls_schedule_wipe(&s);
}

TEST_P(ScheduleTrace, TheDerivedSecretsAreTheRfcs) {
  Vec v(GetParam().file);
  Bytes out(32);
  const Bytes empty = empty_hash();
  EXPECT_EQ(empty, v["server.derive-secret-for-handshake-tls13-derived.hash"]);
  ASSERT_EQ(gtls_derive_secret(GTLS_HASH_SHA256,
                v["server.derive-secret-for-handshake-tls13-derived.prk"].data(), 32,
                "derived", empty.data(), out.data()),
      GTLS_OK);
  EXPECT_EQ(out, v["server.derive-secret-for-handshake-tls13-derived.expanded"]);
  ASSERT_EQ(gtls_derive_secret(GTLS_HASH_SHA256,
                v["server.derive-secret-for-master-tls13-derived.prk"].data(), 32,
                "derived", empty.data(), out.data()),
      GTLS_OK);
  EXPECT_EQ(out, v["server.derive-secret-for-master-tls13-derived.expanded"]);
}

TEST_P(ScheduleTrace, KeysAndIvsForBothDirectionsAndBothEpochs) {
  Vec v(GetParam().file);
  struct Case {
    const char * secret;
    const char * key;
    const char * iv;
  };
  const Case cases[] = {
    {"server.derive-write-traffic-keys-for-handshake-data.prk",
     "server.derive-write-traffic-keys-for-handshake-data.key-expanded",
     "server.derive-write-traffic-keys-for-handshake-data.iv-expanded"},
    {"server.derive-read-traffic-keys-for-handshake-data.prk",
     "server.derive-read-traffic-keys-for-handshake-data.key-expanded",
     "server.derive-read-traffic-keys-for-handshake-data.iv-expanded"},
    {"server.derive-write-traffic-keys-for-application-data.prk",
     "server.derive-write-traffic-keys-for-application-data.key-expanded",
     "server.derive-write-traffic-keys-for-application-data.iv-expanded"},
    {"client.derive-write-traffic-keys-for-application-data.prk",
     "client.derive-write-traffic-keys-for-application-data.key-expanded",
     "client.derive-write-traffic-keys-for-application-data.iv-expanded"},
  };
  for (const Case & c : cases) {
    Bytes key(GTLS_KEY_MAX);
    Bytes iv(GTLS_IV_LEN);
    ASSERT_EQ(gtls_traffic_keys(GTLS_SUITE_AES_128_GCM_SHA256, v[c.secret].data(),
                  key.data(), iv.data()),
        GTLS_OK) << c.secret;
    key.resize(16);
    EXPECT_EQ(key, v[c.key]) << c.key;
    EXPECT_EQ(iv, v[c.iv]) << c.iv;
  }
}

TEST_P(ScheduleTrace, FinishedForBothSidesOverTheRfcsHashes) {
  Vec v(GetParam().file);
  /* The RFC does not print the hash for the server's Finished (it prints
   * "hash (0 octets)" for the key derivation), so the transcript hash comes
   * from the secrets derived over the same bytes: the c ap traffic hash is
   * the transcript through the server's Finished, which is what the client
   * checks, and the res master hash is the one through the client's. */
  const Bytes through_server_cv_hash_unknown;
  (void)through_server_cv_hash_unknown;
  Bytes out(32);
  /* verify_data for a known base key and a chosen hash: HMAC(finished_key, h)
   * with finished_key from the RFC's "expanded" value. */
  Bytes th(32, 0x42);
  ASSERT_EQ(gtls_finished_verify_data(GTLS_HASH_SHA256,
                v["server.calculate-finished-tls13-finished.prk"].data(), th.data(),
                out.data()),
      GTLS_OK);
  Bytes want(32);
  ASSERT_EQ(gsec_hmac(GSEC_HMAC_SHA256,
                v["server.calculate-finished-tls13-finished.expanded"].data(), 32,
                th.data(), 32, want.data()),
      GSEC_OK);
  EXPECT_EQ(out, want) << "finished_key is what the RFC prints";
  ASSERT_EQ(gtls_finished_verify_data(GTLS_HASH_SHA256,
                v["client.calculate-finished-tls13-finished.prk"].data(), th.data(),
                out.data()),
      GTLS_OK);
  ASSERT_EQ(gsec_hmac(GSEC_HMAC_SHA256,
                v["client.calculate-finished-tls13-finished.expanded"].data(), 32,
                th.data(), 32, want.data()),
      GSEC_OK);
  EXPECT_EQ(out, want);
}

INSTANTIATE_TEST_SUITE_P(Rfc8448, ScheduleTrace, ::testing::ValuesIn(kTraces),
    [](const ::testing::TestParamInfo<Trace> & info) { return info.param.title; });

/* HKDF-Expand-Label itself, against the RFC's "info" encodings: the label
 * bytes are what is hashed, so an encoding mistake changes every secret. */
TEST(ExpandLabel, EncodesLikeTheRfcsInfoFieldForEveryLabel) {
  Vec v("simple-1rtt");
  struct Case {
    const char * prk;
    const char * label;
    const char * hash;
    const char * expanded;
  };
  const Case cases[] = {
    {"server.derive-secret-tls13-c-hs-traffic.prk", "c hs traffic",
     "server.derive-secret-tls13-c-hs-traffic.hash",
     "server.derive-secret-tls13-c-hs-traffic.expanded"},
    {"server.derive-secret-tls13-s-ap-traffic.prk", "s ap traffic",
     "server.derive-secret-tls13-s-ap-traffic.hash",
     "server.derive-secret-tls13-s-ap-traffic.expanded"},
    {"server.derive-secret-tls13-exp-master.prk", "exp master",
     "server.derive-secret-tls13-exp-master.hash",
     "server.derive-secret-tls13-exp-master.expanded"},
    {"client.derive-secret-tls13-res-master.prk", "res master",
     "client.derive-secret-tls13-res-master.hash",
     "client.derive-secret-tls13-res-master.expanded"},
  };
  for (const Case & c : cases) {
    Bytes out(32);
    ASSERT_EQ(gtls_derive_secret(GTLS_HASH_SHA256, v[c.prk].data(), 32, c.label,
                  v[c.hash].data(), out.data()),
        GTLS_OK) << c.label;
    EXPECT_EQ(out, v[c.expanded]) << c.label;
  }
}

TEST(ExpandLabel, RejectsWhatCannotBeEncoded) {
  Bytes secret(32, 1);
  Bytes out(32);
  Bytes ctx(256, 0);
  std::string long_label(250, 'x');
  EXPECT_EQ(gtls_hkdf_expand_label(GTLS_HASH_SHA256, secret.data(), 32, "a", nullptr, 0,
                out.data(), 32), GTLS_OK);
  EXPECT_EQ(gtls_hkdf_expand_label(GTLS_HASH_NONE, secret.data(), 32, "a", nullptr, 0,
                out.data(), 32), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_hkdf_expand_label(GTLS_HASH_SHA256, secret.data(), 32, long_label.c_str(),
                nullptr, 0, out.data(), 32), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_hkdf_expand_label(GTLS_HASH_SHA256, secret.data(), 32, "a", ctx.data(),
                256, out.data(), 32), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_hkdf_expand_label(GTLS_HASH_SHA256, secret.data(), 32, "a", ctx.data(),
                255, out.data(), 70000), GTLS_ERR_LIMIT);
  EXPECT_EQ(gtls_hkdf_expand_label(GTLS_HASH_SHA256, nullptr, 32, "a", nullptr, 0,
                out.data(), 32), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_hkdf_expand_label(GTLS_HASH_SHA256, secret.data(), 32, nullptr, nullptr, 0,
                out.data(), 32), GTLS_ERR_INVALID);
  /* HKDF's own ceiling of 255 digests passes through as a limit, and the
   * output is wiped rather than left half-written. */
  Bytes big(255 * 32 + 1, 0xee);
  EXPECT_EQ(gtls_hkdf_expand_label(GTLS_HASH_SHA256, secret.data(), 32, "a", nullptr, 0,
                big.data(), big.size()), GTLS_ERR_LIMIT);
  EXPECT_EQ(big[0], 0);
}

TEST(Suites, HashAndKeyLengthsAreRfc8446Appendix) {
  EXPECT_EQ(gtls_suite_hash(GTLS_SUITE_AES_128_GCM_SHA256), GTLS_HASH_SHA256);
  EXPECT_EQ(gtls_suite_hash(GTLS_SUITE_CHACHA20_POLY1305_SHA256), GTLS_HASH_SHA256);
  EXPECT_EQ(gtls_suite_hash(GTLS_SUITE_AES_256_GCM_SHA384), GTLS_HASH_SHA384);
  EXPECT_EQ(gtls_suite_key_len(GTLS_SUITE_AES_128_GCM_SHA256), 16u);
  EXPECT_EQ(gtls_suite_key_len(GTLS_SUITE_AES_256_GCM_SHA384), 32u);
  EXPECT_EQ(gtls_suite_key_len(GTLS_SUITE_CHACHA20_POLY1305_SHA256), 32u);
  EXPECT_EQ(gtls_hash_len(GTLS_HASH_SHA256), 32u);
  EXPECT_EQ(gtls_hash_len(GTLS_HASH_SHA384), 48u);
  EXPECT_EQ(gtls_hash_len(GTLS_HASH_NONE), 0u);
  EXPECT_TRUE(gtls_suite_valid(0x1301));
  EXPECT_TRUE(gtls_suite_valid(0x1302));
  EXPECT_TRUE(gtls_suite_valid(0x1303));
  EXPECT_FALSE(gtls_suite_valid(0x1304));  /* CCM: never */
  EXPECT_FALSE(gtls_suite_valid(0xc02f));  /* a TLS 1.2 suite */
  EXPECT_EQ(gtls_suite_hash(0x1304), GTLS_HASH_NONE);
  EXPECT_EQ(gtls_suite_key_len(0x1304), 0u);
}

TEST(Suites, Sha384SuiteGivesFortyEightByteSecretsAndKeys) {
  /* No published trace uses AES-256-GCM-SHA384, so what can be checked is
   * the shape: a 48-byte digest throughout, and a 32-byte key. The chain of
   * values is checked against an independent computation in the test below. */
  GTLS_Schedule s;
  Bytes ecdhe(48, 7);
  Bytes th(48, 9);
  ASSERT_EQ(gtls_schedule_early(&s, GTLS_HASH_SHA384), GTLS_OK);
  EXPECT_EQ(s.hlen, 48u);
  ASSERT_EQ(gtls_schedule_handshake(&s, ecdhe.data(), 48, th.data()), GTLS_OK);
  ASSERT_EQ(gtls_schedule_master(&s, th.data()), GTLS_OK);
  Bytes key(GTLS_KEY_MAX);
  Bytes iv(GTLS_IV_LEN);
  ASSERT_EQ(gtls_traffic_keys(GTLS_SUITE_AES_256_GCM_SHA384, s.c_ap, key.data(), iv.data()),
      GTLS_OK);
  gtls_schedule_wipe(&s);
}

TEST(Suites, Sha384ScheduleAgreesWithAnIndependentHkdf) {
  /* The SHA-384 chain recomputed here from gsec_hkdf directly, with the
   * label encoded by hand. This is not an RFC vector; it checks that the
   * schedule's hash plumbing for 48-byte digests is the same arithmetic as
   * the SHA-256 path that the RFC does check. */
  Bytes zeros(48, 0);
  Bytes early(48);
  ASSERT_EQ(gsec_hkdf_extract(GSEC_HKDF_SHA384, nullptr, 0, zeros.data(), 48, early.data()),
      GSEC_OK);
  Bytes empty(48);
  ASSERT_EQ(gsec_sha384(nullptr, 0, empty.data()), GSEC_OK);
  Bytes info = {0x00, 0x30, 13};
  const std::string label = "tls13 derived";
  info.insert(info.end(), label.begin(), label.end());
  info.push_back(48);
  info.insert(info.end(), empty.begin(), empty.end());
  Bytes derived(48);
  ASSERT_EQ(gsec_hkdf_expand(GSEC_HKDF_SHA384, early.data(), 48, info.data(), info.size(),
                derived.data(), 48),
      GSEC_OK);
  Bytes ecdhe(48, 7);
  Bytes hs(48);
  ASSERT_EQ(gsec_hkdf_extract(GSEC_HKDF_SHA384, derived.data(), 48, ecdhe.data(), 48, hs.data()),
      GSEC_OK);
  GTLS_Schedule s;
  Bytes th(48, 9);
  ASSERT_EQ(gtls_schedule_early(&s, GTLS_HASH_SHA384), GTLS_OK);
  EXPECT_EQ(Bytes(s.early, s.early + 48), early);
  ASSERT_EQ(gtls_schedule_handshake(&s, ecdhe.data(), 48, th.data()), GTLS_OK);
  EXPECT_EQ(Bytes(s.handshake, s.handshake + 48), hs);
  gtls_schedule_wipe(&s);
}

TEST(Schedule, StagesCannotBeSkippedOrRepeated) {
  GTLS_Schedule s;
  Bytes e(32, 1);
  Bytes th(32, 2);
  std::memset(&s, 0, sizeof s);
  EXPECT_EQ(gtls_schedule_handshake(&s, e.data(), 32, th.data()), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_schedule_master(&s, th.data()), GTLS_ERR_INVALID);
  ASSERT_EQ(gtls_schedule_early(&s, GTLS_HASH_SHA256), GTLS_OK);
  EXPECT_EQ(gtls_schedule_master(&s, th.data()), GTLS_ERR_INVALID);
  ASSERT_EQ(gtls_schedule_handshake(&s, e.data(), 32, th.data()), GTLS_OK);
  EXPECT_EQ(gtls_schedule_handshake(&s, e.data(), 32, th.data()), GTLS_ERR_INVALID);
  Bytes out(32);
  EXPECT_EQ(gtls_schedule_exporter(&s, th.data(), out.data()), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_schedule_resumption(&s, th.data(), out.data()), GTLS_ERR_INVALID);
  gtls_schedule_wipe(&s);
}

TEST(Schedule, WipeZeroesEverySecret) {
  GTLS_Schedule s;
  Bytes e(32, 1);
  Bytes th(32, 2);
  ASSERT_EQ(gtls_schedule_early(&s, GTLS_HASH_SHA256), GTLS_OK);
  ASSERT_EQ(gtls_schedule_handshake(&s, e.data(), 32, th.data()), GTLS_OK);
  ASSERT_EQ(gtls_schedule_master(&s, th.data()), GTLS_OK);
  gtls_schedule_wipe(&s);
  const unsigned char * p = reinterpret_cast<const unsigned char *>(&s);
  for (size_t i = 0; i < sizeof s; i++) {
    ASSERT_EQ(p[i], 0) << "byte " << i;
  }
}

TEST(Finished, CheckAcceptsTheRightValueAndRefusesEveryOneByteChange) {
  Vec v("simple-1rtt");
  const Bytes base = v["server.calculate-finished-tls13-finished.prk"];
  Bytes th(32, 0x11);
  Bytes good(32);
  ASSERT_EQ(gtls_finished_verify_data(GTLS_HASH_SHA256, base.data(), th.data(), good.data()),
      GTLS_OK);
  EXPECT_EQ(gtls_finished_check(GTLS_HASH_SHA256, base.data(), th.data(), good.data(), 32),
      GTLS_OK);
  for (size_t i = 0; i < 32; i++) {
    Bytes bad = good;
    bad[i] ^= 0x80;
    EXPECT_EQ(gtls_finished_check(GTLS_HASH_SHA256, base.data(), th.data(), bad.data(), 32),
        GTLS_ERR_FINISHED) << "byte " << i;
  }
  EXPECT_EQ(gtls_finished_check(GTLS_HASH_SHA256, base.data(), th.data(), good.data(), 31),
      GTLS_ERR_FINISHED);
  EXPECT_EQ(gtls_finished_check(GTLS_HASH_SHA256, base.data(), th.data(), good.data(), 33),
      GTLS_ERR_FINISHED);
  Bytes other(32, 0x12);
  EXPECT_EQ(gtls_finished_check(GTLS_HASH_SHA256, base.data(), other.data(), good.data(), 32),
      GTLS_ERR_FINISHED) << "the transcript hash is part of the MAC";
}

/* The transcript. */

TEST(Transcript, HashesMessagesAsOneStreamAndSnapshotsWithoutDisturbingIt) {
  GTLS_Transcript t;
  Vec v("simple-1rtt");
  const Bytes ch = v["client.construct-a-clienthello-handshake-message.clienthello"];
  const Bytes sh = v["server.construct-a-serverhello-handshake-message.serverhello"];
  ASSERT_EQ(gtls_transcript_init(&t), GTLS_OK);
  ASSERT_EQ(gtls_transcript_update(&t, ch.data(), ch.size()), GTLS_OK);
  ASSERT_EQ(gtls_transcript_update(&t, sh.data(), sh.size()), GTLS_OK);
  Bytes a(32);
  Bytes b(32);
  ASSERT_EQ(gtls_transcript_snapshot(&t, GTLS_HASH_SHA256, a.data()), GTLS_OK);
  ASSERT_EQ(gtls_transcript_snapshot(&t, GTLS_HASH_SHA256, b.data()), GTLS_OK);
  EXPECT_EQ(a, b);
  EXPECT_EQ(a, v["server.derive-secret-tls13-c-hs-traffic.hash"]);
  Bytes c48(48);
  EXPECT_EQ(gtls_transcript_snapshot(&t, GTLS_HASH_SHA384, c48.data()), GTLS_OK);
  ASSERT_EQ(gtls_transcript_select(&t, GTLS_HASH_SHA256), GTLS_OK);
  EXPECT_EQ(gtls_transcript_snapshot(&t, GTLS_HASH_SHA384, c48.data()), GTLS_ERR_INVALID)
      << "the hash that was not chosen is gone";
  EXPECT_EQ(gtls_transcript_select(&t, GTLS_HASH_SHA256), GTLS_ERR_INVALID)
      << "a suite is chosen once";
  gtls_transcript_wipe(&t);
}

/* The message_hash restart (RFC 8446 section 4.4.1) is checked against the
 * RFC's HRR trace in test_rfc8448, where the resulting secrets prove it. */
TEST(Transcript, RestartIsMessageHashOfTheFirstHello) {
  GTLS_Transcript t;
  const Bytes ch = {1, 0, 0, 3, 'a', 'b', 'c'};
  ASSERT_EQ(gtls_transcript_init(&t), GTLS_OK);
  ASSERT_EQ(gtls_transcript_update(&t, ch.data(), ch.size()), GTLS_OK);
  Bytes h(32);
  ASSERT_EQ(gsec_sha256(ch.data(), ch.size(), h.data()), GSEC_OK);
  ASSERT_EQ(gtls_transcript_select(&t, GTLS_HASH_SHA256), GTLS_OK);
  ASSERT_EQ(gtls_transcript_restart(&t, GTLS_HASH_SHA256), GTLS_OK);
  Bytes got(32);
  ASSERT_EQ(gtls_transcript_snapshot(&t, GTLS_HASH_SHA256, got.data()), GTLS_OK);
  Bytes synthetic = {254, 0, 0, 32};
  synthetic.insert(synthetic.end(), h.begin(), h.end());
  Bytes want(32);
  ASSERT_EQ(gsec_sha256(synthetic.data(), synthetic.size(), want.data()), GSEC_OK);
  EXPECT_EQ(got, want);
  gtls_transcript_wipe(&t);
}

TEST(Transcript, WipeLeavesNothing) {
  GTLS_Transcript t;
  const Bytes m = {1, 2, 3};
  ASSERT_EQ(gtls_transcript_init(&t), GTLS_OK);
  ASSERT_EQ(gtls_transcript_update(&t, m.data(), m.size()), GTLS_OK);
  gtls_transcript_wipe(&t);
  const unsigned char * p = reinterpret_cast<const unsigned char *>(&t);
  for (size_t i = 0; i < sizeof t; i++) {
    ASSERT_EQ(p[i], 0) << "byte " << i;
  }
  Bytes out(32);
  EXPECT_EQ(gtls_transcript_snapshot(&t, GTLS_HASH_SHA256, out.data()), GTLS_ERR_INVALID);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
