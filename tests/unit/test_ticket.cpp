/**
 * @file
 *
 * Tickets and resumption, the pieces that have a known answer: RFC 8448's
 * resumed handshake (section 4) fed through the schedule and the binder, the
 * NewSessionTicket and ServerHello the RFC prints rebuilt byte for byte, the
 * PSK offer of its ClientHello parsed and cut where the binder is computed,
 * and the ClientHello builder's own offer and its retry. Every value is read
 * from tests/data/rfc8448, which tools/extract-rfc8448.py wrote from the
 * pinned RFC text.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

using namespace gtlstest;

namespace ticketkat {

GTLS_Limits limits() {
  GTLS_Limits l;
  gtls_limits_default(&l);
  return l;
}

Bytes sha256(const Bytes & in) {
  Bytes out(32);
  EXPECT_EQ(gsec_sha256(in.data(), in.size(), out.data()), GSEC_OK);
  return out;
}

Bytes slice(const Bytes & b, size_t from, size_t n) {
  return Bytes(b.begin() + static_cast<long>(from), b.begin() + static_cast<long>(from + n));
}

}  // namespace ticketkat

using namespace ticketkat;

/* ------------------------------------------------------------ the secrets */

TEST(ResumedSchedule, ThePskIsTheOneTheTicketStandsFor) {
  Vec simple("simple-1rtt");
  Vec resumed("resumed");
  const Bytes nonce = {0x00, 0x00};   /* the ticket_nonce the RFC's NewSessionTicket carries */
  Bytes psk(32);

  ASSERT_EQ(gtls_resumption_psk(GTLS_HASH_SHA256,
                simple["client.derive-secret-tls13-res-master.expanded"].data(),
                nonce.data(), nonce.size(), psk.data()),
      GTLS_OK);
  EXPECT_EQ(psk, resumed["client.extract-secret-early.ikm"]);
  EXPECT_EQ(psk, simple["server.generate-resumption-secret-tls13-resumption.expanded"]);
}

TEST(ResumedSchedule, TheResumptionMasterSecretIsKeptAndWiped) {
  Vec simple("simple-1rtt");
  GTLS_Schedule s;
  const Bytes sh = simple["server.derive-secret-tls13-c-hs-traffic.hash"];
  const Bytes fin = simple["server.derive-secret-tls13-c-ap-traffic.hash"];

  ASSERT_EQ(gtls_schedule_early(&s, GTLS_HASH_SHA256), GTLS_OK);
  ASSERT_EQ(gtls_schedule_handshake(&s, simple["server.extract-secret-handshake.ikm"].data(),
                32, sh.data()),
      GTLS_OK);
  ASSERT_EQ(gtls_schedule_master(&s, fin.data()), GTLS_OK);
  EXPECT_EQ(s.has_res, 0);
  ASSERT_EQ(gtls_schedule_keep_resumption(&s,
                simple["client.derive-secret-tls13-res-master.hash"].data()),
      GTLS_OK);
  EXPECT_EQ(s.has_res, 1);
  EXPECT_EQ(Bytes(s.res, s.res + 32), simple["client.derive-secret-tls13-res-master.expanded"]);
  gtls_schedule_wipe(&s);
  EXPECT_EQ(Bytes(s.res, s.res + 32), Bytes(32, 0));
  EXPECT_EQ(s.has_res, 0);
}

TEST(ResumedSchedule, TheEarlySecretIsExtractedFromThePsk) {
  Vec v("resumed");
  GTLS_Schedule s;

  ASSERT_EQ(gtls_schedule_early_psk(&s, GTLS_HASH_SHA256,
                v["client.extract-secret-early.ikm"].data(), 32),
      GTLS_OK);
  EXPECT_EQ(Bytes(s.early, s.early + 32), v["client.extract-secret-early.secret"]);
  EXPECT_EQ(s.stage, 1);
  gtls_schedule_wipe(&s);
}

TEST(ResumedSchedule, ThePskMustBeADigestLong) {
  Vec v("resumed");
  GTLS_Schedule s;
  const Bytes psk = v["client.extract-secret-early.ikm"];

  EXPECT_EQ(gtls_schedule_early_psk(&s, GTLS_HASH_SHA256, psk.data(), 31), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_schedule_early_psk(&s, GTLS_HASH_SHA256, psk.data(), 33), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_schedule_early_psk(&s, GTLS_HASH_SHA384, psk.data(), 32), GTLS_ERR_INVALID)
      << "a PSK is not used across hashes";
  EXPECT_EQ(gtls_schedule_early_psk(&s, GTLS_HASH_NONE, psk.data(), 32), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_schedule_early_psk(&s, GTLS_HASH_SHA256, nullptr, 32), GTLS_ERR_INVALID);
}

TEST(ResumedSchedule, TheHandshakeAndApplicationSecretsFollowThePsk) {
  Vec v("resumed");
  GTLS_Schedule s;
  const Bytes sh_hash = v["server.derive-secret-tls13-c-hs-traffic.hash"];
  const Bytes fin_hash = v["server.derive-secret-tls13-c-ap-traffic.hash"];

  ASSERT_EQ(gtls_schedule_early_psk(&s, GTLS_HASH_SHA256,
                v["client.extract-secret-early.ikm"].data(), 32),
      GTLS_OK);
  ASSERT_EQ(gtls_schedule_handshake(&s, v["server.extract-secret-handshake.ikm"].data(), 32,
                sh_hash.data()),
      GTLS_OK);
  EXPECT_EQ(Bytes(s.handshake, s.handshake + 32), v["server.extract-secret-handshake.secret"]);
  EXPECT_EQ(Bytes(s.c_hs, s.c_hs + 32), v["server.derive-secret-tls13-c-hs-traffic.expanded"]);
  EXPECT_EQ(Bytes(s.s_hs, s.s_hs + 32), v["server.derive-secret-tls13-s-hs-traffic.expanded"]);
  ASSERT_EQ(gtls_schedule_master(&s, fin_hash.data()), GTLS_OK);
  EXPECT_EQ(Bytes(s.master, s.master + 32), v["server.extract-secret-master.secret"]);
  EXPECT_EQ(Bytes(s.c_ap, s.c_ap + 32), v["server.derive-secret-tls13-c-ap-traffic.expanded"]);
  EXPECT_EQ(Bytes(s.s_ap, s.s_ap + 32), v["server.derive-secret-tls13-s-ap-traffic.expanded"]);
  gtls_schedule_wipe(&s);
}

/* ---------------------------------------------------------------- binder */

TEST(Binder, TheBinderKeyAndTheBinderAreTheRfcs) {
  Vec v("resumed");
  GTLS_Schedule s;
  Bytes key(32);
  Bytes binder(32);
  const Bytes prefix = v["client.calculate-psk-binder.clienthello-prefix"];
  const Bytes th = sha256(prefix);

  EXPECT_EQ(th, v["client.calculate-psk-binder.binder-hash"]);
  ASSERT_EQ(gtls_schedule_early_psk(&s, GTLS_HASH_SHA256,
                v["client.extract-secret-early.ikm"].data(), 32),
      GTLS_OK);
  ASSERT_EQ(gtls_schedule_binder_key(&s, key.data()), GTLS_OK);
  EXPECT_EQ(key, v["client.calculate-psk-binder.prk"]);
  gtls_schedule_wipe(&s);

  ASSERT_EQ(gtls_binder_compute(GTLS_HASH_SHA256, v["client.extract-secret-early.ikm"].data(),
                32, th.data(), binder.data()),
      GTLS_OK);
  EXPECT_EQ(binder, v["client.calculate-psk-binder.finished"]);
}

TEST(Binder, TheBinderKeyNeedsAPskStage) {
  GTLS_Schedule s;
  Bytes out(32);

  ASSERT_EQ(gtls_schedule_early(&s, GTLS_HASH_SHA256), GTLS_OK);
  s.stage = 2;
  EXPECT_EQ(gtls_schedule_binder_key(&s, out.data()), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_schedule_binder_key(nullptr, out.data()), GTLS_ERR_INVALID);
}

TEST(Binder, TheCheckAcceptsTheRfcsAndRefusesEveryFlippedBit) {
  Vec v("resumed");
  const Bytes psk = v["client.extract-secret-early.ikm"];
  const Bytes th = v["client.calculate-psk-binder.binder-hash"];
  Bytes good = v["client.calculate-psk-binder.finished"];

  ASSERT_EQ(gtls_binder_check(GTLS_HASH_SHA256, psk.data(), 32, th.data(), good.data(), 32),
      GTLS_OK);
  for (size_t byte = 0; byte < good.size(); byte++) {
    for (int bit = 0; bit < 8; bit++) {
      Bytes bad = good;
      bad[byte] ^= static_cast<unsigned char>(1u << bit);
      ASSERT_EQ(gtls_binder_check(GTLS_HASH_SHA256, psk.data(), 32, th.data(), bad.data(), 32),
          GTLS_ERR_MISMATCH) << byte << ":" << bit;
    }
  }
  EXPECT_EQ(gtls_binder_check(GTLS_HASH_SHA256, psk.data(), 32, th.data(), good.data(), 31),
      GTLS_ERR_MISMATCH);
  EXPECT_EQ(gtls_binder_check(GTLS_HASH_SHA256, psk.data(), 32, th.data(), good.data(), 33),
      GTLS_ERR_MISMATCH);
  const Bytes th48(48, 1);
  const Bytes got48(48, 2);
  EXPECT_EQ(gtls_binder_check(GTLS_HASH_SHA384, psk.data(), 32, th48.data(), got48.data(), 48),
      GTLS_ERR_INVALID) << "a PSK of the wrong hash";
  Bytes other_th = th;
  other_th[0] ^= 1;
  EXPECT_EQ(gtls_binder_check(GTLS_HASH_SHA256, psk.data(), 32, other_th.data(), good.data(), 32),
      GTLS_ERR_MISMATCH) << "the binder covers the transcript";
  Bytes other_psk = psk;
  other_psk[31] ^= 1;
  EXPECT_EQ(gtls_binder_check(GTLS_HASH_SHA256, other_psk.data(), 32, th.data(), good.data(), 32),
      GTLS_ERR_MISMATCH) << "the binder is under the PSK";
}

TEST(Binder, TheTranscriptIsTheRunningOneWithTheTruncatedHelloAndItIsNotDisturbed) {
  Vec v("resumed");
  GTLS_Transcript t;
  const Bytes prefix = v["client.calculate-psk-binder.clienthello-prefix"];
  Bytes th(32);
  Bytes before(32);
  Bytes after(32);

  ASSERT_EQ(gtls_transcript_init(&t), GTLS_OK);
  ASSERT_EQ(gtls_transcript_select(&t, GTLS_HASH_SHA256), GTLS_OK);
  ASSERT_EQ(gtls_transcript_snapshot(&t, GTLS_HASH_SHA256, before.data()), GTLS_OK);
  ASSERT_EQ(gtls_binder_transcript(&t, prefix.data(), prefix.size(), th.data()), GTLS_OK);
  EXPECT_EQ(th, v["client.calculate-psk-binder.binder-hash"]);
  ASSERT_EQ(gtls_transcript_snapshot(&t, GTLS_HASH_SHA256, after.data()), GTLS_OK);
  EXPECT_EQ(before, after);

  /* After a HelloRetryRequest the transcript is not empty: the binder covers it too. */
  ASSERT_EQ(gtls_transcript_update(&t, prefix.data(), 5), GTLS_OK);
  Bytes with_history(32);
  ASSERT_EQ(gtls_binder_transcript(&t, prefix.data(), prefix.size(), with_history.data()), GTLS_OK);
  EXPECT_NE(with_history, th);
  EXPECT_EQ(with_history, sha256(cat(slice(prefix, 0, 5), prefix)));

  GTLS_Transcript unselected;
  ASSERT_EQ(gtls_transcript_init(&unselected), GTLS_OK);
  EXPECT_EQ(gtls_binder_transcript(&unselected, prefix.data(), prefix.size(), th.data()),
      GTLS_ERR_INVALID);
  gtls_transcript_wipe(&t);
  gtls_transcript_wipe(&unselected);
}

/* -------------------------------------------------------------- messages */

TEST(ResumedMessages, TheRfcsPskOfferParsesAndIsCutWhereTheBinderStarts) {
  Vec v("resumed");
  const Bytes hello = v["client.send-handshake-record.payload"];
  const Bytes prefix = v["client.calculate-psk-binder.clienthello-prefix"];
  GTLS_ClientHello h;
  GTLS_PskOffer offer;
  GTLS_Limits l = limits();

  ASSERT_EQ(gtls_msg_parse_client_hello(hello.data() + 4, hello.size() - 4, &l, &h), GTLS_OK);
  const GTLS_Ext * e = gtls_msg_find_ext(h.exts, h.ext_count, GTLS_EXT_PRE_SHARED_KEY);
  ASSERT_NE(e, nullptr);
  EXPECT_EQ(h.exts[h.ext_count - 1].type, GTLS_EXT_PRE_SHARED_KEY) << "it is the last extension";
  ASSERT_EQ(gtls_msg_parse_ch_psk_offer(e, &l, &offer), GTLS_OK);
  EXPECT_EQ(offer.count, 1u);
  EXPECT_EQ(offer.stored, 1u);
  EXPECT_EQ(offer.entries[0].identity_len, 0xb2u) << "the RFC's ticket";
  EXPECT_EQ(offer.entries[0].binder_len, 32u);
  EXPECT_EQ(Bytes(offer.entries[0].binder, offer.entries[0].binder + 32),
      v["client.calculate-psk-binder.finished"]);
  const size_t cut = static_cast<size_t>(e->data - (hello.data() + 4)) + 4 + offer.binders_off;
  EXPECT_EQ(cut, prefix.size());
  EXPECT_EQ(slice(hello, 0, cut), prefix) << "the message cut before the binders list";
  EXPECT_EQ(hello.size() - cut, GTLS_PSK_BINDERS_TAIL(32));
}

TEST(ResumedMessages, TheRfcsNewSessionTicketRebuildsByteForByte) {
  Vec v("simple-1rtt");
  const Bytes msg = v["server.construct-a-newsessionticket-handshake-message.newsessionticket"];
  GTLS_NewSessionTicket t;
  GTLS_Limits l = limits();
  GTLS_Buf b;

  ASSERT_EQ(gtls_msg_parse_new_session_ticket(msg.data() + 4, msg.size() - 4, &l, &t), GTLS_OK);
  EXPECT_EQ(t.nonce_len, 2u);
  EXPECT_EQ(t.ticket_len, 178u);
  EXPECT_TRUE(t.early_data);
  gtls_buf_init(&b, nullptr, 1 << 16);
  ASSERT_EQ(gtls_msg_build_new_session_ticket(&t, &b), GTLS_OK);
  EXPECT_EQ(Bytes(b.data, b.data + b.len), msg);
  gtls_buf_free(&b);

  t.early_data = 0;
  gtls_buf_init(&b, nullptr, 1 << 16);
  ASSERT_EQ(gtls_msg_build_new_session_ticket(&t, &b), GTLS_OK);
  EXPECT_EQ(b.len, msg.size() - 8) << "no early_data extension";
  GTLS_NewSessionTicket back;
  ASSERT_EQ(gtls_msg_parse_new_session_ticket(b.data + 4, b.len - 4, &l, &back), GTLS_OK);
  EXPECT_FALSE(back.early_data);
  EXPECT_EQ(back.lifetime, t.lifetime);
  EXPECT_EQ(back.age_add, t.age_add);
  gtls_buf_free(&b);
}

TEST(ResumedMessages, ANewSessionTicketBuilderRefusesWhatCannotBeSent) {
  const Bytes ticket(10, 7);
  GTLS_NewSessionTicket t;
  GTLS_Buf b;

  std::memset(&t, 0, sizeof t);
  t.ticket = ticket.data();
  t.ticket_len = ticket.size();
  t.nonce = ticket.data();
  t.nonce_len = 256;
  gtls_buf_init(&b, nullptr, 1 << 16);
  EXPECT_EQ(gtls_msg_build_new_session_ticket(&t, &b), GTLS_ERR_INVALID) << "a nonce of 256 bytes";
  t.nonce_len = 0;
  t.ticket_len = 0;
  EXPECT_EQ(gtls_msg_build_new_session_ticket(&t, &b), GTLS_ERR_INVALID) << "an empty ticket";
  t.ticket_len = 0x10000;
  EXPECT_EQ(gtls_msg_build_new_session_ticket(&t, &b), GTLS_ERR_INVALID);
  t.ticket_len = ticket.size();
  EXPECT_EQ(gtls_msg_build_new_session_ticket(nullptr, &b), GTLS_ERR_INVALID);
  gtls_buf_free(&b);
}

TEST(ResumedMessages, TheRfcsServerHelloWithItsPskRebuildsByteForByte) {
  Vec v("resumed");
  const Bytes sh = v["server.construct-a-serverhello-handshake-message.serverhello"];
  GTLS_ServerHelloParams p;
  GTLS_Buf b;

  std::memset(&p, 0, sizeof p);
  std::memcpy(p.random, sh.data() + 6, 32);
  p.suite = GTLS_SUITE_AES_128_GCM_SHA256;
  p.group = GTLS_GROUP_X25519;
  const Bytes pub = v["server.create-an-ephemeral-x25519-key-pair.public-key"];
  p.key_exchange = pub.data();
  p.key_exchange_len = pub.size();
  p.psk = 1;
  p.psk_identity = 0;
  gtls_buf_init(&b, nullptr, 4096);
  ASSERT_EQ(gtls_msg_build_server_hello(&p, &b), GTLS_OK);
  EXPECT_EQ(Bytes(b.data, b.data + b.len), sh);
  gtls_buf_free(&b);

  GTLS_ServerHello parsed;
  GTLS_Limits l = limits();
  ASSERT_EQ(gtls_msg_parse_server_hello(sh.data() + 4, sh.size() - 4, &l, &parsed), GTLS_OK);
  EXPECT_NE(parsed.flags & GTLS_SH_FLAG_PSK, 0u);
  EXPECT_EQ(parsed.psk_identity, 0u);
}

TEST(ResumedMessages, ASelectedIdentityIsReadAndMustBeTwoBytes) {
  Vec v("resumed");
  Bytes sh = v["server.construct-a-serverhello-handshake-message.serverhello"];
  GTLS_ServerHello parsed;
  GTLS_Limits l = limits();

  /* Select identity 0x0102, then cut the extension short and make it long. */
  const size_t at = 4 + 2 + 32 + 1 + 2 + 1 + 2;   /* the first extension: pre_shared_key */
  ASSERT_EQ(sh[at], 0x00);
  ASSERT_EQ(sh[at + 1], 0x29);
  sh[at + 4] = 0x01;
  sh[at + 5] = 0x02;
  ASSERT_EQ(gtls_msg_parse_server_hello(sh.data() + 4, sh.size() - 4, &l, &parsed), GTLS_OK);
  EXPECT_EQ(parsed.psk_identity, 0x0102u);

  Bytes shorter = sh;
  shorter[at + 3] = 1;   /* the extension says one byte */
  EXPECT_NE(gtls_msg_parse_server_hello(shorter.data() + 4, shorter.size() - 4, &l, &parsed), GTLS_OK);
  Bytes longer = sh;
  longer[at + 3] = 3;
  EXPECT_NE(gtls_msg_parse_server_hello(longer.data() + 4, longer.size() - 4, &l, &parsed), GTLS_OK);
}

TEST(PskOfferParser, EveryIdentityAndBinderIsReturnedAndTheCountsAreChecked) {
  Bytes ids;
  Bytes bind;
  GTLS_Limits l = limits();
  GTLS_PskOffer o;

  for (unsigned i = 0; i < 3; i++) {
    ids.push_back(0);
    ids.push_back(static_cast<unsigned char>(2 + i));           /* identity length */
    for (unsigned k = 0; k < 2 + i; k++) {
      ids.push_back(static_cast<unsigned char>(0x10 * (i + 1) + k));
    }
    ids.push_back(0);
    ids.push_back(0);
    ids.push_back(0);
    ids.push_back(static_cast<unsigned char>(i + 1));            /* age */
    bind.push_back(32);
    for (unsigned k = 0; k < 32; k++) {
      bind.push_back(static_cast<unsigned char>(0xa0 + i));
    }
  }
  Bytes body;
  body.push_back(static_cast<unsigned char>(ids.size() >> 8));
  body.push_back(static_cast<unsigned char>(ids.size()));
  body.insert(body.end(), ids.begin(), ids.end());
  body.push_back(static_cast<unsigned char>(bind.size() >> 8));
  body.push_back(static_cast<unsigned char>(bind.size()));
  body.insert(body.end(), bind.begin(), bind.end());
  GTLS_Ext e = {GTLS_EXT_PRE_SHARED_KEY, body.data(), body.size()};

  ASSERT_EQ(gtls_msg_parse_ch_psk_offer(&e, &l, &o), GTLS_OK);
  ASSERT_EQ(o.count, 3u);
  ASSERT_EQ(o.stored, 3u);
  for (unsigned i = 0; i < 3; i++) {
    EXPECT_EQ(o.entries[i].identity_len, 2u + i);
    EXPECT_EQ(o.entries[i].identity[0], 0x10 * (i + 1));
    EXPECT_EQ(o.entries[i].age, i + 1);
    EXPECT_EQ(o.entries[i].binder_len, 32u);
    EXPECT_EQ(o.entries[i].binder[0], 0xa0 + i);
  }
  EXPECT_EQ(o.binders_off, 2 + ids.size());

  l.max_tickets = 2;
  EXPECT_EQ(gtls_msg_parse_ch_psk_offer(&e, &l, &o), GTLS_ERR_LIMIT);
  l = limits();
  l.max_ticket_bytes = 3;
  EXPECT_EQ(gtls_msg_parse_ch_psk_offer(&e, &l, &o), GTLS_ERR_LIMIT);
}

TEST(PskOfferParser, MoreIdentitiesThanAreKeptAreCountedAndNotLookedAt) {
  GTLS_Limits l = limits();
  GTLS_PskOffer o;
  Bytes ids;
  Bytes bind;
  const unsigned n = GTLS_PSK_MAX + 4;

  l.max_tickets = 64;
  for (unsigned i = 0; i < n; i++) {
    ids.push_back(0);
    ids.push_back(1);
    ids.push_back(static_cast<unsigned char>(i));
    for (int k = 0; k < 4; k++) {
      ids.push_back(0);
    }
    bind.push_back(32);
    bind.insert(bind.end(), 32, static_cast<unsigned char>(i));
  }
  Bytes body = {static_cast<unsigned char>(ids.size() >> 8), static_cast<unsigned char>(ids.size())};
  body.insert(body.end(), ids.begin(), ids.end());
  body.push_back(static_cast<unsigned char>(bind.size() >> 8));
  body.push_back(static_cast<unsigned char>(bind.size()));
  body.insert(body.end(), bind.begin(), bind.end());
  GTLS_Ext e = {GTLS_EXT_PRE_SHARED_KEY, body.data(), body.size()};

  ASSERT_EQ(gtls_msg_parse_ch_psk_offer(&e, &l, &o), GTLS_OK);
  EXPECT_EQ(o.count, n);
  EXPECT_EQ(o.stored, GTLS_PSK_MAX);
  EXPECT_EQ(o.entries[GTLS_PSK_MAX - 1].identity[0], GTLS_PSK_MAX - 1);
  EXPECT_EQ(o.entries[GTLS_PSK_MAX - 1].binder[0], GTLS_PSK_MAX - 1);
}

/* --------------------------------------------- the ClientHello that offers */

namespace {

GTLS_HelloParams hello_params(const GTLS_PskParams * psk) {
  static const GTLS_Suite suites[] = {GTLS_SUITE_AES_128_GCM_SHA256,
      GTLS_SUITE_CHACHA20_POLY1305_SHA256, GTLS_SUITE_AES_256_GCM_SHA384};
  static const GTLS_Group groups[] = {GTLS_GROUP_X25519, GTLS_GROUP_SECP256R1,
      GTLS_GROUP_SECP384R1};
  static const GCERT_SigScheme sigs[] = {GCERT_SIG_RSA_PSS_SHA256, GCERT_SIG_ED25519};
  GTLS_HelloParams p;
  std::memset(&p, 0, sizeof p);
  for (int i = 0; i < 32; i++) {
    p.random[i] = static_cast<unsigned char>(i);
  }
  p.suites = suites;
  p.suite_count = 3;
  p.host = "example.com";
  p.host_len = 11;
  p.groups = groups;
  p.group_count = 3;
  p.sig_algs = sigs;
  p.sig_alg_count = 2;
  p.share.group = GTLS_GROUP_X25519;
  p.share.pub_len = 32;
  for (int i = 0; i < 32; i++) {
    p.share.pub[i] = static_cast<unsigned char>(0x80 + i);
  }
  p.psk = psk;
  return p;
}

Bytes build_hello(const GTLS_HelloParams & p) {
  GTLS_Buf b;
  gtls_buf_init(&b, nullptr, 1 << 20);
  EXPECT_EQ(gtls_msg_build_client_hello(&p, &b), GTLS_OK);
  Bytes out(b.data, b.data + b.len);
  gtls_buf_free(&b);
  return out;
}

}  // namespace

TEST(PskClientHello, TheOfferIsLastAfterTheModesAndItsBinderIsTheTail) {
  const Bytes identity(50, 0x5a);
  GTLS_PskParams psk = {identity.data(), identity.size(), 0xdeadbeefu, 32};
  const Bytes m = build_hello(hello_params(&psk));
  GTLS_ClientHello h;
  GTLS_PskOffer offer;
  GTLS_Limits l = limits();
  int dhe = 0;

  ASSERT_EQ(gtls_msg_parse_client_hello(m.data() + 4, m.size() - 4, &l, &h), GTLS_OK);
  EXPECT_EQ(h.exts[h.ext_count - 1].type, GTLS_EXT_PRE_SHARED_KEY);
  const GTLS_Ext * modes = gtls_msg_find_ext(h.exts, h.ext_count, GTLS_EXT_PSK_KEY_EXCHANGE_MODES);
  ASSERT_NE(modes, nullptr);
  ASSERT_EQ(gtls_msg_parse_ch_psk_modes(modes, &dhe), GTLS_OK);
  EXPECT_EQ(dhe, 1);
  EXPECT_EQ(modes->len, 2u) << "psk_dhe_ke alone, never psk_ke";
  EXPECT_EQ(modes->data[1], 1);
  ASSERT_EQ(gtls_msg_parse_ch_psk_offer(&h.exts[h.ext_count - 1], &l, &offer), GTLS_OK);
  ASSERT_EQ(offer.count, 1u);
  EXPECT_EQ(offer.entries[0].identity_len, identity.size());
  EXPECT_EQ(offer.entries[0].age, 0xdeadbeefu);
  EXPECT_EQ(Bytes(offer.entries[0].binder, offer.entries[0].binder + 32), Bytes(32, 0));
  const size_t cut = static_cast<size_t>(h.exts[h.ext_count - 1].data - (m.data() + 4)) + 4 +
      offer.binders_off;
  EXPECT_EQ(m.size() - cut, GTLS_PSK_BINDERS_TAIL(32));
}

TEST(PskClientHello, ThePaddingComesBeforeThePskAndTheLengthsStillAddUp) {
  for (size_t id_len = 1; id_len < 400; id_len += 7) {
    const Bytes identity(id_len, 1);
    for (size_t binder_len : {32u, 48u}) {
      GTLS_PskParams psk = {identity.data(), identity.size(), 1, binder_len};
      const Bytes m = build_hello(hello_params(&psk));
      GTLS_ClientHello h;
      GTLS_Limits l = limits();

      ASSERT_EQ(gtls_msg_parse_client_hello(m.data() + 4, m.size() - 4, &l, &h), GTLS_OK)
          << id_len << " " << binder_len;
      ASSERT_EQ(h.exts[h.ext_count - 1].type, GTLS_EXT_PRE_SHARED_KEY);
      EXPECT_FALSE(m.size() >= 256 && m.size() <= 511) << id_len;
      const GTLS_Ext * pad = gtls_msg_find_ext(h.exts, h.ext_count, GTLS_EXT_PADDING);
      if (pad != nullptr) {
        EXPECT_LT(pad, &h.exts[h.ext_count - 1]) << "the padding is before the PSK";
        EXPECT_GE(m.size(), 512u);
        EXPECT_LE(m.size(), 515u);
      }
    }
  }
}

TEST(PskClientHello, ABuilderRefusesAnOfferItCannotWrite) {
  const Bytes identity(10, 1);
  GTLS_Buf b;

  GTLS_PskParams no_identity = {nullptr, 10, 1, 32};
  GTLS_PskParams empty = {identity.data(), 0, 1, 32};
  GTLS_PskParams short_binder = {identity.data(), identity.size(), 1, 31};
  GTLS_PskParams long_binder = {identity.data(), identity.size(), 1, 49};
  const GTLS_PskParams * bad[] = {&no_identity, &empty, &short_binder, &long_binder};

  for (const GTLS_PskParams * p : bad) {
    gtls_buf_init(&b, nullptr, 1 << 20);
    GTLS_HelloParams hp = hello_params(p);
    EXPECT_EQ(gtls_msg_build_client_hello(&hp, &b), GTLS_ERR_INVALID);
    gtls_buf_free(&b);
  }
}

TEST(PskClientHello, TheRetryReplacesTheOfferWithTheNewAgeOrDropsIt) {
  const Bytes identity(20, 9);
  GTLS_PskParams psk = {identity.data(), identity.size(), 100, 32};
  const Bytes m1 = build_hello(hello_params(&psk));
  GTLS_Limits l = limits();
  const Bytes cookie = {1, 2, 3};
  GTLS_Buf b;
  GTLS_ClientHello h;
  GTLS_PskOffer offer;

  GTLS_PskParams later = {identity.data(), identity.size(), 5100, 32};
  gtls_buf_init(&b, nullptr, 1 << 20);
  ASSERT_EQ(gtls_msg_retry_client_hello_psk(m1.data(), m1.size(), nullptr, cookie.data(),
                cookie.size(), &later, &l, &b),
      GTLS_OK);
  Bytes m2(b.data, b.data + b.len);
  gtls_buf_free(&b);
  ASSERT_EQ(gtls_msg_parse_client_hello(m2.data() + 4, m2.size() - 4, &l, &h), GTLS_OK);
  EXPECT_EQ(h.exts[h.ext_count - 1].type, GTLS_EXT_PRE_SHARED_KEY);
  ASSERT_EQ(gtls_msg_parse_ch_psk_offer(&h.exts[h.ext_count - 1], &l, &offer), GTLS_OK);
  EXPECT_EQ(offer.entries[0].age, 5100u);
  EXPECT_EQ(Bytes(offer.entries[0].binder, offer.entries[0].binder + 32), Bytes(32, 0))
      << "a fresh binder is left for the caller";
  EXPECT_NE(gtls_msg_find_ext(h.exts, h.ext_count, GTLS_EXT_COOKIE), nullptr);
  const GTLS_Ext * cookie_ext = gtls_msg_find_ext(h.exts, h.ext_count, GTLS_EXT_COOKIE);
  const GTLS_Ext * modes = gtls_msg_find_ext(h.exts, h.ext_count, GTLS_EXT_PSK_KEY_EXCHANGE_MODES);
  EXPECT_LT(cookie_ext, modes) << "the cookie goes before the modes, as the RFC's does";

  gtls_buf_init(&b, nullptr, 1 << 20);
  ASSERT_EQ(gtls_msg_retry_client_hello_psk(m1.data(), m1.size(), nullptr, cookie.data(),
                cookie.size(), nullptr, &l, &b),
      GTLS_OK);
  Bytes m3(b.data, b.data + b.len);
  gtls_buf_free(&b);
  ASSERT_EQ(gtls_msg_parse_client_hello(m3.data() + 4, m3.size() - 4, &l, &h), GTLS_OK);
  EXPECT_EQ(gtls_msg_find_ext(h.exts, h.ext_count, GTLS_EXT_PRE_SHARED_KEY), nullptr);
  EXPECT_NE(gtls_msg_find_ext(h.exts, h.ext_count, GTLS_EXT_PSK_KEY_EXCHANGE_MODES), nullptr);

  /* The plain retry (no PSK argument) is the PSK dropped. */
  gtls_buf_init(&b, nullptr, 1 << 20);
  ASSERT_EQ(gtls_msg_retry_client_hello(m1.data(), m1.size(), nullptr, cookie.data(),
                cookie.size(), &l, &b),
      GTLS_OK);
  EXPECT_EQ(Bytes(b.data, b.data + b.len), m3);
  gtls_buf_free(&b);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
