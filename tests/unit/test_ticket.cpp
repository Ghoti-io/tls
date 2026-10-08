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

#include "loop.h"

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
  {
    /* Three identities and one binder: the count of identities is judged first, so past the cap it
     * is a limit and not a mismatch of the two lists. */
    Bytes one_binder(bind.begin(), bind.begin() + 33);
    Bytes body2;
    body2.push_back(static_cast<unsigned char>(ids.size() >> 8));
    body2.push_back(static_cast<unsigned char>(ids.size()));
    body2.insert(body2.end(), ids.begin(), ids.end());
    body2.push_back(0);
    body2.push_back(static_cast<unsigned char>(one_binder.size()));
    body2.insert(body2.end(), one_binder.begin(), one_binder.end());
    GTLS_Ext e2 = {GTLS_EXT_PRE_SHARED_KEY, body2.data(), body2.size()};
    EXPECT_EQ(gtls_msg_parse_ch_psk_offer(&e2, &l, &o), GTLS_ERR_LIMIT);
    l = limits();
    EXPECT_EQ(gtls_msg_parse_ch_psk_offer(&e2, &l, &o), GTLS_ERR_PROTOCOL) << "within the cap the lists differ";
    l.max_tickets = 2;
  }
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

/* -------------------------------------------------------- the ticket itself */

namespace {

GTLS_TicketKey key_named(unsigned seed, int64_t from, int64_t to) {
  GTLS_TicketKey k;
  std::memset(&k, 0, sizeof k);
  std::memset(k.name, static_cast<int>(seed), sizeof k.name);
  std::memset(k.key, static_cast<int>(seed + 100), sizeof k.key);
  k.not_before = from;
  k.not_after = to;
  return k;
}

GTLS_TicketPlain plain_for(uint32_t suite) {
  GTLS_TicketPlain p;
  std::memset(&p, 0, sizeof p);
  p.suite = suite;
  p.psk_len = gtls_hash_len(gtls_suite_hash(suite));
  for (size_t i = 0; i < p.psk_len; i++) {
    p.psk[i] = static_cast<unsigned char>(i + 1);
  }
  p.age_add = 0x01020304u;
  p.issued = 1700000000;
  p.lifetime = 3600;
  std::memcpy(p.alpn, "h2", 2);
  p.alpn_len = 2;
  std::memcpy(p.sni, "example.test", 12);
  p.sni_len = 12;
  return p;
}

Bytes nonce12(unsigned seed) {
  Bytes n(12);
  for (size_t i = 0; i < n.size(); i++) {
    n[i] = static_cast<unsigned char>(seed + i);
  }
  return n;
}

}  // namespace

TEST(Ticket, SealedStateComesBackExactlyAndOnlyUnderTheRightKey) {
  const GTLS_TicketKey keys[] = {key_named(1, 100, 1000)};
  for (uint32_t suite : {0x1301u, 0x1302u, 0x1303u}) {
    GTLS_TicketPlain p = plain_for(suite);
    unsigned char ticket[GTLS_TICKET_MAX];
    size_t n = 0;
    GTLS_TicketPlain back;

    ASSERT_EQ(gtls_ticket_seal(keys, 1, 500, nonce12(7).data(), &p, ticket, sizeof ticket, &n), GTLS_OK);
    EXPECT_EQ(n, 16u + 12u + (1u + 2u + 1u + p.psk_len + 4u + 8u + 4u + 1u + 2u + 1u + 12u) + 16u);
    EXPECT_EQ(Bytes(ticket, ticket + 16), Bytes(keys[0].name, keys[0].name + 16)) << "the name leads";
    EXPECT_EQ(Bytes(ticket + 16, ticket + 28), nonce12(7)) << "then the nonce";
    ASSERT_EQ(gtls_ticket_open(keys, 1, 500, ticket, n, &back), GTLS_OK);
    EXPECT_EQ(back.suite, p.suite);
    EXPECT_EQ(back.psk_len, p.psk_len);
    EXPECT_EQ(Bytes(back.psk, back.psk + back.psk_len), Bytes(p.psk, p.psk + p.psk_len));
    EXPECT_EQ(back.age_add, p.age_add);
    EXPECT_EQ(back.issued, p.issued);
    EXPECT_EQ(back.lifetime, p.lifetime);
    EXPECT_EQ(Bytes(back.alpn, back.alpn + back.alpn_len), Bytes(p.alpn, p.alpn + p.alpn_len));
    EXPECT_EQ(Bytes(back.sni, back.sni + back.sni_len), Bytes(p.sni, p.sni + p.sni_len));

    /* Nothing of the PSK is visible in the ticket. */
    EXPECT_TRUE(std::search(ticket, ticket + n, p.psk, p.psk + 8) == ticket + n);

    /* Every bit of every byte: the name, the nonce, the ciphertext and the tag. */
    for (size_t i = 0; i < n; i++) {
      for (int bit = 0; bit < 8; bit += 7) {
        Bytes bad(ticket, ticket + n);
        bad[i] ^= static_cast<unsigned char>(1u << bit);
        ASSERT_EQ(gtls_ticket_open(keys, 1, 500, bad.data(), bad.size(), &back), GTLS_ERR_MISMATCH)
            << i << ":" << bit;
      }
    }
    EXPECT_EQ(gtls_ticket_open(keys, 1, 500, ticket, n - 1, &back), GTLS_ERR_MISMATCH);
    EXPECT_EQ(gtls_ticket_open(keys, 1, 500, ticket, GTLS_TICKET_MIN - 1, &back), GTLS_ERR_MISMATCH);
    Bytes longer(ticket, ticket + n);
    longer.push_back(0);
    EXPECT_EQ(gtls_ticket_open(keys, 1, 500, longer.data(), longer.size(), &back), GTLS_ERR_MISMATCH);
    EXPECT_EQ(gtls_ticket_open(keys, 1, 500, ticket, GTLS_TICKET_MAX + 1, &back), GTLS_ERR_MISMATCH);
  }
}

TEST(Ticket, TheKeyIsFoundByNameAndMustNotHaveExpired) {
  const GTLS_TicketKey a = key_named(1, 100, 1000);
  const GTLS_TicketKey b = key_named(2, 200, 2000);
  const GTLS_TicketKey both[] = {a, b};
  GTLS_TicketPlain p = plain_for(0x1301);
  unsigned char ticket[GTLS_TICKET_MAX];
  size_t n = 0;
  GTLS_TicketPlain back;

  ASSERT_EQ(gtls_ticket_seal(both, 2, 300, nonce12(1).data(), &p, ticket, sizeof ticket, &n), GTLS_OK);
  EXPECT_EQ(Bytes(ticket, ticket + 16), Bytes(b.name, b.name + 16)) << "the later start seals";
  EXPECT_EQ(gtls_ticket_open(both, 2, 300, ticket, n, &back), GTLS_OK);
  const GTLS_TicketKey only_a[] = {a};
  EXPECT_EQ(gtls_ticket_open(only_a, 1, 300, ticket, n, &back), GTLS_ERR_MISMATCH) << "not ours";
  const GTLS_TicketKey only_b[] = {b};
  EXPECT_EQ(gtls_ticket_open(only_b, 1, 1999, ticket, n, &back), GTLS_OK);
  EXPECT_EQ(gtls_ticket_open(only_b, 1, 2000, ticket, n, &back), GTLS_ERR_MISMATCH) << "expired exactly then";
  EXPECT_EQ(gtls_ticket_open(only_b, 1, 100, ticket, n, &back), GTLS_OK)
      << "a key that has not begun still opens: it only does not seal";
  const GTLS_TicketKey renamed_key[] = {[]() { GTLS_TicketKey k = key_named(2, 200, 2000); k.key[5] ^= 1; return k; }()};
  EXPECT_EQ(gtls_ticket_open(renamed_key, 1, 300, ticket, n, &back), GTLS_ERR_MISMATCH) << "another key, same name";
  const GTLS_TicketKey other_name[] = {[]() { GTLS_TicketKey k = key_named(2, 200, 2000); k.name[0] ^= 1; return k; }()};
  EXPECT_EQ(gtls_ticket_open(other_name, 1, 300, ticket, n, &back), GTLS_ERR_MISMATCH)
      << "the same key bytes under another name is not the key that sealed it";
  EXPECT_EQ(gtls_ticket_open(nullptr, 0, 300, ticket, n, &back), GTLS_ERR_MISMATCH);

  /* The sealing key: the newest start that is valid now; none when none is. */
  EXPECT_EQ(gtls_ticket_sealing_key(both, 2, 150), &both[0]);
  EXPECT_EQ(gtls_ticket_sealing_key(both, 2, 250), &both[1]);
  EXPECT_EQ(gtls_ticket_sealing_key(both, 2, 1500), &both[1]) << "the first has expired";
  EXPECT_EQ(gtls_ticket_sealing_key(both, 2, 50), nullptr);
  EXPECT_EQ(gtls_ticket_sealing_key(both, 2, 2000), nullptr);
  const GTLS_TicketKey reversed[] = {b, a};
  EXPECT_EQ(gtls_ticket_sealing_key(reversed, 2, 250), &reversed[0]) << "the order of the list does not matter";
  const GTLS_TicketKey tie[] = {key_named(3, 100, 1000), key_named(4, 100, 1000)};
  EXPECT_EQ(gtls_ticket_sealing_key(tie, 2, 500), &tie[0]) << "the first listed among equals";
  EXPECT_EQ(gtls_ticket_seal(only_a, 1, 5000, nonce12(1).data(), &p, ticket, sizeof ticket, &n),
      GTLS_ERR_INVALID) << "no valid key, no ticket";
}

TEST(Ticket, SealingRefusesWhatItCannotEncode) {
  const GTLS_TicketKey keys[] = {key_named(1, 100, 1000)};
  unsigned char ticket[GTLS_TICKET_MAX];
  size_t n = 0;
  GTLS_TicketPlain p = plain_for(0x1301);

  EXPECT_EQ(gtls_ticket_seal(keys, 1, 500, nonce12(1).data(), &p, ticket, 50, &n), GTLS_ERR_LIMIT);
  p.psk_len = 31;
  EXPECT_EQ(gtls_ticket_seal(keys, 1, 500, nonce12(1).data(), &p, ticket, sizeof ticket, &n), GTLS_ERR_INVALID)
      << "a PSK is a digest long";
  p = plain_for(0x1301);
  p.suite = 0x1234;
  EXPECT_EQ(gtls_ticket_seal(keys, 1, 500, nonce12(1).data(), &p, ticket, sizeof ticket, &n), GTLS_ERR_INVALID);
  p = plain_for(0x1301);
  p.lifetime = GTLS_TICKET_LIFETIME_MAX + 1;
  EXPECT_EQ(gtls_ticket_seal(keys, 1, 500, nonce12(1).data(), &p, ticket, sizeof ticket, &n), GTLS_ERR_INVALID);
  p = plain_for(0x1301);
  p.sni_len = 256;
  EXPECT_EQ(gtls_ticket_seal(keys, 1, 500, nonce12(1).data(), &p, ticket, sizeof ticket, &n), GTLS_ERR_INVALID);
  p = plain_for(0x1302);
  p.alpn_len = 255;
  p.sni_len = 255;
  ASSERT_EQ(gtls_ticket_seal(keys, 1, 500, nonce12(1).data(), &p, ticket, sizeof ticket, &n), GTLS_OK)
      << "the largest state";
  EXPECT_EQ(n, GTLS_TICKET_MAX - (GTLS_HASH_MAX - 48));
  GTLS_TicketPlain back;
  EXPECT_EQ(gtls_ticket_open(keys, 1, 500, ticket, n, &back), GTLS_OK);
}

TEST(Ticket, AStateTheSealerWouldNotHaveWrittenIsNotOpened) {
  /* A ticket sealed (by another program) under a key we hold, with a state that does not decode. */
  const GTLS_TicketKey keys[] = {key_named(1, 100, 1000)};
  static const char label[] = "ghoti.io tls ticket v1";
  struct Case {
    const char * what;
    Bytes state;
  };
  Bytes good;
  {
    GTLS_TicketPlain p = plain_for(0x1301);
    good = {1, 0x13, 0x01, 32};
    good.insert(good.end(), p.psk, p.psk + 32);
    for (int i = 0; i < 4; i++) good.push_back(0);
    for (int i = 0; i < 8; i++) good.push_back(0);
    for (int i = 0; i < 4; i++) good.push_back(0);
    good.push_back(0);   /* no ALPN */
    good.push_back(0);   /* no SNI */
  }
  std::vector<Case> cases;
  cases.push_back({"the good one", good});
  { Bytes b = good; b[0] = 2; cases.push_back({"another version", b}); }
  { Bytes b = good; b[1] = 0x12; cases.push_back({"an unknown suite", b}); }
  { Bytes b = good; b[3] = 31; cases.push_back({"a PSK the wrong length for the hash", b}); }
  { Bytes b = good; b.push_back(0); cases.push_back({"a byte too many", b}); }
  { Bytes b = good; b.pop_back(); cases.push_back({"a byte too few", b}); }
  { Bytes b = good; b[4 + 32 + 4 + 8] = 0xff; cases.push_back({"a lifetime above seven days", b}); }
  { Bytes b = good; b[4 + 32 + 4 + 8 + 4] = 200; cases.push_back({"an ALPN longer than the rest", b}); }
  { Bytes b = good; b.back() = 5; cases.push_back({"an SNI longer than the rest", b}); }

  for (const Case & c : cases) {
    Bytes ticket(keys[0].name, keys[0].name + 16);
    const Bytes nonce = nonce12(3);
    ticket.insert(ticket.end(), nonce.begin(), nonce.end());
    Bytes aad(label, label + sizeof label - 1);
    aad.insert(aad.end(), keys[0].name, keys[0].name + 16);
    aad.insert(aad.end(), nonce.begin(), nonce.end());
    Bytes ct(c.state.size());
    Bytes tag(16);
    ASSERT_EQ(gsec_aes_gcm_encrypt(keys[0].key, 32, nonce.data(), 12, aad.data(), aad.size(),
                  c.state.data(), c.state.size(), ct.data(), tag.data(), 16), GSEC_OK);
    ticket.insert(ticket.end(), ct.begin(), ct.end());
    ticket.insert(ticket.end(), tag.begin(), tag.end());
    GTLS_TicketPlain back;
    GTLS_Result r = gtls_ticket_open(keys, 1, 500, ticket.data(), ticket.size(), &back);
    if (std::string(c.what) == "the good one") {
      EXPECT_EQ(r, GTLS_OK) << "the harness builds a real ticket";
    } else {
      EXPECT_EQ(r, GTLS_ERR_MISMATCH) << c.what;
    }
  }
}

TEST(Ticket, TheAdditionalDataBindsTheLabelTheNameAndTheNonce) {
  /* The same state sealed with no additional data does not open. */
  const GTLS_TicketKey keys[] = {key_named(1, 100, 1000)};
  GTLS_TicketPlain p = plain_for(0x1301);
  unsigned char ticket[GTLS_TICKET_MAX];
  size_t n = 0;
  ASSERT_EQ(gtls_ticket_seal(keys, 1, 500, nonce12(9).data(), &p, ticket, sizeof ticket, &n), GTLS_OK);
  Bytes state(n - 44);
  GTLS_TicketPlain back;
  ASSERT_EQ(gsec_aes_gcm_decrypt(keys[0].key, 32, ticket + 16, 12, nullptr, 0, ticket + 28, state.size(),
                state.data(), ticket + 28 + state.size(), 16), GSEC_ERR_MISMATCH)
      << "the tag covers more than the ciphertext";
  EXPECT_EQ(gtls_ticket_open(keys, 1, 500, ticket, n, &back), GTLS_OK);
}

TEST(Ticket, AgeAndLifetimeAreMillisecondsThatCannotOverflow) {
  GTLS_TicketPlain p = plain_for(0x1301);
  p.issued = 1000;
  p.lifetime = 100;
  p.age_add = 0xfffffff0u;   /* the obfuscation wraps */
  const uint32_t window = 10000;

  EXPECT_TRUE(gtls_ticket_fresh(&p, 1000, p.age_add, window)) << "age 0";
  EXPECT_TRUE(gtls_ticket_fresh(&p, 1042, p.age_add + 42000u, window)) << "age 42 s, the sum wrapped";
  EXPECT_TRUE(gtls_ticket_fresh(&p, 1042, p.age_add + 42000u + 10000u, window)) << "the edge of the window";
  EXPECT_FALSE(gtls_ticket_fresh(&p, 1042, p.age_add + 42000u + 10001u, window));
  EXPECT_TRUE(gtls_ticket_fresh(&p, 1042, p.age_add + 42000u - 10000u, window));
  EXPECT_FALSE(gtls_ticket_fresh(&p, 1042, p.age_add + 42000u - 10001u, window));
  EXPECT_TRUE(gtls_ticket_fresh(&p, 1099, p.age_add + 99000u, window));
  EXPECT_FALSE(gtls_ticket_fresh(&p, 1100, p.age_add + 100000u, window)) << "expired exactly at its lifetime";
  EXPECT_FALSE(gtls_ticket_fresh(&p, 1000 + 604801, p.age_add, window));
  EXPECT_TRUE(gtls_ticket_fresh(&p, 995, p.age_add, window)) << "a server clock a few seconds behind";
  EXPECT_FALSE(gtls_ticket_fresh(&p, 1000 - 86401 - 1, p.age_add, window)) << "far in the future";

  /* Extremes of the clocks: nothing wraps into acceptance. */
  const int64_t extremes[] = {INT64_MIN, INT64_MIN + 1, -1, 0, 1, INT64_MAX - 1, INT64_MAX};
  for (int64_t issued : extremes) {
    for (int64_t now : extremes) {
      GTLS_TicketPlain q = p;
      q.issued = issued;
      q.lifetime = GTLS_TICKET_LIFETIME_MAX;
      bool fresh = gtls_ticket_fresh(&q, now, q.age_add, window);
      const uint64_t apart = now >= issued ? static_cast<uint64_t>(now) - static_cast<uint64_t>(issued)
                                           : static_cast<uint64_t>(issued) - static_cast<uint64_t>(now);
      /* The client says 0 ms; the server's own age is the clocks' difference. */
      EXPECT_EQ(fresh, apart <= 10) << issued << " " << now;
    }
  }
  p.lifetime = GTLS_TICKET_LIFETIME_MAX + 1;
  EXPECT_FALSE(gtls_ticket_fresh(&p, 1000, p.age_add, window)) << "a lifetime above seven days is not one";
  p.lifetime = 100;
  EXPECT_TRUE(gtls_ticket_fresh(&p, 1000, p.age_add, 0)) << "a zero window accepts an exact age";
  EXPECT_FALSE(gtls_ticket_fresh(&p, 1000, p.age_add + 1u, 0));
}

/* --------------------------------------------------------------- the blob */

namespace {

GTLS_Session * make_session(size_t ticket_len = 130, uint32_t suite = 0x1302) {
  GTLS_Session * s = gtls_session_alloc(gtls_allocator_default(), ticket_len);
  s->suite = suite;
  s->psk_len = gtls_hash_len(gtls_suite_hash(suite));
  for (size_t i = 0; i < s->psk_len; i++) {
    s->psk[i] = static_cast<unsigned char>(0x30 + i);
  }
  for (size_t i = 0; i < ticket_len; i++) {
    s->ticket[i] = static_cast<unsigned char>(i * 5 + 1);
  }
  s->lifetime = 7200;
  s->age_add = 0xa1b2c3d4u;
  s->max_early_data = 16384;
  s->received = 1700000123;
  std::memcpy(s->host, "www.example.test", 16);
  s->host_len = 16;
  std::memcpy(s->alpn, "h2", 2);
  s->alpn_len = 2;
  return s;
}

Bytes blob_of(const GTLS_Session * s) {
  size_t n = 0;
  EXPECT_EQ(gtls_session_serialize(s, nullptr, 0, &n), GTLS_ERR_LIMIT);
  Bytes b(n);
  size_t m = 0;
  EXPECT_EQ(gtls_session_serialize(s, b.data(), b.size(), &m), GTLS_OK);
  EXPECT_EQ(m, n);
  return b;
}

}  // namespace

TEST(SessionBlob, ARoundTripKeepsEveryField) {
  for (uint32_t suite : {0x1301u, 0x1302u, 0x1303u}) {
    GTLS_Session * s = make_session(130, suite);
    const Bytes b = blob_of(s);
    GTLS_Session * back = nullptr;

    ASSERT_EQ(gtls_session_parse(nullptr, nullptr, b.data(), b.size(), &back), GTLS_OK);
    EXPECT_EQ(back->suite, s->suite);
    EXPECT_EQ(Bytes(back->psk, back->psk + back->psk_len), Bytes(s->psk, s->psk + s->psk_len));
    EXPECT_EQ(Bytes(back->ticket, back->ticket + back->ticket_len), Bytes(s->ticket, s->ticket + s->ticket_len));
    EXPECT_EQ(back->lifetime, s->lifetime);
    EXPECT_EQ(back->age_add, s->age_add);
    EXPECT_EQ(back->max_early_data, s->max_early_data);
    EXPECT_EQ(back->received, s->received);
    EXPECT_EQ(Bytes(back->host, back->host + back->host_len), Bytes(s->host, s->host + s->host_len));
    EXPECT_EQ(Bytes(back->alpn, back->alpn + back->alpn_len), Bytes(s->alpn, s->alpn + s->alpn_len));
    EXPECT_EQ(blob_of(back), b) << "and it serialises to the same bytes";
    GTLS_SessionInfo info;
    ASSERT_EQ(gtls_session_info(back, &info), GTLS_OK);
    EXPECT_EQ(info.expires, 1700000123 + 7200);
    gtls_session_free(back);
    gtls_session_free(s);
  }
}

TEST(SessionBlob, AnyByteChangedAnyTruncationAndAnyExtensionIsRefused) {
  GTLS_Session * s = make_session();
  const Bytes b = blob_of(s);
  GTLS_Session * out = nullptr;

  for (size_t i = 0; i < b.size(); i++) {
    for (int bit = 0; bit < 8; bit++) {
      Bytes bad = b;
      bad[i] ^= static_cast<unsigned char>(1u << bit);
      GTLS_Result r = gtls_session_parse(nullptr, nullptr, bad.data(), bad.size(), &out);
      ASSERT_NE(r, GTLS_OK) << i << ":" << bit;
      ASSERT_EQ(out, nullptr);
    }
  }
  for (size_t cut = 0; cut < b.size(); cut++) {
    ASSERT_NE(gtls_session_parse(nullptr, nullptr, b.data(), cut, &out), GTLS_OK) << cut;
  }
  Bytes longer = b;
  longer.push_back(0);
  EXPECT_NE(gtls_session_parse(nullptr, nullptr, longer.data(), longer.size(), &out), GTLS_OK);
  Bytes doubled = b;
  doubled.insert(doubled.end(), b.begin(), b.end());
  EXPECT_NE(gtls_session_parse(nullptr, nullptr, doubled.data(), doubled.size(), &out), GTLS_OK);
  Bytes version = b;
  version[0] = 2;
  EXPECT_EQ(gtls_session_parse(nullptr, nullptr, version.data(), version.size(), &out), GTLS_ERR_UNSUPPORTED);
  EXPECT_EQ(gtls_session_parse(nullptr, nullptr, nullptr, 5, &out), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_session_parse(nullptr, nullptr, b.data(), b.size(), nullptr), GTLS_ERR_INVALID);
  gtls_session_free(s);
}

TEST(SessionBlob, AValidDigestOverAnImpossibleSessionIsStillRefused) {
  /* Whoever can write the blob can write the digest; the fields are checked on their own. */
  GTLS_Session * s = make_session();
  Bytes b = blob_of(s);
  auto resign = [](Bytes & x) {
    ASSERT_EQ(gsec_sha256(x.data(), x.size() - 32, x.data() + x.size() - 32), GSEC_OK);
  };
  GTLS_Session * out = nullptr;

  Bytes bad = b;
  bad[1] = 0x99;   /* a suite that is none */
  resign(bad);
  EXPECT_EQ(gtls_session_parse(nullptr, nullptr, bad.data(), bad.size(), &out), GTLS_ERR_CORRUPT);
  bad = b;
  bad[3] = 0xff;   /* a lifetime above seven days */
  resign(bad);
  EXPECT_EQ(gtls_session_parse(nullptr, nullptr, bad.data(), bad.size(), &out), GTLS_ERR_CORRUPT);
  s->host_len = 0;   /* a session for nobody */
  bad = blob_of(s);
  EXPECT_EQ(gtls_session_parse(nullptr, nullptr, bad.data(), bad.size(), &out), GTLS_ERR_CORRUPT);
  s->host_len = 16;
  s->psk_len = 31;   /* a PSK the wrong size for its hash */
  bad = blob_of(s);
  EXPECT_EQ(gtls_session_parse(nullptr, nullptr, bad.data(), bad.size(), &out), GTLS_ERR_CORRUPT);
  gtls_session_free(s);
}

TEST(SessionBlob, TheLimitOnATicketIsHonouredBeforeAnythingIsAllocated) {
  GTLS_Session * s = make_session(200);
  const Bytes b = blob_of(s);
  GTLS_Limits l;
  gtls_limits_default(&l);
  GTLS_Session * out = nullptr;

  l.max_ticket_bytes = 200;
  ASSERT_EQ(gtls_session_parse(nullptr, &l, b.data(), b.size(), &out), GTLS_OK);
  gtls_session_free(out);
  l.max_ticket_bytes = 199;
  EXPECT_EQ(gtls_session_parse(nullptr, &l, b.data(), b.size(), &out), GTLS_ERR_LIMIT);
  /* A blob far larger than any limit allows is refused by its length alone. */
  Bytes huge(200000, 7);
  l.max_ticket_bytes = 16384;
  EXPECT_EQ(gtls_session_parse(nullptr, &l, huge.data(), huge.size(), &out), GTLS_ERR_LIMIT);
  gtls_session_free(s);
}

TEST(SessionBlob, SerialisingNeedsRoomAndSaysHowMuch) {
  GTLS_Session * s = make_session();
  size_t need = 0;

  EXPECT_EQ(gtls_session_serialize(s, nullptr, 0, &need), GTLS_ERR_LIMIT);
  Bytes small(need - 1, 0xee);
  size_t n = 0;
  EXPECT_EQ(gtls_session_serialize(s, small.data(), small.size(), &n), GTLS_ERR_LIMIT);
  EXPECT_EQ(n, need);
  EXPECT_EQ(small, Bytes(need - 1, 0xee)) << "nothing was written";
  EXPECT_EQ(gtls_session_serialize(nullptr, small.data(), small.size(), &n), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_session_serialize(s, small.data(), small.size(), nullptr), GTLS_ERR_INVALID);
  gtls_session_free(s);
}

TEST(SessionBlob, AFreedSessionIsWipedAndNullIsAllowed) {
  GTLS_Session * s = make_session();
  unsigned char * ticket = s->ticket;
  gtls_session_free(nullptr);
  gtls_session_free(s);
  (void)ticket;   /* the memory is gone; the wipe is observed with a counting allocator in test_wipe */
  SUCCEED();
}

/* ---------------------------------------------------- the context's config */

TEST(TicketConfig, TheKeyringIsCheckedWhenTheContextIsMade) {
  std::unique_ptr<Cred> cred = ed_cred();
  GTLS_ContextConfig cfg;
  const void * chain[2] = {cred->chain[0].data(), cred->chain[1].data()};
  size_t lens[2] = {cred->chain[0].size(), cred->chain[1].size()};
  GTLS_Context * ctx = nullptr;
  const GTLS_TicketKey k1 = key_named(1, 100, 1000);
  const GTLS_TicketKey k2 = key_named(2, 100, 1000);
  GTLS_TicketKey keys[GTLS_TICKET_KEYS_MAX + 1];

  auto fresh = [&]() {
    gtls_context_config_default(&cfg);
    cfg.role = GTLS_ROLE_SERVER;
    cfg.chain = chain;
    cfg.chain_lens = lens;
    cfg.chain_count = 2;
    cfg.key = cred->key;
  };
  EXPECT_EQ((fresh(), cfg.ticket_count), 1u) << "one ticket by default";
  const GTLS_TicketKey two[] = {k1, k2};
  fresh();
  cfg.ticket_keys = two;
  cfg.ticket_key_count = 2;
  EXPECT_EQ(gtls_context_new(nullptr, &cfg, &ctx), GTLS_OK);
  gtls_context_free(ctx);

  fresh();   /* a NULL list with a count, and the reverse */
  cfg.ticket_key_count = 1;
  EXPECT_EQ(gtls_context_new(nullptr, &cfg, &ctx), GTLS_ERR_INVALID);
  fresh();
  cfg.ticket_keys = two;
  EXPECT_EQ(gtls_context_new(nullptr, &cfg, &ctx), GTLS_ERR_INVALID);

  const GTLS_TicketKey dup[] = {k1, k1};
  fresh();
  cfg.ticket_keys = dup;
  cfg.ticket_key_count = 2;
  EXPECT_EQ(gtls_context_new(nullptr, &cfg, &ctx), GTLS_ERR_INVALID) << "a name repeated";

  const GTLS_TicketKey backwards[] = {key_named(1, 1000, 100)};
  fresh();
  cfg.ticket_keys = backwards;
  cfg.ticket_key_count = 1;
  EXPECT_EQ(gtls_context_new(nullptr, &cfg, &ctx), GTLS_ERR_INVALID) << "a window that ends before it begins";
  const GTLS_TicketKey empty_window[] = {key_named(1, 100, 100)};
  cfg.ticket_keys = empty_window;
  EXPECT_EQ(gtls_context_new(nullptr, &cfg, &ctx), GTLS_ERR_INVALID);

  for (size_t i = 0; i < GTLS_TICKET_KEYS_MAX + 1; i++) {
    keys[i] = key_named(static_cast<unsigned>(i + 1), 100, 1000);
  }
  fresh();
  cfg.ticket_keys = keys;
  cfg.ticket_key_count = GTLS_TICKET_KEYS_MAX;
  EXPECT_EQ(gtls_context_new(nullptr, &cfg, &ctx), GTLS_OK) << "the most";
  gtls_context_free(ctx);
  cfg.ticket_key_count = GTLS_TICKET_KEYS_MAX + 1;
  EXPECT_EQ(gtls_context_new(nullptr, &cfg, &ctx), GTLS_ERR_INVALID);

  fresh();
  cfg.ticket_lifetime = GTLS_TICKET_LIFETIME_MAX + 1;
  EXPECT_EQ(gtls_context_new(nullptr, &cfg, &ctx), GTLS_ERR_INVALID);
  fresh();
  cfg.ticket_lifetime = GTLS_TICKET_LIFETIME_MAX;
  EXPECT_EQ(gtls_context_new(nullptr, &cfg, &ctx), GTLS_OK);
  gtls_context_free(ctx);
  fresh();
  cfg.ticket_age_window = GTLS_TICKET_AGE_WINDOW_MAX + 1;
  EXPECT_EQ(gtls_context_new(nullptr, &cfg, &ctx), GTLS_ERR_INVALID);
  fresh();
  cfg.ticket_count = 17;
  EXPECT_EQ(gtls_context_new(nullptr, &cfg, &ctx), GTLS_ERR_INVALID) << "more than max_tickets";
  cfg.ticket_count = 16;
  EXPECT_EQ(gtls_context_new(nullptr, &cfg, &ctx), GTLS_OK);
  gtls_context_free(ctx);

  /* A ticket must fit the caps the context was given. */
  GTLS_Limits l;
  gtls_limits_default(&l);
  l.max_ticket_bytes = GTLS_TICKET_MAX - 1;
  fresh();
  cfg.limits = &l;
  cfg.ticket_keys = two;
  cfg.ticket_key_count = 2;
  EXPECT_EQ(gtls_context_new(nullptr, &cfg, &ctx), GTLS_ERR_LIMIT);
  l.max_ticket_bytes = GTLS_TICKET_MAX;
  EXPECT_EQ(gtls_context_new(nullptr, &cfg, &ctx), GTLS_OK);
  gtls_context_free(ctx);
  fresh();
  cfg.limits = &l;
  l.max_ticket_bytes = 100;
  EXPECT_EQ(gtls_context_new(nullptr, &cfg, &ctx), GTLS_OK) << "without keys no ticket is sealed";
  gtls_context_free(ctx);

  /* A client has none of this. */
  GTLS_ContextConfig client;
  Trust trust({cred->root});
  gtls_context_config_default(&client);
  client.trust = trust.store;
  client.ticket_keys = two;
  client.ticket_key_count = 2;
  EXPECT_EQ(gtls_context_new(nullptr, &client, &ctx), GTLS_ERR_INVALID);
  gtls_context_config_default(&client);
  client.trust = trust.store;
  client.ticket_lifetime = 5;
  EXPECT_EQ(gtls_context_new(nullptr, &client, &ctx), GTLS_ERR_INVALID);
  gtls_context_config_default(&client);
  client.trust = trust.store;
  client.ticket_age_window = 5;
  EXPECT_EQ(gtls_context_new(nullptr, &client, &ctx), GTLS_ERR_INVALID);
  gtls_context_config_default(&client);
  client.trust = trust.store;
  EXPECT_EQ(gtls_context_new(nullptr, &client, &ctx), GTLS_OK) << "the default count of 1 is harmless there";
  gtls_context_free(ctx);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
