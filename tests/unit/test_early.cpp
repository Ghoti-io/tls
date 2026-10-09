/**
 * @file
 *
 * Early data (0-RTT, RFC 8446 sections 2.3 and 4.2.10). First the pieces that
 * have a known answer: RFC 8448's resumed handshake with early data (section 4)
 * fed through the schedule, the record layer and the message codec, every value
 * read from tests/data/rfc8448 as tools/extract-rfc8448.py wrote it from the
 * pinned RFC text. Then the connection, the real client against the real
 * server: delivery once through the early read, every reason the server
 * rejects, the client told and able to resend, the stream split at every byte,
 * and the ways it can go wrong.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "loop.h"
#include "rfc_run.h"

#include <functional>
#include <set>

using namespace gtlstest;

namespace earlykat {

Bytes sha256(const Bytes & in) {
  Bytes out(32);
  EXPECT_EQ(gsec_sha256(in.data(), in.size(), out.data()), GSEC_OK);
  return out;
}

GTLS_Limits limits() {
  GTLS_Limits l;
  gtls_limits_default(&l);
  return l;
}

Bytes seal(GTLS_RecordKeys * k, unsigned type, const Bytes & pt) {
  GTLS_Buf b;
  gtls_buf_init(&b, nullptr, 1 << 16);
  EXPECT_EQ(gtls_record_seal(k, type, pt.data(), pt.size(), 0, &b), GTLS_OK);
  Bytes out(b.data, b.data + b.len);
  gtls_buf_free(&b);
  return out;
}

/** The schedule of RFC 8448's resumed handshake, up to the early traffic secret. */
struct EarlyTrace {
  Vec v{"resumed"};
  GTLS_Schedule s;
  Bytes hello = v["client.send-handshake-record.payload"];
  EarlyTrace() {
    EXPECT_EQ(gtls_schedule_early_psk(&s, GTLS_HASH_SHA256,
                  v["client.extract-secret-early.ikm"].data(), 32),
        GTLS_OK);
  }
  ~EarlyTrace() { gtls_schedule_wipe(&s); }
};

}  // namespace earlykat

using namespace earlykat;

/* ------------------------------------------------------------ the schedule */

TEST(EarlyKat, TheTranscriptHashTheRfcDerivesTheEarlySecretFromIsTheWholeClientHello) {
  EarlyTrace t;
  EXPECT_EQ(sha256(t.hello), t.v["client.derive-secret-tls13-c-e-traffic.hash"]);
  /* ... which has the binders in it: the hello cut before them is another hash. */
  const Bytes prefix = t.v["client.calculate-psk-binder.clienthello-prefix"];
  EXPECT_LT(prefix.size(), t.hello.size());
  EXPECT_NE(sha256(prefix), t.v["client.derive-secret-tls13-c-e-traffic.hash"]);
}

TEST(EarlyKat, TheClientEarlyTrafficSecretIsTheRfcs) {
  EarlyTrace t;
  const Bytes th = sha256(t.hello);

  EXPECT_EQ(t.s.has_e, 0);
  ASSERT_EQ(gtls_schedule_early_traffic(&t.s, th.data()), GTLS_OK);
  EXPECT_EQ(t.s.has_e, 1);
  EXPECT_EQ(Bytes(t.s.c_e, t.s.c_e + 32), t.v["client.derive-secret-tls13-c-e-traffic.expanded"]);
  EXPECT_EQ(Bytes(t.s.early, t.s.early + 32), t.v["client.derive-secret-tls13-c-e-traffic.prk"]);

  /* The same secret from the transcript that is not the ClientHello is another one. */
  GTLS_Schedule other;
  const Bytes prefix_hash = sha256(t.v["client.calculate-psk-binder.clienthello-prefix"]);
  ASSERT_EQ(gtls_schedule_early_psk(&other, GTLS_HASH_SHA256,
                t.v["client.extract-secret-early.ikm"].data(), 32),
      GTLS_OK);
  ASSERT_EQ(gtls_schedule_early_traffic(&other, prefix_hash.data()), GTLS_OK);
  EXPECT_NE(Bytes(other.c_e, other.c_e + 32), Bytes(t.s.c_e, t.s.c_e + 32));
  gtls_schedule_wipe(&other);
}

TEST(EarlyKat, TheEarlySecretIsNotTheHandshakeLabel) {
  /* The label is "c e traffic": the handshake and application ones give other secrets. */
  EarlyTrace t;
  const Bytes th = sha256(t.hello);
  Bytes wrong(32);

  ASSERT_EQ(gtls_schedule_early_traffic(&t.s, th.data()), GTLS_OK);
  for (const char * label : {"c hs traffic", "c ap traffic", "e exp master", "c e traffic "}) {
    ASSERT_EQ(gtls_derive_secret(GTLS_HASH_SHA256, t.s.early, 32, label, th.data(), wrong.data()),
        GTLS_OK);
    EXPECT_NE(wrong, Bytes(t.s.c_e, t.s.c_e + 32)) << label;
  }
  ASSERT_EQ(gtls_derive_secret(GTLS_HASH_SHA256, t.s.early, 32, "e exp master", th.data(), wrong.data()),
      GTLS_OK);
  EXPECT_EQ(wrong, t.v["client.derive-secret-tls13-e-exp-master.expanded"])
      << "the same machinery gives the RFC's other early secret";
}

TEST(EarlyKat, TheEarlyTrafficSecretNeedsAPskStageAndAHash) {
  EarlyTrace t;
  const Bytes th = sha256(t.hello);
  GTLS_Schedule empty;

  std::memset(&empty, 0, sizeof empty);
  EXPECT_EQ(gtls_schedule_early_traffic(&empty, th.data()), GTLS_ERR_INVALID) << "stage 0";
  EXPECT_EQ(gtls_schedule_early_traffic(nullptr, th.data()), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_schedule_early_traffic(&t.s, nullptr), GTLS_ERR_INVALID);
  t.s.stage = 2;
  EXPECT_EQ(gtls_schedule_early_traffic(&t.s, th.data()), GTLS_ERR_INVALID) << "after the handshake secret";
  EXPECT_EQ(t.s.has_e, 0);
}

TEST(EarlyKat, TheEarlySecretSurvivesTheHandshakeStagesAndIsWiped) {
  EarlyTrace t;
  const Bytes th = sha256(t.hello);

  ASSERT_EQ(gtls_schedule_early_traffic(&t.s, th.data()), GTLS_OK);
  const Bytes c_e(t.s.c_e, t.s.c_e + 32);
  ASSERT_EQ(gtls_schedule_handshake(&t.s, t.v["server.extract-secret-handshake.ikm"].data(), 32,
                t.v["server.derive-secret-tls13-c-hs-traffic.hash"].data()),
      GTLS_OK);
  EXPECT_EQ(Bytes(t.s.c_e, t.s.c_e + 32), c_e);
  EXPECT_EQ(Bytes(t.s.c_hs, t.s.c_hs + 32), t.v["server.derive-secret-tls13-c-hs-traffic.expanded"]);
  gtls_schedule_wipe(&t.s);
  EXPECT_EQ(Bytes(t.s.c_e, t.s.c_e + 32), Bytes(32, 0));
  EXPECT_EQ(t.s.has_e, 0);
}

/* --------------------------------------------------------- the early records */

TEST(EarlyKat, TheKeyAndIvOfTheEarlyRecordsAreTheRfcs) {
  EarlyTrace t;
  const Bytes th = sha256(t.hello);
  Bytes key(GTLS_KEY_MAX);
  Bytes iv(GTLS_IV_LEN);

  ASSERT_EQ(gtls_schedule_early_traffic(&t.s, th.data()), GTLS_OK);
  ASSERT_EQ(gtls_traffic_keys(GTLS_SUITE_AES_128_GCM_SHA256, t.s.c_e, key.data(), iv.data()), GTLS_OK);
  key.resize(16);
  EXPECT_EQ(key, t.v["client.derive-write-traffic-keys-for-early-application-data.key-expanded"]);
  EXPECT_EQ(iv, t.v["client.derive-write-traffic-keys-for-early-application-data.iv-expanded"]);
}

TEST(EarlyKat, TheEarlyRecordAndEndOfEarlyDataSealToTheRfcsBytes) {
  EarlyTrace t;
  const Bytes th = sha256(t.hello);
  GTLS_RecordKeys keys;

  ASSERT_EQ(gtls_schedule_early_traffic(&t.s, th.data()), GTLS_OK);
  ASSERT_EQ(gtls_record_keys_from_secret(&keys, GTLS_SUITE_AES_128_GCM_SHA256, t.s.c_e, 0), GTLS_OK);
  /* The first record the client sends under the early key is its application data ... */
  EXPECT_EQ(seal(&keys, GTLS_CT_APPLICATION_DATA, t.v["client.send-application-data-record.payload"]),
      t.v["client.send-application-data-record.complete-record"]);
  /* ... and the second, under the same key, is EndOfEarlyData. */
  EXPECT_EQ(seal(&keys, GTLS_CT_HANDSHAKE, t.v["client.send-handshake-record@2.payload"]),
      t.v["client.send-handshake-record@2.complete-record"]);
  gtls_record_keys_wipe(&keys);

  /* The same two records under a secret of another label do not match. */
  Bytes other(32);
  ASSERT_EQ(gtls_derive_secret(GTLS_HASH_SHA256, t.s.early, 32, "c hs traffic", th.data(), other.data()),
      GTLS_OK);
  ASSERT_EQ(gtls_record_keys_from_secret(&keys, GTLS_SUITE_AES_128_GCM_SHA256, other.data(), 0), GTLS_OK);
  EXPECT_NE(seal(&keys, GTLS_CT_APPLICATION_DATA, t.v["client.send-application-data-record.payload"]),
      t.v["client.send-application-data-record.complete-record"]);
  gtls_record_keys_wipe(&keys);
}

TEST(EarlyKat, TheServerOpensTheRfcsEarlyRecordsWithTheKeysItDerives) {
  EarlyTrace t;
  const Bytes th = sha256(t.hello);
  GTLS_RecordKeys keys;
  Bytes buf(GTLS_RECORD_CIPHER_MAX);
  size_t n = 0;
  unsigned inner = 0;
  const Bytes rec = t.v["client.send-application-data-record.complete-record"];
  const Bytes eoed = t.v["client.send-handshake-record@2.complete-record"];

  ASSERT_EQ(gtls_schedule_early_traffic(&t.s, th.data()), GTLS_OK);
  ASSERT_EQ(gtls_record_keys_from_secret(&keys, GTLS_SUITE_AES_128_GCM_SHA256, t.s.c_e, 0), GTLS_OK);
  ASSERT_EQ(gtls_record_open(&keys, rec.data(), rec.data() + 5, rec.size() - 5, 16384, buf.data(), &n, &inner),
      GTLS_OK);
  EXPECT_EQ(inner, GTLS_CT_APPLICATION_DATA);
  EXPECT_EQ(Bytes(buf.begin(), buf.begin() + static_cast<long>(n)),
      t.v["client.send-application-data-record.payload"]);
  ASSERT_EQ(gtls_record_open(&keys, eoed.data(), eoed.data() + 5, eoed.size() - 5, 16384, buf.data(), &n, &inner),
      GTLS_OK);
  EXPECT_EQ(inner, GTLS_CT_HANDSHAKE);
  EXPECT_EQ(Bytes(buf.begin(), buf.begin() + static_cast<long>(n)),
      t.v["client.construct-an-endofearlydata-handshake-message.endofearlydata"]);
  gtls_record_keys_wipe(&keys);
}

/* ------------------------------------------------------------- the messages */

TEST(EarlyKat, EndOfEarlyDataIsTheRfcsFourBytes) {
  Vec v("resumed");
  GTLS_Buf b;

  gtls_buf_init(&b, nullptr, 64);
  ASSERT_EQ(gtls_msg_build_end_of_early_data(&b), GTLS_OK);
  EXPECT_EQ(Bytes(b.data, b.data + b.len), v["client.construct-an-endofearlydata-handshake-message.endofearlydata"]);
  gtls_buf_free(&b);

  EXPECT_EQ(gtls_msg_parse_end_of_early_data(nullptr, 0), GTLS_OK);
  const unsigned char one = 0;
  EXPECT_EQ(gtls_msg_parse_end_of_early_data(&one, 1), GTLS_ERR_CORRUPT) << "it has no body";
}

TEST(EarlyKat, TheRfcsClientHelloOffersEarlyDataAndOursParsesTheSame) {
  Vec v("resumed");
  const Bytes hello = v["client.send-handshake-record.payload"];
  GTLS_ClientHello h;
  GTLS_Limits l = limits();

  ASSERT_EQ(gtls_msg_parse_client_hello(hello.data() + 4, hello.size() - 4, &l, &h), GTLS_OK);
  const GTLS_Ext * e = gtls_msg_find_ext(h.exts, h.ext_count, GTLS_EXT_EARLY_DATA);
  ASSERT_NE(e, nullptr);
  EXPECT_EQ(gtls_msg_parse_ch_early_data(e), GTLS_OK);
  EXPECT_EQ(e->len, 0u);
}

TEST(EarlyKat, TheRfcsNewSessionTicketCarriesTheAllowanceThatTheBuilderWrites) {
  Vec v("simple-1rtt");
  const Bytes msg = v["server.construct-a-newsessionticket-handshake-message.newsessionticket"];
  GTLS_NewSessionTicket t;
  GTLS_Limits l = limits();
  GTLS_Buf b;

  ASSERT_EQ(gtls_msg_parse_new_session_ticket(msg.data() + 4, msg.size() - 4, &l, &t), GTLS_OK);
  EXPECT_TRUE(t.early_data);
  EXPECT_EQ(t.max_early_data, 0x400u);
  gtls_buf_init(&b, nullptr, 4096);
  ASSERT_EQ(gtls_msg_build_new_session_ticket(&t, &b), GTLS_OK);
  EXPECT_EQ(Bytes(b.data, b.data + b.len), msg);
  gtls_buf_free(&b);
}

TEST(EarlyKat, EncryptedExtensionsAnswersWithAnEmptyEarlyDataAndTheParserSeesIt) {
  GTLS_EeParams p;
  GTLS_Buf b;
  GTLS_EncryptedExtensions ee;
  GTLS_Limits l = limits();

  std::memset(&p, 0, sizeof p);
  gtls_buf_init(&b, nullptr, 256);
  ASSERT_EQ(gtls_msg_build_encrypted_extensions(&p, &b), GTLS_OK);
  const Bytes without(b.data, b.data + b.len);
  gtls_buf_free(&b);
  ASSERT_EQ(gtls_msg_parse_encrypted_extensions(without.data() + 4, without.size() - 4, &l, &ee), GTLS_OK);
  EXPECT_EQ(ee.has_early_data, 0);

  p.early_data = 1;
  gtls_buf_init(&b, nullptr, 256);
  ASSERT_EQ(gtls_msg_build_encrypted_extensions(&p, &b), GTLS_OK);
  const Bytes with(b.data, b.data + b.len);
  gtls_buf_free(&b);
  EXPECT_EQ(with.size(), without.size() + 4u) << "an extension type and a zero length";
  ASSERT_EQ(gtls_msg_parse_encrypted_extensions(with.data() + 4, with.size() - 4, &l, &ee), GTLS_OK);
  EXPECT_EQ(ee.has_early_data, 1);

  /* The extension is empty: anything in it is a decode error. */
  Bytes bad = with;
  bad.push_back(0);
  bad[bad.size() - 2] = 1;   /* the extension's length: 1 */
  bad[3] = static_cast<unsigned char>(bad.size() - 4);
  bad[5] = static_cast<unsigned char>(bad.size() - 6);
  EXPECT_EQ(gtls_msg_parse_encrypted_extensions(bad.data() + 4, bad.size() - 4, &l, &ee), GTLS_ERR_CORRUPT);
}

TEST(EarlyKat, TheClientHelloBuilderOffersEarlyDataOnlyWithAPskAndTheRetryDropsIt) {
  GTLS_HelloParams p;
  GTLS_PskParams psk;
  GTLS_Buf b;
  GTLS_ClientHello h;
  GTLS_Limits l = limits();
  const GTLS_Suite suites[] = {GTLS_SUITE_AES_128_GCM_SHA256};
  const GTLS_Group groups[] = {GTLS_GROUP_X25519};
  const GCERT_SigScheme sigs[] = {GCERT_SIG_ED25519};
  const unsigned char identity[8] = {1, 2, 3, 4, 5, 6, 7, 8};

  std::memset(&p, 0, sizeof p);
  p.suites = suites;
  p.suite_count = 1;
  p.groups = groups;
  p.group_count = 1;
  p.sig_algs = sigs;
  p.sig_alg_count = 1;
  p.share.group = GTLS_GROUP_X25519;
  p.share.pub_len = 32;
  std::memset(&psk, 0, sizeof psk);
  psk.identity = identity;
  psk.identity_len = sizeof identity;
  psk.binder_len = 32;

  p.early_data = 1;
  gtls_buf_init(&b, nullptr, 4096);
  EXPECT_EQ(gtls_msg_build_client_hello(&p, &b), GTLS_ERR_INVALID) << "early data needs a PSK";
  gtls_buf_free(&b);

  p.psk = &psk;
  gtls_buf_init(&b, nullptr, 4096);
  ASSERT_EQ(gtls_msg_build_client_hello(&p, &b), GTLS_OK);
  const Bytes with(b.data, b.data + b.len);
  gtls_buf_free(&b);
  ASSERT_EQ(gtls_msg_parse_client_hello(with.data() + 4, with.size() - 4, &l, &h), GTLS_OK);
  EXPECT_NE(gtls_msg_find_ext(h.exts, h.ext_count, GTLS_EXT_EARLY_DATA), nullptr);
  EXPECT_EQ(h.exts[h.ext_count - 1].type, GTLS_EXT_PRE_SHARED_KEY) << "the PSK is still last";

  p.early_data = 0;
  gtls_buf_init(&b, nullptr, 4096);
  ASSERT_EQ(gtls_msg_build_client_hello(&p, &b), GTLS_OK);
  const Bytes without(b.data, b.data + b.len);
  gtls_buf_free(&b);
  ASSERT_EQ(gtls_msg_parse_client_hello(without.data() + 4, without.size() - 4, &l, &h), GTLS_OK);
  EXPECT_EQ(gtls_msg_find_ext(h.exts, h.ext_count, GTLS_EXT_EARLY_DATA), nullptr);

  /* The second hello offers none (section 4.2.10), whether or not it keeps the PSK. */
  GTLS_KeyShare share;
  std::memset(&share, 0, sizeof share);
  share.group = GTLS_GROUP_X25519;
  share.pub_len = 32;
  const GTLS_PskParams * const keeps[] = {&psk, nullptr};
  for (const GTLS_PskParams * keep : keeps) {
    gtls_buf_init(&b, nullptr, 4096);
    ASSERT_EQ(gtls_msg_retry_client_hello_psk(with.data(), with.size(), &share, nullptr, 0, keep, &l, &b),
        GTLS_OK);
    const Bytes second(b.data, b.data + b.len);
    gtls_buf_free(&b);
    ASSERT_EQ(gtls_msg_parse_client_hello(second.data() + 4, second.size() - 4, &l, &h), GTLS_OK);
    EXPECT_EQ(gtls_msg_find_ext(h.exts, h.ext_count, GTLS_EXT_EARLY_DATA), nullptr)
        << (keep != nullptr ? "with the PSK" : "without it");
  }
}

/* ===================================================== the real connection */

namespace earlyconn {

GTLS_TicketKey ekey(unsigned seed) {
  GTLS_TicketKey k;
  std::memset(&k, 0, sizeof k);
  for (unsigned i = 0; i < GTLS_TICKET_KEY_NAME_LEN; i++) {
    k.name[i] = static_cast<unsigned char>(seed * 16 + i);
  }
  for (unsigned i = 0; i < GTLS_TICKET_KEY_LEN; i++) {
    k.key[i] = static_cast<unsigned char>(seed * 7 + i * 3 + 1);
  }
  k.not_before = kNow - 1000;
  k.not_after = kNow + 1000000;
  return k;
}

/** The replay decision, counted: what it was asked and what it answers. */
struct Replay {
  int calls = 0;
  int verdict = 1;
  std::vector<Bytes> ids;
  std::vector<int64_t> issued;
  std::vector<uint32_t> ages;
  static int fn(void * user, const unsigned char id[32], int64_t issued, uint32_t age) {
    Replay * self = static_cast<Replay *>(user);
    self->calls++;
    self->ids.emplace_back(id, id + 32);
    self->issued.push_back(issued);
    self->ages.push_back(age);
    return self->verdict;
  }
};

/** A Pair whose server allows early data and whose client offers it. */
struct EEnv {
  std::unique_ptr<Cred> cred = ed_cred();
  Replay rp;
  Pair p;
  explicit EEnv(uint32_t allowance = 4096) : p(*cred) {
    p.keys = {ekey(1)};
    p.scfg.max_early_data = allowance;
    p.scfg.anti_replay = &Replay::fn;
    p.scfg.anti_replay_user = &rp;
    p.ccfg.max_early_data = allowance;
  }
};

/** The session a connection was sent. */
struct Held {
  GTLS_Session * s = nullptr;
  ~Held() { gtls_session_free(s); }
  void take(const Pair & p, size_t index = 0) {
    gtls_session_free(s);
    s = nullptr;
    ASSERT_GT(gtls_conn_session_count(p.c.conn), index);
    ASSERT_EQ(gtls_conn_session(p.c.conn, index, &s), GTLS_OK);
  }
};

/** A full handshake, and the session it left. */
void prime(EEnv & e, Held & h, size_t chunk = 0) {
  ASSERT_EQ(e.p.build(), GTLS_OK);
  e.p.run(chunk);
  ASSERT_TRUE(e.p.connected()) << result_name(gtls_conn_failure(e.p.c.conn)) << " / "
                               << result_name(gtls_conn_failure(e.p.s.conn));
  ASSERT_NO_FATAL_FAILURE(h.take(e.p));
}

Bytes read_early(GTLS_Conn * c) {
  Bytes out;
  unsigned char buf[4096];
  for (;;) {
    size_t n = 0;
    EXPECT_EQ(gtls_conn_read_early(c, buf, sizeof buf, &n), GTLS_OK);
    if (n == 0) {
      return out;
    }
    out.insert(out.end(), buf, buf + n);
  }
}

Bytes resend(GTLS_Conn * c) {
  Bytes out;
  unsigned char buf[4096];
  for (;;) {
    size_t n = 0;
    EXPECT_EQ(gtls_conn_early_resend(c, buf, sizeof buf, &n), GTLS_OK);
    if (n == 0) {
      return out;
    }
    out.insert(out.end(), buf, buf + n);
  }
}

GTLS_EarlyStatus status_of(const GTLS_Conn * c) {
  GTLS_EarlyStatus st = GTLS_EARLY_NONE;
  GTLS_Result r = gtls_conn_early_status(c, &st);
  EXPECT_TRUE(r == GTLS_OK || r == GTLS_ERR_EARLY_REJECTED) << result_name(r);
  EXPECT_EQ(r == GTLS_ERR_EARLY_REJECTED, st == GTLS_EARLY_REJECTED);
  return st;
}

/** New connections from the same contexts, offering @p session, and @p data written as early data. */
void again_early(Pair & p, const GTLS_Session * session, const Bytes & data) {
  ASSERT_EQ(p.again(session), GTLS_OK);
  if (!data.empty()) {
    size_t w = 0;
    ASSERT_EQ(gtls_conn_write_early(p.c.conn, data.data(), data.size(), &w), GTLS_OK);
    ASSERT_EQ(w, data.size());
  }
}

/** Build the pair offering @p session and write @p data as early data. */
void start_early(Pair & p, const GTLS_Session * session, const Bytes & data) {
  p.offer = session;
  ASSERT_EQ(p.build(), GTLS_OK);
  if (!data.empty()) {
    size_t w = 0;
    ASSERT_EQ(gtls_conn_write_early(p.c.conn, data.data(), data.size(), &w), GTLS_OK);
    ASSERT_EQ(w, data.size());
  }
}

std::vector<Bytes> records_of(const Bytes & wire) {
  std::vector<Bytes> out;
  size_t at = 0;
  while (at + 5 <= wire.size()) {
    size_t n = 5 + ((static_cast<size_t>(wire[at + 3]) << 8) | wire[at + 4]);
    EXPECT_LE(at + n, wire.size());
    out.emplace_back(wire.begin() + static_cast<long>(at), wire.begin() + static_cast<long>(std::min(at + n, wire.size())));
    at += n;
  }
  return out;
}

/** Every byte of the region is zero. */
bool zeros(const void * p, size_t n) {
  const unsigned char * b = static_cast<const unsigned char *>(p);
  for (size_t i = 0; i < n; i++) {
    if (b[i] != 0) {
      return false;
    }
  }
  return true;
}

const GTLS_Suite kEarlySuites[] = {GTLS_SUITE_AES_128_GCM_SHA256, GTLS_SUITE_AES_256_GCM_SHA384,
    GTLS_SUITE_CHACHA20_POLY1305_SHA256};
const GTLS_Group kEarlyGroups[] = {GTLS_GROUP_X25519, GTLS_GROUP_SECP256R1, GTLS_GROUP_SECP384R1};

}  // namespace earlyconn

using namespace earlyconn;

/* -------------------------------------------------------------- the context */

TEST(EarlyContext, AServerNeedsTheAllowanceAndTheCallbackTogether) {
  std::unique_ptr<Cred> cred = ed_cred();
  Replay rp;
  Pair p(*cred);
  GTLS_Context * ctx = nullptr;

  p.scfg.max_early_data = 100;
  ASSERT_EQ(p.build(), GTLS_ERR_LIMIT) << "an allowance and no replay decision";
  Pair q(*cred);
  q.scfg.anti_replay = &Replay::fn;
  q.scfg.anti_replay_user = &rp;
  ASSERT_EQ(q.build(), GTLS_ERR_LIMIT) << "a replay decision and no allowance";
  Pair r(*cred);
  r.scfg.anti_replay = &Replay::fn;
  r.scfg.max_early_data = 1;
  ASSERT_EQ(r.build(), GTLS_OK) << "both, at the least allowance";
  (void)ctx;
}

TEST(EarlyContext, TheAllowanceIsAtMostTheLimitAndTheLimitIsTheDefault) {
  std::unique_ptr<Cred> cred = ed_cred();
  Replay rp;
  GTLS_Limits l;

  gtls_limits_default(&l);
  EXPECT_EQ(l.max_early_data_bytes, 16384u);
  for (uint32_t over : {0u, 1u}) {
    Pair p(*cred);
    p.slimits.max_early_data_bytes = 1000;
    p.scfg.anti_replay = &Replay::fn;
    p.scfg.anti_replay_user = &rp;
    p.scfg.max_early_data = 1000 + over;
    EXPECT_EQ(p.build(), over == 0 ? GTLS_OK : GTLS_ERR_LIMIT) << over;
  }
  Pair c(*cred);
  c.climits.max_early_data_bytes = 50;
  c.ccfg.max_early_data = 51;
  EXPECT_EQ(c.build(), GTLS_ERR_LIMIT) << "a client's offer is capped the same way";
  Pair d(*cred);
  d.ccfg.max_early_data = 16384;
  EXPECT_EQ(d.build(), GTLS_OK) << "the default limit";
  Pair e(*cred);
  e.ccfg.max_early_data = 16385;
  EXPECT_EQ(e.build(), GTLS_ERR_LIMIT);
}

TEST(EarlyContext, AZeroLimitAllowsNoEarlyDataInEitherRole) {
  std::unique_ptr<Cred> cred = ed_cred();
  Replay rp;
  for (bool zero : {false, true}) {
    Pair p(*cred);
    p.slimits.max_early_data_bytes = zero ? GTLS_LIMIT_ZERO : 0;
    p.scfg.anti_replay = &Replay::fn;
    p.scfg.anti_replay_user = &rp;
    p.scfg.max_early_data = 1;
    EXPECT_EQ(p.build(), zero ? GTLS_ERR_LIMIT : GTLS_OK) << "a server allowing one byte";
    Pair c(*cred);
    c.climits.max_early_data_bytes = zero ? GTLS_LIMIT_ZERO : 0;
    c.ccfg.max_early_data = 1;
    EXPECT_EQ(c.build(), zero ? GTLS_ERR_LIMIT : GTLS_OK) << "a client offering one byte";
    Pair n(*cred);
    n.slimits.max_early_data_bytes = zero ? GTLS_LIMIT_ZERO : 0;
    EXPECT_EQ(n.build(), GTLS_OK) << "and a context that allows none is still fine";
  }
}

TEST(EarlyContext, AClientDoesNotTakeTheReplayDecision) {
  std::unique_ptr<Cred> cred = ed_cred();
  Replay rp;
  Pair p(*cred);

  p.ccfg.anti_replay = &Replay::fn;
  EXPECT_EQ(p.build(), GTLS_ERR_INVALID);
}

TEST(EarlyContext, ByDefaultNothingIsOnAndNoEarlyDataIsOffered) {
  std::unique_ptr<Cred> cred = ed_cred();
  Pair p(*cred);

  p.keys = {ekey(1)};
  ASSERT_EQ(p.build(), GTLS_OK);
  p.run();
  ASSERT_TRUE(p.connected());
  Held h;
  ASSERT_NO_FATAL_FAILURE(h.take(p));
  GTLS_SessionInfo info;
  ASSERT_EQ(gtls_session_info(h.s, &info), GTLS_OK);
  EXPECT_EQ(info.max_early_data, 0u) << "the ticket permits none";
  EXPECT_EQ(status_of(p.c.conn), GTLS_EARLY_NONE);
  size_t w = 7;
  EXPECT_EQ(gtls_conn_write_early(p.c.conn, "x", 1, &w), GTLS_ERR_INVALID);
  EXPECT_EQ(w, 0u);
}

/* ------------------------------------------------------------------ accepted */

TEST(Early, TheTicketCarriesTheAllowanceTheContextSets) {
  EEnv e(1234);
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(e, h));
  GTLS_SessionInfo info;
  ASSERT_EQ(gtls_session_info(h.s, &info), GTLS_OK);
  EXPECT_EQ(info.max_early_data, 1234u);
  EXPECT_EQ(e.rp.calls, 0) << "a full handshake asks nothing";
  EXPECT_EQ(status_of(e.p.c.conn), GTLS_EARLY_NONE);
  EXPECT_EQ(status_of(e.p.s.conn), GTLS_EARLY_NONE);
}

TEST(Early, EveryByteIsDeliveredOnceThroughTheEarlyReadAndNotTheOrdinaryOne) {
  for (GTLS_Suite suite : kEarlySuites) {
    for (GTLS_Group group : kEarlyGroups) {
      for (size_t chunk : {static_cast<size_t>(0), static_cast<size_t>(1), static_cast<size_t>(7)}) {
        EEnv e;
        e.p.scfg.suites = &suite;
        e.p.scfg.suite_count = 1;
        e.p.ccfg.groups = &group;
        e.p.ccfg.group_count = 1;
        Held h;
        ASSERT_NO_FATAL_FAILURE(prime(e, h, chunk));
        const Bytes data = pattern(1000, 9);
        ASSERT_NO_FATAL_FAILURE(again_early(e.p, h.s, data));
        e.p.run(chunk);
        ASSERT_TRUE(e.p.connected()) << result_name(gtls_conn_failure(e.p.c.conn)) << " / "
                                     << result_name(gtls_conn_failure(e.p.s.conn))
                                     << " suite " << suite << " group " << group << " chunk " << chunk;
        EXPECT_EQ(gtls_conn_resumed(e.p.s.conn), 1);
        EXPECT_EQ(status_of(e.p.c.conn), GTLS_EARLY_ACCEPTED);
        EXPECT_EQ(status_of(e.p.s.conn), GTLS_EARLY_ACCEPTED);
        EXPECT_TRUE(e.p.s.got.empty()) << "the ordinary read never returns early data";
        EXPECT_EQ(read_early(e.p.s.conn), data);
        EXPECT_TRUE(read_early(e.p.s.conn).empty()) << "once";
        EXPECT_EQ(e.rp.calls, 1);
        size_t n = 1;
        unsigned char b[8];
        EXPECT_EQ(gtls_conn_early_resend(e.p.c.conn, b, sizeof b, &n), GTLS_ERR_INVALID)
            << "an accepted offer has nothing to give back";
        /* The connection is an ordinary one afterwards, both ways. */
        const Bytes up = pattern(500, 1);
        const Bytes down = pattern(700, 2);
        e.p.send_all(e.p.c, e.p.s, up, chunk);
        e.p.send_all(e.p.s, e.p.c, down, chunk);
        e.p.run(chunk);
        EXPECT_EQ(e.p.s.got, up);
        EXPECT_EQ(e.p.c.got, down);
        EXPECT_EQ(gtls_conn_close(e.p.c.conn), GTLS_OK);
        e.p.run(chunk);
        EXPECT_TRUE(gtls_conn_peer_closed(e.p.s.conn));
      }
    }
  }
}

TEST(Early, TheCallbackIsAskedOnceWithAStableIdentifierOfTheTicket) {
  EEnv e;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(e, h));
  const Bytes data = pattern(10, 5);

  ASSERT_NO_FATAL_FAILURE(again_early(e.p, h.s, data));
  e.p.run();
  ASSERT_TRUE(e.p.connected());
  ASSERT_EQ(e.rp.calls, 1);
  /* The identifier is the SHA-256 of the ticket the client sent. */
  EXPECT_EQ(e.rp.ids[0], sha256(Bytes(h.s->ticket, h.s->ticket + h.s->ticket_len)));
  EXPECT_EQ(e.rp.issued[0], kNow) << "the second the ticket was sealed";
  EXPECT_EQ(e.rp.ages[0], 0u) << "presented in the second it was received";

  /* The same ticket again gives the same identifier; another ticket another one. */
  ASSERT_NO_FATAL_FAILURE(again_early(e.p, h.s, data));
  e.p.run();
  ASSERT_EQ(e.rp.calls, 2);
  EXPECT_EQ(e.rp.ids[1], e.rp.ids[0]) << "a replay is recognisable";
  Held second;
  ASSERT_NO_FATAL_FAILURE(second.take(e.p));
  ASSERT_NO_FATAL_FAILURE(again_early(e.p, second.s, data));
  e.p.run();
  ASSERT_EQ(e.rp.calls, 3);
  EXPECT_NE(e.rp.ids[2], e.rp.ids[0]);

  /* The age is what the client reports: time passed on both clocks. */
  e.p.now = kNow + 5;
  ASSERT_NO_FATAL_FAILURE(again_early(e.p, h.s, data));
  e.p.run();
  ASSERT_EQ(e.rp.calls, 4);
  EXPECT_GE(e.rp.ages[3], 4500u);
  EXPECT_LE(e.rp.ages[3], 5500u);
}

TEST(Early, MoreThanOneRecordOfEarlyDataArrivesWhole) {
  EEnv e(60000);
  e.p.slimits.max_early_data_bytes = 60000;
  e.p.climits.max_early_data_bytes = 60000;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(e, h));
  const Bytes data = pattern(50000, 3);

  ASSERT_NO_FATAL_FAILURE(again_early(e.p, h.s, data));
  e.p.run(1);
  ASSERT_TRUE(e.p.connected());
  EXPECT_EQ(read_early(e.p.s.conn), data);
}

TEST(Early, EarlyDataInSeveralWritesAndNoneAtAllBothComplete) {
  EEnv e;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(e, h));

  ASSERT_EQ(e.p.again(h.s), GTLS_OK);
  Bytes all;
  for (int i = 0; i < 5; i++) {
    const Bytes part = pattern(100 + static_cast<size_t>(i), static_cast<unsigned>(i));
    size_t w = 0;
    ASSERT_EQ(gtls_conn_write_early(e.p.c.conn, part.data(), part.size(), &w), GTLS_OK);
    ASSERT_EQ(w, part.size());
    all.insert(all.end(), part.begin(), part.end());
  }
  size_t w = 9;
  ASSERT_EQ(gtls_conn_write_early(e.p.c.conn, "", 0, &w), GTLS_OK);
  EXPECT_EQ(w, 0u);
  e.p.run();
  ASSERT_TRUE(e.p.connected());
  EXPECT_EQ(read_early(e.p.s.conn), all);

  /* Offered, and nothing written: still accepted, and EndOfEarlyData is sent. */
  ASSERT_EQ(e.p.again(h.s), GTLS_OK);
  e.p.run();
  ASSERT_TRUE(e.p.connected());
  EXPECT_EQ(status_of(e.p.c.conn), GTLS_EARLY_ACCEPTED);
  EXPECT_EQ(status_of(e.p.s.conn), GTLS_EARLY_ACCEPTED);
  EXPECT_TRUE(read_early(e.p.s.conn).empty());
}

TEST(Early, WithTheDummyChangeCipherSpecTooAndAfterAHelloRetryRequestNotAtAll) {
  EEnv e;
  e.p.ccfg.middlebox_compat = 1;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(e, h));
  const Bytes data = pattern(300, 4);

  for (size_t chunk : {static_cast<size_t>(0), static_cast<size_t>(1)}) {
    ASSERT_NO_FATAL_FAILURE(again_early(e.p, h.s, data));
    e.p.run(chunk);
    ASSERT_TRUE(e.p.connected()) << chunk;
    EXPECT_EQ(read_early(e.p.s.conn), data);
    EXPECT_EQ(status_of(e.p.c.conn), GTLS_EARLY_ACCEPTED);
  }
}

/* ----------------------------------------------------------------- rejected */

namespace {

/**
 * A second pair that shares the first's ticket key and offers its session with
 * early data, after @p tweak has changed it. Reports whether the handshake
 * completed, and leaves the pair for the test to look at.
 */
struct Refused {
  EEnv e;
  Bytes data = pattern(200, 6);
  explicit Refused(const GTLS_Session * session, const std::function<void(EEnv &)> & tweak,
      size_t chunk = 0) {
    if (tweak) {
      tweak(e);
    }
    start_early(e.p, session, data);
    e.p.run(chunk);
  }
};

/** What every rejection must look like from the outside. */
void expect_rejected(Refused & r, int callback_calls, bool resumed) {
  ASSERT_TRUE(r.e.p.connected()) << result_name(gtls_conn_failure(r.e.p.c.conn)) << " / "
                                 << result_name(gtls_conn_failure(r.e.p.s.conn));
  EXPECT_EQ(r.e.rp.calls, callback_calls);
  EXPECT_EQ(gtls_conn_resumed(r.e.p.s.conn), resumed ? 1 : 0);
  EXPECT_EQ(status_of(r.e.p.c.conn), GTLS_EARLY_REJECTED);
  EXPECT_EQ(status_of(r.e.p.s.conn), GTLS_EARLY_REJECTED);
  GTLS_EarlyStatus st = GTLS_EARLY_NONE;
  EXPECT_EQ(gtls_conn_early_status(r.e.p.c.conn, &st), GTLS_ERR_EARLY_REJECTED)
      << "the client is told, by the result as well as by the status";
  EXPECT_EQ(resend(r.e.p.c.conn), r.data) << "and can have its bytes back";
  EXPECT_TRUE(resend(r.e.p.c.conn).empty()) << "once";
  EXPECT_TRUE(read_early(r.e.p.s.conn).empty()) << "nothing was delivered";
  /* Resent as ordinary data, they arrive: the connection is a good one. */
  const Bytes again = r.data;
  r.e.p.send_all(r.e.p.c, r.e.p.s, again);
  r.e.p.run();
  EXPECT_EQ(r.e.p.s.got, again);
}

}  // namespace

TEST(EarlyRejected, TheCallbackSaysNoOrAnythingButYes) {
  EEnv a;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));

  for (int verdict : {0, 2, -1, 1000}) {
    Refused r(h.s, [&](EEnv & e) { e.rp.verdict = verdict; });
    SCOPED_TRACE(verdict);
    expect_rejected(r, 1, true);
  }
}

TEST(EarlyRejected, TheAlpnProtocolIsNotTheTicketsEvenWhenTheTicketResumes) {
  /* The ticket is for h2. The server now chooses http/1.1 from the same offer. */
  {
    EEnv a;
    a.p.calpn = {"h2", "http/1.1"};
    a.p.salpn = {"h2", "http/1.1"};
    Held h;
    ASSERT_NO_FATAL_FAILURE(prime(a, h));
    ASSERT_EQ(h.s->alpn_len, 2u);

    Refused r(h.s, [](EEnv & e) {
      e.p.calpn = {"h2", "http/1.1"};
      e.p.salpn = {"http/1.1"};
    });
    expect_rejected(r, 0, true);

    Refused same(h.s, [](EEnv & e) {
      e.p.calpn = {"h2", "http/1.1"};
      e.p.salpn = {"h2", "http/1.1"};
    });
    ASSERT_TRUE(same.e.p.connected());
    EXPECT_EQ(status_of(same.e.p.s.conn), GTLS_EARLY_ACCEPTED) << "the control: the same protocol";
    EXPECT_EQ(same.e.rp.calls, 1);
  }
  /* The ticket is for no protocol. The server now chooses one. */
  {
    EEnv a;
    Held h;
    ASSERT_NO_FATAL_FAILURE(prime(a, h));
    ASSERT_EQ(h.s->alpn_len, 0u);
    Refused r(h.s, [](EEnv & e) {
      e.p.calpn = {"h2"};
      e.p.salpn = {"h2"};
    });
    expect_rejected(r, 0, true);
  }
}

TEST(EarlyRejected, ATicketTheServerPassesOverGivesAFullHandshakeAndNoEarlyData) {
  EEnv a;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  {
    Refused r(h.s, [](EEnv & e) { e.p.keys = {ekey(2)}; });
    SCOPED_TRACE("another key");
    expect_rejected(r, 0, false);
  }
  {
    Refused r(h.s, [](EEnv & e) {
      e.p.now = kNow + 100;
      e.p.offer_time = kNow;
    });
    SCOPED_TRACE("an age outside the window");
    expect_rejected(r, 0, false);
  }
  {
    Refused r(h.s, [](EEnv & e) { e.p.keys.clear(); });
    SCOPED_TRACE("no keyring");
    expect_rejected(r, 0, false);
  }
}

TEST(EarlyRejected, ASuiteTheServerNoLongerHasIsNotResumedEither) {
  EEnv a;
  static const GTLS_Suite chacha = GTLS_SUITE_CHACHA20_POLY1305_SHA256;
  static const GTLS_Suite aes = GTLS_SUITE_AES_128_GCM_SHA256;
  a.p.scfg.suites = &chacha;
  a.p.scfg.suite_count = 1;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  Refused r(h.s, [](EEnv & e) {
    e.p.scfg.suites = &aes;
    e.p.scfg.suite_count = 1;
  });
  expect_rejected(r, 0, false);
}

TEST(EarlyRejected, AHelloRetryRequestEndsTheOfferAndTheClientIsToldAtOnce) {
  EEnv a;
  static const GTLS_Group p256[] = {GTLS_GROUP_SECP256R1};
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));

  for (size_t chunk : {static_cast<size_t>(0), static_cast<size_t>(1)}) {
    Refused r(h.s, [](EEnv & e) {
      e.p.scfg.groups = p256;
      e.p.scfg.group_count = 1;
    }, chunk);
    SCOPED_TRACE(chunk);
    EXPECT_EQ(gtls_conn_retried(r.e.p.c.conn), 1);
    expect_rejected(r, 0, true);
  }
}

TEST(EarlyRejected, AServerThatHasTurnedEarlyDataOffSkipsItAndResumes) {
  EEnv a;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  Refused r(h.s, [](EEnv & e) {
    e.p.scfg.max_early_data = 0;
    e.p.scfg.anti_replay = nullptr;
  });
  expect_rejected(r, 0, true);
}

TEST(EarlyRejected, ATicketThatPermitsNoneAndAClientThatOffersNoneSendNothing) {
  /* A ticket without an allowance: the client does not offer, though its context would. */
  {
    EEnv a;
    a.p.scfg.max_early_data = 0;
    a.p.scfg.anti_replay = nullptr;
    Held h;
    ASSERT_NO_FATAL_FAILURE(prime(a, h));
    GTLS_SessionInfo info;
    ASSERT_EQ(gtls_session_info(h.s, &info), GTLS_OK);
    EXPECT_EQ(info.max_early_data, 0u);

    EEnv b;
    b.p.offer = h.s;
    ASSERT_EQ(b.p.build(), GTLS_OK);
    size_t w = 0;
    EXPECT_EQ(gtls_conn_write_early(b.p.c.conn, "x", 1, &w), GTLS_ERR_INVALID);
    b.p.run();
    ASSERT_TRUE(b.p.connected());
    EXPECT_EQ(gtls_conn_resumed(b.p.s.conn), 1);
    EXPECT_EQ(status_of(b.p.c.conn), GTLS_EARLY_NONE);
    EXPECT_EQ(status_of(b.p.s.conn), GTLS_EARLY_NONE);
    EXPECT_EQ(b.rp.calls, 0);
  }
  /* A permitting ticket and a client context that does not take part. */
  {
    EEnv a;
    Held h;
    ASSERT_NO_FATAL_FAILURE(prime(a, h));
    EEnv b;
    b.p.ccfg.max_early_data = 0;
    b.p.offer = h.s;
    ASSERT_EQ(b.p.build(), GTLS_OK);
    size_t w = 0;
    EXPECT_EQ(gtls_conn_write_early(b.p.c.conn, "x", 1, &w), GTLS_ERR_INVALID);
    b.p.run();
    ASSERT_TRUE(b.p.connected());
    EXPECT_EQ(status_of(b.p.c.conn), GTLS_EARLY_NONE);
    EXPECT_EQ(status_of(b.p.s.conn), GTLS_EARLY_NONE) << "the hello did not carry early_data";
    EXPECT_EQ(b.rp.calls, 0);
    EXPECT_EQ(gtls_conn_resumed(b.p.s.conn), 1);
  }
}

/* --------------------------------------------------------------- the client */

TEST(EarlyClient, NoSessionNoEarlyData) {
  EEnv e;
  ASSERT_EQ(e.p.build(), GTLS_OK);
  size_t w = 5;
  EXPECT_EQ(gtls_conn_write_early(e.p.c.conn, "x", 1, &w), GTLS_ERR_INVALID);
  EXPECT_EQ(w, 0u);
  EXPECT_EQ(gtls_conn_write_early(e.p.s.conn, "x", 1, &w), GTLS_ERR_INVALID) << "a server writes none";
  unsigned char b[4];
  size_t got = 5;
  EXPECT_EQ(gtls_conn_read_early(e.p.c.conn, b, sizeof b, &got), GTLS_ERR_INVALID) << "a client reads none";
  EXPECT_EQ(got, 0u);
  EXPECT_EQ(gtls_conn_early_resend(e.p.s.conn, b, sizeof b, &got), GTLS_ERR_INVALID) << "a server has nothing to give back";
  EXPECT_EQ(gtls_conn_early_resend(e.p.c.conn, b, sizeof b, &got), GTLS_ERR_INVALID) << "nor a client whose offer was not refused";
  e.p.run();
  ASSERT_TRUE(e.p.connected());
  EXPECT_EQ(status_of(e.p.c.conn), GTLS_EARLY_NONE);
  EXPECT_EQ(gtls_conn_write_early(e.p.c.conn, "x", 1, &w), GTLS_ERR_INVALID);
}

TEST(EarlyClient, TheAllowanceIsTheSmallerOfTheSessionsAndTheContextsAndOverIsRefusedWhole) {
  EEnv a(100);
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  for (int which = 0; which < 2; which++) {
    EEnv e(which == 0 ? 100 : 5000);
    e.p.ccfg.max_early_data = which == 0 ? 50 : 5000;   /* the context's is lower, then the session's is */
    e.p.offer = h.s;
    ASSERT_EQ(e.p.build(), GTLS_OK);
    const size_t cap = which == 0 ? 50u : 100u;
    size_t w = 0;
    Bytes over(cap + 1, 'x');
    EXPECT_EQ(gtls_conn_write_early(e.p.c.conn, over.data(), over.size(), &w), GTLS_ERR_LIMIT) << which;
    EXPECT_EQ(w, 0u) << "nothing was taken";
    EXPECT_FALSE(gtls_conn_is_failed(e.p.c.conn)) << "and the connection is not failed";
    Bytes exact(cap - 1, 'y');
    ASSERT_EQ(gtls_conn_write_early(e.p.c.conn, exact.data(), exact.size(), &w), GTLS_OK);
    EXPECT_EQ(w, exact.size());
    EXPECT_EQ(gtls_conn_write_early(e.p.c.conn, "zz", 2, &w), GTLS_ERR_LIMIT) << "the total counts";
    EXPECT_EQ(gtls_conn_write_early(e.p.c.conn, "z", 1, &w), GTLS_OK);
    EXPECT_EQ(w, 1u);
    EXPECT_EQ(gtls_conn_write_early(e.p.c.conn, "z", 1, &w), GTLS_ERR_LIMIT);
    e.p.run();
    ASSERT_TRUE(e.p.connected());
    EXPECT_EQ(read_early(e.p.s.conn).size(), cap);
  }
}

TEST(EarlyClient, NoEarlyDataOnceTheServerHasBegunToAnswer) {
  EEnv a;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  ASSERT_NO_FATAL_FAILURE(again_early(a.p, h.s, pattern(10, 1)));
  a.p.carry(a.p.c, a.p.s, 0);
  a.p.carry(a.p.s, a.p.c, 0);
  size_t w = 0;
  EXPECT_EQ(gtls_conn_write_early(a.p.c.conn, "x", 1, &w), GTLS_ERR_INVALID);
  a.p.run();
  ASSERT_TRUE(a.p.connected());
  EXPECT_EQ(gtls_conn_write_early(a.p.c.conn, "x", 1, &w), GTLS_ERR_INVALID);
  EXPECT_EQ(read_early(a.p.s.conn).size(), 10u);
}

TEST(EarlyClient, TheMessageInterfaceHasNoEarlyWrite) {
  std::unique_ptr<Cred> cred = ed_cred();
  Replay rp;
  MessagePair m(*cred);
  Held h;
  {
    EEnv a;
    ASSERT_NO_FATAL_FAILURE(prime(a, h));
  }
  m.keys = {ekey(1)};
  m.scfg.max_early_data = 100;
  m.scfg.anti_replay = &Replay::fn;
  m.scfg.anti_replay_user = &rp;
  m.ccfg.max_early_data = 100;
  m.offer = h.s;
  ASSERT_EQ(m.build(), GTLS_OK);
  m.run();
  ASSERT_TRUE(m.connected());
  size_t w = 0;
  EXPECT_EQ(gtls_conn_write_early(m.c.conn, "x", 1, &w), GTLS_ERR_INVALID) << "a connection carried by messages";
  EXPECT_EQ(status_of(m.c.conn), GTLS_EARLY_ACCEPTED) << "the offer is the same; only the carrying differs";
  EXPECT_EQ(status_of(m.s.conn), GTLS_EARLY_ACCEPTED);
  EXPECT_EQ(rp.calls, 1);
}

/* ------------------------------------------------------------------ limits */

namespace {

/** The client's first flight, in records, and a server fed none of it yet. */
struct Staged {
  EEnv e;
  std::vector<Bytes> recs;
  explicit Staged(const GTLS_Session * session, const Bytes & data, uint32_t allowance = 4096,
      const std::function<void(EEnv &)> & tweak = nullptr)
      : e(allowance) {
    if (tweak) {
      tweak(e);
    }
    start_early(e.p, session, data);
    const Bytes out = stream_out(e.p.c.conn);
    recs = records_of(out);
    EXPECT_EQ(gtls_conn_stream_consume(e.p.c.conn, out.size()), GTLS_OK);
  }
  GTLS_Result feed(const Bytes & b) {
    size_t used = 0;
    return gtls_conn_stream_feed(e.p.s.conn, b.data(), b.size(), e.p.now, &used);
  }
  const GTLS_Conn * server() const { return e.p.s.conn; }
};

}  // namespace

TEST(EarlyLimits, TheServerFailsOnOneByteMoreThanTheTicketAllowsAndAcceptsTheAllowance) {
  EEnv a(100);
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  for (size_t total : {static_cast<size_t>(99), static_cast<size_t>(100), static_cast<size_t>(101)}) {
    for (bool one_write : {true, false}) {
      EEnv e(100);
      e.p.offer = h.s;
      ASSERT_EQ(e.p.build(), GTLS_OK);
      e.p.c.conn->early_max = 1000;   /* a client that does not keep to it */
      e.p.c.conn->early_sent.max = 1000;
      const Bytes data = pattern(total, 2);
      size_t w = 0;
      if (one_write) {
        ASSERT_EQ(gtls_conn_write_early(e.p.c.conn, data.data(), data.size(), &w), GTLS_OK);
      } else {
        ASSERT_EQ(gtls_conn_write_early(e.p.c.conn, data.data(), total - 1, &w), GTLS_OK);
        ASSERT_EQ(gtls_conn_write_early(e.p.c.conn, data.data() + total - 1, 1, &w), GTLS_OK);
      }
      e.p.run();
      SCOPED_TRACE(total);
      if (total <= 100) {
        ASSERT_TRUE(e.p.connected());
        EXPECT_EQ(read_early(e.p.s.conn), data);
      } else {
        EXPECT_TRUE(gtls_conn_is_failed(e.p.s.conn));
        EXPECT_EQ(gtls_conn_failure(e.p.s.conn), GTLS_ERR_LIMIT);
        EXPECT_EQ(gtls_conn_alert(e.p.s.conn), GTLS_ALERT_UNEXPECTED_MESSAGE);
        EXPECT_TRUE(gtls_conn_secrets_are_wiped(e.p.s.conn));
        size_t n = 1;
        unsigned char b[4];
        EXPECT_EQ(gtls_conn_read_early(e.p.s.conn, b, sizeof b, &n), GTLS_ERR_FAILED);
        EXPECT_EQ(e.p.s.conn->early_in.len, 0u) << "what was kept is dropped";
      }
    }
  }
}

TEST(EarlyLimits, TheServerTakesTheSmallerOfTheTicketsAllowanceAndItsOwnNow) {
  EEnv a(100);
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  /* The ticket says 100. The server now allows 60: it takes 60, and not 61. */
  for (size_t total : {static_cast<size_t>(60), static_cast<size_t>(61)}) {
    EEnv e(60);
    e.p.offer = h.s;
    ASSERT_EQ(e.p.build(), GTLS_OK);
    e.p.c.conn->early_max = 100;
    e.p.c.conn->early_sent.max = 100;
    const Bytes data = pattern(total, 2);
    size_t w = 0;
    ASSERT_EQ(gtls_conn_write_early(e.p.c.conn, data.data(), data.size(), &w), GTLS_OK);
    e.p.run();
    if (total == 60) {
      ASSERT_TRUE(e.p.connected());
    } else {
      EXPECT_EQ(gtls_conn_failure(e.p.s.conn), GTLS_ERR_LIMIT);
    }
  }
}

TEST(EarlyLimits, EmptyRecordsCostOneEachSoTheyEndToo) {
  EEnv a(4);
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  for (int empties : {3, 4}) {
    Staged st(h.s, Bytes(1, 'a'), 4, nullptr);
    ASSERT_EQ(st.recs.size(), 2u);
    ASSERT_EQ(st.feed(st.recs[0]), GTLS_OK);
    ASSERT_EQ(st.feed(st.recs[1]), GTLS_OK) << "one byte of four";
    GTLS_RecordKeys k = st.e.p.c.conn->sec.wr;
    GTLS_Result last = GTLS_OK;
    for (int i = 0; i < empties; i++) {
      GTLS_Buf b;
      gtls_buf_init(&b, nullptr, 256);
      ASSERT_EQ(gtls_record_seal(&k, GTLS_CT_APPLICATION_DATA, "", 0, 0, &b), GTLS_OK);
      last = st.feed(Bytes(b.data, b.data + b.len));
      gtls_buf_free(&b);
      if (last != GTLS_OK) {
        break;
      }
    }
    if (empties == 3) {
      EXPECT_EQ(last, GTLS_OK) << "three empties and one byte are four";
    } else {
      EXPECT_EQ(last, GTLS_ERR_LIMIT) << "the fourth empty is the fifth";
      EXPECT_EQ(gtls_conn_alert(st.server()), GTLS_ALERT_UNEXPECTED_MESSAGE);
    }
  }
}

/* ------------------------------------------------- EndOfEarlyData and records */

namespace {

/** A server that has accepted early data and the two records the client sends at the end of it. */
struct Ended {
  EEnv e;
  std::vector<Bytes> first;   /* the ClientHello and the early records */
  std::vector<Bytes> fin;     /* EndOfEarlyData, then the Finished */
  Bytes early_secret;         /* the client's, taken before it wipes it */
  explicit Ended(const GTLS_Session * session, const std::function<void(EEnv &)> & tweak = nullptr) {
    if (tweak) {
      tweak(e);
    }
    start_early(e.p, session, pattern(40, 8));
    early_secret.assign(e.p.c.conn->sec.schedule.c_e, e.p.c.conn->sec.schedule.c_e + e.p.c.conn->sec.schedule.hlen);
    const Bytes out = stream_out(e.p.c.conn);
    first = records_of(out);
    EXPECT_EQ(gtls_conn_stream_consume(e.p.c.conn, out.size()), GTLS_OK);
    for (const Bytes & r : first) {
      size_t used = 0;
      EXPECT_EQ(gtls_conn_stream_feed(e.p.s.conn, r.data(), r.size(), e.p.now, &used), GTLS_OK);
    }
    e.p.carry(e.p.s, e.p.c, 0);
    fin = records_of(stream_out(e.p.c.conn));
  }
  GTLS_Result feed(const Bytes & b) {
    size_t used = 0;
    return gtls_conn_stream_feed(e.p.s.conn, b.data(), b.size(), e.p.now, &used);
  }
};

void expect_failed_with(const GTLS_Conn * c, GTLS_Result result, unsigned alert) {
  EXPECT_TRUE(gtls_conn_is_failed(c));
  EXPECT_EQ(gtls_conn_failure(c), result);
  EXPECT_EQ(gtls_conn_alert(c), alert);
  EXPECT_TRUE(gtls_conn_secrets_are_wiped(c));
}

}  // namespace

TEST(EarlyEnd, TheClientsLastTwoRecordsAreEndOfEarlyDataAndTheFinished) {
  EEnv a;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  Ended n(h.s);
  ASSERT_EQ(n.first.size(), 2u);
  ASSERT_EQ(n.fin.size(), 2u);
  EXPECT_EQ(gtls_conn_state(n.e.p.s.conn), GTLS_STATE_S_WAIT_EOED);
  ASSERT_EQ(n.feed(n.fin[0]), GTLS_OK);
  EXPECT_EQ(gtls_conn_state(n.e.p.s.conn), GTLS_STATE_S_WAIT_FIN);
  ASSERT_EQ(n.feed(n.fin[1]), GTLS_OK);
  EXPECT_EQ(gtls_conn_state(n.e.p.s.conn), GTLS_STATE_CONNECTED);
  EXPECT_EQ(read_early(n.e.p.s.conn), pattern(40, 8));
}

TEST(EarlyEnd, WithoutEndOfEarlyDataTheServerFailsUnexpectedMessage) {
  EEnv a;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  Ended n(h.s);
  ASSERT_EQ(n.fin.size(), 2u);
  EXPECT_EQ(n.feed(n.fin[1]), GTLS_ERR_PROTOCOL) << "the Finished, straight after the early data";
  expect_failed_with(n.e.p.s.conn, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNEXPECTED_MESSAGE);
}

TEST(EarlyEnd, ARecordUnderNeitherKeyIsABadMacAndNotAnUnexpectedMessage) {
  EEnv a;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  Ended n(h.s);
  Bytes junk = n.fin[1];
  junk[junk.size() - 1] ^= 1;   /* the Finished with a bit changed opens under neither */
  EXPECT_EQ(n.feed(junk), GTLS_ERR_MISMATCH);
  expect_failed_with(n.e.p.s.conn, GTLS_ERR_MISMATCH, GTLS_ALERT_BAD_RECORD_MAC);
}

TEST(EarlyEnd, ATamperedEndOfEarlyDataIsABadMac) {
  EEnv a;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  for (size_t at = 0; at < 22; at += 3) {
    Ended n(h.s);
    Bytes bad = n.fin[0];
    bad[bad.size() - 1 - at] ^= 0x01;
    EXPECT_EQ(n.feed(bad), GTLS_ERR_MISMATCH) << at;
    expect_failed_with(n.e.p.s.conn, GTLS_ERR_MISMATCH, GTLS_ALERT_BAD_RECORD_MAC);
  }
}

TEST(EarlyEnd, AnEarlyRecordAfterEndOfEarlyDataIsRefused) {
  EEnv a;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  Ended n(h.s);
  ASSERT_EQ(n.feed(n.fin[0]), GTLS_OK);
  /* The next record under the early key: the client's own, as if it kept using it. */
  GTLS_RecordKeys k;
  ASSERT_EQ(gtls_record_keys_from_secret(&k, GTLS_SUITE_AES_128_GCM_SHA256, n.early_secret.data(), 0),
      GTLS_OK);
  k.seq = 2;   /* the data was record 0, EndOfEarlyData record 1 */
  GTLS_Buf b;
  gtls_buf_init(&b, nullptr, 256);
  ASSERT_EQ(gtls_record_seal(&k, GTLS_CT_APPLICATION_DATA, "late", 4, 0, &b), GTLS_OK);
  EXPECT_EQ(n.feed(Bytes(b.data, b.data + b.len)), GTLS_ERR_MISMATCH);
  gtls_buf_free(&b);
  expect_failed_with(n.e.p.s.conn, GTLS_ERR_MISMATCH, GTLS_ALERT_BAD_RECORD_MAC);
  {
    unsigned char buf[8];
    size_t got = 1;
    EXPECT_EQ(gtls_conn_read_early(n.e.p.s.conn, buf, sizeof buf, &got), GTLS_ERR_FAILED)
        << "and what it held is not given out";
    EXPECT_EQ(got, 0u);
  }
}

TEST(EarlyEnd, EndOfEarlyDataTwiceIsRefused) {
  EEnv a;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  Ended n(h.s);
  ASSERT_EQ(n.feed(n.fin[0]), GTLS_OK);
  EXPECT_EQ(n.feed(n.fin[0]), GTLS_ERR_MISMATCH) << "the same bytes again: not under the key in force";
  expect_failed_with(n.e.p.s.conn, GTLS_ERR_MISMATCH, GTLS_ALERT_BAD_RECORD_MAC);
}

TEST(EarlyEnd, TheAlertOfAServerWaitingForEarlyDataIsSealedUnderTheKeyTheClientReads) {
  EEnv a;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  Ended n(h.s);
  /* The client has read the flight and is connected as far as it can be; the server
   * waits, and gets a record that opens under no key. */
  ASSERT_EQ(gtls_conn_state(n.e.p.s.conn), GTLS_STATE_S_WAIT_EOED);
  Bytes junk = n.fin[0];
  junk[junk.size() - 1] ^= 1;
  ASSERT_EQ(n.feed(junk), GTLS_ERR_MISMATCH);
  Bytes alert = stream_out(n.e.p.s.conn);
  ASSERT_FALSE(alert.empty());
  size_t used = 0;
  EXPECT_EQ(gtls_conn_stream_feed(n.e.p.c.conn, alert.data(), alert.size(), n.e.p.now, &used), GTLS_ERR_ALERT)
      << "the client could open it, and it is the server's bad_record_mac";
  EXPECT_EQ(gtls_conn_peer_alert(n.e.p.c.conn), GTLS_ALERT_BAD_RECORD_MAC);
}

TEST(EarlyEnd, EndOfEarlyDataToAServerThatDidNotAcceptIsUnexpected) {
  EEnv a;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  Ended n(h.s, [](EEnv & e) { e.rp.verdict = 0; });
  /* The client reports the rejection and sends only a Finished. */
  ASSERT_EQ(n.fin.size(), 1u);
  EXPECT_EQ(gtls_conn_state(n.e.p.s.conn), GTLS_STATE_S_WAIT_FIN);
  /* An EndOfEarlyData, sealed as the client would under its handshake key. */
  GTLS_RecordKeys k;
  ASSERT_EQ(gtls_record_keys_from_secret(&k, GTLS_SUITE_AES_128_GCM_SHA256,
                n.e.p.c.conn->sec.schedule.c_hs, 0),
      GTLS_OK);
  GTLS_Buf b;
  gtls_buf_init(&b, nullptr, 256);
  const unsigned char eoed[4] = {5, 0, 0, 0};
  ASSERT_EQ(gtls_record_seal(&k, GTLS_CT_HANDSHAKE, eoed, 4, 0, &b), GTLS_OK);
  EXPECT_EQ(n.feed(Bytes(b.data, b.data + b.len)), GTLS_ERR_PROTOCOL);
  gtls_buf_free(&b);
  expect_failed_with(n.e.p.s.conn, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNEXPECTED_MESSAGE);
}

TEST(EarlyEnd, AnEarlyRecordThatDoesNotOpenIsABadMacOnAnAcceptingServer) {
  EEnv a;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  Staged st(h.s, pattern(20, 1));
  ASSERT_EQ(st.recs.size(), 2u);
  ASSERT_EQ(st.feed(st.recs[0]), GTLS_OK);
  Bytes bad = st.recs[1];
  bad[7] ^= 1;
  EXPECT_EQ(st.feed(bad), GTLS_ERR_MISMATCH) << "it was accepted, so a record that does not open is not skipped";
  expect_failed_with(st.e.p.s.conn, GTLS_ERR_MISMATCH, GTLS_ALERT_BAD_RECORD_MAC);
}

namespace {

/** The two ends through the message interface, up to the point where the client's last messages are out. */
struct MsgEnded {
  std::unique_ptr<Cred> cred = ed_cred();
  Replay rp;
  MessagePair m;
  Bytes eoed, fin;
  Bytes client_secret;   /* the client's early secret, taken before it wipes it */
  MsgEnded(const GTLS_Session * session, int verdict = 1) : m(*cred) {
    rp.verdict = verdict;
    m.keys = {ekey(1)};
    m.scfg.max_early_data = 100;
    m.scfg.anti_replay = &Replay::fn;
    m.scfg.anti_replay_user = &rp;
    m.ccfg.max_early_data = 100;
    m.offer = session;
    EXPECT_EQ(m.build(), GTLS_OK);
    {
      Bytes sec(GTLS_HASH_MAX);
      size_t n = 0;
      if (gtls_conn_secret(m.c.conn, GTLS_EPOCH_EARLY, GTLS_DIR_WRITE, sec.data(), sec.size(), &n) == GTLS_OK) {
        client_secret.assign(sec.begin(), sec.begin() + static_cast<long>(n));
      }
    }
    Bytes hello = MessagePair::pending(m.c, GTLS_EPOCH_INITIAL);
    EXPECT_EQ(gtls_conn_feed(m.s.conn, GTLS_EPOCH_INITIAL, hello.data(), hello.size(), m.now), GTLS_OK);
    for (int e = 0; e < GTLS_EPOCH_COUNT; e++) {
      Bytes b = MessagePair::pending(m.s, static_cast<GTLS_Epoch>(e));
      if (!b.empty()) {
        EXPECT_EQ(gtls_conn_feed(m.c.conn, static_cast<GTLS_Epoch>(e), b.data(), b.size(), m.now), GTLS_OK) << e;
      }
    }
    eoed = MessagePair::pending(m.c, GTLS_EPOCH_EARLY);
    fin = MessagePair::pending(m.c, GTLS_EPOCH_HANDSHAKE);
  }
  GTLS_Result feed(GTLS_Epoch e, const Bytes & b) {
    return gtls_conn_feed(m.s.conn, e, b.data(), b.size(), m.now);
  }
};

}  // namespace

TEST(EarlyEnd, InTheMessageInterfaceEndOfEarlyDataIsAnEarlyEpochMessageAndTheOrderIsEnforced) {
  EEnv a;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  {
    MsgEnded n(h.s);
    ASSERT_EQ(n.eoed, (Bytes{5, 0, 0, 0}));
    ASSERT_EQ(n.fin.size(), 36u);
    EXPECT_EQ(gtls_conn_state(n.m.s.conn), GTLS_STATE_S_WAIT_EOED);
    EXPECT_EQ(n.feed(GTLS_EPOCH_EARLY, n.eoed), GTLS_OK);
    EXPECT_EQ(n.feed(GTLS_EPOCH_HANDSHAKE, n.fin), GTLS_OK);
    EXPECT_TRUE(gtls_conn_is_connected(n.m.s.conn));
  }
  {
    MsgEnded n(h.s);
    EXPECT_EQ(n.feed(GTLS_EPOCH_HANDSHAKE, n.fin), GTLS_ERR_PROTOCOL) << "the Finished first";
    expect_failed_with(n.m.s.conn, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNEXPECTED_MESSAGE);
  }
  {
    MsgEnded n(h.s);
    EXPECT_EQ(n.feed(GTLS_EPOCH_EARLY, n.eoed), GTLS_OK);
    EXPECT_EQ(n.feed(GTLS_EPOCH_EARLY, n.eoed), GTLS_ERR_PROTOCOL) << "twice";
    expect_failed_with(n.m.s.conn, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNEXPECTED_MESSAGE);
  }
  {
    MsgEnded n(h.s);
    EXPECT_EQ(n.feed(GTLS_EPOCH_EARLY, n.eoed), GTLS_OK);
    EXPECT_EQ(n.feed(GTLS_EPOCH_HANDSHAKE, n.eoed), GTLS_ERR_PROTOCOL) << "a second one, in the epoch the Finished is due in";
    expect_failed_with(n.m.s.conn, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNEXPECTED_MESSAGE);
  }
  {
    MsgEnded n(h.s);
    EXPECT_EQ(n.feed(GTLS_EPOCH_HANDSHAKE, n.eoed), GTLS_ERR_PROTOCOL) << "in the wrong epoch";
    expect_failed_with(n.m.s.conn, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNEXPECTED_MESSAGE);
  }
  {
    MsgEnded n(h.s);
    Bytes full = n.eoed;
    full.push_back(0);   /* a body, and the length to match */
    full[3] = 1;
    EXPECT_EQ(n.feed(GTLS_EPOCH_EARLY, full), GTLS_ERR_CORRUPT);
    expect_failed_with(n.m.s.conn, GTLS_ERR_CORRUPT, GTLS_ALERT_DECODE_ERROR);
  }
  {
    MsgEnded n(h.s);
    Bytes both = n.eoed;
    both.insert(both.end(), n.fin.begin(), n.fin.end());
    EXPECT_EQ(n.feed(GTLS_EPOCH_EARLY, both), GTLS_ERR_PROTOCOL) << "the Finished may not ride in the early epoch";
  }
  {
    MsgEnded n(h.s, 0);   /* not accepted: EndOfEarlyData is not expected at all */
    EXPECT_EQ(n.eoed.size(), 0u);
    EXPECT_EQ(n.feed(GTLS_EPOCH_HANDSHAKE, Bytes{5, 0, 0, 0}), GTLS_ERR_PROTOCOL);
    expect_failed_with(n.m.s.conn, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNEXPECTED_MESSAGE);
  }
}

TEST(EarlyEnd, TheEarlySecretIsExposedToTheMessageInterfaceInTheDirectionsThatExist) {
  EEnv a;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  MsgEnded n(h.s);
  Bytes sr(48), none(48);
  size_t sn = 0, x = 0;

  ASSERT_EQ(n.client_secret.size(), 32u) << "the client had it from the moment its hello was built";
  ASSERT_EQ(gtls_conn_secret(n.m.s.conn, GTLS_EPOCH_EARLY, GTLS_DIR_READ, sr.data(), sr.size(), &sn), GTLS_OK);
  ASSERT_EQ(sn, 32u);
  sr.resize(sn);
  EXPECT_EQ(n.client_secret, sr) << "one secret, the client's";
  EXPECT_NE(sr, Bytes(32, 0));
  EXPECT_EQ(gtls_conn_secret(n.m.c.conn, GTLS_EPOCH_EARLY, GTLS_DIR_WRITE, none.data(), none.size(), &x),
      GTLS_ERR_INVALID) << "and gone from it once it has queued EndOfEarlyData";
  EXPECT_EQ(gtls_conn_secret(n.m.c.conn, GTLS_EPOCH_EARLY, GTLS_DIR_READ, none.data(), none.size(), &x),
      GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_secret(n.m.s.conn, GTLS_EPOCH_EARLY, GTLS_DIR_WRITE, none.data(), none.size(), &x),
      GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_secret(n.m.s.conn, GTLS_EPOCH_EARLY, GTLS_DIR_READ, none.data(), 31, &x),
      GTLS_ERR_LIMIT);
  ASSERT_EQ(n.feed(GTLS_EPOCH_EARLY, n.eoed), GTLS_OK);
  EXPECT_EQ(gtls_conn_secret(n.m.s.conn, GTLS_EPOCH_EARLY, GTLS_DIR_READ, none.data(), none.size(), &x),
      GTLS_ERR_INVALID) << "and from the server once it has read it";
  EXPECT_TRUE(zeros(n.m.s.conn->sec.schedule.c_e, sizeof n.m.s.conn->sec.schedule.c_e));
  EXPECT_TRUE(zeros(n.m.c.conn->sec.schedule.c_e, sizeof n.m.c.conn->sec.schedule.c_e));
}

TEST(EarlyEnd, NoEarlySecretWhereThereIsNoEarlyData) {
  EEnv a;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  Bytes out(48);
  size_t n = 0;

  /* A full handshake: neither end has one. */
  EXPECT_EQ(gtls_conn_secret(a.p.c.conn, GTLS_EPOCH_EARLY, GTLS_DIR_WRITE, out.data(), out.size(), &n),
      GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_secret(a.p.s.conn, GTLS_EPOCH_EARLY, GTLS_DIR_READ, out.data(), out.size(), &n),
      GTLS_ERR_INVALID);
  /* Rejected: the server never had one, and the client's is gone. */
  Refused r(h.s, [](EEnv & e) { e.rp.verdict = 0; });
  ASSERT_TRUE(r.e.p.connected());
  EXPECT_EQ(gtls_conn_secret(r.e.p.c.conn, GTLS_EPOCH_EARLY, GTLS_DIR_WRITE, out.data(), out.size(), &n),
      GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_secret(r.e.p.s.conn, GTLS_EPOCH_EARLY, GTLS_DIR_READ, out.data(), out.size(), &n),
      GTLS_ERR_INVALID);
  EXPECT_EQ(Bytes(r.e.p.c.conn->sec.schedule.c_e, r.e.p.c.conn->sec.schedule.c_e + 32), Bytes(32, 0));
}

/* ------------------------------------------------- the client checks the answer */

TEST(EarlyClientChecks, AnAcceptanceTheClientDidNotAskForOrCannotBelieveIsRefused) {
  EEnv a;
  a.p.calpn = {"h2"};
  a.p.salpn = {"h2"};
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  /* An early_data extension, empty, before the server's own EncryptedExtensions content. */
  static const unsigned char kEarlyExt[] = {0x00, 0x2a, 0x00, 0x00};

  struct Case {
    const char * what;
    std::function<void(EEnv &)> tweak;
    bool offered;
    unsigned alert;
    GTLS_Result result;
  };
  const std::vector<Case> cases = {
      {"the client offered none", [](EEnv & e) {
         e.p.calpn = {"h2"}; e.p.salpn = {"h2"}; e.p.ccfg.max_early_data = 0; }, false,
       GTLS_ALERT_UNSUPPORTED_EXTENSION, GTLS_ERR_PROTOCOL},
      {"the server did not take the PSK", [](EEnv & e) {
         e.p.calpn = {"h2"}; e.p.salpn = {"h2"}; e.p.keys = {ekey(2)}; }, true,
       GTLS_ALERT_UNSUPPORTED_EXTENSION, GTLS_ERR_PROTOCOL},
      {"the server chose another protocol", [](EEnv & e) {
         e.p.calpn = {"h2", "http/1.1"}; e.p.salpn = {"http/1.1"}; }, true,
       GTLS_ALERT_ILLEGAL_PARAMETER, GTLS_ERR_PROTOCOL},
  };
  for (const Case & c : cases) {
    SCOPED_TRACE(c.what);
    EEnv e;
    c.tweak(e);
    e.p.offer = h.s;
    ASSERT_EQ(e.p.build(), GTLS_OK);
    gtls_conn_set_server_hooks(e.p.s.conn, nullptr, nullptr, nullptr, nullptr, 0, 0, kEarlyExt, sizeof kEarlyExt);
    e.p.run();
    EXPECT_TRUE(gtls_conn_is_failed(e.p.c.conn));
    EXPECT_EQ(gtls_conn_failure(e.p.c.conn), c.result);
    EXPECT_EQ(gtls_conn_alert(e.p.c.conn), c.alert);
    EXPECT_TRUE(gtls_conn_secrets_are_wiped(e.p.c.conn));
  }
}

TEST(EarlyRejected, ATicketWithoutAnAllowanceIsRefusedEvenWhenTheClientOffers) {
  EEnv a;
  a.p.scfg.max_early_data = 0;
  a.p.scfg.anti_replay = nullptr;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  ASSERT_EQ(h.s->max_early_data, 0u);
  h.s->max_early_data = 1000;   /* a client that claims more than the ticket gave */
  Refused r(h.s, nullptr);
  expect_rejected(r, 0, true);
}

TEST(EarlyRejected, AProtocolThatOnlyBeginsLikeTheTicketsIsNotTheTickets) {
  EEnv a;
  a.p.calpn = {"h2", "h"};
  a.p.salpn = {"h2"};
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  ASSERT_EQ(h.s->alpn_len, 2u);
  Refused r(h.s, [](EEnv & e) {
    e.p.calpn = {"h2", "h"};
    e.p.salpn = {"h", "h2"};   /* the server prefers the shorter one, whose bytes are the first of the other's */
  });
  expect_rejected(r, 0, true);
  Refused same_length(h.s, [](EEnv & e) {
    e.p.calpn = {"h2", "h3"};
    e.p.salpn = {"h3", "h2"};   /* as long as the ticket's, and not the same */
  });
  expect_rejected(same_length, 0, true);
}

TEST(EarlyClient, TheOfferEndsAtTheMessageThatEndsItNotLater) {
  EEnv a;
  static const GTLS_Group p256[] = {GTLS_GROUP_SECP256R1};
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  Bytes out;
  size_t used = 0;
  size_t w = 0;

  /* A HelloRetryRequest. */
  {
    EEnv b;
    b.p.scfg.groups = p256;
    b.p.scfg.group_count = 1;
    ASSERT_NO_FATAL_FAILURE(start_early(b.p, h.s, pattern(30, 1)));
    ASSERT_EQ(status_of(b.p.c.conn), GTLS_EARLY_PENDING);
    b.p.carry(b.p.c, b.p.s, 0);
    b.p.carry(b.p.s, b.p.c, 0);   /* the retry, and nothing else yet */
    EXPECT_EQ(status_of(b.p.c.conn), GTLS_EARLY_REJECTED);
    Bytes sec(48);
    size_t n = 0;
    EXPECT_EQ(gtls_conn_secret(b.p.c.conn, GTLS_EPOCH_EARLY, GTLS_DIR_WRITE, sec.data(), sec.size(), &n),
        GTLS_ERR_INVALID) << "the key is gone with the offer";
    EXPECT_EQ(gtls_conn_write_early(b.p.c.conn, "x", 1, &w), GTLS_ERR_INVALID);
    EXPECT_EQ(b.p.c.conn->wr_epoch, GTLS_EPOCH_INITIAL);
    EXPECT_TRUE(zeros(&b.p.c.conn->sec.wr, sizeof b.p.c.conn->sec.wr)) << "the keys that sealed it are wiped";
    EXPECT_TRUE(zeros(b.p.c.conn->sec.wr_secret, sizeof b.p.c.conn->sec.wr_secret));
    EXPECT_TRUE(zeros(b.p.c.conn->sec.schedule.c_e, sizeof b.p.c.conn->sec.schedule.c_e));
  }
  /* A ServerHello that does select it, and nothing after it yet: the offer is open and the write is not. */
  {
    EEnv b;
    ASSERT_NO_FATAL_FAILURE(start_early(b.p, h.s, pattern(30, 1)));
    out = stream_out(b.p.c.conn);
    ASSERT_EQ(gtls_conn_stream_consume(b.p.c.conn, out.size()), GTLS_OK);
    ASSERT_EQ(gtls_conn_stream_feed(b.p.s.conn, out.data(), out.size(), b.p.now, &used), GTLS_OK);
    const std::vector<Bytes> flight = records_of(stream_out(b.p.s.conn));
    ASSERT_GE(flight.size(), 2u);
    ASSERT_EQ(gtls_conn_stream_feed(b.p.c.conn, flight[0].data(), flight[0].size(), b.p.now, &used), GTLS_OK);
    EXPECT_EQ(gtls_conn_state(b.p.c.conn), GTLS_STATE_WAIT_EE);
    EXPECT_EQ(status_of(b.p.c.conn), GTLS_EARLY_PENDING) << "the answer is in EncryptedExtensions";
    EXPECT_EQ(gtls_conn_write_early(b.p.c.conn, "x", 1, &w), GTLS_ERR_INVALID) << "but the server has begun to answer";
    EXPECT_EQ(w, 0u);
  }
  /* A ServerHello that does not select the PSK. */
  {
    EEnv b;
    b.p.keys = {ekey(2)};
    ASSERT_NO_FATAL_FAILURE(start_early(b.p, h.s, pattern(30, 1)));
    out = stream_out(b.p.c.conn);
    ASSERT_EQ(gtls_conn_stream_consume(b.p.c.conn, out.size()), GTLS_OK);
    ASSERT_EQ(gtls_conn_stream_feed(b.p.s.conn, out.data(), out.size(), b.p.now, &used), GTLS_OK);
    const std::vector<Bytes> flight = records_of(stream_out(b.p.s.conn));
    ASSERT_GE(flight.size(), 2u);
    ASSERT_EQ(gtls_conn_stream_feed(b.p.c.conn, flight[0].data(), flight[0].size(), b.p.now, &used), GTLS_OK);
    EXPECT_EQ(gtls_conn_state(b.p.c.conn), GTLS_STATE_WAIT_EE);
    EXPECT_EQ(status_of(b.p.c.conn), GTLS_EARLY_REJECTED) << "at the ServerHello, before EncryptedExtensions";
    EXPECT_TRUE(zeros(&b.p.c.conn->sec.wr, sizeof b.p.c.conn->sec.wr)) << "the keys that sealed it are wiped";
    EXPECT_TRUE(zeros(b.p.c.conn->sec.wr_secret, sizeof b.p.c.conn->sec.wr_secret));
  }
}

TEST(Early, TheDummyRecordFollowsTheHelloAheadOfTheEarlyRecords) {
  EEnv a;
  a.p.ccfg.middlebox_compat = 1;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  ASSERT_NO_FATAL_FAILURE(again_early(a.p, h.s, pattern(30, 1)));
  const std::vector<Bytes> recs = records_of(stream_out(a.p.c.conn));
  ASSERT_EQ(recs.size(), 3u);
  EXPECT_EQ(recs[0][0], 22) << "the ClientHello";
  EXPECT_EQ(recs[1][0], 20) << "the dummy change_cipher_spec, right after it (appendix D.4)";
  EXPECT_EQ(recs[2][0], 23) << "and then the early data";
}

TEST(EarlyEnd, AnotherMessageWhereEndOfEarlyDataIsDueIsUnexpected) {
  EEnv a;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  MsgEnded n(h.s);
  EXPECT_EQ(n.feed(GTLS_EPOCH_EARLY, Bytes{GTLS_HS_FINISHED, 0, 0, 0}), GTLS_ERR_PROTOCOL);
  expect_failed_with(n.m.s.conn, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNEXPECTED_MESSAGE);
}

TEST(EarlyEnd, AnApplicationRecordInTheMiddleOfAHandshakeMessageIsUnexpected) {
  EEnv a;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  Staged st(h.s, pattern(10, 1));
  ASSERT_EQ(st.recs.size(), 2u);
  ASSERT_EQ(st.feed(st.recs[0]), GTLS_OK);
  ASSERT_EQ(st.feed(st.recs[1]), GTLS_OK);
  GTLS_RecordKeys k = st.e.p.c.conn->sec.wr;   /* the client's early keys, a record on */
  GTLS_Buf b;
  gtls_buf_init(&b, nullptr, 256);
  const unsigned char half[2] = {5, 0};
  ASSERT_EQ(gtls_record_seal(&k, GTLS_CT_HANDSHAKE, half, 2, 0, &b), GTLS_OK);
  ASSERT_EQ(st.feed(Bytes(b.data, b.data + b.len)), GTLS_OK) << "half of an EndOfEarlyData";
  gtls_buf_free(&b);
  gtls_buf_init(&b, nullptr, 256);
  ASSERT_EQ(gtls_record_seal(&k, GTLS_CT_APPLICATION_DATA, "more", 4, 0, &b), GTLS_OK);
  EXPECT_EQ(st.feed(Bytes(b.data, b.data + b.len)), GTLS_ERR_PROTOCOL);
  gtls_buf_free(&b);
  expect_failed_with(st.e.p.s.conn, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNEXPECTED_MESSAGE);
}

TEST(EarlyEnd, AClientThatFailsHoldsNoneOfTheBytesItSent) {
  EEnv a;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  const Bytes data = pattern(300, 7);
  ASSERT_NO_FATAL_FAILURE(again_early(a.p, h.s, data));
  ASSERT_EQ(a.p.c.conn->early_sent.len, 300u);
  ASSERT_NE(std::search(a.p.c.conn->early_sent.data, a.p.c.conn->early_sent.data + a.p.c.conn->early_sent.cap,
                data.begin(), data.begin() + 64),
      a.p.c.conn->early_sent.data + a.p.c.conn->early_sent.cap)
      << "so there is something to look for";
  const Bytes junk(10, 0x42);
  size_t used = 0;
  EXPECT_NE(gtls_conn_stream_feed(a.p.c.conn, junk.data(), junk.size(), a.p.now, &used), GTLS_OK);
  ASSERT_TRUE(gtls_conn_is_failed(a.p.c.conn));
  EXPECT_EQ(a.p.c.conn->early_sent.len, 0u);
  EXPECT_EQ(std::search(a.p.c.conn->early_sent.data, a.p.c.conn->early_sent.data + a.p.c.conn->early_sent.cap,
                data.begin(), data.begin() + 64),
      a.p.c.conn->early_sent.data + a.p.c.conn->early_sent.cap)
      << "wiped at the failure, not only at the free";
  unsigned char b[8];
  size_t n = 1;
  EXPECT_EQ(gtls_conn_early_resend(a.p.c.conn, b, sizeof b, &n), GTLS_ERR_FAILED);
}

/* ============================================== the review of early data, patched */

namespace {

uint16_t be16(const unsigned char * p) {
  return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

void put16(Bytes & b, size_t v) {
  b.push_back(static_cast<unsigned char>(v >> 8));
  b.push_back(static_cast<unsigned char>(v));
}

/**
 * The client's ClientHello record with a second identity in its pre_shared_key,
 * one that is no ticket, ahead of the real one or after it, and the real one's
 * binder computed again over the hello as it now is. The server cannot tell it
 * from a client that offered two.
 */
Bytes two_identity_hello(const Bytes & record, const GTLS_Session * s, bool valid_first) {
  Bytes msg(record.begin() + 5, record.end());
  GTLS_ClientHello h;
  GTLS_Limits l = earlykat::limits();
  EXPECT_EQ(gtls_msg_parse_client_hello(msg.data() + 4, msg.size() - 4, &l, &h), GTLS_OK);
  const GTLS_Ext * e = gtls_msg_find_ext(h.exts, h.ext_count, GTLS_EXT_PRE_SHARED_KEY);
  EXPECT_NE(e, nullptr);
  const size_t body = static_cast<size_t>(e->data - msg.data());
  const size_t ids_len = be16(e->data);
  const size_t binders_at = body + 2 + ids_len;
  EXPECT_EQ(be16(msg.data() + binders_at), 33u);

  Bytes unknown;
  put16(unknown, 8);
  unknown.insert(unknown.end(), 8, 0x7e);
  unknown.insert(unknown.end(), {1, 2, 3, 4});
  const Bytes ids_old(msg.begin() + static_cast<long>(body) + 2, msg.begin() + static_cast<long>(binders_at));
  Bytes ids = valid_first ? ids_old : unknown;
  const Bytes & second = valid_first ? unknown : ids_old;
  ids.insert(ids.end(), second.begin(), second.end());
  const Bytes dummy(33, 0);   /* a binder's length byte, then 32 bytes that are wrong */
  Bytes binders;
  put16(binders, 66);
  binders.insert(binders.end(), 66, 0);
  binders[2] = binders[2 + 33] = 32;

  Bytes out(msg.begin(), msg.begin() + static_cast<long>(body) - 2);   /* up to the extension's length */
  const size_t ext_len = 2 + ids.size() + binders.size();
  put16(out, ext_len);
  put16(out, ids.size());
  out.insert(out.end(), ids.begin(), ids.end());
  const size_t cut = out.size();
  out.insert(out.end(), binders.begin(), binders.end());
  /* The block of extensions says how long it is, before the first one. */
  size_t at = 4 + 2 + 32;
  at += 1 + out[at];                               /* legacy_session_id */
  at += 2 + be16(out.data() + at);                 /* cipher_suites */
  at += 1 + out[at];                               /* compression methods */
  const size_t block = be16(out.data() + at) + (out.size() - msg.size());
  out[at] = static_cast<unsigned char>(block >> 8);
  out[at + 1] = static_cast<unsigned char>(block);
  const size_t len = out.size() - 4;
  out[1] = static_cast<unsigned char>(len >> 16);
  out[2] = static_cast<unsigned char>(len >> 8);
  out[3] = static_cast<unsigned char>(len);

  GTLS_Transcript t;
  unsigned char th[GTLS_HASH_MAX];
  unsigned char binder[GTLS_HASH_MAX];
  const GTLS_Hash hash = gtls_suite_hash(s->suite);
  EXPECT_EQ(gtls_transcript_init(&t), GTLS_OK);
  EXPECT_EQ(gtls_transcript_select(&t, hash), GTLS_OK);
  EXPECT_EQ(gtls_binder_transcript(&t, out.data(), cut, th), GTLS_OK);
  EXPECT_EQ(gtls_binder_compute(hash, s->psk, s->psk_len, th, binder), GTLS_OK);
  gtls_transcript_wipe(&t);
  std::memcpy(out.data() + cut + 2 + 1 + (valid_first ? 0 : 33), binder, 32);

  Bytes rec{22, 3, 1};
  put16(rec, out.size());
  rec.insert(rec.end(), out.begin(), out.end());
  return rec;
}

}  // namespace

TEST(EarlyRejected, OnlyTheFirstOfSeveralPsksMayCarryEarlyData) {
  EEnv a;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  for (bool valid_first : {true, false}) {
    SCOPED_TRACE(valid_first ? "[valid, unknown]" : "[unknown, valid]");
    EEnv e;
    ASSERT_NO_FATAL_FAILURE(start_early(e.p, h.s, Bytes()));
    const std::vector<Bytes> recs = records_of(stream_out(e.p.c.conn));
    ASSERT_GE(recs.size(), 1u);
    const Bytes hello = two_identity_hello(recs[0], h.s, valid_first);
    size_t used = 0;
    ASSERT_EQ(gtls_conn_stream_feed(e.p.s.conn, hello.data(), hello.size(), e.p.now, &used), GTLS_OK);
    EXPECT_EQ(gtls_conn_resumed(e.p.s.conn), 1) << "the ticket is good wherever it stands";
    if (valid_first) {
      EXPECT_EQ(e.rp.calls, 1) << "the control: the same hello, the ticket first";
      EXPECT_EQ(status_of(e.p.s.conn), GTLS_EARLY_ACCEPTED);
      EXPECT_EQ(gtls_conn_state(e.p.s.conn), GTLS_STATE_S_WAIT_EOED);
    } else {
      EXPECT_EQ(e.rp.calls, 0) << "the callback is not even asked (section 4.2.10)";
      EXPECT_EQ(status_of(e.p.s.conn), GTLS_EARLY_REJECTED);
      EXPECT_EQ(gtls_conn_state(e.p.s.conn), GTLS_STATE_S_WAIT_FIN);
    }
  }
}

TEST(EarlyRejected, RecordsOfAnyLengthAreSkippedWithinTheAllowanceAThickerWireWouldHaveEnded) {
  EEnv a(16384);
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  for (size_t piece : {static_cast<size_t>(1), static_cast<size_t>(80), static_cast<size_t>(200),
           static_cast<size_t>(16384)}) {
    SCOPED_TRACE(piece);
    EEnv e(16384);
    e.rp.verdict = 0;
    e.p.climits.max_output_bytes = 1u << 22;
    e.p.offer = h.s;
    ASSERT_EQ(e.p.build(), GTLS_OK);
    const Bytes data = pattern(16384, 4);
    for (size_t at = 0; at < data.size(); at += piece) {
      size_t n = std::min(piece, data.size() - at);
      size_t w = 0;
      ASSERT_EQ(gtls_conn_write_early(e.p.c.conn, data.data() + at, n, &w), GTLS_OK);
      ASSERT_EQ(w, n);
    }
    e.p.run();
    ASSERT_TRUE(e.p.connected()) << result_name(gtls_conn_failure(e.p.s.conn)) << " / "
                                 << result_name(gtls_conn_failure(e.p.c.conn));
    EXPECT_EQ(status_of(e.p.s.conn), GTLS_EARLY_REJECTED);
    EXPECT_EQ(resend(e.p.c.conn), data);
  }
}

TEST(EarlyRejected, TheSkipBudgetIsTheLargerOfTheLimitAndTheContextsAllowanceAndOneOverEndsIt) {
  EEnv a(4096);
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  struct Case {
    uint32_t limit, allowance, budget;
  };
  for (const Case & c : {Case{100, 60, 100}, Case{50, 120, 120}}) {
    for (uint32_t total : {c.budget, c.budget + 1}) {
      SCOPED_TRACE(::testing::Message() << "limit " << c.limit << ", allowance " << c.allowance
                                        << ", sent " << total);
      EEnv e(c.allowance);
      e.rp.verdict = 0;
      e.p.slimits.max_early_skip_bytes = c.limit;
      e.p.ccfg.max_early_data = 4096;
      e.p.offer = h.s;
      ASSERT_EQ(e.p.build(), GTLS_OK);
      for (uint32_t i = 0; i < total; i++) {
        size_t w = 0;
        const unsigned char b = static_cast<unsigned char>(i);
        ASSERT_EQ(gtls_conn_write_early(e.p.c.conn, &b, 1, &w), GTLS_OK);
      }
      e.p.run();
      if (total == c.budget) {
        ASSERT_TRUE(e.p.connected());
        EXPECT_EQ(status_of(e.p.s.conn), GTLS_EARLY_REJECTED);
      } else {
        EXPECT_TRUE(gtls_conn_is_failed(e.p.s.conn));
        EXPECT_EQ(gtls_conn_failure(e.p.s.conn), GTLS_ERR_LIMIT);
        EXPECT_EQ(gtls_conn_alert(e.p.s.conn), GTLS_ALERT_UNEXPECTED_MESSAGE);
      }
    }
  }
}

TEST(EarlyRejected, AZeroSkipBudgetFailsOnTheFirstRecordOfAServerWithEarlyDataOff) {
  EEnv a(4096);
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  for (bool zero : {false, true}) {
    EEnv e(4096);
    e.p.scfg.max_early_data = 0;          /* this server takes none, so what the client sends is skipped */
    e.p.scfg.anti_replay = nullptr;
    e.p.slimits.max_early_skip_bytes = zero ? GTLS_LIMIT_ZERO : 0;
    e.p.offer = h.s;
    ASSERT_EQ(e.p.build(), GTLS_OK);
    size_t w = 0;
    ASSERT_EQ(gtls_conn_write_early(e.p.c.conn, "x", 1, &w), GTLS_OK);
    e.p.run();
    if (zero) {
      EXPECT_TRUE(gtls_conn_is_failed(e.p.s.conn));
      EXPECT_EQ(gtls_conn_failure(e.p.s.conn), GTLS_ERR_LIMIT);
      EXPECT_EQ(gtls_conn_alert(e.p.s.conn), GTLS_ALERT_UNEXPECTED_MESSAGE);
    } else {
      ASSERT_TRUE(e.p.connected()) << "0 is the default budget, which has room for a byte";
      EXPECT_EQ(status_of(e.p.s.conn), GTLS_EARLY_REJECTED);
    }
  }
}

TEST(EarlyRejected, EmptyRecordsCostOneEachAgainstTheSkipBudget) {
  EEnv a(4096);
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  for (int empties : {9, 10}) {
    Staged st(h.s, Bytes(1, 'a'), 4, [](EEnv & e) {
      e.rp.verdict = 0;
      e.p.slimits.max_early_skip_bytes = 10;
    });
    ASSERT_EQ(st.recs.size(), 2u);
    ASSERT_EQ(st.feed(st.recs[0]), GTLS_OK);
    ASSERT_EQ(st.feed(st.recs[1]), GTLS_OK) << "one of ten";
    GTLS_RecordKeys k = st.e.p.c.conn->sec.wr;
    GTLS_Result last = GTLS_OK;
    for (int i = 0; i < empties; i++) {
      GTLS_Buf b;
      gtls_buf_init(&b, nullptr, 256);
      ASSERT_EQ(gtls_record_seal(&k, GTLS_CT_APPLICATION_DATA, "", 0, 0, &b), GTLS_OK);
      last = st.feed(Bytes(b.data, b.data + b.len));
      gtls_buf_free(&b);
      if (last != GTLS_OK) {
        break;
      }
    }
    if (empties == 9) {
      EXPECT_EQ(last, GTLS_OK) << "nine empties and one byte are ten";
    } else {
      EXPECT_EQ(last, GTLS_ERR_LIMIT) << "the tenth empty is the eleventh";
      EXPECT_EQ(gtls_conn_alert(st.server()), GTLS_ALERT_UNEXPECTED_MESSAGE);
    }
  }
}

TEST(EarlyLimits, TheServerTakesTheTicketsSmallerAllowanceWhenItsOwnIsLarger) {
  EEnv a(100);
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  /* The ticket says 100, issued when the server allowed 100; the server now allows 4096. */
  for (size_t total : {static_cast<size_t>(100), static_cast<size_t>(101)}) {
    EEnv e(4096);
    e.p.offer = h.s;
    ASSERT_EQ(e.p.build(), GTLS_OK);
    e.p.c.conn->early_max = 1000;   /* a client that does not keep to it */
    e.p.c.conn->early_sent.max = 1000;
    const Bytes data = pattern(total, 2);
    size_t w = 0;
    ASSERT_EQ(gtls_conn_write_early(e.p.c.conn, data.data(), data.size(), &w), GTLS_OK);
    e.p.run();
    SCOPED_TRACE(total);
    if (total == 100) {
      ASSERT_TRUE(e.p.connected());
      EXPECT_EQ(read_early(e.p.s.conn), data);
    } else {
      EXPECT_EQ(gtls_conn_failure(e.p.s.conn), GTLS_ERR_LIMIT) << "the ticket's allowance, not the context's";
    }
  }
}

TEST(EarlyClientChecks, AServerThatAcceptsEarlyDataUnderAnotherSuiteOfTheSameHashIsRefused) {
  EEnv a;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  ASSERT_EQ(h.s->suite, static_cast<uint32_t>(GTLS_SUITE_AES_128_GCM_SHA256));
  /* The session says the early records are under ChaCha20 (the same hash, SHA-256, so the PSK is
   * good for both); the server resumes the ticket's suite, AES-128, and says it accepts. */
  h.s->suite = GTLS_SUITE_CHACHA20_POLY1305_SHA256;
  EEnv e;
  ASSERT_NO_FATAL_FAILURE(start_early(e.p, h.s, Bytes()));
  e.p.run();
  EXPECT_EQ(e.rp.calls, 1) << "the server did accept";
  EXPECT_TRUE(gtls_conn_is_failed(e.p.c.conn));
  EXPECT_EQ(gtls_conn_failure(e.p.c.conn), GTLS_ERR_PROTOCOL);
  EXPECT_EQ(gtls_conn_alert(e.p.c.conn), GTLS_ALERT_ILLEGAL_PARAMETER);
  EXPECT_TRUE(gtls_conn_secrets_are_wiped(e.p.c.conn));
}

TEST(EarlyClientChecks, AServerHelloThatSelectsThePskWithAnotherHashIsIllegalBeforeAnythingIsBuilt) {
  EEnv a;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  EEnv e;
  ASSERT_NO_FATAL_FAILURE(start_early(e.p, h.s, pattern(10, 1)));
  const Bytes out = stream_out(e.p.c.conn);
  ASSERT_EQ(gtls_conn_stream_consume(e.p.c.conn, out.size()), GTLS_OK);
  size_t used = 0;
  ASSERT_EQ(gtls_conn_stream_feed(e.p.s.conn, out.data(), out.size(), e.p.now, &used), GTLS_OK);
  const std::vector<Bytes> flight = records_of(stream_out(e.p.s.conn));
  ASSERT_GE(flight.size(), 1u);
  Bytes sh = flight[0];
  ASSERT_EQ(sh[5], GTLS_HS_SERVER_HELLO);
  const size_t suite_at = 5 + 4 + 2 + 32 + 1 + sh[5 + 4 + 2 + 32];
  ASSERT_EQ(be16(sh.data() + suite_at), static_cast<unsigned>(GTLS_SUITE_AES_128_GCM_SHA256));
  /* The control: as it stands it is accepted. */
  {
    EEnv c;
    ASSERT_NO_FATAL_FAILURE(start_early(c.p, h.s, pattern(10, 1)));
    (void)stream_out(c.p.c.conn);
    EXPECT_EQ(gtls_conn_stream_feed(c.p.c.conn, sh.data(), sh.size(), c.p.now, &used), GTLS_OK);
  }
  sh[suite_at] = 0x13;
  sh[suite_at + 1] = 0x02;   /* AES-256-GCM-SHA384, which the client offered; the PSK is for SHA-256 */
  EXPECT_EQ(gtls_conn_stream_feed(e.p.c.conn, sh.data(), sh.size(), e.p.now, &used), GTLS_ERR_PROTOCOL);
  EXPECT_EQ(gtls_conn_alert(e.p.c.conn), GTLS_ALERT_ILLEGAL_PARAMETER);
  EXPECT_TRUE(gtls_conn_secrets_are_wiped(e.p.c.conn));
}

TEST(Early, ExactlyOneDummyRecordHoweverOftenTheEarlyWritesAndTheFlushesRepeat) {
  EEnv a;
  a.p.ccfg.middlebox_compat = 1;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  EEnv e;
  e.p.ccfg.middlebox_compat = 1;
  ASSERT_NO_FATAL_FAILURE(start_early(e.p, h.s, Bytes()));
  Bytes all, sent;
  size_t used = 0;
  auto pump = [&]() {
    for (int i = 0; i < 50; i++) {
      const Bytes co = stream_out(e.p.c.conn);
      if (!co.empty()) {
        ASSERT_EQ(gtls_conn_stream_consume(e.p.c.conn, co.size()), GTLS_OK);
        all.insert(all.end(), co.begin(), co.end());
        ASSERT_EQ(gtls_conn_stream_feed(e.p.s.conn, co.data(), co.size(), e.p.now, &used), GTLS_OK);
      }
      const Bytes so = stream_out(e.p.s.conn);
      if (!so.empty()) {
        ASSERT_EQ(gtls_conn_stream_consume(e.p.s.conn, so.size()), GTLS_OK);
        ASSERT_EQ(gtls_conn_stream_feed(e.p.c.conn, so.data(), so.size(), e.p.now, &used), GTLS_OK);
      }
      if (co.empty() && so.empty()) {
        break;
      }
    }
  };
  for (unsigned i = 0; i < 5; i++) {
    const Bytes piece = pattern(10 + i, i);
    size_t w = 0;
    ASSERT_EQ(gtls_conn_write_early(e.p.c.conn, piece.data(), piece.size(), &w), GTLS_OK);
    sent.insert(sent.end(), piece.begin(), piece.end());
    size_t none = 0;
    ASSERT_EQ(gtls_conn_write_early(e.p.c.conn, "", 0, &none), GTLS_OK);
    const Bytes co = stream_out(e.p.c.conn);   /* flushes: the hello, the dummy record, the early records */
    ASSERT_EQ(gtls_conn_stream_consume(e.p.c.conn, co.size()), GTLS_OK);
    all.insert(all.end(), co.begin(), co.end());
    ASSERT_EQ(gtls_conn_stream_feed(e.p.s.conn, co.data(), co.size(), e.p.now, &used), GTLS_OK);
  }
  pump();
  ASSERT_TRUE(e.p.connected());
  size_t ccs = 0;
  for (const Bytes & r : records_of(all)) {
    ccs += r[0] == GTLS_CT_CHANGE_CIPHER_SPEC ? 1u : 0u;
  }
  EXPECT_EQ(ccs, 1u) << "one dummy change_cipher_spec per connection";
  EXPECT_EQ(read_early(e.p.s.conn), sent);
}

TEST(Early, AWriteOfNothingFlushesNoHelloAndInstallsNoKey) {
  EEnv a;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  EEnv e;
  e.p.offer = h.s;
  ASSERT_EQ(e.p.build(), GTLS_OK);
  GTLS_Conn * c = e.p.c.conn;
  size_t w = 7;
  EXPECT_EQ(gtls_conn_write_early(c, "", 0, &w), GTLS_OK);
  EXPECT_EQ(w, 0u);
  w = 7;
  EXPECT_EQ(gtls_conn_write_early(c, nullptr, 0, &w), GTLS_OK);
  EXPECT_EQ(w, 0u);
  EXPECT_EQ(c->wr_epoch, GTLS_EPOCH_INITIAL) << "no early key was installed";
  EXPECT_EQ(c->wire.len, 0u) << "and nothing was sealed or flushed";
  EXPECT_FALSE(c->hello_flushed) << "the ClientHello is still where it was";
  /* And a write that follows still works, once. */
  const Bytes data = pattern(20, 5);
  ASSERT_EQ(gtls_conn_write_early(c, data.data(), data.size(), &w), GTLS_OK);
  e.p.run();
  ASSERT_TRUE(e.p.connected());
  EXPECT_EQ(read_early(e.p.s.conn), data);
}

TEST(Early, AClientThatWroteNothingEndsItsEarlyDataAllTheSame) {
  EEnv a;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  EEnv e;
  ASSERT_NO_FATAL_FAILURE(start_early(e.p, h.s, Bytes()));
  e.p.run();
  ASSERT_TRUE(e.p.connected());
  EXPECT_EQ(status_of(e.p.c.conn), GTLS_EARLY_ACCEPTED);
  EXPECT_EQ(status_of(e.p.s.conn), GTLS_EARLY_ACCEPTED);
  EXPECT_TRUE(read_early(e.p.s.conn).empty());
  EXPECT_EQ(e.rp.calls, 1);
}

TEST(EarlyEnd, EndOfEarlyDataAndFinishedInOneEarlyRecordAreUnexpectedOverAStreamToo) {
  EEnv a;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  Staged st(h.s, pattern(10, 1));
  ASSERT_EQ(st.recs.size(), 2u);
  ASSERT_EQ(st.feed(st.recs[0]), GTLS_OK);
  ASSERT_EQ(st.feed(st.recs[1]), GTLS_OK);
  GTLS_RecordKeys k = st.e.p.c.conn->sec.wr;   /* the client's early keys, a record on */
  Bytes both{5, 0, 0, 0};                      /* EndOfEarlyData, */
  both.insert(both.end(), {20, 0, 0, 32});     /* and the head of a Finished, in the same record */
  both.insert(both.end(), 32, 0x11);
  EXPECT_EQ(st.feed(seal(&k, GTLS_CT_HANDSHAKE, both)), GTLS_ERR_PROTOCOL);
  expect_failed_with(st.e.p.s.conn, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNEXPECTED_MESSAGE);
}

TEST(EarlyEnd, TheEarlySecretAndTheKeysAreWipedWhenTheyHaveDoneTheirWork) {
  EEnv a;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  Ended n(h.s);
  GTLS_Conn * c = n.e.p.c.conn;
  GTLS_Conn * s = n.e.p.s.conn;
  Bytes sec(GTLS_HASH_MAX);
  size_t len = 0;

  /* The client has queued EndOfEarlyData and the Finished, and sent them. */
  ASSERT_EQ(n.early_secret.size(), 32u);
  EXPECT_NE(n.early_secret, Bytes(32, 0));
  EXPECT_FALSE(c->sec.schedule.has_e);
  EXPECT_TRUE(zeros(c->sec.schedule.c_e, sizeof c->sec.schedule.c_e));
  EXPECT_EQ(gtls_conn_secret(c, GTLS_EPOCH_EARLY, GTLS_DIR_WRITE, sec.data(), sec.size(), &len), GTLS_ERR_INVALID);
  ASSERT_EQ(gtls_conn_debug_secret(c, GTLS_SECRET_CLIENT_EARLY, sec.data(), sec.size(), &len), GTLS_OK);
  EXPECT_EQ(Bytes(sec.begin(), sec.begin() + static_cast<long>(len)), Bytes(len, 0));
  EXPECT_NE(c->sec.wr_secret[0] | c->sec.wr_secret[1] | c->sec.wr_secret[2], 0) << "the keys in force are the handshake's";
  EXPECT_EQ(c->wr_epoch, GTLS_EPOCH_APPLICATION);

  /* The server has it until it reads EndOfEarlyData, and not after. */
  ASSERT_EQ(gtls_conn_secret(s, GTLS_EPOCH_EARLY, GTLS_DIR_READ, sec.data(), sec.size(), &len), GTLS_OK);
  EXPECT_EQ(Bytes(sec.begin(), sec.begin() + static_cast<long>(len)), n.early_secret);
  EXPECT_NE(s->sec.schedule.c_e[0] | s->sec.schedule.c_e[1], 0);
  ASSERT_EQ(n.feed(n.fin[0]), GTLS_OK);
  EXPECT_EQ(gtls_conn_state(s), GTLS_STATE_S_WAIT_FIN);
  EXPECT_FALSE(s->sec.schedule.has_e);
  EXPECT_TRUE(zeros(s->sec.schedule.c_e, sizeof s->sec.schedule.c_e));
  EXPECT_TRUE(zeros(&s->sec.rd, sizeof s->sec.rd)) << "the keys that opened the early records";
  EXPECT_TRUE(zeros(s->sec.rd_secret, sizeof s->sec.rd_secret));
  EXPECT_EQ(gtls_conn_secret(s, GTLS_EPOCH_EARLY, GTLS_DIR_READ, sec.data(), sec.size(), &len), GTLS_ERR_INVALID);
  ASSERT_EQ(n.feed(n.fin[1]), GTLS_OK);
  ASSERT_TRUE(gtls_conn_is_connected(s));
  EXPECT_EQ(gtls_conn_secret(s, GTLS_EPOCH_EARLY, GTLS_DIR_READ, sec.data(), sec.size(), &len), GTLS_ERR_INVALID);
  ASSERT_EQ(gtls_conn_debug_secret(s, GTLS_SECRET_CLIENT_EARLY, sec.data(), sec.size(), &len), GTLS_OK);
  EXPECT_EQ(Bytes(sec.begin(), sec.begin() + static_cast<long>(len)), Bytes(len, 0));
  EXPECT_EQ(read_early(s), pattern(40, 8));
}

TEST(EarlyRead, ThePlaintextHandedOverIsWipedFromTheBufferItCameFrom) {
  EEnv a;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  {
    EEnv e;
    const Bytes data = pattern(300, 3);
    ASSERT_NO_FATAL_FAILURE(start_early(e.p, h.s, data));
    e.p.run();
    ASSERT_TRUE(e.p.connected());
    GTLS_Conn * s = e.p.s.conn;
    unsigned char buf[300];
    size_t n = 0;
    ASSERT_EQ(gtls_conn_read_early(s, buf, 100, &n), GTLS_OK);
    ASSERT_EQ(n, 100u);
    ASSERT_EQ(s->early_in.len, 200u);
    EXPECT_TRUE(zeros(s->early_in.data + 200, 100)) << "the stale copy the move leaves";
    EXPECT_EQ(Bytes(s->early_in.data, s->early_in.data + 200), Bytes(data.begin() + 100, data.end()));
    ASSERT_EQ(gtls_conn_read_early(s, buf, sizeof buf, &n), GTLS_OK);
    ASSERT_EQ(n, 200u);
    EXPECT_EQ(s->early_in.len, 0u);
    EXPECT_TRUE(zeros(s->early_in.data, 300)) << "and when nothing is left";
  }
  {
    Refused r(h.s, [](EEnv & e) { e.rp.verdict = 0; });
    ASSERT_TRUE(r.e.p.connected());
    GTLS_Conn * c = r.e.p.c.conn;
    unsigned char buf[300];
    size_t n = 0;
    ASSERT_EQ(c->early_sent.len, 200u);
    ASSERT_EQ(gtls_conn_early_resend(c, buf, 50, &n), GTLS_OK);
    ASSERT_EQ(n, 50u);
    EXPECT_TRUE(zeros(c->early_sent.data + 150, 50));
    ASSERT_EQ(gtls_conn_early_resend(c, buf, sizeof buf, &n), GTLS_OK);
    ASSERT_EQ(n, 150u);
    EXPECT_TRUE(zeros(c->early_sent.data, 200));
  }
}

TEST(EarlyRead, NeitherReadWritesPastTheBufferItIsGiven) {
  EEnv a;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  {
    EEnv e;
    ASSERT_NO_FATAL_FAILURE(start_early(e.p, h.s, pattern(300, 3)));
    e.p.run();
    ASSERT_TRUE(e.p.connected());
    for (size_t cap : {static_cast<size_t>(100), static_cast<size_t>(1), static_cast<size_t>(199)}) {
      unsigned char buf[300 + 8];
      std::memset(buf, 0xab, sizeof buf);
      size_t n = 0;
      ASSERT_EQ(gtls_conn_read_early(e.p.s.conn, buf, cap, &n), GTLS_OK);
      EXPECT_EQ(n, cap);
      for (size_t i = cap; i < sizeof buf; i++) {
        ASSERT_EQ(buf[i], 0xab) << "byte " << i << " of a buffer of " << cap;
      }
    }
  }
  {
    Refused r(h.s, [](EEnv & e) { e.rp.verdict = 0; });
    ASSERT_TRUE(r.e.p.connected());
    for (size_t cap : {static_cast<size_t>(50), static_cast<size_t>(1), static_cast<size_t>(99)}) {
      unsigned char buf[200 + 8];
      std::memset(buf, 0xab, sizeof buf);
      size_t n = 0;
      ASSERT_EQ(gtls_conn_early_resend(r.e.p.c.conn, buf, cap, &n), GTLS_OK);
      EXPECT_EQ(n, cap);
      for (size_t i = cap; i < sizeof buf; i++) {
        ASSERT_EQ(buf[i], 0xab) << "byte " << i << " of a buffer of " << cap;
      }
    }
  }
}

/* ------------------------------------------ closing in the early window */

TEST(EarlyClose, ACloseBeforeTheHandshakeIsDoneSaysNothingUnderTheEarlyKey) {
  EEnv a;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  for (int variant = 0; variant < 3; variant++) {
    SCOPED_TRACE(variant == 0 ? "the hello and the data were sent"
                              : variant == 1 ? "nothing was taken from the output"
                                             : "the ServerHello has been read");
    EEnv e;
    const Bytes data = pattern(40, 8);
    ASSERT_NO_FATAL_FAILURE(start_early(e.p, h.s, data));
    GTLS_Conn * c = e.p.c.conn;
    GTLS_Conn * s = e.p.s.conn;
    size_t used = 0;
    ASSERT_EQ(c->wr_epoch, GTLS_EPOCH_EARLY);
    if (variant != 1) {
      const Bytes out = stream_out(c);
      ASSERT_EQ(gtls_conn_stream_consume(c, out.size()), GTLS_OK);
      ASSERT_EQ(gtls_conn_stream_feed(s, out.data(), out.size(), e.p.now, &used), GTLS_OK);
    }
    if (variant == 2) {
      const std::vector<Bytes> flight = records_of(stream_out(s));
      ASSERT_GE(flight.size(), 1u);
      ASSERT_EQ(gtls_conn_stream_feed(c, flight[0].data(), flight[0].size(), e.p.now, &used), GTLS_OK);
      ASSERT_EQ(gtls_conn_state(c), GTLS_STATE_WAIT_EE);
    }
    /* This end is ended, locally, and the caller is told. */
    EXPECT_EQ(gtls_conn_close(c), GTLS_ERR_CLOSED);
    EXPECT_TRUE(gtls_conn_is_failed(c));
    EXPECT_EQ(gtls_conn_failure(c), GTLS_ERR_CLOSED);
    EXPECT_EQ(gtls_conn_alert(c), GTLS_ALERT_NONE);
    EXPECT_TRUE(gtls_conn_secrets_are_wiped(c));
    EXPECT_TRUE(stream_out(c).empty()) << "no close_notify, under the early key or any other, and nothing unsent";
    EXPECT_EQ(gtls_conn_close(c), GTLS_ERR_FAILED);
    size_t w = 0;
    EXPECT_EQ(gtls_conn_write_early(c, "x", 1, &w), GTLS_ERR_FAILED);
    /* The server's view: what it was sent, and then the stream ends. */
    if (variant != 1) {
      EXPECT_EQ(gtls_conn_state(s), GTLS_STATE_S_WAIT_EOED);
      EXPECT_EQ(read_early(s), data);
      EXPECT_EQ(gtls_conn_stream_eof(s), GTLS_ERR_TRUNCATED) << "and it does not wait for ever";
      EXPECT_TRUE(gtls_conn_is_failed(s));
    }
  }
}

TEST(EarlyClose, ACloseOnceTheHandshakeIsCompleteSpeaksUnderTheApplicationKeyEvenWithTheEndStillQueued) {
  EEnv a;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  EEnv e;
  ASSERT_NO_FATAL_FAILURE(start_early(e.p, h.s, pattern(40, 8)));
  GTLS_Conn * c = e.p.c.conn;
  GTLS_Conn * s = e.p.s.conn;
  size_t used = 0;
  const Bytes out = stream_out(c);
  ASSERT_EQ(gtls_conn_stream_consume(c, out.size()), GTLS_OK);
  ASSERT_EQ(gtls_conn_stream_feed(s, out.data(), out.size(), e.p.now, &used), GTLS_OK);
  const Bytes flight = stream_out(s);
  ASSERT_EQ(gtls_conn_stream_consume(s, flight.size()), GTLS_OK);
  /* In pieces, so that the client's last message is the end of what it was fed. */
  ASSERT_EQ(gtls_conn_stream_feed(c, flight.data(), flight.size(), e.p.now, &used), GTLS_OK);
  ASSERT_TRUE(gtls_conn_is_connected(c));
  EXPECT_EQ(gtls_conn_close(c), GTLS_OK) << "the client is connected, and the early window is over";
  EXPECT_FALSE(gtls_conn_is_failed(c));
  const Bytes rest = stream_out(c);
  ASSERT_EQ(gtls_conn_stream_consume(c, rest.size()), GTLS_OK);
  ASSERT_EQ(gtls_conn_stream_feed(s, rest.data(), rest.size(), e.p.now, &used), GTLS_OK);
  EXPECT_TRUE(gtls_conn_is_connected(s));
  EXPECT_TRUE(gtls_conn_peer_closed(s)) << "EndOfEarlyData, the Finished, then close_notify";
  EXPECT_EQ(read_early(s), pattern(40, 8));
}

TEST(EarlyClose, AServerWaitingForEndOfEarlyDataClosesUnderItsApplicationKey) {
  EEnv a;
  Held h;
  ASSERT_NO_FATAL_FAILURE(prime(a, h));
  Ended n(h.s);
  GTLS_Conn * s = n.e.p.s.conn;
  GTLS_Conn * c = n.e.p.c.conn;
  ASSERT_EQ(gtls_conn_state(s), GTLS_STATE_S_WAIT_EOED);
  EXPECT_EQ(gtls_conn_close(s), GTLS_OK);
  n.e.p.carry(n.e.p.s, n.e.p.c, 0);
  EXPECT_TRUE(gtls_conn_peer_closed(c)) << "the client reads it under the server's application key";
  EXPECT_FALSE(gtls_conn_is_failed(c));
  EXPECT_EQ(n.feed(n.fin[0]), GTLS_OK) << "and the server still reads what the client sends";
  EXPECT_EQ(n.feed(n.fin[1]), GTLS_OK);
  EXPECT_TRUE(gtls_conn_is_connected(s));
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
