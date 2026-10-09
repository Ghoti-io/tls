/**
 * @file
 *
 * Record protection against RFC 8448's records, byte for byte and in both
 * directions, for the handshake keys and the application keys; then the
 * rules around it: the nonce, the sequence number and its limit, padding,
 * every position of a record tampered, the size caps, the key that follows
 * a key, and the wiping of keys.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "rfc_run.h"

#include <ghoti.io/security/aes_gcm.h>
#include <ghoti.io/security/hkdf.h>

using namespace gtlstest;

namespace {

struct Rec {
  unsigned type;
  const char * payload;
  const char * record;
};

/** Keys from the RFC's own key and IV lines, under @p prefix. */
GTLS_RecordKeys keys_from(const Vec & v, const std::string & prefix, uint64_t limit = 0) {
  GTLS_RecordKeys k;
  EXPECT_EQ(gtls_record_keys_from_raw(&k, GTLS_SUITE_AES_128_GCM_SHA256,
                v[prefix + ".key-expanded"].data(), v[prefix + ".iv-expanded"].data(), limit),
      GTLS_OK);
  return k;
}

Bytes seal_one(GTLS_RecordKeys * k, unsigned type, const Bytes & pt, size_t pad = 0) {
  GTLS_Buf b;
  gtls_buf_init(&b, nullptr, 1 << 16);
  EXPECT_EQ(gtls_record_seal(k, type, pt.data(), pt.size(), pad, &b), GTLS_OK);
  Bytes out(b.data, b.data + b.len);
  gtls_buf_free(&b);
  return out;
}

GTLS_Result open_one(GTLS_RecordKeys * k, const Bytes & rec, Bytes * pt, unsigned * type,
    size_t max_padding = 16384) {
  Bytes buf(GTLS_RECORD_CIPHER_MAX);
  size_t n = 0;
  GTLS_Result r = gtls_record_open(k, rec.data(), rec.data() + 5, rec.size() - 5, max_padding,
      buf.data(), &n, type);
  if (r == GTLS_OK) {
    buf.resize(n);
    *pt = buf;
  }
  return r;
}

/** Seal, in order, what the RFC sealed under one key, and open it again. */
void check_run(const Vec & v, const std::string & prefix, const std::vector<Rec> & recs,
    const char * what) {
  GTLS_RecordKeys w = keys_from(v, prefix);
  GTLS_RecordKeys r = keys_from(v, prefix);
  for (const Rec & rec : recs) {
    if (!v.has(rec.payload) || !v.has(rec.record)) {
      ADD_FAILURE() << what << ": the trace has no " << rec.payload;
      continue;
    }
    Bytes got = seal_one(&w, rec.type, v[rec.payload]);
    EXPECT_EQ(got, v[rec.record]) << what << " " << rec.payload << " sealed";
    Bytes pt;
    unsigned type = 0;
    ASSERT_EQ(open_one(&r, v[rec.record], &pt, &type), GTLS_OK) << what << " " << rec.record;
    EXPECT_EQ(pt, v[rec.payload]) << what << " opened";
    EXPECT_EQ(type, rec.type) << what;
  }
  EXPECT_EQ(w.seq, recs.size());
  EXPECT_EQ(r.seq, recs.size());
}

}  // namespace

TEST(Rfc8448Records, SimpleTraceInBothDirectionsAtBothKeyLevels) {
  Vec v("simple-1rtt");
  check_run(v, "server.derive-write-traffic-keys-for-handshake-data",
      {{GTLS_CT_HANDSHAKE, "server.send-handshake-record@2.payload",
          "server.send-handshake-record@2.complete-record"}},
      "server handshake");
  check_run(v, "server.derive-read-traffic-keys-for-handshake-data",
      {{GTLS_CT_HANDSHAKE, "client.send-handshake-record@2.payload",
          "client.send-handshake-record@2.complete-record"}},
      "client handshake");
  check_run(v, "server.derive-write-traffic-keys-for-application-data",
      {{GTLS_CT_HANDSHAKE, "server.send-handshake-record@3.payload",
           "server.send-handshake-record@3.complete-record"},
          {GTLS_CT_APPLICATION_DATA, "server.send-application-data-record.payload",
              "server.send-application-data-record.complete-record"},
          {GTLS_CT_ALERT, "server.send-alert-record.payload",
              "server.send-alert-record.complete-record"}},
      "server application");
  check_run(v, "client.derive-write-traffic-keys-for-application-data",
      {{GTLS_CT_APPLICATION_DATA, "client.send-application-data-record.payload",
           "client.send-application-data-record.complete-record"},
          {GTLS_CT_ALERT, "client.send-alert-record.payload",
              "client.send-alert-record.complete-record"}},
      "client application");
}

TEST(Rfc8448Records, HelloRetryRequestTrace) {
  Vec v("hrr");
  check_run(v, "server.derive-write-traffic-keys-for-handshake-data",
      {{GTLS_CT_HANDSHAKE, "server.send-handshake-record@3.payload",
          "server.send-handshake-record@3.complete-record"}},
      "server handshake");
  check_run(v, "server.derive-read-traffic-keys-for-handshake-data",
      {{GTLS_CT_HANDSHAKE, "client.send-handshake-record@3.payload",
          "client.send-handshake-record@3.complete-record"}},
      "client handshake");
  check_run(v, "server.derive-write-traffic-keys-for-application-data",
      {{GTLS_CT_ALERT, "server.send-alert-record.payload",
          "server.send-alert-record.complete-record"}},
      "server application");
  check_run(v, "client.derive-write-traffic-keys-for-application-data",
      {{GTLS_CT_ALERT, "client.send-alert-record.payload",
          "client.send-alert-record.complete-record"}},
      "client application");
}

TEST(Rfc8448Records, KeysFromATrafficSecretAreTheRfcsKeyAndIv) {
  for (const char * file : {"simple-1rtt", "hrr"}) {
    Vec v(file);
    struct P {
      const char * secret;
      const char * prefix;
    };
    const P cases[] = {
        {"server.derive-secret-tls13-s-hs-traffic.expanded",
            "server.derive-write-traffic-keys-for-handshake-data"},
        {"server.derive-secret-tls13-c-hs-traffic.expanded",
            "server.derive-read-traffic-keys-for-handshake-data"},
        {"server.derive-secret-tls13-s-ap-traffic.expanded",
            "server.derive-write-traffic-keys-for-application-data"},
        {"server.derive-secret-tls13-c-ap-traffic.expanded",
            "client.derive-write-traffic-keys-for-application-data"},
    };
    for (const P & c : cases) {
      GTLS_RecordKeys k;
      ASSERT_EQ(gtls_record_keys_from_secret(&k, GTLS_SUITE_AES_128_GCM_SHA256, v[c.secret].data(), 0),
          GTLS_OK);
      EXPECT_EQ(Bytes(k.key, k.key + 16), v[std::string(c.prefix) + ".key-expanded"]) << file << c.secret;
      EXPECT_EQ(Bytes(k.iv, k.iv + 12), v[std::string(c.prefix) + ".iv-expanded"]) << file << c.secret;
      EXPECT_EQ(k.seq, 0u);
      EXPECT_EQ(k.active, 1);
    }
  }
}

TEST(Records, TheNonceIsTheIvXoredWithTheSequenceNumber) {
  /* An oracle that does not share the library's nonce code: the same record
   * sealed with AES-GCM called directly, the nonce written out here. */
  Bytes key(16, 0x11), iv(12);
  for (size_t i = 0; i < 12; i++) iv[i] = static_cast<unsigned char>(0xa0 + i);
  GTLS_RecordKeys k;
  ASSERT_EQ(gtls_record_keys_from_raw(&k, GTLS_SUITE_AES_128_GCM_SHA256, key.data(), iv.data(), 0), GTLS_OK);
  const uint64_t seqs[] = {0, 1, 2, 255, 256, 0x0102030405060708ull};
  Bytes pt = {'h', 'i'};
  for (uint64_t seq : seqs) {
    k.seq = seq;
    Bytes rec = seal_one(&k, GTLS_CT_APPLICATION_DATA, pt);
    EXPECT_EQ(k.seq, seq + 1);
    Bytes nonce = iv;
    for (int i = 0; i < 8; i++) {
      nonce[11 - i] ^= static_cast<unsigned char>(seq >> (8 * i));
    }
    Bytes inner = {'h', 'i', GTLS_CT_APPLICATION_DATA};
    Bytes header = {0x17, 3, 3, 0, static_cast<unsigned char>(inner.size() + 16)};
    Bytes ct(inner.size()), tag(16);
    ASSERT_EQ(gsec_aes_gcm_encrypt(key.data(), 16, nonce.data(), 12, header.data(), 5, inner.data(),
                  inner.size(), ct.data(), tag.data(), 16),
        GSEC_OK);
    Bytes want = header;
    want.insert(want.end(), ct.begin(), ct.end());
    want.insert(want.end(), tag.begin(), tag.end());
    EXPECT_EQ(rec, want) << "sequence " << seq;
  }
}

TEST(Records, TwoRecordsOfOneContentUnderOneKeyDiffer) {
  Bytes key(16, 1), iv(12, 2);
  GTLS_RecordKeys k;
  ASSERT_EQ(gtls_record_keys_from_raw(&k, GTLS_SUITE_AES_128_GCM_SHA256, key.data(), iv.data(), 0), GTLS_OK);
  Bytes a = seal_one(&k, GTLS_CT_APPLICATION_DATA, Bytes(20, 9));
  Bytes b = seal_one(&k, GTLS_CT_APPLICATION_DATA, Bytes(20, 9));
  EXPECT_NE(a, b);
}

TEST(Records, EverySuiteSealsAndOpens) {
  for (GTLS_Suite suite : {GTLS_SUITE_AES_128_GCM_SHA256, GTLS_SUITE_AES_256_GCM_SHA384,
           GTLS_SUITE_CHACHA20_POLY1305_SHA256}) {
    Bytes secret(gtls_hash_len(gtls_suite_hash(suite)), 0x5a);
    GTLS_RecordKeys w, r;
    ASSERT_EQ(gtls_record_keys_from_secret(&w, suite, secret.data(), 0), GTLS_OK);
    ASSERT_EQ(gtls_record_keys_from_secret(&r, suite, secret.data(), 0), GTLS_OK);
    for (size_t n : {size_t(0), size_t(1), size_t(100), size_t(16384)}) {
      Bytes pt = Bytes(n, static_cast<unsigned char>(n));
      Bytes rec = seal_one(&w, GTLS_CT_APPLICATION_DATA, pt);
      EXPECT_EQ(rec.size(), 5 + n + 1 + 16);
      Bytes got;
      unsigned type = 0;
      ASSERT_EQ(open_one(&r, rec, &got, &type), GTLS_OK) << suite << " " << n;
      EXPECT_EQ(got, pt);
      EXPECT_EQ(type, GTLS_CT_APPLICATION_DATA);
    }
  }
}

TEST(Records, ASuiteKeyAndAKeyOfAnotherSuiteDoNotMix) {
  Bytes secret(32, 0x5a);
  GTLS_RecordKeys gcm, chacha;
  ASSERT_EQ(gtls_record_keys_from_secret(&gcm, GTLS_SUITE_AES_128_GCM_SHA256, secret.data(), 0), GTLS_OK);
  ASSERT_EQ(gtls_record_keys_from_secret(&chacha, GTLS_SUITE_CHACHA20_POLY1305_SHA256, secret.data(), 0),
      GTLS_OK);
  Bytes rec = seal_one(&gcm, GTLS_CT_APPLICATION_DATA, Bytes(10, 1));
  Bytes pt;
  unsigned type = 0;
  EXPECT_EQ(open_one(&chacha, rec, &pt, &type), GTLS_ERR_MISMATCH);
  EXPECT_EQ(chacha.seq, 0u) << "a failed open does not advance the counter";
}

TEST(Records, TheSequenceNumberAdvancesOnlyOnSuccess) {
  Bytes secret(32, 7);
  GTLS_RecordKeys w, r;
  ASSERT_EQ(gtls_record_keys_from_secret(&w, GTLS_SUITE_AES_128_GCM_SHA256, secret.data(), 0), GTLS_OK);
  ASSERT_EQ(gtls_record_keys_from_secret(&r, GTLS_SUITE_AES_128_GCM_SHA256, secret.data(), 0), GTLS_OK);
  Bytes rec = seal_one(&w, GTLS_CT_APPLICATION_DATA, Bytes(10, 1));
  Bytes bad = rec;
  bad.back() ^= 1;
  Bytes pt;
  unsigned type = 0;
  EXPECT_EQ(open_one(&r, bad, &pt, &type), GTLS_ERR_MISMATCH);
  EXPECT_EQ(r.seq, 0u);
  EXPECT_EQ(open_one(&r, rec, &pt, &type), GTLS_OK) << "the next, genuine, record is still number 0";
  EXPECT_EQ(r.seq, 1u);
}

TEST(Records, ARecordSealedOrOpenedTwiceAtOneNumberDoesNotOpen) {
  Bytes secret(32, 7);
  GTLS_RecordKeys w, r;
  ASSERT_EQ(gtls_record_keys_from_secret(&w, GTLS_SUITE_AES_128_GCM_SHA256, secret.data(), 0), GTLS_OK);
  ASSERT_EQ(gtls_record_keys_from_secret(&r, GTLS_SUITE_AES_128_GCM_SHA256, secret.data(), 0), GTLS_OK);
  Bytes rec = seal_one(&w, GTLS_CT_APPLICATION_DATA, Bytes(10, 1));
  Bytes pt;
  unsigned type = 0;
  ASSERT_EQ(open_one(&r, rec, &pt, &type), GTLS_OK);
  EXPECT_EQ(open_one(&r, rec, &pt, &type), GTLS_ERR_MISMATCH) << "a replay";
}

TEST(Records, TheCounterAtItsLimitRefusesInsteadOfRepeating) {
  Bytes secret(32, 7);
  GTLS_RecordKeys w, r;
  ASSERT_EQ(gtls_record_keys_from_secret(&w, GTLS_SUITE_AES_128_GCM_SHA256, secret.data(), 3), GTLS_OK);
  ASSERT_EQ(gtls_record_keys_from_secret(&r, GTLS_SUITE_AES_128_GCM_SHA256, secret.data(), 3), GTLS_OK);
  GTLS_Buf b;
  gtls_buf_init(&b, nullptr, 1 << 16);
  Bytes pt(5, 1);
  std::vector<Bytes> recs;
  for (int i = 0; i < 3; i++) {
    size_t before = b.len;
    ASSERT_EQ(gtls_record_seal(&w, GTLS_CT_APPLICATION_DATA, pt.data(), pt.size(), 0, &b), GTLS_OK);
    recs.push_back(Bytes(b.data + before, b.data + b.len));
  }
  size_t len = b.len;
  EXPECT_EQ(gtls_record_seal(&w, GTLS_CT_APPLICATION_DATA, pt.data(), pt.size(), 0, &b), GTLS_ERR_LIMIT);
  EXPECT_EQ(b.len, len) << "nothing was written";
  EXPECT_EQ(w.seq, 3u) << "and the counter did not move";
  gtls_buf_free(&b);
  for (const Bytes & rec : recs) {
    Bytes got;
    unsigned type = 0;
    EXPECT_EQ(open_one(&r, rec, &got, &type), GTLS_OK);
  }
  Bytes fourth = recs[0];
  Bytes got;
  unsigned type = 0;
  EXPECT_EQ(open_one(&r, fourth, &got, &type), GTLS_ERR_LIMIT) << "the reading side stops there too";
  /* and the counter never wraps */
  w.limit = UINT64_MAX - 1;
  w.seq = UINT64_MAX - 1;
  gtls_buf_init(&b, nullptr, 1 << 16);
  EXPECT_EQ(gtls_record_seal(&w, GTLS_CT_APPLICATION_DATA, pt.data(), pt.size(), 0, &b), GTLS_ERR_LIMIT);
  gtls_buf_free(&b);
}

TEST(Records, PaddingIsAcceptedAndCappedAndNotSentByDefault) {
  Bytes secret(32, 7);
  for (size_t pad : {size_t(1), size_t(7), size_t(255), size_t(1000)}) {
    GTLS_RecordKeys w, r;
    ASSERT_EQ(gtls_record_keys_from_secret(&w, GTLS_SUITE_AES_128_GCM_SHA256, secret.data(), 0), GTLS_OK);
    ASSERT_EQ(gtls_record_keys_from_secret(&r, GTLS_SUITE_AES_128_GCM_SHA256, secret.data(), 0), GTLS_OK);
    Bytes pt(30, 0x42);
    Bytes rec = seal_one(&w, GTLS_CT_HANDSHAKE, pt, pad);
    EXPECT_EQ(rec.size(), 5 + 30 + 1 + pad + 16);
    Bytes got;
    unsigned type = 0;
    EXPECT_EQ(open_one(&r, rec, &got, &type, pad - 1), GTLS_ERR_LIMIT) << "padding past the cap";
    EXPECT_EQ(r.seq, 0u);
    ASSERT_EQ(open_one(&r, rec, &got, &type, pad), GTLS_OK) << pad;
    EXPECT_EQ(got, pt);
    EXPECT_EQ(type, GTLS_CT_HANDSHAKE);
  }
  GTLS_RecordKeys w;
  ASSERT_EQ(gtls_record_keys_from_secret(&w, GTLS_SUITE_AES_128_GCM_SHA256, secret.data(), 0), GTLS_OK);
  Bytes rec = seal_one(&w, GTLS_CT_APPLICATION_DATA, Bytes(30, 1));
  EXPECT_EQ(rec.size(), 5u + 30 + 1 + 16) << "no padding unless asked";
}

TEST(Records, ARecordWithNothingButZerosHasNoContentType) {
  /* Built with AES-GCM directly: the library refuses to seal a type of 0. */
  Bytes key(16, 0x33), iv(12, 0x44);
  GTLS_RecordKeys r;
  ASSERT_EQ(gtls_record_keys_from_raw(&r, GTLS_SUITE_AES_128_GCM_SHA256, key.data(), iv.data(), 0), GTLS_OK);
  for (size_t n : {size_t(0), size_t(1), size_t(30)}) {
    Bytes inner(n, 0);
    Bytes header = {0x17, 3, 3, 0, static_cast<unsigned char>(n + 16)};
    Bytes ct(n), tag(16);
    ASSERT_EQ(gsec_aes_gcm_encrypt(key.data(), 16, iv.data(), 12, header.data(), 5,
                  n == 0 ? nullptr : inner.data(), n, n == 0 ? nullptr : ct.data(), tag.data(), 16),
        GSEC_OK);
    Bytes rec = header;
    rec.insert(rec.end(), ct.begin(), ct.end());
    rec.insert(rec.end(), tag.begin(), tag.end());
    Bytes got;
    unsigned type = 0;
    r.seq = 0;
    EXPECT_EQ(open_one(&r, rec, &got, &type), GTLS_ERR_PROTOCOL) << n << " zero bytes";
  }
  GTLS_RecordKeys w = r;
  GTLS_Buf b;
  gtls_buf_init(&b, nullptr, 1 << 16);
  EXPECT_EQ(gtls_record_seal(&w, 0, "x", 1, 0, &b), GTLS_ERR_INVALID) << "type 0 cannot be sealed";
  gtls_buf_free(&b);
}

TEST(Records, EveryBitOfARecordAndItsHeaderFlippedFailsToOpen) {
  Bytes secret(32, 7);
  for (GTLS_Suite suite : {GTLS_SUITE_AES_128_GCM_SHA256, GTLS_SUITE_CHACHA20_POLY1305_SHA256}) {
    Bytes sec(gtls_hash_len(gtls_suite_hash(suite)), 7);
    GTLS_RecordKeys w;
    ASSERT_EQ(gtls_record_keys_from_secret(&w, suite, sec.data(), 0), GTLS_OK);
    Bytes rec = seal_one(&w, GTLS_CT_APPLICATION_DATA, Bytes(40, 0x61));
    for (size_t i = 0; i < rec.size(); i++) {
      for (int bit = 0; bit < 8; bit++) {
        GTLS_RecordKeys r;
        ASSERT_EQ(gtls_record_keys_from_secret(&r, suite, sec.data(), 0), GTLS_OK);
        Bytes bad = rec;
        bad[i] ^= static_cast<unsigned char>(1u << bit);
        Bytes out(GTLS_RECORD_CIPHER_MAX);
        size_t out_len = 0;
        unsigned type = 0;
        /* The length is not read from the header here (the caller took the
         * body by it), so a flipped length bit is caught as additional data. */
        GTLS_Result res = gtls_record_open(&r, bad.data(), bad.data() + 5, bad.size() - 5, 16384,
            out.data(), &out_len, &type);
        EXPECT_EQ(res, GTLS_ERR_MISMATCH) << "byte " << i << " bit " << bit;
        EXPECT_EQ(r.seq, 0u);
      }
    }
  }
}

TEST(Records, TheCapsOnSizeAreTheRfcs) {
  Bytes secret(32, 7);
  GTLS_RecordKeys w;
  ASSERT_EQ(gtls_record_keys_from_secret(&w, GTLS_SUITE_AES_128_GCM_SHA256, secret.data(), 0), GTLS_OK);
  GTLS_Buf b;
  gtls_buf_init(&b, nullptr, 1 << 20);
  Bytes big(16385, 1);
  EXPECT_EQ(gtls_record_seal(&w, GTLS_CT_APPLICATION_DATA, big.data(), big.size(), 0, &b), GTLS_ERR_LIMIT)
      << "2^14 + 1 bytes of content do not fit a record";
  EXPECT_EQ(gtls_record_seal(&w, GTLS_CT_APPLICATION_DATA, big.data(), 16384, 0, &b), GTLS_OK);
  EXPECT_EQ(b.len, 5u + 16384 + 1 + 16);
  EXPECT_LE(b.len - 5, GTLS_RECORD_CIPHER_MAX);
  EXPECT_EQ(gtls_record_plain(GTLS_CT_HANDSHAKE, 0x0303, big.data(), big.size(), &b), GTLS_ERR_LIMIT);
  gtls_buf_free(&b);

  GTLS_RecordKeys r;
  ASSERT_EQ(gtls_record_keys_from_secret(&r, GTLS_SUITE_AES_128_GCM_SHA256, secret.data(), 0), GTLS_OK);
  Bytes header = {0x17, 3, 3, 0x41, 0x01};
  Bytes ct(GTLS_RECORD_CIPHER_MAX + 1, 0);
  Bytes out(GTLS_RECORD_CIPHER_MAX);
  size_t n = 0;
  unsigned type = 0;
  EXPECT_EQ(gtls_record_open(&r, header.data(), ct.data(), GTLS_RECORD_CIPHER_MAX + 1, 100, out.data(), &n, &type),
      GTLS_ERR_LIMIT);
  EXPECT_EQ(gtls_record_open(&r, header.data(), ct.data(), 15, 100, out.data(), &n, &type), GTLS_ERR_MISMATCH)
      << "too short to hold a tag";
  EXPECT_EQ(gtls_record_open(&r, header.data(), ct.data(), 0, 100, out.data(), &n, &type), GTLS_ERR_MISMATCH);
  EXPECT_EQ(gtls_record_open(&r, header.data(), ct.data(), 16, 100, out.data(), &n, &type), GTLS_ERR_MISMATCH)
      << "a tag that does not verify";
}

TEST(Records, ABufferThatIsFullRefusesTheRecordAndKeepsTheCounter) {
  Bytes secret(32, 7);
  GTLS_RecordKeys w;
  ASSERT_EQ(gtls_record_keys_from_secret(&w, GTLS_SUITE_AES_128_GCM_SHA256, secret.data(), 0), GTLS_OK);
  GTLS_Buf b;
  gtls_buf_init(&b, nullptr, 34);
  Bytes pt(30, 1);
  EXPECT_EQ(gtls_record_seal(&w, GTLS_CT_APPLICATION_DATA, pt.data(), pt.size(), 0, &b), GTLS_ERR_LIMIT);
  EXPECT_EQ(w.seq, 0u);
  EXPECT_EQ(b.len, 0u);
  EXPECT_EQ(gtls_record_plain(GTLS_CT_HANDSHAKE, 0x0303, pt.data(), pt.size(), &b), GTLS_ERR_LIMIT);
  EXPECT_EQ(b.len, 0u);
  gtls_buf_free(&b);
}

TEST(Records, ThePlainRecordIsAHeaderAndTheBytes) {
  GTLS_Buf b;
  gtls_buf_init(&b, nullptr, 1000);
  Bytes pt = {1, 2, 3};
  ASSERT_EQ(gtls_record_plain(GTLS_CT_HANDSHAKE, 0x0301, pt.data(), pt.size(), &b), GTLS_OK);
  EXPECT_EQ(Bytes(b.data, b.data + b.len), (Bytes{22, 3, 1, 0, 3, 1, 2, 3}));
  gtls_buf_free(&b);
}

TEST(Records, TheNextSecretIsHkdfExpandLabelOfTrafficUpd) {
  /* The label and the context are written out here, apart from the
   * library's gtls_hkdf_expand_label: HkdfLabel is the length, "tls13 "
   * and the label, and an empty context. */
  for (GTLS_Suite suite : {GTLS_SUITE_AES_128_GCM_SHA256, GTLS_SUITE_AES_256_GCM_SHA384}) {
    size_t hlen = gtls_hash_len(gtls_suite_hash(suite));
    Bytes secret(hlen);
    for (size_t i = 0; i < hlen; i++) secret[i] = static_cast<unsigned char>(i * 3 + 1);
    const std::string label = "tls13 traffic upd";
    Bytes info = {static_cast<unsigned char>(hlen >> 8), static_cast<unsigned char>(hlen),
        static_cast<unsigned char>(label.size())};
    info.insert(info.end(), label.begin(), label.end());
    info.push_back(0);
    Bytes want(hlen);
    ASSERT_EQ(gsec_hkdf_expand(suite == GTLS_SUITE_AES_128_GCM_SHA256 ? GSEC_HKDF_SHA256 : GSEC_HKDF_SHA384,
                  secret.data(), hlen, info.data(), info.size(), want.data(), hlen),
        GSEC_OK);
    Bytes got(hlen);
    ASSERT_EQ(t_record_next_secret(suite, secret.data(), got.data()), GTLS_OK);
    EXPECT_EQ(got, want);
    /* in place */
    Bytes inplace = secret;
    ASSERT_EQ(t_record_next_secret(suite, inplace.data(), inplace.data()), GTLS_OK);
    EXPECT_EQ(inplace, want);
    EXPECT_NE(got, secret);
  }
  Bytes out(32);
  EXPECT_EQ(t_record_next_secret(static_cast<uint32_t>(0), out.data(), out.data()), GTLS_ERR_INVALID);
}

TEST(Records, WipingAKeyZeroesEveryByteOfIt) {
  Bytes secret(32, 7);
  GTLS_RecordKeys k;
  ASSERT_EQ(gtls_record_keys_from_secret(&k, GTLS_SUITE_AES_128_GCM_SHA256, secret.data(), 5), GTLS_OK);
  gtls_record_keys_wipe(&k);
  const unsigned char * p = reinterpret_cast<const unsigned char *>(&k);
  unsigned acc = 0;
  for (size_t i = 0; i < sizeof k; i++) acc |= p[i];
  EXPECT_EQ(acc, 0u);
  GTLS_Buf b;
  gtls_buf_init(&b, nullptr, 1000);
  EXPECT_EQ(gtls_record_seal(&k, GTLS_CT_APPLICATION_DATA, "x", 1, 0, &b), GTLS_ERR_INVALID)
      << "a wiped key is not a key";
  gtls_buf_free(&b);
  gtls_record_keys_wipe(nullptr);
}

TEST(Records, ArgumentsAreChecked) {
  GTLS_RecordKeys k;
  Bytes key(32, 1), iv(12, 2);
  EXPECT_EQ(gtls_record_keys_from_raw(nullptr, GTLS_SUITE_AES_128_GCM_SHA256, key.data(), iv.data(), 0), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_record_keys_from_raw(&k, 0, key.data(), iv.data(), 0), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_record_keys_from_raw(&k, GTLS_SUITE_AES_128_GCM_SHA256, nullptr, iv.data(), 0), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_record_keys_from_secret(&k, GTLS_SUITE_AES_128_GCM_SHA256, nullptr, 0), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_record_keys_from_secret(&k, 0x9999, key.data(), 0), GTLS_ERR_INVALID);
  GTLS_Buf b;
  gtls_buf_init(&b, nullptr, 1000);
  ASSERT_EQ(gtls_record_keys_from_raw(&k, GTLS_SUITE_AES_128_GCM_SHA256, key.data(), iv.data(), 0), GTLS_OK);
  EXPECT_EQ(gtls_record_seal(&k, 256, "x", 1, 0, &b), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_record_seal(&k, 23, nullptr, 3, 0, &b), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_record_seal(nullptr, 23, "x", 1, 0, &b), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_record_plain(23, 0x0303, nullptr, 3, &b), GTLS_ERR_INVALID);
  gtls_buf_free(&b);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
