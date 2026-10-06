/**
 * @file
 *
 * Handshake message encoding and decoding: the ClientHello builder and its
 * retry transform, and every parser, each against well-formed input, against
 * every truncation of it, and against the caps in GTLS_Limits.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

using namespace gtlstest;

namespace {

void put16(Bytes & b, unsigned v) { b.push_back(v >> 8); b.push_back(v & 255); }
void put24(Bytes & b, unsigned v) { b.push_back(v >> 16); b.push_back((v >> 8) & 255); b.push_back(v & 255); }
void put(Bytes & b, const Bytes & o) { b.insert(b.end(), o.begin(), o.end()); }

Bytes ext(unsigned type, const Bytes & data) {
  Bytes e;
  put16(e, type);
  put16(e, data.size());
  put(e, data);
  return e;
}

Bytes ext_block(const std::vector<Bytes> & exts) {
  Bytes body;
  for (const Bytes & e : exts) {
    put(body, e);
  }
  Bytes out;
  put16(out, body.size());
  put(out, body);
  return out;
}

GTLS_Limits limits() {
  GTLS_Limits l;
  gtls_limits_default(&l);
  return l;
}

GTLS_HelloParams params() {
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
  return p;
}

Bytes build(const GTLS_HelloParams & p) {
  GTLS_Buf b;
  gtls_buf_init(&b, nullptr, 1 << 20);
  EXPECT_EQ(gtls_msg_build_client_hello(&p, &b), GTLS_OK);
  Bytes out(b.data, b.data + b.len);
  gtls_buf_free(&b);
  return out;
}

GTLS_Result parse_hello(const Bytes & msg, GTLS_ClientHello * h) {
  GTLS_Limits l = limits();
  return gtls_msg_parse_client_hello(msg.data() + 4, msg.size() - 4, &l, h);
}

Bytes body_of(const Bytes & msg) { return Bytes(msg.begin() + 4, msg.end()); }

}  // namespace

/* ------------------------------------------------------------ ClientHello */

TEST(ClientHello, HeaderLengthsAreTheLengthsOfWhatFollows) {
  Bytes m = build(params());
  ASSERT_GT(m.size(), 4u);
  EXPECT_EQ(m[0], 1);
  EXPECT_EQ((size_t(m[1]) << 16 | size_t(m[2]) << 8 | m[3]), m.size() - 4);
  GTLS_ClientHello h;
  ASSERT_EQ(parse_hello(m, &h), GTLS_OK) << "the whole body is consumed, to the byte";
}

TEST(ClientHello, CarriesWhatWasAskedFor) {
  GTLS_HelloParams p = params();
  Bytes m = build(p);
  GTLS_ClientHello h;
  ASSERT_EQ(parse_hello(m, &h), GTLS_OK);
  EXPECT_EQ(h.legacy_version, 0x0303u);
  EXPECT_EQ(Bytes(h.random, h.random + 32), Bytes(p.random, p.random + 32));
  EXPECT_EQ(h.session_id_len, 0u) << "empty unless middlebox compatibility asks";
  EXPECT_EQ(Bytes(h.suites, h.suites + h.suites_len),
      (Bytes{0x13, 0x01, 0x13, 0x03, 0x13, 0x02}));

  const GTLS_Ext * sv = gtls_msg_find_ext(h.exts, h.ext_count, GTLS_EXT_SUPPORTED_VERSIONS);
  ASSERT_NE(sv, nullptr);
  EXPECT_EQ(Bytes(sv->data, sv->data + sv->len), (Bytes{2, 3, 4})) << "TLS 1.3 only";

  const GTLS_Ext * sn = gtls_msg_find_ext(h.exts, h.ext_count, GTLS_EXT_SERVER_NAME);
  ASSERT_NE(sn, nullptr);
  Bytes want_sni = {0, 14, 0, 0, 11};
  want_sni.insert(want_sni.end(), {'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'});
  EXPECT_EQ(Bytes(sn->data, sn->data + sn->len), want_sni);

  const GTLS_Ext * g = gtls_msg_find_ext(h.exts, h.ext_count, GTLS_EXT_SUPPORTED_GROUPS);
  ASSERT_NE(g, nullptr);
  EXPECT_EQ(Bytes(g->data, g->data + g->len),
      (Bytes{0, 6, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18}));

  const GTLS_Ext * sa = gtls_msg_find_ext(h.exts, h.ext_count, GTLS_EXT_SIGNATURE_ALGORITHMS);
  ASSERT_NE(sa, nullptr);
  EXPECT_EQ(Bytes(sa->data, sa->data + sa->len), (Bytes{0, 4, 0x08, 0x04, 0x08, 0x07}));

  const GTLS_Ext * ks = gtls_msg_find_ext(h.exts, h.ext_count, GTLS_EXT_KEY_SHARE);
  ASSERT_NE(ks, nullptr);
  ASSERT_EQ(ks->len, 2u + 4u + 32u);
  EXPECT_EQ(Bytes(ks->data, ks->data + 6), (Bytes{0, 36, 0x00, 0x1d, 0, 32}));
  EXPECT_EQ(Bytes(ks->data + 6, ks->data + ks->len), Bytes(p.share.pub, p.share.pub + 32));

  EXPECT_EQ(gtls_msg_find_ext(h.exts, h.ext_count, GTLS_EXT_ALPN), nullptr);
  EXPECT_EQ(gtls_msg_find_ext(h.exts, h.ext_count, GTLS_EXT_COOKIE), nullptr);
  EXPECT_EQ(gtls_msg_find_ext(h.exts, h.ext_count, GTLS_EXT_PRE_SHARED_KEY), nullptr)
      << "no PSK is offered";
}

TEST(ClientHello, NoServerNameForAnIpLiteralAndAlpnWhenAsked) {
  GTLS_HelloParams p = params();
  p.host = nullptr;
  p.host_len = 0;
  const unsigned char alpn[] = {2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
  p.alpn = alpn;
  p.alpn_len = sizeof alpn;
  GTLS_ClientHello h;
  Bytes m = build(p);
  ASSERT_EQ(parse_hello(m, &h), GTLS_OK);
  EXPECT_EQ(gtls_msg_find_ext(h.exts, h.ext_count, GTLS_EXT_SERVER_NAME), nullptr);
  const GTLS_Ext * a = gtls_msg_find_ext(h.exts, h.ext_count, GTLS_EXT_ALPN);
  ASSERT_NE(a, nullptr);
  EXPECT_EQ(a->len, 2u + sizeof alpn);
  EXPECT_EQ(Bytes(a->data, a->data + 2), (Bytes{0, 12}));
}

TEST(ClientHello, SessionIdForMiddleboxCompatibilityIsThirtyTwoBytesAndEchoed) {
  GTLS_HelloParams p = params();
  p.session_id_len = 32;
  for (int i = 0; i < 32; i++) {
    p.session_id[i] = static_cast<unsigned char>(0xa0 + i);
  }
  GTLS_ClientHello h;
  const Bytes m = build(p);  /* the views in h point into this */
  ASSERT_EQ(parse_hello(m, &h), GTLS_OK);
  EXPECT_EQ(h.session_id_len, 32u);
  EXPECT_EQ(h.session_id[0], 0xa0);
  p.session_id_len = 31;
  GTLS_Buf b;
  gtls_buf_init(&b, nullptr, 4096);
  EXPECT_EQ(gtls_msg_build_client_hello(&p, &b), GTLS_ERR_INVALID);
  gtls_buf_free(&b);
}

/* RFC 7685: a hello of 256 to 511 bytes upsets some servers, so it is padded
 * to 512. Swept over every size that range and its edges can be reached at. */
TEST(ClientHello, PaddingKeepsEveryLengthOutOfTwoFiftySixToFiveEleven) {
  bool padded = false;
  bool unpadded_small = false;
  bool large = false;
  for (size_t alpn_len = 0; alpn_len < 700; alpn_len += 1) {
    GTLS_HelloParams p = params();
    Bytes alpn;
    if (alpn_len >= 2) {
      /* protocol names of up to 200 bytes, each with its length byte, until
       * alpn_len bytes are used */
      size_t left = alpn_len;
      while (left >= 2) {
        size_t name = left - 1 > 200 ? 200 : left - 1;
        alpn.push_back(static_cast<unsigned char>(name));
        alpn.insert(alpn.end(), name, 'p');
        left -= name + 1;
      }
      p.alpn = alpn.data();
      p.alpn_len = alpn.size();
    }
    Bytes m = build(p);
    GTLS_ClientHello h;
    ASSERT_EQ(parse_hello(m, &h), GTLS_OK) << alpn_len;
    EXPECT_TRUE(m.size() < 256 || m.size() >= 512) << "length " << m.size();
    const GTLS_Ext * pad = gtls_msg_find_ext(h.exts, h.ext_count, GTLS_EXT_PADDING);
    if (pad != nullptr) {
      padded = true;
      for (size_t i = 0; i < pad->len; i++) {
        EXPECT_EQ(pad->data[i], 0);
      }
      EXPECT_LE(m.size(), 515u);
      EXPECT_EQ(pad->data + pad->len, m.data() + m.size()) << "padding is last";
    } else if (m.size() < 256) {
      unpadded_small = true;
    } else {
      large = true;
    }
  }
  EXPECT_TRUE(padded);
  EXPECT_TRUE(unpadded_small);
  EXPECT_TRUE(large);
}

TEST(ClientHello, RejectsParametersThatCannotBeEncoded) {
  GTLS_Buf b;
  GTLS_HelloParams p = params();
  p.suite_count = 0;
  gtls_buf_init(&b, nullptr, 4096);
  EXPECT_EQ(gtls_msg_build_client_hello(&p, &b), GTLS_ERR_INVALID);
  gtls_buf_free(&b);
  p = params();
  p.group_count = 0;
  gtls_buf_init(&b, nullptr, 4096);
  EXPECT_EQ(gtls_msg_build_client_hello(&p, &b), GTLS_ERR_INVALID);
  gtls_buf_free(&b);
  p = params();
  gtls_buf_init(&b, nullptr, 100);
  EXPECT_EQ(gtls_msg_build_client_hello(&p, &b), GTLS_ERR_LIMIT) << "the buffer's ceiling";
  gtls_buf_free(&b);
}

TEST(ClientHello, EveryTruncationOfTheBodyIsRefused) {
  Bytes body = body_of(build(params()));
  GTLS_Limits l = limits();
  for (size_t n = 0; n < body.size(); n++) {
    GTLS_ClientHello h;
    EXPECT_NE(gtls_msg_parse_client_hello(body.data(), n, &l, &h), GTLS_OK) << n;
  }
}

TEST(ClientHello, ATrailingByteIsRefused) {
  Bytes body = body_of(build(params()));
  body.push_back(0);
  GTLS_Limits l = limits();
  GTLS_ClientHello h;
  EXPECT_EQ(gtls_msg_parse_client_hello(body.data(), body.size(), &l, &h), GTLS_ERR_CORRUPT);
}

/* The retry transform. */

TEST(RetryClientHello, ReplacesTheShareAddsTheCookieAndKeepsTheRest) {
  GTLS_HelloParams p = params();
  Bytes m1 = build(p);
  GTLS_KeyShare share;
  std::memset(&share, 0, sizeof share);
  share.group = GTLS_GROUP_SECP256R1;
  share.pub_len = 65;
  share.pub[0] = 4;
  for (int i = 1; i < 65; i++) {
    share.pub[i] = static_cast<unsigned char>(i);
  }
  const Bytes cookie = {9, 8, 7, 6};
  GTLS_Buf b;
  GTLS_Limits l = limits();
  gtls_buf_init(&b, nullptr, 1 << 16);
  ASSERT_EQ(gtls_msg_retry_client_hello(m1.data(), m1.size(), &share, cookie.data(),
                cookie.size(), &l, &b), GTLS_OK);
  Bytes m2(b.data, b.data + b.len);
  gtls_buf_free(&b);

  GTLS_ClientHello h1;
  GTLS_ClientHello h2;
  ASSERT_EQ(parse_hello(m1, &h1), GTLS_OK);
  ASSERT_EQ(parse_hello(m2, &h2), GTLS_OK);
  EXPECT_EQ(Bytes(h2.random, h2.random + 32), Bytes(h1.random, h1.random + 32))
      << "same random (RFC 8446 section 4.1.2)";
  EXPECT_EQ(h2.suites_len, h1.suites_len);
  const GTLS_Ext * ks = gtls_msg_find_ext(h2.exts, h2.ext_count, GTLS_EXT_KEY_SHARE);
  ASSERT_NE(ks, nullptr);
  EXPECT_EQ(Bytes(ks->data, ks->data + 6), (Bytes{0, 69, 0x00, 0x17, 0, 65}));
  const GTLS_Ext * ck = gtls_msg_find_ext(h2.exts, h2.ext_count, GTLS_EXT_COOKIE);
  ASSERT_NE(ck, nullptr);
  EXPECT_EQ(Bytes(ck->data, ck->data + ck->len), (Bytes{0, 4, 9, 8, 7, 6}));
  /* Every other extension, in order and byte for byte. */
  size_t j = 0;
  for (size_t i = 0; i < h1.ext_count; i++) {
    if (h1.exts[i].type == GTLS_EXT_KEY_SHARE || h1.exts[i].type == GTLS_EXT_PADDING) {
      continue;
    }
    while (j < h2.ext_count && (h2.exts[j].type == GTLS_EXT_COOKIE ||
                                   h2.exts[j].type == GTLS_EXT_KEY_SHARE ||
                                   h2.exts[j].type == GTLS_EXT_PADDING)) {
      j++;
    }
    ASSERT_LT(j, h2.ext_count);
    EXPECT_EQ(h2.exts[j].type, h1.exts[i].type);
    EXPECT_EQ(Bytes(h2.exts[j].data, h2.exts[j].data + h2.exts[j].len),
        Bytes(h1.exts[i].data, h1.exts[i].data + h1.exts[i].len));
    j++;
  }
}

TEST(RetryClientHello, CookieOnlyKeepsTheShareAndCookieGoesBeforePskModes) {
  GTLS_HelloParams p = params();
  Bytes m1 = build(p);
  /* Splice a psk_key_exchange_modes extension in before key_share, to see
   * where the cookie lands relative to it. */
  GTLS_ClientHello h;
  ASSERT_EQ(parse_hello(m1, &h), GTLS_OK);
  Bytes body = body_of(m1);
  Bytes prefix(body.begin(), body.begin() + h.prefix_len);
  std::vector<Bytes> exts;
  for (size_t i = 0; i < h.ext_count; i++) {
    exts.push_back(ext(h.exts[i].type, Bytes(h.exts[i].data, h.exts[i].data + h.exts[i].len)));
  }
  exts.push_back(ext(GTLS_EXT_PSK_KEY_EXCHANGE_MODES, Bytes{1, 1}));
  Bytes body2 = prefix;
  put(body2, ext_block(exts));
  Bytes m;
  m.push_back(1);
  put24(m, body2.size());
  put(m, body2);

  const Bytes cookie = {1, 2, 3};
  GTLS_Buf b;
  GTLS_Limits l = limits();
  gtls_buf_init(&b, nullptr, 1 << 16);
  ASSERT_EQ(gtls_msg_retry_client_hello(m.data(), m.size(), nullptr, cookie.data(), 3, &l, &b),
      GTLS_OK);
  Bytes m2(b.data, b.data + b.len);
  gtls_buf_free(&b);
  GTLS_ClientHello h2;
  ASSERT_EQ(parse_hello(m2, &h2), GTLS_OK);
  size_t cookie_at = h2.ext_count;
  size_t modes_at = h2.ext_count;
  for (size_t i = 0; i < h2.ext_count; i++) {
    if (h2.exts[i].type == GTLS_EXT_COOKIE) cookie_at = i;
    if (h2.exts[i].type == GTLS_EXT_PSK_KEY_EXCHANGE_MODES) modes_at = i;
  }
  ASSERT_LT(cookie_at, h2.ext_count);
  ASSERT_LT(modes_at, h2.ext_count);
  EXPECT_EQ(cookie_at + 1, modes_at) << "immediately before psk_key_exchange_modes";
  /* The share was not replaced. */
  const GTLS_Ext * ks1 = gtls_msg_find_ext(h.exts, h.ext_count, GTLS_EXT_KEY_SHARE);
  const GTLS_Ext * ks2 = gtls_msg_find_ext(h2.exts, h2.ext_count, GTLS_EXT_KEY_SHARE);
  ASSERT_NE(ks2, nullptr);
  EXPECT_EQ(Bytes(ks2->data, ks2->data + ks2->len), Bytes(ks1->data, ks1->data + ks1->len));
}

TEST(RetryClientHello, WithoutPskModesTheCookieIsLast) {
  Bytes m1 = build(params());
  const Bytes cookie = {5, 5};
  GTLS_Buf b;
  GTLS_Limits l = limits();
  gtls_buf_init(&b, nullptr, 1 << 16);
  ASSERT_EQ(gtls_msg_retry_client_hello(m1.data(), m1.size(), nullptr, cookie.data(), 2, &l, &b),
      GTLS_OK);
  Bytes m2(b.data, b.data + b.len);
  gtls_buf_free(&b);
  GTLS_ClientHello h;
  ASSERT_EQ(parse_hello(m2, &h), GTLS_OK);
  EXPECT_EQ(h.exts[h.ext_count - 1].type, GTLS_EXT_COOKIE);
}

TEST(RetryClientHello, RefusesWhatIsNotAClientHello) {
  GTLS_Buf b;
  GTLS_Limits l = limits();
  gtls_buf_init(&b, nullptr, 1 << 16);
  Bytes m = build(params());
  EXPECT_EQ(gtls_msg_retry_client_hello(m.data(), m.size() - 1, nullptr, nullptr, 0, &l, &b),
      GTLS_ERR_INVALID) << "header length disagrees with the data";
  m[0] = 2;
  EXPECT_EQ(gtls_msg_retry_client_hello(m.data(), m.size(), nullptr, nullptr, 0, &l, &b),
      GTLS_ERR_INVALID);
  gtls_buf_free(&b);
}

/* ------------------------------------------------------------ ServerHello */

namespace {

Bytes server_hello_body(const std::vector<Bytes> & exts, bool with_ext_block = true,
    unsigned suite = 0x1301, const Bytes * random = nullptr, unsigned session_len = 0) {
  Bytes b;
  put16(b, 0x0303);
  if (random != nullptr) {
    put(b, *random);
  } else {
    b.insert(b.end(), 32, 0x11);
  }
  b.push_back(session_len);
  b.insert(b.end(), session_len, 0x22);
  put16(b, suite);
  b.push_back(0);
  if (with_ext_block) {
    put(b, ext_block(exts));
  }
  return b;
}

Bytes versions13() { return ext(GTLS_EXT_SUPPORTED_VERSIONS, Bytes{3, 4}); }
Bytes keyshare(unsigned group, const Bytes & kx) {
  Bytes d;
  put16(d, group);
  put16(d, kx.size());
  put(d, kx);
  return ext(GTLS_EXT_KEY_SHARE, d);
}

}  // namespace

TEST(ServerHello, ParsesTheSimpleCase) {
  GTLS_Limits l = limits();
  Bytes kx(32, 0x77);
  Bytes body = server_hello_body({keyshare(0x1d, kx), versions13()});
  GTLS_ServerHello s;
  ASSERT_EQ(gtls_msg_parse_server_hello(body.data(), body.size(), &l, &s), GTLS_OK);
  EXPECT_FALSE(s.is_hrr);
  EXPECT_EQ(s.legacy_version, 0x0303u);
  EXPECT_EQ(s.suite, 0x1301u);
  EXPECT_EQ(s.compression, 0u);
  EXPECT_EQ(s.selected_version, 0x0304u);
  EXPECT_EQ(s.group, 0x1du);
  EXPECT_EQ(s.key_exchange_len, 32u);
  EXPECT_EQ(s.flags, GTLS_SH_FLAG_VERSION | GTLS_SH_FLAG_KEY_SHARE);
}

TEST(ServerHello, TheHrrRandomMakesItAnHrrWhoseKeyShareIsOnlyAGroup) {
  GTLS_Limits l = limits();
  Bytes hrr(32);
  ASSERT_EQ(gsec_sha256("HelloRetryRequest", 17, hrr.data()), GSEC_OK)
      << "RFC 8446 section 4.1.3 defines the value as this hash";
  EXPECT_TRUE(gtls_msg_is_hrr_random(hrr.data()));
  Bytes other = hrr;
  other[31] ^= 1;
  EXPECT_FALSE(gtls_msg_is_hrr_random(other.data()));
  Bytes group;
  put16(group, 0x17);
  Bytes cookie;
  put16(cookie, 3);
  cookie.insert(cookie.end(), {1, 2, 3});
  Bytes body = server_hello_body({ext(GTLS_EXT_KEY_SHARE, group),
      ext(GTLS_EXT_COOKIE, cookie), versions13()}, true, 0x1301, &hrr);
  GTLS_ServerHello s;
  ASSERT_EQ(gtls_msg_parse_server_hello(body.data(), body.size(), &l, &s), GTLS_OK);
  EXPECT_TRUE(s.is_hrr);
  EXPECT_EQ(s.group, 0x17u);
  EXPECT_EQ(s.cookie_len, 3u);
  EXPECT_EQ(s.flags & GTLS_SH_FLAG_COOKIE, GTLS_SH_FLAG_COOKIE);
}

TEST(ServerHello, ADowngradeSentinelIsRecognisedAtTheEndOfTheRandom) {
  Bytes r(32, 0);
  EXPECT_EQ(gtls_msg_downgrade_sentinel(r.data()), 0);
  const unsigned char tail[7] = {0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44};
  std::memcpy(r.data() + 24, tail, 7);
  r[31] = 1;
  EXPECT_EQ(gtls_msg_downgrade_sentinel(r.data()), 2) << "TLS 1.2";
  r[31] = 0;
  EXPECT_EQ(gtls_msg_downgrade_sentinel(r.data()), 3) << "TLS 1.1 or below";
  r[31] = 2;
  EXPECT_EQ(gtls_msg_downgrade_sentinel(r.data()), 0) << "the last byte decides";
  r[31] = 1;
  r[24] ^= 1;
  EXPECT_EQ(gtls_msg_downgrade_sentinel(r.data()), 0);
}

TEST(ServerHello, FlagsPskAndUnknownExtensionsInsteadOfIgnoringThem) {
  GTLS_Limits l = limits();
  Bytes body = server_hello_body({versions13(), ext(GTLS_EXT_PRE_SHARED_KEY, Bytes{0, 0}),
      ext(0x1234, Bytes{1})});
  GTLS_ServerHello s;
  ASSERT_EQ(gtls_msg_parse_server_hello(body.data(), body.size(), &l, &s), GTLS_OK);
  EXPECT_NE(s.flags & GTLS_SH_FLAG_PSK, 0u);
  EXPECT_NE(s.flags & GTLS_SH_FLAG_UNKNOWN, 0u);
  EXPECT_EQ(s.unknown_ext, 0x1234u);
}

TEST(ServerHello, NoExtensionBlockIsAnOlderServerNotAParseError) {
  GTLS_Limits l = limits();
  Bytes body = server_hello_body({}, false);
  GTLS_ServerHello s;
  ASSERT_EQ(gtls_msg_parse_server_hello(body.data(), body.size(), &l, &s), GTLS_OK);
  EXPECT_EQ(s.flags, 0u) << "so the caller sees 'no supported_versions'";
}

TEST(ServerHello, EveryOtherTruncationIsRefused) {
  GTLS_Limits l = limits();
  Bytes body = server_hello_body({keyshare(0x1d, Bytes(32, 1)), versions13()});
  const size_t after_compression = 2 + 32 + 1 + 2 + 1;
  for (size_t n = 0; n < body.size(); n++) {
    GTLS_ServerHello s;
    GTLS_Result r = gtls_msg_parse_server_hello(body.data(), n, &l, &s);
    if (n == after_compression) {
      EXPECT_EQ(r, GTLS_OK) << "the one cut that is a valid pre-1.3 hello";
    } else {
      EXPECT_EQ(r, GTLS_ERR_CORRUPT) << n;
    }
  }
}

TEST(ServerHello, DuplicateExtensionsAreAProtocolError) {
  GTLS_Limits l = limits();
  Bytes body = server_hello_body({versions13(), versions13()});
  GTLS_ServerHello s;
  EXPECT_EQ(gtls_msg_parse_server_hello(body.data(), body.size(), &l, &s), GTLS_ERR_PROTOCOL);
}

TEST(ServerHello, CookieLargerThanTheLimitIsALimitNotATruncation) {
  GTLS_Limits l = limits();
  l.max_cookie_bytes = 8;
  Bytes cookie;
  put16(cookie, 9);
  cookie.insert(cookie.end(), 9, 7);
  Bytes hrr(32);
  ASSERT_EQ(gsec_sha256("HelloRetryRequest", 17, hrr.data()), GSEC_OK);
  Bytes body = server_hello_body({ext(GTLS_EXT_COOKIE, cookie), versions13()}, true, 0x1301, &hrr);
  GTLS_ServerHello s;
  EXPECT_EQ(gtls_msg_parse_server_hello(body.data(), body.size(), &l, &s), GTLS_ERR_LIMIT);
  l.max_cookie_bytes = 9;
  EXPECT_EQ(gtls_msg_parse_server_hello(body.data(), body.size(), &l, &s), GTLS_OK);
}

TEST(ServerHello, MoreExtensionsThanTheLimitIsALimit) {
  GTLS_Limits l = limits();
  l.max_extensions = 3;
  Bytes body = server_hello_body({versions13(), ext(0x100, {}), ext(0x101, {}), ext(0x102, {})});
  GTLS_ServerHello s;
  EXPECT_EQ(gtls_msg_parse_server_hello(body.data(), body.size(), &l, &s), GTLS_ERR_LIMIT);
  l.max_extensions = 4;
  EXPECT_EQ(gtls_msg_parse_server_hello(body.data(), body.size(), &l, &s), GTLS_OK);
}

TEST(ServerHello, SessionIdLongerThanThirtyTwoIsRefused) {
  GTLS_Limits l = limits();
  Bytes body = server_hello_body({versions13()}, true, 0x1301, nullptr, 33);
  GTLS_ServerHello s;
  EXPECT_EQ(gtls_msg_parse_server_hello(body.data(), body.size(), &l, &s), GTLS_ERR_CORRUPT);
}

/* ----------------------------------------------------- EncryptedExtensions */

TEST(EncryptedExtensions, ParsesAlpnAndServerNameAndListsTheTypes) {
  GTLS_Limits l = limits();
  Bytes alpn = {0, 3, 2, 'h', '2'};
  Bytes body = ext_block({ext(GTLS_EXT_ALPN, alpn), ext(GTLS_EXT_SERVER_NAME, {}),
      ext(GTLS_EXT_SUPPORTED_GROUPS, Bytes{0, 2, 0, 0x1d})});
  GTLS_EncryptedExtensions e;
  ASSERT_EQ(gtls_msg_parse_encrypted_extensions(body.data(), body.size(), &l, &e), GTLS_OK);
  EXPECT_TRUE(e.has_alpn);
  EXPECT_EQ(Bytes(e.alpn, e.alpn + e.alpn_len), (Bytes{'h', '2'}));
  EXPECT_TRUE(e.has_server_name);
  EXPECT_EQ(e.ext_count, 3u);
}

TEST(EncryptedExtensions, EmptyIsFine) {
  GTLS_Limits l = limits();
  Bytes body = {0, 0};
  GTLS_EncryptedExtensions e;
  ASSERT_EQ(gtls_msg_parse_encrypted_extensions(body.data(), body.size(), &l, &e), GTLS_OK);
  EXPECT_EQ(e.ext_count, 0u);
  EXPECT_FALSE(e.has_alpn);
}

TEST(EncryptedExtensions, AlpnMustNameExactlyOneProtocol) {
  GTLS_Limits l = limits();
  GTLS_EncryptedExtensions e;
  Bytes two = ext_block({ext(GTLS_EXT_ALPN, Bytes{0, 6, 2, 'h', '2', 1, 'x'})});
  EXPECT_EQ(gtls_msg_parse_encrypted_extensions(two.data(), two.size(), &l, &e), GTLS_ERR_CORRUPT);
  Bytes none = ext_block({ext(GTLS_EXT_ALPN, Bytes{0, 0})});
  EXPECT_EQ(gtls_msg_parse_encrypted_extensions(none.data(), none.size(), &l, &e), GTLS_ERR_CORRUPT);
  Bytes empty_name = ext_block({ext(GTLS_EXT_ALPN, Bytes{0, 1, 0})});
  EXPECT_EQ(gtls_msg_parse_encrypted_extensions(empty_name.data(), empty_name.size(), &l, &e),
      GTLS_ERR_CORRUPT);
  Bytes trailing = ext_block({ext(GTLS_EXT_ALPN, Bytes{0, 3, 2, 'h', '2', 0})});
  EXPECT_EQ(gtls_msg_parse_encrypted_extensions(trailing.data(), trailing.size(), &l, &e),
      GTLS_ERR_CORRUPT);
}

TEST(EncryptedExtensions, ServerNameMustBeEmpty) {
  GTLS_Limits l = limits();
  GTLS_EncryptedExtensions e;
  Bytes body = ext_block({ext(GTLS_EXT_SERVER_NAME, Bytes{0, 0})});
  EXPECT_EQ(gtls_msg_parse_encrypted_extensions(body.data(), body.size(), &l, &e), GTLS_ERR_PROTOCOL);
}

TEST(EncryptedExtensions, EveryTruncationAndATrailingByteAreRefused) {
  GTLS_Limits l = limits();
  Bytes body = ext_block({ext(GTLS_EXT_ALPN, Bytes{0, 3, 2, 'h', '2'}), ext(GTLS_EXT_SERVER_NAME, {})});
  for (size_t n = 0; n < body.size(); n++) {
    GTLS_EncryptedExtensions e;
    EXPECT_NE(gtls_msg_parse_encrypted_extensions(body.data(), n, &l, &e), GTLS_OK) << n;
  }
  body.push_back(0);
  GTLS_EncryptedExtensions e;
  EXPECT_EQ(gtls_msg_parse_encrypted_extensions(body.data(), body.size(), &l, &e), GTLS_ERR_CORRUPT);
}

TEST(EncryptedExtensions, DuplicatesAreAProtocolErrorAndTheCountIsCapped) {
  GTLS_Limits l = limits();
  GTLS_EncryptedExtensions e;
  Bytes dup = ext_block({ext(GTLS_EXT_SERVER_NAME, {}), ext(GTLS_EXT_SERVER_NAME, {})});
  EXPECT_EQ(gtls_msg_parse_encrypted_extensions(dup.data(), dup.size(), &l, &e), GTLS_ERR_PROTOCOL);
  l.max_extensions = 2;
  Bytes three = ext_block({ext(100, {}), ext(101, {}), ext(102, {})});
  EXPECT_EQ(gtls_msg_parse_encrypted_extensions(three.data(), three.size(), &l, &e), GTLS_ERR_LIMIT);
}

/* ------------------------------------------------------------ Certificate */

namespace {

Bytes certificate_body(const std::vector<Bytes> & certs, const Bytes & entry_ext = {0, 0},
    unsigned context_len = 0) {
  Bytes list;
  for (const Bytes & c : certs) {
    put24(list, c.size());
    put(list, c);
    put(list, entry_ext);
  }
  Bytes b;
  b.push_back(context_len);
  b.insert(b.end(), context_len, 0x33);
  put24(b, list.size());
  put(b, list);
  return b;
}

}  // namespace

TEST(CertificateMsg, ParsesAChainInOrder) {
  GTLS_Limits l = limits();
  Bytes body = certificate_body({Bytes(10, 1), Bytes(20, 2), Bytes(30, 3)});
  GTLS_CertificateMsg c;
  ASSERT_EQ(gtls_msg_parse_certificate(body.data(), body.size(), &l, &c), GTLS_OK);
  ASSERT_EQ(c.count, 3u);
  EXPECT_EQ(c.der_len[0], 10u);
  EXPECT_EQ(c.der_len[2], 30u);
  EXPECT_EQ(c.der[1][0], 2);
  EXPECT_EQ(c.context_len, 0u);
  EXPECT_FALSE(c.has_entry_extensions);
}

TEST(CertificateMsg, EmptyListAndRequestContextAreReportedNotJudged) {
  GTLS_Limits l = limits();
  GTLS_CertificateMsg c;
  Bytes none = certificate_body({});
  ASSERT_EQ(gtls_msg_parse_certificate(none.data(), none.size(), &l, &c), GTLS_OK);
  EXPECT_EQ(c.count, 0u);
  Bytes ctx = certificate_body({Bytes(4, 1)}, {0, 0}, 5);
  ASSERT_EQ(gtls_msg_parse_certificate(ctx.data(), ctx.size(), &l, &c), GTLS_OK);
  EXPECT_EQ(c.context_len, 5u);
}

TEST(CertificateMsg, EntryExtensionsAreFlagged) {
  GTLS_Limits l = limits();
  GTLS_CertificateMsg c;
  Bytes body = certificate_body({Bytes(4, 1)}, ext(GTLS_EXT_STATUS_REQUEST, Bytes{1, 0, 0}));
  ASSERT_EQ(gtls_msg_parse_certificate(body.data(), body.size(), &l, &c), GTLS_OK);
  EXPECT_TRUE(c.has_entry_extensions);
}

TEST(CertificateMsg, CountAndSizeCapsAreLimitsAtTheirEdges) {
  GTLS_Limits l = limits();
  GTLS_CertificateMsg c;
  l.max_certificates = 3;
  Bytes four = certificate_body({Bytes(4, 1), Bytes(4, 1), Bytes(4, 1), Bytes(4, 1)});
  EXPECT_EQ(gtls_msg_parse_certificate(four.data(), four.size(), &l, &c), GTLS_ERR_LIMIT);
  Bytes three = certificate_body({Bytes(4, 1), Bytes(4, 1), Bytes(4, 1)});
  EXPECT_EQ(gtls_msg_parse_certificate(three.data(), three.size(), &l, &c), GTLS_OK);
  l.max_certificate_bytes = 100;
  Bytes big = certificate_body({Bytes(101, 1)});
  EXPECT_EQ(gtls_msg_parse_certificate(big.data(), big.size(), &l, &c), GTLS_ERR_LIMIT);
  Bytes edge = certificate_body({Bytes(100, 1)});
  EXPECT_EQ(gtls_msg_parse_certificate(edge.data(), edge.size(), &l, &c), GTLS_OK);
  /* A cap above the parser's own array is clamped to it, not overrun. */
  l = limits();
  l.max_certificates = 1000;
  std::vector<Bytes> many(GTLS_CERT_MAX + 1, Bytes(4, 1));
  Bytes lots = certificate_body(many);
  EXPECT_EQ(gtls_msg_parse_certificate(lots.data(), lots.size(), &l, &c), GTLS_ERR_LIMIT);
}

TEST(CertificateMsg, ZeroLengthCertificateAndEveryTruncationAreRefused) {
  GTLS_Limits l = limits();
  GTLS_CertificateMsg c;
  Bytes zero = certificate_body({Bytes()});
  EXPECT_EQ(gtls_msg_parse_certificate(zero.data(), zero.size(), &l, &c), GTLS_ERR_CORRUPT);
  Bytes body = certificate_body({Bytes(10, 1), Bytes(12, 2)});
  for (size_t n = 0; n < body.size(); n++) {
    EXPECT_NE(gtls_msg_parse_certificate(body.data(), n, &l, &c), GTLS_OK) << n;
  }
  body.push_back(0);
  EXPECT_EQ(gtls_msg_parse_certificate(body.data(), body.size(), &l, &c), GTLS_ERR_CORRUPT);
}

/* -------------------------------------------------------- CertificateVerify */

TEST(CertificateVerifyMsg, ParsesAndEnforcesItsCap) {
  GTLS_Limits l = limits();
  Bytes body;
  put16(body, 0x0804);
  put16(body, 5);
  body.insert(body.end(), 5, 0x44);
  GTLS_CertificateVerifyMsg cv;
  ASSERT_EQ(gtls_msg_parse_certificate_verify(body.data(), body.size(), &l, &cv), GTLS_OK);
  EXPECT_EQ(cv.scheme, 0x0804u);
  EXPECT_EQ(cv.signature_len, 5u);
  l.max_signature_bytes = 4;
  EXPECT_EQ(gtls_msg_parse_certificate_verify(body.data(), body.size(), &l, &cv), GTLS_ERR_LIMIT);
  l.max_signature_bytes = 5;
  EXPECT_EQ(gtls_msg_parse_certificate_verify(body.data(), body.size(), &l, &cv), GTLS_OK);
}

TEST(CertificateVerifyMsg, EmptySignatureTruncationsAndTrailingBytesAreRefused) {
  GTLS_Limits l = limits();
  GTLS_CertificateVerifyMsg cv;
  Bytes empty = {0x08, 0x04, 0, 0};
  EXPECT_EQ(gtls_msg_parse_certificate_verify(empty.data(), empty.size(), &l, &cv), GTLS_ERR_CORRUPT);
  Bytes body = {0x08, 0x04, 0, 3, 1, 2, 3};
  for (size_t n = 0; n < body.size(); n++) {
    EXPECT_NE(gtls_msg_parse_certificate_verify(body.data(), n, &l, &cv), GTLS_OK) << n;
  }
  body.push_back(0);
  EXPECT_EQ(gtls_msg_parse_certificate_verify(body.data(), body.size(), &l, &cv), GTLS_ERR_CORRUPT);
}

/* ------------------------------------------------------- NewSessionTicket */

namespace {

Bytes ticket_body(size_t nonce, size_t ticket, const Bytes & exts = {0, 0}) {
  Bytes b = {0, 0, 0x1c, 0x20, 1, 2, 3, 4};
  b.push_back(nonce);
  b.insert(b.end(), nonce, 9);
  put16(b, ticket);
  b.insert(b.end(), ticket, 8);
  put(b, exts);
  return b;
}

}  // namespace

TEST(NewSessionTicket, ParsesEveryField) {
  GTLS_Limits l = limits();
  GTLS_NewSessionTicket t;
  Bytes body = ticket_body(4, 20);
  ASSERT_EQ(gtls_msg_parse_new_session_ticket(body.data(), body.size(), &l, &t), GTLS_OK);
  EXPECT_EQ(t.lifetime, 7200u);
  EXPECT_EQ(t.age_add, 0x01020304u);
  EXPECT_EQ(t.nonce_len, 4u);
  EXPECT_EQ(t.ticket_len, 20u);
  EXPECT_FALSE(t.early_data);
}

TEST(NewSessionTicket, EarlyDataExtensionCarriesTheMaximum) {
  GTLS_Limits l = limits();
  GTLS_NewSessionTicket t;
  Bytes body = ticket_body(0, 3, ext_block({ext(GTLS_EXT_EARLY_DATA, Bytes{0, 0, 4, 0})}));
  ASSERT_EQ(gtls_msg_parse_new_session_ticket(body.data(), body.size(), &l, &t), GTLS_OK);
  EXPECT_TRUE(t.early_data);
  EXPECT_EQ(t.max_early_data, 1024u);
  Bytes bad = ticket_body(0, 3, ext_block({ext(GTLS_EXT_EARLY_DATA, Bytes{0, 0, 4})}));
  EXPECT_EQ(gtls_msg_parse_new_session_ticket(bad.data(), bad.size(), &l, &t), GTLS_ERR_CORRUPT);
}

TEST(NewSessionTicket, TicketCapIsALimitAndAnEmptyTicketIsRefused) {
  GTLS_Limits l = limits();
  GTLS_NewSessionTicket t;
  l.max_ticket_bytes = 20;
  Bytes over = ticket_body(0, 21);
  EXPECT_EQ(gtls_msg_parse_new_session_ticket(over.data(), over.size(), &l, &t), GTLS_ERR_LIMIT);
  Bytes at = ticket_body(0, 20);
  EXPECT_EQ(gtls_msg_parse_new_session_ticket(at.data(), at.size(), &l, &t), GTLS_OK);
  Bytes empty = ticket_body(0, 0);
  EXPECT_EQ(gtls_msg_parse_new_session_ticket(empty.data(), empty.size(), &l, &t), GTLS_ERR_CORRUPT);
}

TEST(NewSessionTicket, EveryTruncationAndATrailingByteAreRefused) {
  GTLS_Limits l = limits();
  GTLS_NewSessionTicket t;
  Bytes body = ticket_body(3, 5, ext_block({ext(GTLS_EXT_EARLY_DATA, Bytes{0, 0, 0, 1})}));
  for (size_t n = 0; n < body.size(); n++) {
    EXPECT_NE(gtls_msg_parse_new_session_ticket(body.data(), n, &l, &t), GTLS_OK) << n;
  }
  body.push_back(0);
  EXPECT_EQ(gtls_msg_parse_new_session_ticket(body.data(), body.size(), &l, &t), GTLS_ERR_CORRUPT);
}

/* The RFC's own NewSessionTicket parses, with its early_data extension. */
TEST(NewSessionTicket, TheRfc8448TicketParses) {
  Vec v("simple-1rtt");
  const Bytes m = v["server.construct-a-newsessionticket-handshake-message.newsessionticket"];
  GTLS_Limits l = limits();
  GTLS_NewSessionTicket t;
  ASSERT_EQ(gtls_msg_parse_new_session_ticket(m.data() + 4, m.size() - 4, &l, &t), GTLS_OK);
  /* 00 00 00 1e | fa d6 aa c5 | 02 00 00 | 00 b2 ... | 00 08 00 2a 00 04 00 00 04 00 */
  EXPECT_EQ(t.lifetime, 30u);
  EXPECT_EQ(t.age_add, 0xfad6aac5u);
  EXPECT_EQ(t.nonce_len, 2u);
  EXPECT_EQ(t.ticket_len, 178u);
  EXPECT_TRUE(t.early_data);
  EXPECT_EQ(t.max_early_data, 1024u);
}

/* ----------------------------------------------------------------- buffer */

TEST(Buf, AppendConsumeAndTheCeiling) {
  GTLS_Buf b;
  gtls_buf_init(&b, nullptr, 10);
  EXPECT_EQ(gtls_buf_append(&b, "abcdef", 6), GTLS_OK);
  EXPECT_EQ(gtls_buf_append(&b, "ghij", 4), GTLS_OK);
  EXPECT_EQ(b.len, 10u);
  EXPECT_EQ(gtls_buf_append(&b, "k", 1), GTLS_ERR_LIMIT);
  EXPECT_EQ(gtls_buf_append(&b, "", 0), GTLS_ERR_LIMIT) << "the first failure sticks";
  gtls_buf_consume(&b, 3);
  EXPECT_EQ(b.len, 7u);
  EXPECT_EQ(std::memcmp(b.data, "defghij", 7), 0);
  gtls_buf_free(&b);
  EXPECT_EQ(b.data, nullptr);
}

TEST(Buf, LengthFieldsThatDoNotFitAreALimitNotAWrap) {
  GTLS_Buf b;
  gtls_buf_init(&b, nullptr, 1 << 20);
  size_t at = gtls_buf_begin(&b, 1);
  Bytes big(256, 1);
  gtls_buf_append(&b, big.data(), big.size());
  gtls_buf_end(&b, at, 1);
  EXPECT_EQ(b.err, GTLS_ERR_LIMIT);
  gtls_buf_free(&b);
  gtls_buf_init(&b, nullptr, 1 << 20);
  at = gtls_buf_begin(&b, 1);
  gtls_buf_append(&b, big.data(), 255);
  gtls_buf_end(&b, at, 1);
  EXPECT_EQ(b.err, GTLS_OK);
  EXPECT_EQ(b.data[0], 255);
  gtls_buf_free(&b);
}

TEST(Buf, AnAllocationFailureIsRememberedAsOom) {
  GTLS_Allocator failing;
  failing.ctx = nullptr;
  failing.malloc_fn = [](void *, size_t) -> void * { return nullptr; };
  failing.calloc_fn = [](void *, size_t, size_t) -> void * { return nullptr; };
  failing.realloc_fn = [](void *, void *, size_t) -> void * { return nullptr; };
  failing.free_fn = [](void *, void *) {};
  GTLS_Buf b;
  gtls_buf_init(&b, &failing, 100);
  EXPECT_EQ(gtls_buf_append(&b, "x", 1), GTLS_ERR_OOM);
  EXPECT_EQ(b.err, GTLS_ERR_OOM);
}

TEST(Reader, VectorBoundsAndNoReadPastTheEnd) {
  const unsigned char data[] = {3, 1, 2, 3, 9};
  GTLS_Reader r;
  GTLS_Reader sub;
  gtls_reader_init(&r, data, sizeof data);
  ASSERT_EQ(gtls_reader_vector(&r, 1, 1, 3, &sub), GTLS_OK);
  EXPECT_EQ(sub.len, 3u);
  EXPECT_EQ(gtls_reader_left(&r), 1u);
  unsigned v;
  EXPECT_EQ(gtls_reader_u16(&r, &v), GTLS_ERR_CORRUPT) << "one byte left";
  EXPECT_EQ(gtls_reader_u24(&r, &v), GTLS_ERR_CORRUPT);
  EXPECT_EQ(gtls_reader_u8(&r, &v), GTLS_OK);
  EXPECT_EQ(gtls_reader_end(&r), GTLS_OK);
  gtls_reader_init(&r, data, sizeof data);
  EXPECT_EQ(gtls_reader_vector(&r, 1, 4, 0, &sub), GTLS_ERR_CORRUPT) << "below the minimum";
  gtls_reader_init(&r, data, sizeof data);
  EXPECT_EQ(gtls_reader_vector(&r, 1, 0, 2, &sub), GTLS_ERR_CORRUPT) << "above the maximum";
  const unsigned char huge[] = {0xff, 0xff, 0xff, 1};
  gtls_reader_init(&r, huge, sizeof huge);
  EXPECT_EQ(gtls_reader_vector(&r, 3, 0, 0, &sub), GTLS_ERR_CORRUPT) << "a length past the data";
  const unsigned char more[] = {1, 2};
  gtls_reader_init(&r, more, 2);
  const unsigned char * p;
  EXPECT_EQ(gtls_reader_bytes(&r, 3, &p), GTLS_ERR_CORRUPT);
  EXPECT_EQ(gtls_reader_left(&r), 2u) << "a failed read consumes nothing";
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
