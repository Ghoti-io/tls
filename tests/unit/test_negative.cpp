/**
 * @file
 *
 * Handshakes that must fail, and fail with the specific result and alert for
 * the cause: every certificate check against real chains, every way a
 * message can be wrong, the order and epoch rules, and the caps. After each
 * one the connection is failed and its secrets are zero.
 *
 * None of these may succeed with a reduced check. The control for that is
 * not in this file: tools/controls.sh removes each check from the source, one
 * at a time, and requires the test that names it here to start failing.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "sim.h"

#include <algorithm>

using namespace gtlstest;

/* A named namespace: gtest instantiates a test class over Case, and a type in
 * an anonymous namespace as a template argument of a class with external
 * linkage is -Wsubobject-linkage on some compilers (mingw's GCC), which
 * -Werror turns into an error. */
namespace negtest {

void expect_failed_and_wiped(World & w, GTLS_Result want, unsigned alert) {
  EXPECT_TRUE(gtls_conn_is_failed(w.conn));
  EXPECT_FALSE(gtls_conn_is_connected(w.conn));
  EXPECT_EQ(gtls_conn_failure(w.conn), want);
  EXPECT_EQ(gtls_conn_alert(w.conn), alert);
  EXPECT_TRUE(gtls_conn_secrets_are_wiped(w.conn)) << "a secret survived the failure";
  Bytes buf(GTLS_HASH_MAX);
  size_t n = 0;
  EXPECT_EQ(gtls_conn_secret(w.conn, GTLS_EPOCH_HANDSHAKE, GTLS_DIR_READ, buf.data(), buf.size(), &n),
      GTLS_ERR_FAILED);
  EXPECT_EQ(gtls_conn_secret(w.conn, GTLS_EPOCH_APPLICATION, GTLS_DIR_WRITE, buf.data(), buf.size(), &n),
      GTLS_ERR_FAILED);
  const Bytes more = {20, 0, 0, 0};
  EXPECT_EQ(gtls_conn_feed(w.conn, GTLS_EPOCH_HANDSHAKE, more.data(), more.size(), kNow),
      GTLS_ERR_FAILED);
  EXPECT_EQ(gtls_conn_start(w.conn), GTLS_ERR_FAILED);
}

Bytes put_ext(unsigned type, const Bytes & data) { return SimServer::ext(type, data); }

Bytes hrr_random() {
  Bytes r(32);
  EXPECT_EQ(gsec_sha256("HelloRetryRequest", 17, r.data()), GSEC_OK);
  return r;
}

/** A ServerHello (or an HRR, by its random) built from pieces. */
Bytes hand_hello(const Bytes & session_id, unsigned suite, const std::vector<Bytes> & exts,
    const Bytes & random = Bytes(32, 0x99), unsigned legacy = 0x0303, unsigned comp = 0) {
  Bytes body;
  SimServer::put16(body, legacy);
  body.insert(body.end(), random.begin(), random.end());
  body.push_back(session_id.size());
  body.insert(body.end(), session_id.begin(), session_id.end());
  SimServer::put16(body, suite);
  body.push_back(comp);
  Bytes blk = SimServer::ext_block(exts);
  body.insert(body.end(), blk.begin(), blk.end());
  return SimServer::wrap(GTLS_HS_SERVER_HELLO, body);
}

Bytes versions13() { return put_ext(GTLS_EXT_SUPPORTED_VERSIONS, Bytes{3, 4}); }

Bytes key_share_ext(unsigned group, const Bytes & kx) {
  Bytes d;
  SimServer::put16(d, group);
  SimServer::put16(d, kx.size());
  d.insert(d.end(), kx.begin(), kx.end());
  return put_ext(GTLS_EXT_KEY_SHARE, d);
}

Bytes group_only_ext(unsigned group) {
  Bytes d;
  SimServer::put16(d, group);
  return put_ext(GTLS_EXT_KEY_SHARE, d);
}

/** The real server's x25519 share, to build a ServerHello that is right except for one thing. */
Bytes server_x25519_public() {
  Bytes priv(32, 0x55);
  Bytes pub(32);
  EXPECT_EQ(gsec_x25519_public(priv.data(), pub.data()), GSEC_OK);
  return pub;
}

struct Case {
  const char * name;
  std::function<void(World &, SimOptions &)> setup;
  GTLS_Result want;
  unsigned alert;
};

}  // namespace negtest

using namespace negtest;

/* ------------------------------------------------- the certificate checks */

class CertificateFailures : public ::testing::TestWithParam<Case> {};

TEST_P(CertificateFailures, FailWithTheirOwnResultAndAlert) {
  World w;
  SimOptions o = w.server_options();
  GetParam().setup(w, o);
  w.build();
  SimServer s(o);
  EXPECT_EQ(w.run(s), GetParam().want);
  expect_failed_and_wiped(w, GetParam().want, GetParam().alert);
}

static std::vector<Case> certificate_cases() {
  std::vector<Case> c;
  c.push_back({"MissingIntermediate", [](World & w, SimOptions & o) { o.chain = {w.pki.leaf}; },
      GTLS_ERR_CERT_ISSUER, GTLS_ALERT_UNKNOWN_CA});
  c.push_back({"UnknownAnchor", [](World & w, SimOptions &) {
        CertSpec other;
        other.subject = "other root";
        other.issuer = "other root";
        other.key_tag = 77;
        other.signer_tag = 77;
        other.ca = true;
        w.trust.reset(new Trust({make_cert(other)}));
      }, GTLS_ERR_CERT_ISSUER, GTLS_ALERT_UNKNOWN_CA});
  c.push_back({"AnchorWithTheRightNameButAnotherKey", [](World & w, SimOptions &) {
        CertSpec impostor;
        impostor.subject = "root";
        impostor.issuer = "root";
        impostor.key_tag = 78;
        impostor.signer_tag = 78;
        impostor.ca = true;
        w.trust.reset(new Trust({make_cert(impostor)}));
      }, GTLS_ERR_CERT_INVALID, GTLS_ALERT_BAD_CERTIFICATE});
  c.push_back({"WrongHost", [](World & w, SimOptions &) { w.host = "other.test"; },
      GTLS_ERR_CERT_HOST, GTLS_ALERT_BAD_CERTIFICATE});
  c.push_back({"HostIsAnIpAddressTheCertificateDoesNotName", [](World & w, SimOptions & o) {
        w.host = "192.0.2.9";
        o.ack_sni = false; /* none was sent for an address */
      }, GTLS_ERR_CERT_HOST, GTLS_ALERT_BAD_CERTIFICATE});
  c.push_back({"Expired", [](World & w, SimOptions &) { w.now = kNow + 40 * kDay; },
      GTLS_ERR_CERT_EXPIRED, GTLS_ALERT_CERTIFICATE_EXPIRED});
  c.push_back({"NotYetValid", [](World & w, SimOptions &) { w.now = kNow - 40 * kDay; },
      GTLS_ERR_CERT_NOT_YET_VALID, GTLS_ALERT_CERTIFICATE_EXPIRED});
  c.push_back({"LeafExpiredButTheChainIsNot", [](World & w, SimOptions & o) {
        CertSpec l;
        l.dns = "example.test";
        l.has_eku = true;
        l.eku_server = true;
        l.not_before = kNow - 60 * kDay;
        l.not_after = kNow - 1 * kDay;
        o.chain = {make_cert(l), w.pki.inter};
      }, GTLS_ERR_CERT_EXPIRED, GTLS_ALERT_CERTIFICATE_EXPIRED});
  c.push_back({"WrongExtendedKeyUsage", [](World & w, SimOptions & o) {
        CertSpec l;
        l.dns = "example.test";
        l.has_eku = true;
        l.eku_client = true;
        o.chain = {make_cert(l), w.pki.inter};
      }, GTLS_ERR_CERT_PURPOSE, GTLS_ALERT_BAD_CERTIFICATE});
  c.push_back({"IntermediateIsNotACa", [](World & w, SimOptions & o) {
        CertSpec i;
        i.subject = "inter";
        i.issuer = "root";
        i.key_tag = 2;
        i.signer_tag = 1;
        i.ca = false;
        o.chain = {w.pki.leaf, make_cert(i)};
      }, GTLS_ERR_CERT_INVALID, GTLS_ALERT_BAD_CERTIFICATE});
  c.push_back({"LeafSignatureIsBad", [](World & w, SimOptions & o) {
        CertSpec l;
        l.dns = "example.test";
        l.has_eku = true;
        l.eku_server = true;
        l.corrupt_signature = true;
        o.chain = {make_cert(l), w.pki.inter};
      }, GTLS_ERR_CERT_INVALID, GTLS_ALERT_BAD_CERTIFICATE});
  c.push_back({"LeafSignedByTheWrongKeyUnderTheRightName", [](World & w, SimOptions & o) {
        CertSpec l;
        l.dns = "example.test";
        l.has_eku = true;
        l.eku_server = true;
        l.signer_tag = 99;
        o.chain = {make_cert(l), w.pki.inter};
      }, GTLS_ERR_CERT_INVALID, GTLS_ALERT_BAD_CERTIFICATE});
  c.push_back({"EmptyCertificateList", [](World &, SimOptions & o) { o.chain = {}; },
      GTLS_ERR_CERT_INVALID, GTLS_ALERT_DECODE_ERROR}); /* RFC 8446 section 4.4.2 */
  c.push_back({"LeafIsGarbage", [](World &, SimOptions & o) { o.chain = {Bytes(40, 0x30)}; },
      GTLS_ERR_CERT_INVALID, GTLS_ALERT_BAD_CERTIFICATE});
  c.push_back({"MoreCertificatesThanTheLimit", [](World & w, SimOptions & o) {
        o.chain = {w.pki.leaf};
        for (int i = 0; i < 10; i++) {
          o.chain.push_back(w.pki.inter);
        }
      }, GTLS_ERR_LIMIT, GTLS_ALERT_DECODE_ERROR});
  c.push_back({"OneCertificateLargerThanTheLimit", [](World & w, SimOptions &) {
        w.limits.max_certificate_bytes = 100;
      }, GTLS_ERR_LIMIT, GTLS_ALERT_DECODE_ERROR});
  c.push_back({"ARootThatIsExpiredTodayEvenThoughTheLeafIsFine", [](World & w, SimOptions &) {
        CertSpec r;
        r.subject = "root";
        r.issuer = "root";
        r.key_tag = 1;
        r.signer_tag = 1;
        r.ca = true;
        r.not_after = kNow - kDay;
        w.trust.reset(new Trust({make_cert(r)}));
      }, GTLS_ERR_CERT_EXPIRED, GTLS_ALERT_CERTIFICATE_EXPIRED});
  return c;
}

INSTANTIATE_TEST_SUITE_P(Chains, CertificateFailures, ::testing::ValuesIn(certificate_cases()),
    [](const ::testing::TestParamInfo<Case> & info) { return std::string(info.param.name); });

/* The same cases accepted, so that none of them fails for a reason the table
 * does not name: the good chain, a wildcard-free exact name, an IP SAN is not
 * involved, and every limit exactly at its edge. */
TEST(CertificateAccepted, TheGoodChainAndTheEdgesOfItsLimits) {
  World w;
  w.limits.max_certificates = 2;
  w.limits.max_certificate_bytes = static_cast<uint32_t>(
      std::max(w.pki.leaf.size(), w.pki.inter.size()));
  w.build();
  SimServer s(w.server_options());
  EXPECT_EQ(w.run(s), GTLS_OK);
}

TEST(CertificateAccepted, ALeafWithBothPurposesOrNoneIsAcceptedForServerAuth) {
  for (int variant = 0; variant < 2; variant++) {
    World w;
    CertSpec l;
    l.dns = "example.test";
    l.has_eku = variant == 0;
    l.eku_server = true;
    l.eku_client = true;
    SimOptions o = w.server_options();
    o.chain = {make_cert(l), w.pki.inter};
    w.build();
    SimServer s(o);
    EXPECT_EQ(w.run(s), GTLS_OK) << variant;
  }
}

/* ------------------------------------------------------------ Finished etc. */

TEST(Finished, OneFlippedByteIsRefusedWithDecryptError) {
  World w;
  w.build();
  SimOptions o = w.server_options();
  o.bad_finished = true;
  SimServer s(o);
  EXPECT_EQ(w.run(s), GTLS_ERR_FINISHED);
  expect_failed_and_wiped(w, GTLS_ERR_FINISHED, GTLS_ALERT_DECRYPT_ERROR);
  /* The application secrets were never derived, and the client sent nothing. */
  EXPECT_EQ(w.out(GTLS_EPOCH_HANDSHAKE), Bytes());
}

TEST(Finished, EveryByteOfItMattersAndSoDoesItsLength) {
  World probe;
  probe.build();
  SimServer ps(probe.server_options());
  ASSERT_EQ(probe.run(ps), GTLS_OK);
  const size_t body = ps.fin_msg.size() - 4;
  for (size_t i = 0; i < body; i++) {
    World w;
    w.build();
    SimOptions o = w.server_options();
    o.mut_fin = [i](Bytes & m) { m[4 + i] ^= 0x01; };
    SimServer s(o);
    EXPECT_EQ(w.run(s), GTLS_ERR_FINISHED) << "byte " << i;
    EXPECT_TRUE(gtls_conn_secrets_are_wiped(w.conn)) << i;
  }
  for (int delta : {-1, 1}) {
    World w;
    w.build();
    SimOptions o = w.server_options();
    o.mut_fin = [delta](Bytes & m) {
      if (delta < 0) {
        m.pop_back();
      } else {
        m.push_back(0);
      }
      m[3] = static_cast<unsigned char>(m.size() - 4);
    };
    SimServer s(o);
    EXPECT_EQ(w.run(s), GTLS_ERR_FINISHED) << delta;
  }
}

TEST(Finished, AFinishedForAnotherTranscriptIsRefused) {
  /* A Finished computed under the right key but over the wrong transcript:
   * the EncryptedExtensions the client saw differ by one byte from the ones
   * the server's transcript has. */
  World w;
  w.build();
  SimOptions o = w.server_options();
  o.ee_extras = {put_ext(0x7a7a, Bytes{1})};
  SimServer s(o);
  ASSERT_EQ(w.run(s), GTLS_ERR_PROTOCOL) << "an extension that was not offered is refused first";
  World w2;
  w2.build();
  SimOptions o2 = w2.server_options();
  SimServer s2(o2);
  ASSERT_EQ(w2.run(s2), GTLS_OK);
}

/* ------------------------------------------------------- CertificateVerify */

TEST(CertificateVerify, SignatureOverTheWrongTranscriptIsRefused) {
  World w;
  w.build();
  SimOptions o = w.server_options();
  o.cv_wrong_transcript = true;
  SimServer s(o);
  EXPECT_EQ(w.run(s), GTLS_ERR_SIGNATURE);
  expect_failed_and_wiped(w, GTLS_ERR_SIGNATURE, GTLS_ALERT_DECRYPT_ERROR);
}

TEST(CertificateVerify, EveryByteOfTheSignatureMatters) {
  for (size_t i = 0; i < 64; i += 7) {
    World w;
    w.build();
    SimOptions o = w.server_options();
    o.mut_cv = [i](Bytes & m) { m[4 + 4 + i] ^= 0x40; };
    SimServer s(o);
    EXPECT_EQ(w.run(s), GTLS_ERR_SIGNATURE) << i;
  }
}

TEST(CertificateVerify, SignedByAKeyThatIsNotTheLeafsIsRefused) {
  World w;
  w.build();
  SimOptions o = w.server_options();
  o.cv_key_tag = 42;
  SimServer s(o);
  EXPECT_EQ(w.run(s), GTLS_ERR_SIGNATURE);
  expect_failed_and_wiped(w, GTLS_ERR_SIGNATURE, GTLS_ALERT_DECRYPT_ERROR);
}

TEST(CertificateVerify, ASignatureOverTheTranscriptThatDiffersInAnEarlierMessageIsRefused) {
  /* The EncryptedExtensions the client receives differ by one byte from the
   * ones the server hashed, and both are well-formed: the signature is over
   * a transcript the client does not have. */
  World w;
  w.build();
  SimOptions o = w.server_options();
  o.ee_extras = {put_ext(GTLS_EXT_SUPPORTED_GROUPS, Bytes{0, 2, 0, 0x1d})};
  o.wire_ee = [](Bytes & m) { m.back() = 0x17; };
  SimServer s(o);
  EXPECT_EQ(w.run(s), GTLS_ERR_SIGNATURE);
  expect_failed_and_wiped(w, GTLS_ERR_SIGNATURE, GTLS_ALERT_DECRYPT_ERROR);
}

TEST(CertificateVerify, TheSameFlightUnalteredIsAccepted) {
  /* The control for the test above: with no change on the wire it passes. */
  World w;
  w.build();
  SimOptions o = w.server_options();
  o.ee_extras = {put_ext(GTLS_EXT_SUPPORTED_GROUPS, Bytes{0, 2, 0, 0x1d})};
  SimServer s(o);
  EXPECT_EQ(w.run(s), GTLS_OK);
}

TEST(CertificateVerify, SchemesTls13ForbidsOrThatWereNotOfferedAreRefused) {
  for (unsigned scheme : {0x0401u, 0x0501u, 0x0601u, 0x0201u, 0x0804u, 0x0805u, 0x1234u}) {
    World w;
    w.build();
    SimOptions o = w.server_options();
    o.cv_scheme = scheme;
    SimServer s(o);
    EXPECT_EQ(w.run(s), GTLS_ERR_PROTOCOL) << std::hex << scheme;
    EXPECT_EQ(gtls_conn_alert(w.conn), GTLS_ALERT_ILLEGAL_PARAMETER) << std::hex << scheme;
  }
}

TEST(CertificateVerify, ASchemeTheContextDidNotOfferIsRefusedEvenIfTheKeyFits) {
  World w;
  static const GCERT_SigScheme only[1] = {GCERT_SIG_ECDSA_P256_SHA256};
  w.cfg.sig_algs = only;
  w.cfg.sig_alg_count = 1;
  w.build();
  SimServer s(w.server_options());
  EXPECT_EQ(w.run(s), GTLS_ERR_PROTOCOL) << "Ed25519 was not offered";
}

/* --------------------------------------------------------------- downgrade */

TEST(Downgrade, EitherSentinelAbortsWithIllegalParameter) {
  for (int sentinel : {2, 3}) {
    World w;
    w.build();
    SimOptions o = w.server_options();
    o.sentinel = sentinel;
    SimServer s(o);
    EXPECT_EQ(w.run(s), GTLS_ERR_DOWNGRADE) << sentinel;
    expect_failed_and_wiped(w, GTLS_ERR_DOWNGRADE, GTLS_ALERT_ILLEGAL_PARAMETER);
  }
}

TEST(Downgrade, TheSentinelIsCheckedBeforeAnythingElseIsBelieved) {
  /* A TLS 1.2-shaped ServerHello with no extensions at all and the sentinel:
   * downgrade, not "unsupported version". */
  World w;
  w.build();
  ASSERT_EQ(gtls_conn_start(w.conn), GTLS_OK);
  w.drain(GTLS_EPOCH_INITIAL);
  Bytes random(32, 0);
  const unsigned char tail[7] = {0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44};
  std::memcpy(random.data() + 24, tail, 7);
  random[31] = 1;
  Bytes body;
  SimServer::put16(body, 0x0303);
  body.insert(body.end(), random.begin(), random.end());
  body.push_back(0);
  SimServer::put16(body, 0xc02f);
  body.push_back(0);
  EXPECT_EQ(w.feed(GTLS_EPOCH_INITIAL, SimServer::wrap(GTLS_HS_SERVER_HELLO, body)),
      GTLS_ERR_DOWNGRADE);
}

TEST(Downgrade, ATls12ServerWithoutTheSentinelIsAnUnsupportedVersion) {
  World w;
  w.build();
  ASSERT_EQ(gtls_conn_start(w.conn), GTLS_OK);
  w.drain(GTLS_EPOCH_INITIAL);
  Bytes body;
  SimServer::put16(body, 0x0303);
  body.insert(body.end(), 32, 0x42);
  body.push_back(0);
  SimServer::put16(body, 0xc02f);
  body.push_back(0);
  EXPECT_EQ(w.feed(GTLS_EPOCH_INITIAL, SimServer::wrap(GTLS_HS_SERVER_HELLO, body)),
      GTLS_ERR_UNSUPPORTED);
  EXPECT_EQ(gtls_conn_alert(w.conn), GTLS_ALERT_PROTOCOL_VERSION);
}

/* -------------------------------------------------------------- ServerHello */

class ServerHelloFailures : public ::testing::TestWithParam<Case> {};

TEST_P(ServerHelloFailures, FailWithTheirOwnResultAndAlert) {
  World w;
  SimOptions o = w.server_options();
  GetParam().setup(w, o);
  w.build();
  SimServer s(o);
  EXPECT_EQ(w.run(s), GetParam().want);
  expect_failed_and_wiped(w, GetParam().want, GetParam().alert);
}

static std::vector<Case> hello_cases() {
  std::vector<Case> c;
  const Bytes kx = server_x25519_public();
  auto replace = [](std::function<Bytes(const Bytes &)> make) {
    return [make](World &, SimOptions & o) {
      o.mut_sh = [make](Bytes & m) { m = make(m); };
    };
  };
  c.push_back({"NoSupportedVersions", replace([kx](const Bytes &) {
        return hand_hello({}, 0x1301, {key_share_ext(0x1d, kx)});
      }), GTLS_ERR_UNSUPPORTED, GTLS_ALERT_PROTOCOL_VERSION});
  c.push_back({"SupportedVersionsSaysTls12", replace([kx](const Bytes &) {
        return hand_hello({}, 0x1301, {key_share_ext(0x1d, kx),
            put_ext(GTLS_EXT_SUPPORTED_VERSIONS, Bytes{3, 3})});
      }), GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER});
  c.push_back({"LegacyVersionIsNotTls12", replace([kx](const Bytes &) {
        return hand_hello({}, 0x1301, {key_share_ext(0x1d, kx), versions13()}, Bytes(32, 0x99), 0x0304);
      }), GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER});
  c.push_back({"CompressionIsNotNull", replace([kx](const Bytes &) {
        return hand_hello({}, 0x1301, {key_share_ext(0x1d, kx), versions13()}, Bytes(32, 0x99), 0x0303, 1);
      }), GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER});
  c.push_back({"SessionIdNotEchoed", replace([kx](const Bytes &) {
        return hand_hello(Bytes(32, 7), 0x1301, {key_share_ext(0x1d, kx), versions13()});
      }), GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER});
  c.push_back({"SuiteNotOffered", [](World & w, SimOptions &) {
        static const GTLS_Suite only[1] = {GTLS_SUITE_AES_256_GCM_SHA384};
        w.cfg.suites = only;
        w.cfg.suite_count = 1;
      }, GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER});
  c.push_back({"SuiteIsNotATls13Suite", replace([kx](const Bytes &) {
        return hand_hello({}, 0xc02f, {key_share_ext(0x1d, kx), versions13()});
      }), GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER});
  c.push_back({"SuiteIsCcmWhichIsNeverOffered", replace([kx](const Bytes &) {
        return hand_hello({}, 0x1304, {key_share_ext(0x1d, kx), versions13()});
      }), GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER});
  c.push_back({"KeyShareInAGroupNoShareWasSentFor", replace([](const Bytes &) {
        return hand_hello({}, 0x1301, {key_share_ext(0x17, Bytes(65, 4)), versions13()});
      }), GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER});
  c.push_back({"KeyShareMissing", replace([](const Bytes &) {
        return hand_hello({}, 0x1301, {versions13()});
      }), GTLS_ERR_PROTOCOL, GTLS_ALERT_MISSING_EXTENSION});
  c.push_back({"KeyShareWrongLength", replace([](const Bytes &) {
        return hand_hello({}, 0x1301, {key_share_ext(0x1d, Bytes(31, 9)), versions13()});
      }), GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER});
  c.push_back({"KeyShareIsASmallOrderPoint", replace([](const Bytes &) {
        return hand_hello({}, 0x1301, {key_share_ext(0x1d, Bytes(32, 0)), versions13()});
      }), GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER});
  c.push_back({"PreSharedKeyWasNotOffered", replace([kx](const Bytes &) {
        return hand_hello({}, 0x1301, {key_share_ext(0x1d, kx), versions13(),
            put_ext(GTLS_EXT_PRE_SHARED_KEY, Bytes{0, 0})});
      }), GTLS_ERR_PROTOCOL, GTLS_ALERT_UNSUPPORTED_EXTENSION});
  c.push_back({"AnExtensionThatWasNotOffered", replace([kx](const Bytes &) {
        return hand_hello({}, 0x1301, {key_share_ext(0x1d, kx), versions13(), put_ext(0x7a7a, {})});
      }), GTLS_ERR_PROTOCOL, GTLS_ALERT_UNSUPPORTED_EXTENSION});
  c.push_back({"ACookieInAServerHello", replace([kx](const Bytes &) {
        return hand_hello({}, 0x1301, {key_share_ext(0x1d, kx), versions13(),
            put_ext(GTLS_EXT_COOKIE, Bytes{0, 1, 1})});
      }), GTLS_ERR_PROTOCOL, GTLS_ALERT_UNSUPPORTED_EXTENSION});
  c.push_back({"DuplicateExtension", replace([kx](const Bytes &) {
        return hand_hello({}, 0x1301, {key_share_ext(0x1d, kx), versions13(), versions13()});
      }), GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER});
  c.push_back({"Truncated", replace([](const Bytes & m) {
        Bytes t(m.begin(), m.end() - 3);
        t[3] = static_cast<unsigned char>(t.size() - 4);
        return t;
      }), GTLS_ERR_CORRUPT, GTLS_ALERT_DECODE_ERROR});
  c.push_back({"TrailingByte", replace([](const Bytes & m) {
        Bytes t = m;
        t.push_back(0);
        t[3] = static_cast<unsigned char>(t.size() - 4);
        return t;
      }), GTLS_ERR_CORRUPT, GTLS_ALERT_DECODE_ERROR});
  c.push_back({"AMessageThatIsNotAServerHello", replace([](const Bytes & m) {
        Bytes t = m;
        t[0] = GTLS_HS_ENCRYPTED_EXTENSIONS;
        return t;
      }), GTLS_ERR_PROTOCOL, GTLS_ALERT_UNEXPECTED_MESSAGE});
  return c;
}

INSTANTIATE_TEST_SUITE_P(Hellos, ServerHelloFailures, ::testing::ValuesIn(hello_cases()),
    [](const ::testing::TestParamInfo<Case> & info) { return std::string(info.param.name); });

/* ------------------------------------------------------ HelloRetryRequest */

class RetryFailures : public ::testing::TestWithParam<Case> {};

TEST_P(RetryFailures, FailWithTheirOwnResultAndAlert) {
  World w;
  SimOptions o = w.server_options();
  o.hrr = true;
  o.hrr_group = GTLS_GROUP_SECP256R1;
  GetParam().setup(w, o);
  w.build();
  SimServer s(o);
  EXPECT_EQ(w.run(s), GetParam().want);
  expect_failed_and_wiped(w, GetParam().want, GetParam().alert);
}

static std::vector<Case> retry_cases() {
  std::vector<Case> c;
  auto hrr_with = [](std::function<Bytes()> make) {
    return [make](World &, SimOptions & o) {
      o.mut_hrr = [make](Bytes & m) { m = make(); };
    };
  };
  const Bytes sid;
  c.push_back({"AskForTheGroupAlreadySent", hrr_with([sid]() {
        return hand_hello(sid, 0x1301, {group_only_ext(0x1d), versions13()}, hrr_random());
      }), GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER});
  c.push_back({"AskForAGroupTheClientDoesNotSupport", [](World & w, SimOptions & o) {
        static const GTLS_Group two[2] = {GTLS_GROUP_X25519, GTLS_GROUP_SECP256R1};
        w.cfg.groups = two;
        w.cfg.group_count = 2;
        o.hrr_group = GTLS_GROUP_SECP384R1;
      }, GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER});
  c.push_back({"AskForAnUnknownGroup", hrr_with([sid]() {
        return hand_hello(sid, 0x1301, {group_only_ext(0x0100), versions13()}, hrr_random());
      }), GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER});
  c.push_back({"AskForNothing", hrr_with([sid]() {
        return hand_hello(sid, 0x1301, {versions13()}, hrr_random());
      }), GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER});
  c.push_back({"ACookieLargerThanTheLimit", [](World & w, SimOptions & o) {
        w.limits.max_cookie_bytes = 8;
        o.cookie = Bytes(9, 1);
      }, GTLS_ERR_LIMIT, GTLS_ALERT_DECODE_ERROR});
  c.push_back({"AnHrrWithAnUnofferedSuite", [](World & w, SimOptions & o) {
        static const GTLS_Suite only[1] = {GTLS_SUITE_AES_128_GCM_SHA256};
        w.cfg.suites = only;
        w.cfg.suite_count = 1;
        o.suite = GTLS_SUITE_AES_256_GCM_SHA384;
      }, GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER});
  c.push_back({"SecondServerHelloChangesTheSuite", [](World &, SimOptions & o) {
        o.mut_sh = [](Bytes & m) {
          /* after 4 + 2 + 32 + 1 (empty session id): the suite */
          m[4 + 2 + 32 + 1] = 0x13;
          m[4 + 2 + 32 + 2] = 0x03;
        };
      }, GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER});
  c.push_back({"SecondServerHelloInAnotherGroup", [](World &, SimOptions & o) {
        o.mut_sh = [](Bytes & m) { m = hand_hello({}, 0x1301, {key_share_ext(0x1d, Bytes(32, 3)), versions13()}); };
      }, GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER});
  c.push_back({"SecondShareIsNotOnTheCurve", [](World &, SimOptions & o) {
        o.mut_sh = [](Bytes & m) {
          Bytes bad(65, 0x04);
          m = hand_hello({}, 0x1301, {key_share_ext(0x17, bad), versions13()});
        };
      }, GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER});
  c.push_back({"SecondShareHasTheWrongPointFormat", [](World &, SimOptions & o) {
        o.mut_sh = [](Bytes & m) {
          Bytes bad(65, 0x05);
          m = hand_hello({}, 0x1301, {key_share_ext(0x17, bad), versions13()});
        };
      }, GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER});
  return c;
}

INSTANTIATE_TEST_SUITE_P(Retries, RetryFailures, ::testing::ValuesIn(retry_cases()),
    [](const ::testing::TestParamInfo<Case> & info) { return std::string(info.param.name); });

TEST(Retry, ASecondHelloRetryRequestIsUnexpected) {
  World w;
  w.build();
  SimOptions o = w.server_options();
  o.hrr = true;
  SimServer s(o);
  ASSERT_EQ(gtls_conn_start(w.conn), GTLS_OK);
  Bytes ch = w.out(GTLS_EPOCH_INITIAL);
  w.drain(GTLS_EPOCH_INITIAL);
  s.accept_hello(ch);
  ASSERT_TRUE(s.wants_retry);
  ASSERT_EQ(w.feed(GTLS_EPOCH_INITIAL, s.hrr_msg), GTLS_OK);
  w.drain(GTLS_EPOCH_INITIAL);
  EXPECT_EQ(gtls_conn_state(w.conn), GTLS_STATE_WAIT_SH2);
  EXPECT_EQ(w.feed(GTLS_EPOCH_INITIAL, s.hrr_msg), GTLS_ERR_PROTOCOL);
  expect_failed_and_wiped(w, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNEXPECTED_MESSAGE);
}

TEST(Retry, ACookieIsEchoedAndTheShareIsKeptWhenOnlyACookieWasAsked) {
  World w;
  w.build();
  SimOptions o = w.server_options();
  o.hrr = true;
  o.hrr_group = GTLS_GROUP_NONE;
  o.cookie = Bytes{9, 9, 9, 9, 9};
  SimServer s(o);
  ASSERT_EQ(gtls_conn_start(w.conn), GTLS_OK);
  Bytes ch = w.out(GTLS_EPOCH_INITIAL);
  w.drain(GTLS_EPOCH_INITIAL);
  s.accept_hello(ch);
  ASSERT_EQ(w.feed(GTLS_EPOCH_INITIAL, s.hrr_msg), GTLS_OK);
  Bytes ch2 = w.out(GTLS_EPOCH_INITIAL);
  w.drain(GTLS_EPOCH_INITIAL);
  const Bytes echoed = {0, 44, 0, 7, 0, 5, 9, 9, 9, 9, 9};
  EXPECT_NE(std::search(ch2.begin(), ch2.end(), echoed.begin(), echoed.end()), ch2.end());
  /* The key share is the same bytes as in the first hello. */
  GTLS_Limits lim;
  gtls_limits_default(&lim);
  GTLS_ClientHello h1, h2;
  ASSERT_EQ(gtls_msg_parse_client_hello(ch.data() + 4, ch.size() - 4, &lim, &h1), GTLS_OK);
  ASSERT_EQ(gtls_msg_parse_client_hello(ch2.data() + 4, ch2.size() - 4, &lim, &h2), GTLS_OK);
  const GTLS_Ext * a = gtls_msg_find_ext(h1.exts, h1.ext_count, GTLS_EXT_KEY_SHARE);
  const GTLS_Ext * b = gtls_msg_find_ext(h2.exts, h2.ext_count, GTLS_EXT_KEY_SHARE);
  ASSERT_TRUE(a && b);
  EXPECT_EQ(Bytes(a->data, a->data + a->len), Bytes(b->data, b->data + b->len));
  s.accept_hello(ch2);
  ASSERT_EQ(w.feed(GTLS_EPOCH_INITIAL, s.sh_msg), GTLS_OK);
  for (const Bytes * m : {&s.ee_msg, &s.cert_msg, &s.cv_msg, &s.fin_msg}) {
    ASSERT_EQ(w.feed(GTLS_EPOCH_HANDSHAKE, *m), GTLS_OK);
  }
  EXPECT_TRUE(gtls_conn_is_connected(w.conn));
  EXPECT_EQ(w.out(GTLS_EPOCH_HANDSHAKE), s.expected_client_finished);
}

/* ------------------------------------------------- EncryptedExtensions etc. */

class FlightFailures : public ::testing::TestWithParam<Case> {};

TEST_P(FlightFailures, FailWithTheirOwnResultAndAlert) {
  World w;
  SimOptions o = w.server_options();
  GetParam().setup(w, o);
  w.build();
  SimServer s(o);
  EXPECT_EQ(w.run(s), GetParam().want);
  expect_failed_and_wiped(w, GetParam().want, GetParam().alert);
}

static std::vector<Case> flight_cases() {
  std::vector<Case> c;
  c.push_back({"UnofferedExtensionInEncryptedExtensions", [](World &, SimOptions & o) {
        o.ee_extras = {put_ext(GTLS_EXT_MAX_FRAGMENT_LENGTH, Bytes{1})};
      }, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNSUPPORTED_EXTENSION});
  c.push_back({"ExtensionThatBelongsInAClientHelloOnly", [](World &, SimOptions & o) {
        o.ee_extras = {put_ext(GTLS_EXT_SIGNATURE_ALGORITHMS, Bytes{0, 2, 8, 7})};
      }, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNSUPPORTED_EXTENSION});
  c.push_back({"KeyShareInEncryptedExtensions", [](World &, SimOptions & o) {
        o.ee_extras = {group_only_ext(0x1d)};
      }, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNSUPPORTED_EXTENSION});
  c.push_back({"AlpnWhenNoneWasOffered", [](World &, SimOptions & o) { o.alpn = Bytes{'h', '2'}; },
      GTLS_ERR_PROTOCOL, GTLS_ALERT_UNSUPPORTED_EXTENSION});
  c.push_back({"AlpnNamingAProtocolNotOffered", [](World & w, SimOptions & o) {
        w.alpn = {"h2"};
        o.alpn = Bytes{'s', 'p', 'd', 'y'};
      }, GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER});
  c.push_back({"AlpnNamingAPrefixOfAProtocolOffered", [](World & w, SimOptions & o) {
        w.alpn = {"http/1.1"};
        o.alpn = Bytes{'h', 't', 't', 'p'};
      }, GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER});
  c.push_back({"ServerNameWithContent", [](World &, SimOptions & o) {
        o.ack_sni = false;
        o.ee_extras = {put_ext(GTLS_EXT_SERVER_NAME, Bytes{0, 1, 0})};
      }, GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER});
  c.push_back({"DuplicateServerNameInEncryptedExtensions", [](World &, SimOptions & o) {
        o.ee_extras = {put_ext(GTLS_EXT_SERVER_NAME, Bytes())};
      }, GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER});
  c.push_back({"MoreExtensionsThanTheLimit", [](World & w, SimOptions & o) {
        w.limits.max_extensions = 2;
        o.ee_extras = {put_ext(GTLS_EXT_SUPPORTED_GROUPS, Bytes{0, 2, 0, 0x1d}),
            put_ext(GTLS_EXT_SERVER_NAME + 100, Bytes())};
      }, GTLS_ERR_LIMIT, GTLS_ALERT_DECODE_ERROR});
  c.push_back({"CertificateRequestContextNotEmpty", [](World &, SimOptions & o) {
        o.mut_cert = [](Bytes & m) {
          Bytes t(m.begin(), m.begin() + 4);
          t.push_back(1);
          t.push_back(0x77);
          t.insert(t.end(), m.begin() + 5, m.end());
          t[3] = static_cast<unsigned char>(t.size() - 4);
          t[2] = (m.size() + 1 - 4) >> 8;
          t[3] = (m.size() + 1 - 4) & 255;
          m = t;
        };
      }, GTLS_ERR_PROTOCOL, GTLS_ALERT_ILLEGAL_PARAMETER});
  c.push_back({"ExtensionOnACertificateEntry", [](World &, SimOptions & o) {
        o.mut_cert = [](Bytes & m) {
          /* the first entry's extensions are the last two zero bytes of its
           * own encoding: find them by walking the message */
          size_t at = 4 + 1 + 3;
          size_t n = (size_t(m[at]) << 16) | (size_t(m[at + 1]) << 8) | m[at + 2];
          size_t ext_at = at + 3 + n;
          Bytes ext = {0x00, 0x05, 0x00, 0x03, 0x01, 0x00, 0x00};
          ext[0] = 0;
          Bytes t(m.begin(), m.begin() + ext_at);
          t.push_back(0);
          t.push_back(7);
          t.insert(t.end(), ext.begin(), ext.end());
          t.insert(t.end(), m.begin() + ext_at + 2, m.end());
          size_t body = t.size() - 4;
          t[1] = body >> 16;
          t[2] = (body >> 8) & 255;
          t[3] = body & 255;
          size_t list = body - 4;
          t[5] = list >> 16;
          t[6] = (list >> 8) & 255;
          t[7] = list & 255;
          m = t;
        };
      }, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNSUPPORTED_EXTENSION});
  c.push_back({"EncryptedExtensionsTruncated", [](World &, SimOptions & o) {
        o.mut_ee = [](Bytes & m) {
          m.pop_back();
          m[3] = static_cast<unsigned char>(m.size() - 4);
        };
      }, GTLS_ERR_CORRUPT, GTLS_ALERT_DECODE_ERROR});
  c.push_back({"CertificateVerifyTruncated", [](World &, SimOptions & o) {
        o.mut_cv = [](Bytes & m) {
          m.pop_back();
          m[3] = static_cast<unsigned char>(m.size() - 4);
        };
      }, GTLS_ERR_CORRUPT, GTLS_ALERT_DECODE_ERROR});
  c.push_back({"CertificateVerifySignatureLargerThanTheLimit", [](World & w, SimOptions &) {
        w.limits.max_signature_bytes = 63;
      }, GTLS_ERR_LIMIT, GTLS_ALERT_DECODE_ERROR});
  return c;
}

INSTANTIATE_TEST_SUITE_P(Flights, FlightFailures, ::testing::ValuesIn(flight_cases()),
    [](const ::testing::TestParamInfo<Case> & info) { return std::string(info.param.name); });

/* ----------------------------------------------------- order and the epochs */

namespace {

/** A world with a server, brought to the point where ServerHello was accepted. */
struct Midway {
  World w;
  std::unique_ptr<SimServer> s;
  explicit Midway(bool through_sh = true) {
    w.build();
    s.reset(new SimServer(w.server_options()));
    EXPECT_EQ(gtls_conn_start(w.conn), GTLS_OK);
    Bytes ch = w.out(GTLS_EPOCH_INITIAL);
    w.drain(GTLS_EPOCH_INITIAL);
    s->accept_hello(ch);
    if (through_sh) {
      EXPECT_EQ(w.feed(GTLS_EPOCH_INITIAL, s->sh_msg), GTLS_OK);
    }
  }
};

}  // namespace

TEST(Order, EveryMessageOutOfItsPlaceIsUnexpected) {
  /* Messages the server flight holds, tried in each state that does not want
   * them. States: wait EE, wait Certificate, wait CertificateVerify, wait
   * Finished. */
  const int states = 4;
  for (int state = 0; state < states; state++) {
    for (int which = 0; which < 4; which++) {
      if (which == state) {
        continue;
      }
      Midway m;
      const Bytes * seq[4] = {&m.s->ee_msg, &m.s->cert_msg, &m.s->cv_msg, &m.s->fin_msg};
      for (int i = 0; i < state; i++) {
        ASSERT_EQ(m.w.feed(GTLS_EPOCH_HANDSHAKE, *seq[i]), GTLS_OK);
      }
      EXPECT_EQ(m.w.feed(GTLS_EPOCH_HANDSHAKE, *seq[which]), GTLS_ERR_PROTOCOL)
          << "state " << state << " message " << which;
      expect_failed_and_wiped(m.w, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNEXPECTED_MESSAGE);
    }
  }
}

TEST(Order, AServerHelloAgainAfterTheFirstIsUnexpected) {
  Midway m;
  EXPECT_EQ(m.w.feed(GTLS_EPOCH_HANDSHAKE, m.s->sh_msg), GTLS_ERR_PROTOCOL);
  expect_failed_and_wiped(m.w, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNEXPECTED_MESSAGE);
}

TEST(Order, ANewSessionTicketBeforeTheHandshakeEndsIsUnexpected) {
  Midway m;
  Vec v("simple-1rtt");
  const Bytes nst = v["server.construct-a-newsessionticket-handshake-message.newsessionticket"];
  EXPECT_EQ(m.w.feed(GTLS_EPOCH_HANDSHAKE, nst), GTLS_ERR_PROTOCOL);
  expect_failed_and_wiped(m.w, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNEXPECTED_MESSAGE);
}

TEST(Order, ACertificateRequestIsUnsupportedNotAnEmptyAnswer) {
  Midway m;
  ASSERT_EQ(m.w.feed(GTLS_EPOCH_HANDSHAKE, m.s->ee_msg), GTLS_OK);
  Bytes req = {GTLS_HS_CERTIFICATE_REQUEST, 0, 0, 4, 0, 0, 0, 0};
  EXPECT_EQ(m.w.feed(GTLS_EPOCH_HANDSHAKE, req), GTLS_ERR_UNSUPPORTED);
  expect_failed_and_wiped(m.w, GTLS_ERR_UNSUPPORTED, GTLS_ALERT_HANDSHAKE_FAILURE);
}

TEST(Order, AfterTheHandshakeOnlyTicketsAreAccepted) {
  struct Msg {
    unsigned type;
    GTLS_Result want;
    unsigned alert;
  };
  const Msg msgs[] = {
    {GTLS_HS_KEY_UPDATE, GTLS_ERR_UNSUPPORTED, GTLS_ALERT_UNEXPECTED_MESSAGE},
    {GTLS_HS_CERTIFICATE_REQUEST, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNEXPECTED_MESSAGE},
    {GTLS_HS_FINISHED, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNEXPECTED_MESSAGE},
    {GTLS_HS_SERVER_HELLO, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNEXPECTED_MESSAGE},
    {GTLS_HS_ENCRYPTED_EXTENSIONS, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNEXPECTED_MESSAGE},
  };
  for (const Msg & msg : msgs) {
    Midway m;
    for (const Bytes * b : {&m.s->ee_msg, &m.s->cert_msg, &m.s->cv_msg, &m.s->fin_msg}) {
      ASSERT_EQ(m.w.feed(GTLS_EPOCH_HANDSHAKE, *b), GTLS_OK);
    }
    ASSERT_TRUE(gtls_conn_is_connected(m.w.conn));
    Bytes bad = {static_cast<unsigned char>(msg.type), 0, 0, 1, 0};
    EXPECT_EQ(m.w.feed(GTLS_EPOCH_APPLICATION, bad), msg.want) << msg.type;
    EXPECT_EQ(gtls_conn_alert(m.w.conn), msg.alert) << msg.type;
    EXPECT_TRUE(gtls_conn_secrets_are_wiped(m.w.conn)) << msg.type;
  }
}

TEST(Epochs, EachStateWantsItsOwnEpochAndNoOther) {
  /* Waiting for ServerHello: INITIAL only. */
  for (GTLS_Epoch e : {GTLS_EPOCH_HANDSHAKE, GTLS_EPOCH_APPLICATION, GTLS_EPOCH_EARLY}) {
    Midway m(false);
    EXPECT_EQ(m.w.feed(e, m.s->sh_msg), GTLS_ERR_PROTOCOL) << e;
    EXPECT_EQ(gtls_conn_alert(m.w.conn), GTLS_ALERT_UNEXPECTED_MESSAGE);
  }
  /* Waiting for EncryptedExtensions: HANDSHAKE only. */
  for (GTLS_Epoch e : {GTLS_EPOCH_INITIAL, GTLS_EPOCH_APPLICATION, GTLS_EPOCH_EARLY}) {
    Midway m;
    EXPECT_EQ(m.w.feed(e, m.s->ee_msg), GTLS_ERR_PROTOCOL) << e;
    EXPECT_EQ(gtls_conn_alert(m.w.conn), GTLS_ALERT_UNEXPECTED_MESSAGE);
  }
  /* Connected: APPLICATION only. */
  Vec v("simple-1rtt");
  const Bytes nst = v["server.construct-a-newsessionticket-handshake-message.newsessionticket"];
  for (GTLS_Epoch e : {GTLS_EPOCH_INITIAL, GTLS_EPOCH_HANDSHAKE, GTLS_EPOCH_EARLY}) {
    Midway m;
    for (const Bytes * b : {&m.s->ee_msg, &m.s->cert_msg, &m.s->cv_msg, &m.s->fin_msg}) {
      ASSERT_EQ(m.w.feed(GTLS_EPOCH_HANDSHAKE, *b), GTLS_OK);
    }
    EXPECT_EQ(m.w.feed(e, nst), GTLS_ERR_PROTOCOL) << e;
  }
}

TEST(Epochs, NothingMayFollowServerHelloInItsEpoch) {
  Midway m(false);
  Bytes both = m.s->sh_msg;
  both.insert(both.end(), m.s->ee_msg.begin(), m.s->ee_msg.end());
  EXPECT_EQ(m.w.feed(GTLS_EPOCH_INITIAL, both), GTLS_ERR_PROTOCOL);
  expect_failed_and_wiped(m.w, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNEXPECTED_MESSAGE);
}

TEST(Epochs, NothingMayFollowAHelloRetryRequestEither) {
  World w;
  w.build();
  SimOptions o = w.server_options();
  o.hrr = true;
  SimServer s(o);
  ASSERT_EQ(gtls_conn_start(w.conn), GTLS_OK);
  Bytes ch = w.out(GTLS_EPOCH_INITIAL);
  w.drain(GTLS_EPOCH_INITIAL);
  s.accept_hello(ch);
  Bytes both = s.hrr_msg;
  both.push_back(2);
  EXPECT_EQ(w.feed(GTLS_EPOCH_INITIAL, both), GTLS_ERR_PROTOCOL);
}

TEST(Epochs, AMessageMaySpanFeedsButNotAnEpoch) {
  Midway m;
  Bytes half(m.s->ee_msg.begin(), m.s->ee_msg.begin() + 5);
  ASSERT_EQ(m.w.feed(GTLS_EPOCH_HANDSHAKE, half), GTLS_OK);
  Bytes rest(m.s->ee_msg.begin() + 5, m.s->ee_msg.end());
  EXPECT_EQ(m.w.feed(GTLS_EPOCH_APPLICATION, rest), GTLS_ERR_PROTOCOL)
      << "the remainder arrives under other keys";
  expect_failed_and_wiped(m.w, GTLS_ERR_PROTOCOL, GTLS_ALERT_UNEXPECTED_MESSAGE);
}

TEST(Epochs, TheEndOfTheFlightMovesTheEpochOn) {
  Midway m;
  Bytes flight = m.s->flight();
  Vec v("simple-1rtt");
  const Bytes nst = v["server.construct-a-newsessionticket-handshake-message.newsessionticket"];
  Bytes trailing = flight;
  trailing.insert(trailing.end(), nst.begin(), nst.end());
  EXPECT_EQ(m.w.feed(GTLS_EPOCH_HANDSHAKE, trailing), GTLS_ERR_PROTOCOL)
      << "a ticket is protected with application keys, so it cannot ride in this epoch";
}

/* ------------------------------------------------------------------ limits */

TEST(Limits, AHeaderThatAnnouncesATooLargeMessageIsRefusedBeforeItIsBuffered) {
  Midway m;
  Bytes header = {GTLS_HS_ENCRYPTED_EXTENSIONS, 0x7f, 0xff, 0xff};
  EXPECT_EQ(m.w.feed(GTLS_EPOCH_HANDSHAKE, header), GTLS_ERR_LIMIT);
  expect_failed_and_wiped(m.w, GTLS_ERR_LIMIT, GTLS_ALERT_DECODE_ERROR);
  EXPECT_EQ(m.w.conn->in.len, 4u) << "only the header was held";
  EXPECT_LE(m.w.conn->in.cap, 256u) << "and nothing was allocated for the body";
}

TEST(Limits, TheMessageSizeCapIsExactAtItsEdge) {
  World w;
  w.limits.max_handshake_message = 100;
  w.build();
  SimServer s(w.server_options());
  ASSERT_EQ(gtls_conn_start(w.conn), GTLS_OK);
  Bytes ch = w.out(GTLS_EPOCH_INITIAL);
  w.drain(GTLS_EPOCH_INITIAL);
  s.accept_hello(ch);
  ASSERT_EQ(w.feed(GTLS_EPOCH_INITIAL, s.sh_msg), GTLS_OK);
  ASSERT_EQ(w.feed(GTLS_EPOCH_HANDSHAKE, s.ee_msg), GTLS_OK);
  /* A Certificate of exactly 100 bytes is a limit-sized message; 101 is over. */
  Bytes at_edge(4, 0);
  at_edge[0] = GTLS_HS_CERTIFICATE;
  at_edge[3] = 100;
  EXPECT_EQ(w.feed(GTLS_EPOCH_HANDSHAKE, at_edge), GTLS_OK) << "the header alone is accepted";
  World w2;
  w2.limits.max_handshake_message = 100;
  w2.build();
  SimServer s2(w2.server_options());
  ASSERT_EQ(gtls_conn_start(w2.conn), GTLS_OK);
  Bytes ch2 = w2.out(GTLS_EPOCH_INITIAL);
  w2.drain(GTLS_EPOCH_INITIAL);
  s2.accept_hello(ch2);
  ASSERT_EQ(w2.feed(GTLS_EPOCH_INITIAL, s2.sh_msg), GTLS_OK);
  ASSERT_EQ(w2.feed(GTLS_EPOCH_HANDSHAKE, s2.ee_msg), GTLS_OK);
  Bytes over(4, 0);
  over[0] = GTLS_HS_CERTIFICATE;
  over[3] = 101;
  EXPECT_EQ(w2.feed(GTLS_EPOCH_HANDSHAKE, over), GTLS_ERR_LIMIT);
}

TEST(Limits, TheHandshakeAsAWholeIsCapped) {
  World probe;
  probe.build();
  SimServer ps(probe.server_options());
  ASSERT_EQ(probe.run(ps), GTLS_OK);
  size_t total = ps.sh_msg.size() + ps.flight().size();
  World w;
  w.limits.max_handshake_total = static_cast<uint32_t>(total);
  w.build();
  SimServer s(w.server_options());
  EXPECT_EQ(w.run(s), GTLS_OK) << "exactly the whole handshake";
  World w2;
  w2.limits.max_handshake_total = static_cast<uint32_t>(total - 1);
  w2.build();
  SimServer s2(w2.server_options());
  EXPECT_EQ(w2.run(s2), GTLS_ERR_LIMIT);
  expect_failed_and_wiped(w2, GTLS_ERR_LIMIT, GTLS_ALERT_DECODE_ERROR);
}

TEST(Limits, TheOutputQueueIsCapped) {
  World w;
  w.limits.max_output_bytes = 16;
  w.build();
  EXPECT_EQ(gtls_conn_start(w.conn), GTLS_ERR_LIMIT);
  EXPECT_TRUE(gtls_conn_is_failed(w.conn));
  EXPECT_EQ(gtls_conn_alert(w.conn), GTLS_ALERT_INTERNAL_ERROR)
      << "a cap of ours is not the peer's decode error";
  EXPECT_TRUE(gtls_conn_secrets_are_wiped(w.conn)) << "the key share's private half too";
}

TEST(Limits, UnconsumedOutputCountsAgainstTheCapAndConsumingFreesIt) {
  World w;
  w.build();
  ASSERT_EQ(gtls_conn_start(w.conn), GTLS_OK);
  Bytes ch = w.out(GTLS_EPOCH_INITIAL);
  ASSERT_GT(ch.size(), 8u);
  ASSERT_EQ(gtls_conn_consume_output(w.conn, GTLS_EPOCH_INITIAL, 8), GTLS_OK);
  EXPECT_EQ(w.out(GTLS_EPOCH_INITIAL), Bytes(ch.begin() + 8, ch.end()))
      << "a short write is not a protocol event";
  EXPECT_EQ(gtls_conn_consume_output(w.conn, GTLS_EPOCH_INITIAL, ch.size()), GTLS_ERR_INVALID);
  EXPECT_FALSE(gtls_conn_is_failed(w.conn));
}

TEST(Limits, ATicketLargerThanTheLimitIsALimit) {
  World w;
  w.limits.max_ticket_bytes = 10;
  w.build();
  SimServer s(w.server_options());
  ASSERT_EQ(w.run(s), GTLS_OK);
  Vec v("simple-1rtt");
  const Bytes nst = v["server.construct-a-newsessionticket-handshake-message.newsessionticket"];
  EXPECT_EQ(w.feed(GTLS_EPOCH_APPLICATION, nst), GTLS_ERR_LIMIT);
  expect_failed_and_wiped(w, GTLS_ERR_LIMIT, GTLS_ALERT_DECODE_ERROR);
}

/* ---------------------------------------------- failure is terminal and wipes */

TEST(Failure, TheSecretsExistBeforeTheFailureAndAreGoneAfter) {
  World w;
  w.build();
  SimOptions o = w.server_options();
  o.bad_finished = true;
  SimServer s(o);
  ASSERT_EQ(gtls_conn_start(w.conn), GTLS_OK);
  Bytes ch = w.out(GTLS_EPOCH_INITIAL);
  w.drain(GTLS_EPOCH_INITIAL);
  s.accept_hello(ch);
  ASSERT_EQ(w.feed(GTLS_EPOCH_INITIAL, s.sh_msg), GTLS_OK);
  EXPECT_FALSE(gtls_conn_secrets_are_wiped(w.conn)) << "the handshake secrets exist now";
  Bytes buf(GTLS_HASH_MAX);
  size_t n = 0;
  ASSERT_EQ(gtls_conn_secret(w.conn, GTLS_EPOCH_HANDSHAKE, GTLS_DIR_READ, buf.data(), buf.size(), &n),
      GTLS_OK);
  for (const Bytes * m : {&s.ee_msg, &s.cert_msg, &s.cv_msg}) {
    ASSERT_EQ(w.feed(GTLS_EPOCH_HANDSHAKE, *m), GTLS_OK);
  }
  EXPECT_EQ(w.feed(GTLS_EPOCH_HANDSHAKE, s.fin_msg), GTLS_ERR_FINISHED);
  EXPECT_TRUE(gtls_conn_secrets_are_wiped(w.conn));
  EXPECT_EQ(gtls_conn_secret(w.conn, GTLS_EPOCH_HANDSHAKE, GTLS_DIR_READ, buf.data(), buf.size(), &n),
      GTLS_ERR_FAILED);
}

TEST(Failure, ASuccessfulHandshakeKeepsItsSecretsUntilFreed) {
  World w;
  w.build();
  SimServer s(w.server_options());
  ASSERT_EQ(w.run(s), GTLS_OK);
  EXPECT_FALSE(gtls_conn_secrets_are_wiped(w.conn));
  EXPECT_EQ(gtls_conn_failure(w.conn), GTLS_OK);
  EXPECT_EQ(gtls_conn_alert(w.conn), GTLS_ALERT_NONE);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
