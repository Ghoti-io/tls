/**
 * @file
 *
 * The client handshake against RFC 8448: the simple 1-RTT trace and the
 * HelloRetryRequest trace, fed whole and fed one byte at a time, with every
 * secret, the second ClientHello, and the client's Finished compared with the
 * RFC byte for byte.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "rfc_run.h"

using namespace gtlstest;

class Rfc8448 : public ::testing::TestWithParam<std::tuple<bool, size_t>> {
 protected:
  Trace trace() const { return std::get<0>(GetParam()) ? hrr_trace() : simple_trace(); }
  size_t chunk() const { return std::get<1>(GetParam()); }
};

TEST_P(Rfc8448, ClientHelloGoesOutExactlyAsTheRfcHasIt) {
  Flow r(trace());
  r.start();
  EXPECT_EQ(r.pending(GTLS_EPOCH_INITIAL), r.v[trace().ch1()]);
  EXPECT_EQ(r.pending(GTLS_EPOCH_HANDSHAKE), Bytes());
  EXPECT_EQ(r.pending(GTLS_EPOCH_APPLICATION), Bytes());
  EXPECT_EQ(gtls_conn_state(r.conn), GTLS_STATE_WAIT_SH);
}

TEST_P(Rfc8448, HandshakeSecretsAndTheTranscriptAfterServerHello) {
  Flow r(trace());
  r.start();
  r.take(GTLS_EPOCH_INITIAL);
  ASSERT_EQ(r.through_server_hello(chunk()), GTLS_OK);
  EXPECT_EQ(gtls_conn_state(r.conn), GTLS_STATE_WAIT_EE);
  EXPECT_EQ(gtls_conn_suite(r.conn), GTLS_SUITE_AES_128_GCM_SHA256);
  EXPECT_EQ(gtls_conn_group(r.conn),
      trace().hrr ? GTLS_GROUP_SECP256R1 : GTLS_GROUP_X25519);
  EXPECT_EQ(gtls_conn_retried(r.conn), trace().hrr ? 1 : 0);

  Vec & v = r.v;
  EXPECT_EQ(r.secret(GTLS_SECRET_EARLY), v["server.extract-secret-early.secret"]);
  EXPECT_EQ(r.secret(GTLS_SECRET_HANDSHAKE), v["server.extract-secret-handshake.secret"]);
  EXPECT_EQ(r.secret(GTLS_SECRET_CLIENT_HS),
      v["server.derive-secret-tls13-c-hs-traffic.expanded"]);
  EXPECT_EQ(r.secret(GTLS_SECRET_SERVER_HS),
      v["server.derive-secret-tls13-s-hs-traffic.expanded"]);
  EXPECT_EQ(r.transcript(), v["server.derive-secret-tls13-c-hs-traffic.hash"]);

  /* The same secrets by the public call, from the client's point of view. */
  Bytes out(GTLS_HASH_MAX);
  size_t n = 0;
  ASSERT_EQ(gtls_conn_secret(r.conn, GTLS_EPOCH_HANDSHAKE, GTLS_DIR_WRITE, out.data(),
                out.size(), &n), GTLS_OK);
  EXPECT_EQ(Bytes(out.begin(), out.begin() + n),
      v["server.derive-secret-tls13-c-hs-traffic.expanded"]);
  ASSERT_EQ(gtls_conn_secret(r.conn, GTLS_EPOCH_HANDSHAKE, GTLS_DIR_READ, out.data(),
                out.size(), &n), GTLS_OK);
  EXPECT_EQ(Bytes(out.begin(), out.begin() + n),
      v["server.derive-secret-tls13-s-hs-traffic.expanded"]);
  /* ...and none from an epoch that has not been reached. */
  EXPECT_EQ(gtls_conn_secret(r.conn, GTLS_EPOCH_APPLICATION, GTLS_DIR_WRITE, out.data(),
                out.size(), &n), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_secret(r.conn, GTLS_EPOCH_INITIAL, GTLS_DIR_WRITE, out.data(),
                out.size(), &n), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_secret(r.conn, GTLS_EPOCH_EARLY, GTLS_DIR_WRITE, out.data(),
                out.size(), &n), GTLS_ERR_UNSUPPORTED);
}

TEST_P(Rfc8448, TheWholeHandshakeToApplicationSecrets) {
  Flow r(trace());
  r.start();
  r.take(GTLS_EPOCH_INITIAL);
  ASSERT_EQ(r.through_server_hello(chunk()), GTLS_OK);
  ASSERT_EQ(r.feed(GTLS_EPOCH_HANDSHAKE, r.v[trace().flight()], chunk()), GTLS_OK);
  EXPECT_TRUE(gtls_conn_is_connected(r.conn));
  EXPECT_FALSE(gtls_conn_is_failed(r.conn));
  EXPECT_EQ(r.verdict.calls, 1) << "the chain was judged once, on the Certificate message";

  Vec & v = r.v;
  /* What the client sends is the RFC's Finished, nothing else. */
  EXPECT_EQ(r.pending(GTLS_EPOCH_HANDSHAKE), v[trace().client_finished()]);
  EXPECT_EQ(r.pending(GTLS_EPOCH_INITIAL), Bytes());
  EXPECT_EQ(r.pending(GTLS_EPOCH_APPLICATION), Bytes());

  EXPECT_EQ(r.secret(GTLS_SECRET_MASTER), v["server.extract-secret-master.secret"]);
  EXPECT_EQ(r.secret(GTLS_SECRET_CLIENT_AP),
      v["server.derive-secret-tls13-c-ap-traffic.expanded"]);
  EXPECT_EQ(r.secret(GTLS_SECRET_SERVER_AP),
      v["server.derive-secret-tls13-s-ap-traffic.expanded"]);
  /* The transcript now runs through the client's Finished, which is what the
   * resumption secret is taken over. */
  EXPECT_EQ(r.transcript(), v["client.derive-secret-tls13-res-master.hash"]);
  Bytes res(32);
  ASSERT_EQ(gtls_schedule_resumption(&r.conn->sec.schedule, r.transcript().data(), res.data()),
      GTLS_OK);
  EXPECT_EQ(res, v["client.derive-secret-tls13-res-master.expanded"]);

  Bytes out(GTLS_HASH_MAX);
  size_t n = 0;
  ASSERT_EQ(gtls_conn_secret(r.conn, GTLS_EPOCH_APPLICATION, GTLS_DIR_WRITE, out.data(),
                out.size(), &n), GTLS_OK);
  EXPECT_EQ(Bytes(out.begin(), out.begin() + n),
      v["server.derive-secret-tls13-c-ap-traffic.expanded"]);
  ASSERT_EQ(gtls_conn_secret(r.conn, GTLS_EPOCH_APPLICATION, GTLS_DIR_READ, out.data(),
                out.size(), &n), GTLS_OK);
  EXPECT_EQ(Bytes(out.begin(), out.begin() + n),
      v["server.derive-secret-tls13-s-ap-traffic.expanded"]);
  /* Keys and IVs from those secrets: what the record layer will use. */
  Bytes key(GTLS_KEY_MAX);
  Bytes iv(GTLS_IV_LEN);
  ASSERT_EQ(gtls_traffic_keys(gtls_conn_suite(r.conn), out.data(), key.data(), iv.data()),
      GTLS_OK);
  key.resize(16);
  EXPECT_EQ(key, v["server.derive-write-traffic-keys-for-application-data.key-expanded"]);
  EXPECT_EQ(iv, v["server.derive-write-traffic-keys-for-application-data.iv-expanded"]);

  /* The server's certificate is available to the caller once it was accepted. */
  const unsigned char * der = nullptr;
  size_t der_len = 0;
  ASSERT_EQ(gtls_conn_peer_certificate(r.conn, &der, &der_len), GTLS_OK);
  EXPECT_EQ(der_len, 4u + 0x1acu) << "30 82 01 ac: the DER the RFC prints";
  EXPECT_EQ(der[0], 0x30);
  const unsigned char * proto = reinterpret_cast<const unsigned char *>("x");
  ASSERT_EQ(gtls_conn_alpn(r.conn, &proto, &n), GTLS_OK);
  EXPECT_EQ(n, 0u);
  EXPECT_EQ(proto, nullptr);
  EXPECT_TRUE(sni_ack(r.conn))
      << "the RFC's EncryptedExtensions ends with an empty server_name";
}

INSTANTIATE_TEST_SUITE_P(Traces, Rfc8448,
    ::testing::Combine(::testing::Bool(), ::testing::Values<size_t>(0, 1, 3, 64)),
    [](const ::testing::TestParamInfo<std::tuple<bool, size_t>> & info) {
      return std::string(std::get<0>(info.param) ? "Hrr" : "Simple") + "Chunk" +
          std::to_string(std::get<1>(info.param));
    });

TEST(Rfc8448Hrr, ASecondClientHelloIsTheRfcsByteForByteAndNothingElseWasDrawn) {
  for (size_t chunk : {size_t(0), size_t(1), size_t(7)}) {
    Flow r(hrr_trace());
    r.start();
    r.take(GTLS_EPOCH_INITIAL);
    ASSERT_EQ(r.feed(GTLS_EPOCH_INITIAL, r.v[hrr_trace().hrr_msg()], chunk), GTLS_OK);
    EXPECT_EQ(gtls_conn_state(r.conn), GTLS_STATE_WAIT_SH2);
    EXPECT_EQ(r.pending(GTLS_EPOCH_INITIAL), r.v[hrr_trace().ch2()]) << "chunk " << chunk;
    EXPECT_EQ(r.rnd.draws, 1) << "one draw: the P-256 scalar";
    EXPECT_TRUE(r.rnd.chunks.empty());
  }
}

/* Fed at every split of the server flight, not only at fixed sizes: two
 * pieces, cut at each of the 657 offsets. The result is the same as whole. */
TEST(Rfc8448Split, ServerFlightCutAtEveryOffsetGivesTheSameConnection) {
  Flow whole(simple_trace());
  whole.start();
  whole.take(GTLS_EPOCH_INITIAL);
  ASSERT_EQ(whole.through_server_hello(), GTLS_OK);
  const Bytes flight = whole.v[simple_trace().flight()];
  ASSERT_EQ(whole.feed(GTLS_EPOCH_HANDSHAKE, flight), GTLS_OK);
  const Bytes want_out = whole.pending(GTLS_EPOCH_HANDSHAKE);
  const Bytes want_ap = whole.secret(GTLS_SECRET_CLIENT_AP);
  for (size_t cut = 1; cut < flight.size(); cut++) {
    Flow r(simple_trace());
    r.start();
    r.take(GTLS_EPOCH_INITIAL);
    ASSERT_EQ(r.through_server_hello(), GTLS_OK);
    Bytes a(flight.begin(), flight.begin() + cut);
    Bytes b(flight.begin() + cut, flight.end());
    ASSERT_EQ(r.feed(GTLS_EPOCH_HANDSHAKE, a), GTLS_OK) << "cut " << cut;
    EXPECT_FALSE(gtls_conn_is_connected(r.conn)) << "cut " << cut;
    ASSERT_EQ(r.feed(GTLS_EPOCH_HANDSHAKE, b), GTLS_OK) << "cut " << cut;
    ASSERT_TRUE(gtls_conn_is_connected(r.conn)) << "cut " << cut;
    EXPECT_EQ(r.pending(GTLS_EPOCH_HANDSHAKE), want_out) << "cut " << cut;
    EXPECT_EQ(r.secret(GTLS_SECRET_CLIENT_AP), want_ap) << "cut " << cut;
  }
}

TEST(Rfc8448Split, ServerHelloCutAtEveryOffset) {
  Flow whole(simple_trace());
  const Bytes sh = whole.v[simple_trace().sh()];
  for (size_t cut = 1; cut < sh.size(); cut++) {
    Flow r(simple_trace());
    r.start();
    r.take(GTLS_EPOCH_INITIAL);
    Bytes a(sh.begin(), sh.begin() + cut);
    Bytes b(sh.begin() + cut, sh.end());
    ASSERT_EQ(r.feed(GTLS_EPOCH_INITIAL, a), GTLS_OK) << cut;
    EXPECT_EQ(gtls_conn_state(r.conn), GTLS_STATE_WAIT_SH) << cut;
    ASSERT_EQ(r.feed(GTLS_EPOCH_INITIAL, b), GTLS_OK) << cut;
    EXPECT_EQ(gtls_conn_state(r.conn), GTLS_STATE_WAIT_EE) << cut;
  }
}

/* The NewSessionTicket the RFC's server sends after the handshake is parsed
 * and thrown away. */
TEST(Rfc8448Post, NewSessionTicketIsAcceptedAndDiscarded) {
  Flow r(simple_trace());
  r.start();
  r.take(GTLS_EPOCH_INITIAL);
  ASSERT_EQ(r.through_server_hello(), GTLS_OK);
  ASSERT_EQ(r.feed(GTLS_EPOCH_HANDSHAKE, r.v[simple_trace().flight()]), GTLS_OK);
  r.take(GTLS_EPOCH_HANDSHAKE);
  const Bytes nst = r.v["server.construct-a-newsessionticket-handshake-message.newsessionticket"];
  ASSERT_EQ(r.feed(GTLS_EPOCH_APPLICATION, nst), GTLS_OK);
  ASSERT_EQ(r.feed(GTLS_EPOCH_APPLICATION, nst, 5), GTLS_OK) << "and one byte at a time";
  EXPECT_TRUE(gtls_conn_is_connected(r.conn));
  EXPECT_EQ(r.conn->tickets, 2u);
  EXPECT_EQ(r.pending(GTLS_EPOCH_APPLICATION), Bytes()) << "nothing is stored or sent";
}

TEST(Rfc8448Post, TooManyTicketsIsALimit) {
  Flow r(simple_trace());
  r.start();
  r.take(GTLS_EPOCH_INITIAL);
  ASSERT_EQ(r.through_server_hello(), GTLS_OK);
  ASSERT_EQ(r.feed(GTLS_EPOCH_HANDSHAKE, r.v[simple_trace().flight()]), GTLS_OK);
  const Bytes nst = r.v["server.construct-a-newsessionticket-handshake-message.newsessionticket"];
  GTLS_Limits lim;
  gtls_limits_default(&lim);
  for (uint32_t i = 0; i < lim.max_tickets; i++) {
    ASSERT_EQ(r.feed(GTLS_EPOCH_APPLICATION, nst), GTLS_OK) << i;
  }
  EXPECT_EQ(r.feed(GTLS_EPOCH_APPLICATION, nst), GTLS_ERR_LIMIT);
  EXPECT_TRUE(gtls_conn_is_failed(r.conn));
}

/* What the verdict seam stands in for: the real check, on the RFC's own
 * certificate, refuses it. This is why the seam exists, and it is the control
 * that shows the default is not the accept-all the other tests use. */
TEST(Rfc8448Chain, TheRealCheckRefusesTheRfcsCertificate) {
  Flow r(simple_trace());
  gtls_conn_set_hooks(r.conn, ScriptedRandom::fn, &r.rnd, nullptr, nullptr);
  r.start();
  r.take(GTLS_EPOCH_INITIAL);
  ASSERT_EQ(r.through_server_hello(), GTLS_OK);
  GTLS_Result got = r.feed(GTLS_EPOCH_HANDSHAKE, r.v[simple_trace().flight()]);
  EXPECT_EQ(got, GTLS_ERR_CERT_ISSUER) << "the trust store is empty";
  EXPECT_EQ(gtls_conn_alert(r.conn), GTLS_ALERT_UNKNOWN_CA);
  EXPECT_TRUE(gtls_conn_is_failed(r.conn));
}

/* A control for the seam itself: a verdict of "refused" is honoured. */
TEST(Rfc8448Chain, ARefusingVerdictFailsTheHandshakeWithItsOwnResult) {
  Flow r(simple_trace());
  r.verdict.result = GTLS_ERR_CERT_HOST;
  r.start();
  r.take(GTLS_EPOCH_INITIAL);
  ASSERT_EQ(r.through_server_hello(), GTLS_OK);
  EXPECT_EQ(r.feed(GTLS_EPOCH_HANDSHAKE, r.v[simple_trace().flight()]), GTLS_ERR_CERT_HOST);
  EXPECT_EQ(gtls_conn_alert(r.conn), GTLS_ALERT_BAD_CERTIFICATE);
  EXPECT_TRUE(gtls_conn_secrets_are_wiped(r.conn));
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
