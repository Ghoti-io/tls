/**
 * @file
 *
 * Resumption, the real client against the real server: every suite and group
 * with the stream split at one byte, after a HelloRetryRequest, in the
 * message interface, ticket rotation, and each way a ticket can fail to
 * qualify (which is a full handshake and not an error) beside the one that is
 * fatal (a binder that is wrong). A resumed handshake has no Certificate; a
 * new ticket comes with every connection.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "loop.h"
#include "rfc_run.h"

#include <functional>

using namespace gtlstest;

namespace {

const GTLS_Suite kSuites[] = {GTLS_SUITE_AES_128_GCM_SHA256, GTLS_SUITE_AES_256_GCM_SHA384,
    GTLS_SUITE_CHACHA20_POLY1305_SHA256};
const GTLS_Group kGroups[] = {GTLS_GROUP_X25519, GTLS_GROUP_SECP256R1, GTLS_GROUP_SECP384R1};

GTLS_TicketKey tkey(unsigned seed, int64_t from = kNow - 1000, int64_t to = kNow + 1000000) {
  GTLS_TicketKey k;
  std::memset(&k, 0, sizeof k);
  for (unsigned i = 0; i < GTLS_TICKET_KEY_NAME_LEN; i++) {
    k.name[i] = static_cast<unsigned char>(seed * 16 + i);
  }
  for (unsigned i = 0; i < GTLS_TICKET_KEY_LEN; i++) {
    k.key[i] = static_cast<unsigned char>(seed * 7 + i * 3 + 1);
  }
  k.not_before = from;
  k.not_after = to;
  return k;
}

/** One credential, and a Pair with a keyring. */
struct Env {
  std::unique_ptr<Cred> cred = ed_cred();
  Pair p;
  Env() : p(*cred) { p.keys = {tkey(1)}; }
};

/** A Pair that shares the credential and the keyring of another. */
struct Next {
  Pair p;
  explicit Next(const Env & e) : p(*e.cred) { p.keys = e.p.keys; }
};

void run_full(Pair & p, size_t chunk = 0) {
  ASSERT_EQ(p.build(), GTLS_OK);
  p.run(chunk);
  ASSERT_TRUE(p.connected()) << "client: " << result_name(gtls_conn_failure(p.c.conn))
                             << ", server: " << result_name(gtls_conn_failure(p.s.conn));
}

/** The session a connection was sent, or the test fails. */
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

size_t peer_cert_len(const Pair & p) {
  const unsigned char * der = nullptr;
  size_t n = 0;
  EXPECT_EQ(gtls_conn_peer_certificate(p.c.conn, &der, &n), GTLS_OK);
  return n;
}

void expect_resumed(const Pair & p, bool resumed) {
  EXPECT_EQ(gtls_conn_resumed(p.c.conn), resumed ? 1 : 0) << "client";
  EXPECT_EQ(gtls_conn_resumed(p.s.conn), resumed ? 1 : 0) << "server";
  if (resumed) {
    EXPECT_EQ(peer_cert_len(p), 0u) << "no certificate in an abbreviated handshake";
  } else {
    EXPECT_GT(peer_cert_len(p), 0u);
  }
}

void talk(Pair & p, size_t chunk) {
  const Bytes up = pattern(3000, 3);
  const Bytes down = pattern(9000, 4);
  p.send_all(p.c, p.s, up, chunk);
  p.send_all(p.s, p.c, down, chunk);
  p.run(chunk);
  EXPECT_EQ(p.s.got, up);
  EXPECT_EQ(p.c.got, down);
}

size_t chain_bytes(const Cred & c) {
  size_t n = 0;
  for (const Bytes & d : c.chain) {
    n += d.size();
  }
  return n;
}

/** The ServerHello message in the first record of what a server sent. */
Bytes server_hello_in(const Bytes & wire) {
  if (wire.size() < 9 || wire[0] != 22) {
    return Bytes();
  }
  size_t n = 4 + ((static_cast<size_t>(wire[6]) << 16) | (static_cast<size_t>(wire[7]) << 8) | wire[8]);
  return Bytes(wire.begin() + 5, wire.begin() + 5 + static_cast<long>(n));
}

GTLS_ServerHello parse_sh(const Bytes & msg) {
  GTLS_ServerHello sh;
  GTLS_Limits lim;
  gtls_limits_default(&lim);
  EXPECT_EQ(gtls_msg_parse_server_hello(msg.data() + 4, msg.size() - 4, &lim, &sh), GTLS_OK);
  return sh;
}

/**
 * Offer @p session from a fresh pair that shares @p e's credential and keys,
 * let @p tweak change the pair first, feed the server the client's hello, and
 * report whether the server resumed (-1 when it failed).
 */
int decision(const Env & e, const GTLS_Session * session,
    const std::function<void(Pair &)> & tweak = nullptr, int64_t at = 0) {
  Next n(e);
  if (tweak) {
    tweak(n.p);
  }
  n.p.offer = session;
  n.p.offer_time = at;
  EXPECT_EQ(n.p.build(), GTLS_OK);
  Bytes hello = stream_out(n.p.c.conn);
  size_t used = 0;
  GTLS_Result r = gtls_conn_stream_feed(n.p.s.conn, hello.data(), hello.size(), n.p.now, &used);
  if (r != GTLS_OK) {
    return -1;
  }
  return gtls_conn_resumed(n.p.s.conn);
}

}  // namespace

/* ---------------------------------------------------------------- the basics */

TEST(Resume, EverySuiteAndGroupWithTheStreamSplitAtEveryByte) {
  for (GTLS_Suite suite : kSuites) {
    for (GTLS_Group group : kGroups) {
      for (size_t chunk : {static_cast<size_t>(0), static_cast<size_t>(1), static_cast<size_t>(7)}) {
        Env e;
        e.p.scfg.suites = &suite;
        e.p.scfg.suite_count = 1;
        e.p.ccfg.groups = &group;
        e.p.ccfg.group_count = 1;
        ASSERT_NO_FATAL_FAILURE(run_full(e.p, chunk));
        expect_resumed(e.p, false);
        ASSERT_EQ(gtls_conn_session_count(e.p.c.conn), 1u) << "one ticket by default";
        const size_t first_sent = e.p.s.sent;
        Held h;
        ASSERT_NO_FATAL_FAILURE(h.take(e.p));
        GTLS_SessionInfo info;
        ASSERT_EQ(gtls_session_info(h.s, &info), GTLS_OK);
        EXPECT_EQ(info.suite, suite);
        EXPECT_EQ(info.lifetime, GTLS_TICKET_LIFETIME_DEFAULT);

        e.p.s.sent = 0;
        ASSERT_EQ(e.p.again(h.s), GTLS_OK);
        e.p.run(chunk);
        ASSERT_TRUE(e.p.connected()) << "client: " << result_name(gtls_conn_failure(e.p.c.conn))
                                     << ", server: " << result_name(gtls_conn_failure(e.p.s.conn))
                                     << " suite " << suite << " group " << group << " chunk " << chunk;
        expect_resumed(e.p, true);
        EXPECT_EQ(gtls_conn_suite(e.p.c.conn), suite);
        EXPECT_EQ(gtls_conn_suite(e.p.s.conn), suite);
        EXPECT_EQ(gtls_conn_group(e.p.c.conn), group) << "the key exchange is still ephemeral";
        EXPECT_LE(e.p.s.sent + chain_bytes(*e.cred), first_sent)
            << "the server sent no certificate";
        ASSERT_NO_FATAL_FAILURE(talk(e.p, chunk));
        EXPECT_EQ(gtls_conn_session_count(e.p.c.conn), 1u) << "a new ticket on a resumed connection";
        ASSERT_EQ(gtls_conn_close(e.p.c.conn), GTLS_OK);
        e.p.run(chunk);
        EXPECT_TRUE(gtls_conn_peer_closed(e.p.s.conn));
      }
    }
  }
}

TEST(Resume, ASessionResumesMoreThanOnceAndASecondGenerationToo) {
  Env e;
  ASSERT_NO_FATAL_FAILURE(run_full(e.p));
  Held first;
  ASSERT_NO_FATAL_FAILURE(first.take(e.p));
  for (int i = 0; i < 3; i++) {
    ASSERT_EQ(e.p.again(first.s), GTLS_OK);
    e.p.run();
    ASSERT_TRUE(e.p.connected()) << i;
    expect_resumed(e.p, true);
  }
  /* The ticket a resumed connection sent resumes too. */
  Held second;
  ASSERT_NO_FATAL_FAILURE(second.take(e.p));
  ASSERT_EQ(e.p.again(second.s), GTLS_OK);
  e.p.run();
  ASSERT_TRUE(e.p.connected());
  expect_resumed(e.p, true);
}

TEST(Resume, AfterAHelloRetryRequestBothBindersAreRight) {
  Env e;
  /* The server wants P-256; the client's first share is X25519. */
  static const GTLS_Group server_groups[] = {GTLS_GROUP_SECP256R1};
  e.p.scfg.groups = server_groups;
  e.p.scfg.group_count = 1;
  ASSERT_NO_FATAL_FAILURE(run_full(e.p));
  EXPECT_TRUE(gtls_conn_retried(e.p.c.conn));
  Held h;
  ASSERT_NO_FATAL_FAILURE(h.take(e.p));

  for (size_t chunk : {static_cast<size_t>(0), static_cast<size_t>(1)}) {
    ASSERT_EQ(e.p.again(h.s), GTLS_OK);
    e.p.run(chunk);
    ASSERT_TRUE(e.p.connected()) << "client: " << result_name(gtls_conn_failure(e.p.c.conn))
                                 << ", server: " << result_name(gtls_conn_failure(e.p.s.conn));
    EXPECT_TRUE(gtls_conn_retried(e.p.c.conn));
    EXPECT_TRUE(gtls_conn_retried(e.p.s.conn));
    expect_resumed(e.p, true);
    ASSERT_NO_FATAL_FAILURE(talk(e.p, chunk));
  }
}

TEST(Resume, AfterARetryThatNamesAnotherHashTheOfferIsDroppedAndTheHandshakeIsFull) {
  Env e;
  static const GTLS_Suite sha384[] = {GTLS_SUITE_AES_256_GCM_SHA384};
  e.p.scfg.suites = sha384;
  e.p.scfg.suite_count = 1;
  ASSERT_NO_FATAL_FAILURE(run_full(e.p));
  Held h;
  ASSERT_NO_FATAL_FAILURE(h.take(e.p));

  /* A server that now serves only a SHA-256 suite, and wants another group: it cannot use the ticket and retries. */
  static const GTLS_Suite sha256[] = {GTLS_SUITE_AES_128_GCM_SHA256};
  static const GTLS_Group p256[] = {GTLS_GROUP_SECP256R1};
  Next n(e);
  n.p.scfg.suites = sha256;
  n.p.scfg.suite_count = 1;
  n.p.scfg.groups = p256;
  n.p.scfg.group_count = 1;
  n.p.offer = h.s;
  ASSERT_EQ(n.p.build(), GTLS_OK);
  n.p.carry(n.p.c, n.p.s, 0);   /* the first hello, with the offer */
  n.p.carry(n.p.s, n.p.c, 0);   /* the retry */
  {
    /* The second hello: no pre_shared_key, though the modes stay. */
    Bytes wire = stream_out(n.p.c.conn);
    ASSERT_GT(wire.size(), 9u);
    GTLS_ClientHello h2;
    GTLS_Limits lim;
    gtls_limits_default(&lim);
    ASSERT_EQ(gtls_msg_parse_client_hello(wire.data() + 9, wire.size() - 9, &lim, &h2), GTLS_OK);
    EXPECT_EQ(gtls_msg_find_ext(h2.exts, h2.ext_count, GTLS_EXT_PRE_SHARED_KEY), nullptr)
        << "a PSK for SHA-384 is not offered again under a SHA-256 retry";
    EXPECT_EQ(n.p.c.conn->offer, nullptr) << "and the session is let go";
  }
  n.p.run();
  ASSERT_TRUE(n.p.connected());
  EXPECT_TRUE(gtls_conn_retried(n.p.c.conn));
  expect_resumed(n.p, false);
  EXPECT_EQ(gtls_conn_suite(n.p.c.conn), GTLS_SUITE_AES_128_GCM_SHA256);
}

TEST(Resume, ARetryThatNamesAnotherSuiteOfTheSameHashKeepsTheOfferAndTheServerStillDoesNotResume) {
  Env e;
  static const GTLS_Suite aes128[] = {GTLS_SUITE_AES_128_GCM_SHA256};
  e.p.scfg.suites = aes128;
  e.p.scfg.suite_count = 1;
  ASSERT_NO_FATAL_FAILURE(run_full(e.p));
  Held h;
  ASSERT_NO_FATAL_FAILURE(h.take(e.p));

  /* The server prefers ChaCha20 and wants P-256, and its clock is a minute ahead of
   * the client's when the first hello arrives, so the ticket is too stale to use.
   * The retry names ChaCha20 (the same hash as the ticket's suite: the client
   * offers the PSK again, with a fresh age), and the second hello's ticket is
   * good. It is for AES-128, and the ServerHello must name the retry's suite. */
  static const GTLS_Suite order[] = {GTLS_SUITE_CHACHA20_POLY1305_SHA256, GTLS_SUITE_AES_128_GCM_SHA256};
  static const GTLS_Group p256[] = {GTLS_GROUP_SECP256R1};
  Next n(e);
  n.p.scfg.suites = order;
  n.p.scfg.suite_count = 2;
  n.p.scfg.groups = p256;
  n.p.scfg.group_count = 1;
  n.p.offer = h.s;
  n.p.offer_time = kNow;
  n.p.now = kNow + 60;
  ASSERT_EQ(n.p.build(), GTLS_OK);
  n.p.run();
  ASSERT_TRUE(n.p.connected()) << "client: " << result_name(gtls_conn_failure(n.p.c.conn))
                               << ", server: " << result_name(gtls_conn_failure(n.p.s.conn));
  EXPECT_TRUE(gtls_conn_retried(n.p.c.conn));
  EXPECT_EQ(gtls_conn_suite(n.p.s.conn), GTLS_SUITE_CHACHA20_POLY1305_SHA256)
      << "the retry's suite, not the ticket's";
  expect_resumed(n.p, false);
}

TEST(Resume, TheServerResumesUnderTheTicketsSuiteWhateverItPrefers) {
  Env e;
  static const GTLS_Suite sha384[] = {GTLS_SUITE_AES_256_GCM_SHA384};
  e.p.scfg.suites = sha384;
  e.p.scfg.suite_count = 1;
  ASSERT_NO_FATAL_FAILURE(run_full(e.p));
  Held h;
  ASSERT_NO_FATAL_FAILURE(h.take(e.p));

  Next n(e);
  static const GTLS_Suite both[] = {GTLS_SUITE_AES_128_GCM_SHA256, GTLS_SUITE_AES_256_GCM_SHA384};
  n.p.scfg.suites = both;
  n.p.scfg.suite_count = 2;
  n.p.offer = h.s;
  ASSERT_NO_FATAL_FAILURE(run_full(n.p));
  expect_resumed(n.p, true);
  EXPECT_EQ(gtls_conn_suite(n.p.s.conn), GTLS_SUITE_AES_256_GCM_SHA384);
}

TEST(Resume, TheMessageInterfaceResumesToo) {
  std::unique_ptr<Cred> cred = ed_cred();
  MessagePair p(*cred);
  p.keys = {tkey(1)};
  ASSERT_EQ(p.build(), GTLS_OK);
  p.run();
  ASSERT_TRUE(p.connected());
  ASSERT_EQ(gtls_conn_session_count(p.c.conn), 1u) << "tickets travel at the application epoch";
  Held h;
  ASSERT_NO_FATAL_FAILURE(h.take(p));

  ASSERT_EQ(p.again(h.s), GTLS_OK);
  p.run(1);
  ASSERT_TRUE(p.connected());
  expect_resumed(p, true);
  Bytes cs, ss;
  size_t n = 0;
  cs.resize(GTLS_HASH_MAX);
  ss.resize(GTLS_HASH_MAX);
  ASSERT_EQ(gtls_conn_secret(p.c.conn, GTLS_EPOCH_APPLICATION, GTLS_DIR_WRITE, cs.data(), cs.size(), &n), GTLS_OK);
  ASSERT_EQ(gtls_conn_secret(p.s.conn, GTLS_EPOCH_APPLICATION, GTLS_DIR_READ, ss.data(), ss.size(), &n), GTLS_OK);
  EXPECT_EQ(cs, ss) << "the same traffic secret on both ends";
}

/* ------------------------------------------------- what is not an error */

TEST(Resume, AnExpiredTicketIsAFullHandshakeAndSoIsOneTheServerHasAgedOut) {
  Env e;
  e.p.scfg.ticket_lifetime = 60;
  ASSERT_NO_FATAL_FAILURE(run_full(e.p));
  Held h;
  ASSERT_NO_FATAL_FAILURE(h.take(e.p));
  GTLS_SessionInfo info;
  ASSERT_EQ(gtls_session_info(h.s, &info), GTLS_OK);
  EXPECT_EQ(info.lifetime, 60u);

  Next n(e);
  n.p.scfg.ticket_lifetime = 60;
  n.p.now = kNow + 3000;   /* the server's clock; the client's offer is made at kNow + 30 */
  n.p.offer = h.s;
  n.p.offer_time = kNow + 30;
  ASSERT_NO_FATAL_FAILURE(run_full(n.p));
  expect_resumed(n.p, false);
}

TEST(Resume, ATicketOnTheLastSecondOfItsLifeIsRefusedAndOneBeforeItIsAccepted) {
  Env e;
  e.p.scfg.ticket_lifetime = 60;
  e.p.scfg.ticket_age_window = 100;
  ASSERT_NO_FATAL_FAILURE(run_full(e.p));
  Held h;
  ASSERT_NO_FATAL_FAILURE(h.take(e.p));
  auto tweak = [](Pair & p) { p.scfg.ticket_age_window = 100; };
  /* server and client agree on the time here, so only the lifetime decides */
  EXPECT_EQ(decision(e, h.s, [&](Pair & p) { tweak(p); p.now = kNow + 59; }, kNow + 59), 1);
  EXPECT_EQ(decision(e, h.s, [&](Pair & p) { tweak(p); p.now = kNow + 60; }, kNow + 59), 0)
      << "the server counts 60 seconds elapsed";
}

TEST(Resume, AnAgeOutsideTheWindowIsAFullHandshakeAndInsideItIsNot) {
  Env e;
  ASSERT_NO_FATAL_FAILURE(run_full(e.p));
  Held h;
  ASSERT_NO_FATAL_FAILURE(h.take(e.p));

  EXPECT_EQ(decision(e, h.s, nullptr, kNow + 5), 1) << "5 s apart, a 10 s window";
  EXPECT_EQ(decision(e, h.s, nullptr, kNow + 100), 0) << "the client says 100 s, the server counts 0";
  EXPECT_EQ(decision(e, h.s, [](Pair & p) { p.scfg.ticket_age_window = 3; }, kNow + 5), 0)
      << "5 s apart, a 3 s window";
  EXPECT_EQ(decision(e, h.s, [](Pair & p) { p.scfg.ticket_age_window = 3; }, kNow + 3), 1);
  /* The server's clock ahead of the client's by more than the window. */
  EXPECT_EQ(decision(e, h.s, [](Pair & p) { p.now = kNow + 50; }, kNow + 1), 0);
  /* A server whose clock is behind the ticket's issue time. */
  EXPECT_EQ(decision(e, h.s, [](Pair & p) { p.now = kNow - 60; }, kNow + 1), 0);
  /* ... and by less than the window it is forgiven. */
  EXPECT_EQ(decision(e, h.s, [](Pair & p) { p.now = kNow - 5; }, kNow + 1), 1);
}

TEST(Resume, ATamperedTicketAndAnUnknownAndARotatedOutKeyAreFullHandshakes) {
  Env e;
  ASSERT_NO_FATAL_FAILURE(run_full(e.p));
  Held h;
  ASSERT_NO_FATAL_FAILURE(h.take(e.p));
  ASSERT_GT(h.s->ticket_len, 100u);

  /* Every byte of the ticket flipped, one at a time: the name, the nonce, the ciphertext, the tag. */
  for (size_t i = 0; i < h.s->ticket_len; i++) {
    GTLS_Session * bad = gtls_session_copy(gtls_allocator_default(), h.s);
    ASSERT_NE(bad, nullptr);
    bad->ticket[i] ^= 0x40;
    int d = decision(e, bad);
    gtls_session_free(bad);
    ASSERT_EQ(d, 0) << "byte " << i;
  }
  /* Truncated, extended and garbage tickets. */
  for (size_t cut : {static_cast<size_t>(1), static_cast<size_t>(16), static_cast<size_t>(60)}) {
    GTLS_Session * bad = gtls_session_copy(gtls_allocator_default(), h.s);
    bad->ticket_len -= cut;
    int d = decision(e, bad);
    gtls_session_free(bad);
    EXPECT_EQ(d, 0) << "cut by " << cut;
  }
  {
    GTLS_Session * bad = gtls_session_copy(gtls_allocator_default(), h.s);
    std::memset(bad->ticket, 0x5a, bad->ticket_len);
    EXPECT_EQ(decision(e, bad), 0) << "garbage";
    gtls_session_free(bad);
  }
  /* The key is not the server's any more. */
  EXPECT_EQ(decision(e, h.s, [](Pair & p) { p.keys = {tkey(2)}; }), 0) << "rotated out";
  EXPECT_EQ(decision(e, h.s, [](Pair & p) {
      GTLS_TicketKey k = tkey(1);
      k.key[0] ^= 1;
      p.keys = {k};
    }), 0) << "same name, another key";
  EXPECT_EQ(decision(e, h.s, [](Pair & p) { p.keys = {tkey(1, kNow - 1000, kNow - 1)}; }), 0)
      << "expired key";
}

TEST(Resume, ANameOrAnAlpnProtocolThatChangedIsAFullHandshake) {
  Env e;
  static const char * const both[] = {"h2", "http/1.1"};
  static const char * const only_http1[] = {"http/1.1"};
  static const char * const http1_first[] = {"http/1.1", "h2"};
  e.p.calpn = {"h2", "http/1.1"};
  e.p.salpn = {"h2", "http/1.1"};
  (void)both;
  ASSERT_NO_FATAL_FAILURE(run_full(e.p));
  Held h;
  ASSERT_NO_FATAL_FAILURE(h.take(e.p));
  GTLS_SessionInfo info;
  ASSERT_EQ(gtls_session_info(h.s, &info), GTLS_OK);
  ASSERT_EQ(info.alpn_len, 2u);
  EXPECT_EQ(std::string(reinterpret_cast<const char *>(info.alpn), info.alpn_len), "h2");

  auto server_alpn = [](Pair & p) { p.salpn = {"h2", "http/1.1"}; };
  EXPECT_EQ(decision(e, h.s, [&](Pair & p) { server_alpn(p); p.calpn = {"h2", "http/1.1"}; }), 1);
  EXPECT_EQ(decision(e, h.s, [&](Pair & p) { server_alpn(p); p.calpn = {"http/1.1"}; }), 0)
      << "h2 is not offered again";
  EXPECT_EQ(decision(e, h.s, [&](Pair & p) { server_alpn(p); p.calpn = {"http/1.1", "h2"}; }), 1)
      << "offered again, in another place";
  EXPECT_EQ(decision(e, h.s, [&](Pair & p) { server_alpn(p); p.calpn.clear(); }), 0)
      << "no ALPN at all";
  (void)only_http1;
  (void)http1_first;

  /* The name: a session carried to a connection for another name (its own check was met by editing the session). */
  {
    GTLS_Session * other = gtls_session_copy(gtls_allocator_default(), h.s);
    const std::string host = "other.test";
    std::memcpy(other->host, host.data(), host.size());
    other->host_len = host.size();
    EXPECT_EQ(decision(e, other, [&](Pair & p) { server_alpn(p); p.calpn = {"h2"}; p.host = host; }), 0)
        << "the ticket says example.test";
    gtls_session_free(other);
  }
}

TEST(Resume, ANoAlpnSessionResumesWhateverIsOfferedNow) {
  Env e;
  ASSERT_NO_FATAL_FAILURE(run_full(e.p));
  Held h;
  ASSERT_NO_FATAL_FAILURE(h.take(e.p));
  GTLS_SessionInfo info;
  ASSERT_EQ(gtls_session_info(h.s, &info), GTLS_OK);
  EXPECT_EQ(info.alpn_len, 0u);
  EXPECT_EQ(decision(e, h.s, [](Pair & p) { p.calpn = {"h2"}; p.salpn = {"h2"}; }), 1);
}

namespace {

/**
 * A ClientHello (as a plaintext record) that offers @p session's ticket,
 * with the suites it lists, a binder of @p binder_len bytes, and the right
 * binder at the front of it when @p right_binder.
 */
Bytes crafted_hello(const Env & e, const GTLS_Session * session, const GTLS_Suite * suites,
    size_t suite_count, size_t binder_len, bool right_binder) {
  static const GTLS_Group groups[] = {GTLS_GROUP_X25519};
  static const GCERT_SigScheme sigs[] = {GCERT_SIG_ED25519};
  GTLS_HelloParams hp;
  std::memset(&hp, 0, sizeof hp);
  hp.suites = suites;
  hp.suite_count = suite_count;
  hp.host = e.cred->name.data();
  hp.host_len = e.cred->name.size();
  hp.groups = groups;
  hp.group_count = 1;
  hp.sig_algs = sigs;
  hp.sig_alg_count = 1;
  hp.share.group = GTLS_GROUP_X25519;
  hp.share.pub_len = 32;
  Bytes priv(32, 0x11);
  EXPECT_EQ(gsec_x25519_public(priv.data(), hp.share.pub), GSEC_OK);
  GTLS_PskParams psk = {session->ticket, session->ticket_len, session->age_add, binder_len};
  hp.psk = &psk;
  GTLS_Buf b;
  gtls_buf_init(&b, nullptr, 1 << 16);
  EXPECT_EQ(gtls_msg_build_client_hello(&hp, &b), GTLS_OK);
  Bytes hello{22, 3, 1};
  hello.push_back(static_cast<unsigned char>(b.len >> 8));
  hello.push_back(static_cast<unsigned char>(b.len));
  hello.insert(hello.end(), b.data, b.data + b.len);
  gtls_buf_free(&b);
  if (right_binder) {
    GTLS_Transcript t;
    unsigned char th[GTLS_HASH_MAX];
    unsigned char binder[GTLS_HASH_MAX];
    const GTLS_Hash hash = gtls_suite_hash(session->suite);
    const size_t cut = hello.size() - GTLS_PSK_BINDERS_TAIL(binder_len);

    EXPECT_EQ(gtls_transcript_init(&t), GTLS_OK);
    EXPECT_EQ(gtls_transcript_select(&t, hash), GTLS_OK);
    EXPECT_EQ(gtls_binder_transcript(&t, hello.data() + 5, cut - 5, th), GTLS_OK);
    EXPECT_EQ(gtls_binder_compute(hash, session->psk, session->psk_len, th, binder), GTLS_OK);
    gtls_transcript_wipe(&t);
    std::memcpy(hello.data() + hello.size() - binder_len, binder, session->psk_len);
  }
  return hello;
}

}  // namespace

TEST(Resume, ATicketForASuiteTheClientDidNotOfferIsPassedOver) {
  Env e;
  ASSERT_NO_FATAL_FAILURE(run_full(e.p));
  Held h;
  ASSERT_NO_FATAL_FAILURE(h.take(e.p));
  ASSERT_EQ(h.s->suite, GTLS_SUITE_AES_128_GCM_SHA256);
  static const GTLS_Suite other[] = {GTLS_SUITE_CHACHA20_POLY1305_SHA256};   /* the same hash */
  static const GTLS_Suite same[] = {GTLS_SUITE_AES_128_GCM_SHA256};
  size_t used = 0;

  {
    Next n(e);
    ASSERT_EQ(n.p.build(), GTLS_OK);
    Bytes hello = crafted_hello(e, h.s, other, 1, 32, true);
    ASSERT_EQ(gtls_conn_stream_feed(n.p.s.conn, hello.data(), hello.size(), kNow, &used), GTLS_OK);
    EXPECT_EQ(gtls_conn_resumed(n.p.s.conn), 0) << "the suite of the ticket is not among those offered";
    EXPECT_EQ(gtls_conn_suite(n.p.s.conn), GTLS_SUITE_CHACHA20_POLY1305_SHA256);
  }
  {
    Next n(e);
    ASSERT_EQ(n.p.build(), GTLS_OK);
    Bytes hello = crafted_hello(e, h.s, same, 1, 32, true);
    ASSERT_EQ(gtls_conn_stream_feed(n.p.s.conn, hello.data(), hello.size(), kNow, &used), GTLS_OK);
    EXPECT_EQ(gtls_conn_resumed(n.p.s.conn), 1) << "and with the suite offered it is resumed: the hello is good";
  }
}

TEST(Resume, ASessionResumesWithNoSignatureSchemeInCommonBecauseNoneIsNeeded) {
  Env e;
  ASSERT_NO_FATAL_FAILURE(run_full(e.p));
  Held h;
  ASSERT_NO_FATAL_FAILURE(h.take(e.p));
  static const GCERT_SigScheme pss[] = {GCERT_SIG_RSA_PSS_SHA256};   /* the server's key is Ed25519 */

  Next full(e);
  full.p.ccfg.sig_algs = pss;
  full.p.ccfg.sig_alg_count = 1;
  EXPECT_EQ(full.p.build(), GTLS_OK);
  full.p.run();
  EXPECT_FALSE(full.p.connected()) << "without a session there is no scheme to sign with";
  EXPECT_EQ(gtls_conn_failure(full.p.s.conn), GTLS_ERR_NO_COMMON);

  Next n(e);
  n.p.ccfg.sig_algs = pss;
  n.p.ccfg.sig_alg_count = 1;
  n.p.offer = h.s;
  ASSERT_NO_FATAL_FAILURE(run_full(n.p));
  expect_resumed(n.p, true);
}

TEST(Resume, AnOfferThatCannotUseDheIsAFullHandshake) {
  Env e;
  ASSERT_NO_FATAL_FAILURE(run_full(e.p));
  Held h;
  ASSERT_NO_FATAL_FAILURE(h.take(e.p));

  Next n(e);
  n.p.offer = h.s;
  ASSERT_EQ(n.p.build(), GTLS_OK);
  Bytes hello = stream_out(n.p.c.conn);
  /* psk_key_exchange_modes: 00 2d 00 02 01 01 -> psk_ke only. The binder no longer
   * matches, which is not looked at: there is nothing to resume with. */
  size_t at = 0;
  for (size_t i = 5; i + 6 <= hello.size() && at == 0; i++) {
    if (hello[i] == 0x00 && hello[i + 1] == 0x2d && hello[i + 2] == 0x00 && hello[i + 3] == 0x02 &&
        hello[i + 4] == 0x01 && hello[i + 5] == 0x01) {
      at = i + 5;
    }
  }
  ASSERT_NE(at, 0u);
  hello[at] = 0x00;
  size_t used = 0;
  ASSERT_EQ(gtls_conn_stream_feed(n.p.s.conn, hello.data(), hello.size(), n.p.now, &used), GTLS_OK);
  EXPECT_EQ(gtls_conn_resumed(n.p.s.conn), 0);
  Bytes out = stream_out(n.p.s.conn);
  Bytes sh = server_hello_in(out);
  ASSERT_FALSE(sh.empty());
  EXPECT_EQ(parse_sh(sh).flags & GTLS_SH_FLAG_PSK, 0u) << "no pre_shared_key in the ServerHello";
}

TEST(Resume, NoKeyringOrNoTicketsOrNoValidKeyMeansNoTicketsAndNoResumption) {
  Env e;
  e.p.keys.clear();
  ASSERT_NO_FATAL_FAILURE(run_full(e.p));
  EXPECT_EQ(gtls_conn_session_count(e.p.c.conn), 0u);

  Env zero;
  zero.p.scfg.ticket_count = 0;
  ASSERT_NO_FATAL_FAILURE(run_full(zero.p));
  EXPECT_EQ(gtls_conn_session_count(zero.p.c.conn), 0u);

  Env later;
  later.p.keys = {tkey(1, kNow + 500, kNow + 1000)};
  ASSERT_NO_FATAL_FAILURE(run_full(later.p));
  EXPECT_EQ(gtls_conn_session_count(later.p.c.conn), 0u) << "no key is valid yet";

  /* A server that issues none cannot resume what another issued, and says nothing about it. */
  Env issuer;
  ASSERT_NO_FATAL_FAILURE(run_full(issuer.p));
  Held h;
  ASSERT_NO_FATAL_FAILURE(h.take(issuer.p));
  Next n(issuer);
  n.p.keys.clear();
  n.p.offer = h.s;
  ASSERT_NO_FATAL_FAILURE(run_full(n.p));
  expect_resumed(n.p, false);
}

/* ------------------------------------------------------------- what is fatal */

TEST(Resume, ABadBinderIsDecryptErrorAndTheServerIsWiped) {
  Env e;
  ASSERT_NO_FATAL_FAILURE(run_full(e.p));
  Held h;
  ASSERT_NO_FATAL_FAILURE(h.take(e.p));

  /* Every bit of the last byte of the binder, and then each of its bytes. */
  for (size_t back = 1; back <= 32; back++) {
    for (int bit : {0, 7}) {
      Next n(e);
      n.p.offer = h.s;
      ASSERT_EQ(n.p.build(), GTLS_OK);
      Bytes hello = stream_out(n.p.c.conn);
      hello[hello.size() - back] ^= static_cast<unsigned char>(1u << bit);
      size_t used = 0;
      EXPECT_EQ(gtls_conn_stream_feed(n.p.s.conn, hello.data(), hello.size(), n.p.now, &used),
          GTLS_ERR_MISMATCH) << back << ":" << bit;
      EXPECT_TRUE(gtls_conn_is_failed(n.p.s.conn));
      EXPECT_EQ(gtls_conn_alert(n.p.s.conn), GTLS_ALERT_DECRYPT_ERROR);
      EXPECT_TRUE(gtls_conn_secrets_are_wiped(n.p.s.conn)) << "nothing left behind";
      EXPECT_EQ(gtls_conn_resumed(n.p.s.conn), 0) << "it never resumed";
      Bytes alert = stream_out(n.p.s.conn);
      ASSERT_GE(alert.size(), 7u);
      EXPECT_EQ(alert[0], 21) << "an alert record, in the clear";
      EXPECT_EQ(alert[6], GTLS_ALERT_DECRYPT_ERROR);
    }
  }
}

TEST(Resume, ABinderIsOverTheWholeHelloSoAChangeAnywhereBeforeItBreaksIt) {
  Env e;
  ASSERT_NO_FATAL_FAILURE(run_full(e.p));
  Held h;
  ASSERT_NO_FATAL_FAILURE(h.take(e.p));
  Next probe(e);
  probe.p.offer = h.s;
  ASSERT_EQ(probe.p.build(), GTLS_OK);
  const size_t len = stream_out(probe.p.c.conn).size();

  /* The client random, the legacy session id region, the server name, the key share. */
  for (size_t at : {static_cast<size_t>(15), static_cast<size_t>(40), static_cast<size_t>(100), static_cast<size_t>(200)}) {
    Next n(e);
    n.p.offer = h.s;
    ASSERT_EQ(n.p.build(), GTLS_OK);
    Bytes hello = stream_out(n.p.c.conn);
    ASSERT_EQ(hello.size(), len);
    hello[at] ^= 0x01;
    size_t used = 0;
    GTLS_Result r = gtls_conn_stream_feed(n.p.s.conn, hello.data(), hello.size(), n.p.now, &used);
    EXPECT_NE(r, GTLS_OK) << "offset " << at;
    if (r == GTLS_ERR_MISMATCH) {
      EXPECT_EQ(gtls_conn_alert(n.p.s.conn), GTLS_ALERT_DECRYPT_ERROR);
    }
  }
}

TEST(Resume, ABinderOfTheWrongLengthForTheTicketIsAlsoABadBinder) {
  Env e;
  ASSERT_NO_FATAL_FAILURE(run_full(e.p));
  Held h;
  ASSERT_NO_FATAL_FAILURE(h.take(e.p));
  ASSERT_EQ(gtls_suite_hash(h.s->suite), GTLS_HASH_SHA256);

  /* The ticket is for a SHA-256 suite; this hello offers it with a 48-byte binder. */
  static const GTLS_Suite suites[] = {GTLS_SUITE_AES_128_GCM_SHA256};
  static const GTLS_Group groups[] = {GTLS_GROUP_X25519};
  static const GCERT_SigScheme sigs[] = {GCERT_SIG_ED25519};
  GTLS_HelloParams hp;
  std::memset(&hp, 0, sizeof hp);
  hp.suites = suites;
  hp.suite_count = 1;
  hp.host = e.cred->name.data();
  hp.host_len = e.cred->name.size();
  hp.groups = groups;
  hp.group_count = 1;
  hp.sig_algs = sigs;
  hp.sig_alg_count = 1;
  hp.share.group = GTLS_GROUP_X25519;
  hp.share.pub_len = 32;
  Bytes priv(32, 0x11);
  ASSERT_EQ(gsec_x25519_public(priv.data(), hp.share.pub), GSEC_OK);
  GTLS_PskParams psk = {h.s->ticket, h.s->ticket_len, h.s->age_add, 48};  /* an age of zero: the ticket is fresh */
  hp.psk = &psk;
  GTLS_Buf b;
  gtls_buf_init(&b, nullptr, 1 << 16);
  ASSERT_EQ(gtls_msg_build_client_hello(&hp, &b), GTLS_OK);
  Bytes hello{22, 3, 1};
  hello.push_back(static_cast<unsigned char>(b.len >> 8));
  hello.push_back(static_cast<unsigned char>(b.len));
  hello.insert(hello.end(), b.data, b.data + b.len);
  gtls_buf_free(&b);

  Next n(e);
  ASSERT_EQ(n.p.build(), GTLS_OK);
  size_t used = 0;
  EXPECT_EQ(gtls_conn_stream_feed(n.p.s.conn, hello.data(), hello.size(), kNow, &used), GTLS_ERR_MISMATCH);
  EXPECT_EQ(gtls_conn_alert(n.p.s.conn), GTLS_ALERT_DECRYPT_ERROR);

  /* The same, with the 32 bytes of the right binder at the front of the 48: the
   * length alone is what is wrong, and it is wrong enough. */
  {
    GTLS_Transcript t;
    unsigned char th[GTLS_HASH_MAX];
    unsigned char binder[GTLS_HASH_MAX];
    const size_t cut = hello.size() - GTLS_PSK_BINDERS_TAIL(48);

    ASSERT_EQ(gtls_transcript_init(&t), GTLS_OK);
    ASSERT_EQ(gtls_transcript_select(&t, GTLS_HASH_SHA256), GTLS_OK);
    ASSERT_EQ(gtls_binder_transcript(&t, hello.data() + 5, cut - 5, th), GTLS_OK);
    ASSERT_EQ(gtls_binder_compute(GTLS_HASH_SHA256, h.s->psk, 32, th, binder), GTLS_OK);
    gtls_transcript_wipe(&t);
    std::memcpy(hello.data() + hello.size() - 48, binder, 32);
    Next m(e);
    ASSERT_EQ(m.p.build(), GTLS_OK);
    EXPECT_EQ(gtls_conn_stream_feed(m.p.s.conn, hello.data(), hello.size(), kNow, &used), GTLS_ERR_MISMATCH);
    EXPECT_EQ(gtls_conn_alert(m.p.s.conn), GTLS_ALERT_DECRYPT_ERROR);
    /* ... and the 32-byte binder itself, written the same way, is accepted: the computation is right. */
    GTLS_PskParams ok_psk = {h.s->ticket, h.s->ticket_len, h.s->age_add, 32};
    hp.psk = &ok_psk;
    GTLS_Buf b2;
    gtls_buf_init(&b2, nullptr, 1 << 16);
    ASSERT_EQ(gtls_msg_build_client_hello(&hp, &b2), GTLS_OK);
    Bytes good{22, 3, 1};
    good.push_back(static_cast<unsigned char>(b2.len >> 8));
    good.push_back(static_cast<unsigned char>(b2.len));
    good.insert(good.end(), b2.data, b2.data + b2.len);
    gtls_buf_free(&b2);
    ASSERT_EQ(gtls_transcript_init(&t), GTLS_OK);
    ASSERT_EQ(gtls_transcript_select(&t, GTLS_HASH_SHA256), GTLS_OK);
    ASSERT_EQ(gtls_binder_transcript(&t, good.data() + 5, good.size() - 5 - GTLS_PSK_BINDERS_TAIL(32), th), GTLS_OK);
    ASSERT_EQ(gtls_binder_compute(GTLS_HASH_SHA256, h.s->psk, 32, th, binder), GTLS_OK);
    gtls_transcript_wipe(&t);
    std::memcpy(good.data() + good.size() - 32, binder, 32);
    Next k(e);
    ASSERT_EQ(k.p.build(), GTLS_OK);
    EXPECT_EQ(gtls_conn_stream_feed(k.p.s.conn, good.data(), good.size(), kNow, &used), GTLS_OK);
    EXPECT_EQ(gtls_conn_resumed(k.p.s.conn), 1);
  }
}

/* --------------------------------------------- what the client will not take */

TEST(Resume, AServerHelloThatSelectsAPskNeverOfferedIsIllegalParameter) {
  Env e;
  ASSERT_NO_FATAL_FAILURE(run_full(e.p));

  Next n(e);
  ASSERT_EQ(n.p.build(), GTLS_OK);   /* no session offered */
  Bytes hello = stream_out(n.p.c.conn);
  size_t used = 0;
  ASSERT_EQ(gtls_conn_stream_feed(n.p.s.conn, hello.data(), hello.size(), n.p.now, &used), GTLS_OK);
  Bytes wire = stream_out(n.p.s.conn);
  /* Append pre_shared_key (selected identity 0) to the ServerHello and fix its three lengths. */
  ASSERT_EQ(wire[0], 22);
  Bytes hacked = wire;
  const Bytes ext = {0x00, 0x29, 0x00, 0x02, 0x00, 0x00};
  const size_t rec_len = (static_cast<size_t>(wire[3]) << 8) | wire[4];
  const size_t msg_len = 4 + ((static_cast<size_t>(wire[6]) << 16) | (static_cast<size_t>(wire[7]) << 8) | wire[8]);
  ASSERT_LE(msg_len, rec_len);
  hacked.insert(hacked.begin() + 5 + static_cast<long>(msg_len), ext.begin(), ext.end());
  const size_t new_rec = rec_len + ext.size();
  hacked[3] = static_cast<unsigned char>(new_rec >> 8);
  hacked[4] = static_cast<unsigned char>(new_rec);
  const size_t new_body = msg_len - 4 + ext.size();
  hacked[6] = static_cast<unsigned char>(new_body >> 16);
  hacked[7] = static_cast<unsigned char>(new_body >> 8);
  hacked[8] = static_cast<unsigned char>(new_body);
  /* The extensions block length precedes the extensions: 2 bytes at the end of the fixed part. */
  const size_t sid = wire[5 + 4 + 2 + 32];
  const size_t ext_len_at = 5 + 4 + 2 + 32 + 1 + sid + 2 + 1;
  const size_t old_ext = (static_cast<size_t>(wire[ext_len_at]) << 8) | wire[ext_len_at + 1];
  hacked[ext_len_at] = static_cast<unsigned char>((old_ext + ext.size()) >> 8);
  hacked[ext_len_at + 1] = static_cast<unsigned char>(old_ext + ext.size());

  EXPECT_EQ(gtls_conn_stream_feed(n.p.c.conn, hacked.data(), hacked.size(), n.p.now, &used),
      GTLS_ERR_PROTOCOL);
  EXPECT_EQ(gtls_conn_alert(n.p.c.conn), GTLS_ALERT_ILLEGAL_PARAMETER);
  EXPECT_TRUE(gtls_conn_secrets_are_wiped(n.p.c.conn));
}

namespace {

/** The server's first flight to a client that offered @p session, with the pre_shared_key's identity changed to @p index. */
GTLS_Result client_meets_selection(Env & e, const GTLS_Session * session, unsigned index,
    unsigned * alert, bool* wiped) {
  Next n(e);
  n.p.offer = session;
  EXPECT_EQ(n.p.build(), GTLS_OK);
  Bytes hello = stream_out(n.p.c.conn);
  size_t used = 0;
  EXPECT_EQ(gtls_conn_stream_feed(n.p.s.conn, hello.data(), hello.size(), n.p.now, &used), GTLS_OK);
  EXPECT_EQ(gtls_conn_resumed(n.p.s.conn), 1);
  Bytes wire = stream_out(n.p.s.conn);
  Bytes sh = server_hello_in(wire);
  EXPECT_FALSE(sh.empty());
  /* The selected identity is the last two bytes of the first extension, pre_shared_key. */
  const size_t sid = sh[4 + 2 + 32];
  const size_t first_ext = 4 + 2 + 32 + 1 + sid + 2 + 1 + 2;
  EXPECT_EQ(sh[first_ext], 0x00);
  EXPECT_EQ(sh[first_ext + 1], 0x29);
  wire[5 + first_ext + 4] = static_cast<unsigned char>(index >> 8);
  wire[5 + first_ext + 5] = static_cast<unsigned char>(index);
  GTLS_Result r = gtls_conn_stream_feed(n.p.c.conn, wire.data(), wire.size(), n.p.now, &used);
  *alert = gtls_conn_alert(n.p.c.conn);
  *wiped = gtls_conn_secrets_are_wiped(n.p.c.conn);
  return r;
}

}  // namespace

TEST(Resume, AnIndexOutOfRangeIsIllegalParameterAndIndexZeroIsAccepted) {
  Env e;
  ASSERT_NO_FATAL_FAILURE(run_full(e.p));
  Held h;
  ASSERT_NO_FATAL_FAILURE(h.take(e.p));
  unsigned alert = 0;
  bool wiped = false;

  EXPECT_EQ(client_meets_selection(e, h.s, 0, &alert, &wiped), GTLS_OK);
  for (unsigned index : {1u, 2u, 255u, 65535u}) {
    EXPECT_EQ(client_meets_selection(e, h.s, index, &alert, &wiped), GTLS_ERR_PROTOCOL) << index;
    EXPECT_EQ(alert, GTLS_ALERT_ILLEGAL_PARAMETER) << index;
    EXPECT_TRUE(wiped) << index;
  }
}

TEST(Resume, ASelectedPskUnderASuiteOfAnotherHashIsIllegalParameter) {
  Env e;
  ASSERT_NO_FATAL_FAILURE(run_full(e.p));
  Held h;
  ASSERT_NO_FATAL_FAILURE(h.take(e.p));
  ASSERT_EQ(h.s->suite, GTLS_SUITE_AES_128_GCM_SHA256);

  Next n(e);
  n.p.offer = h.s;
  ASSERT_EQ(n.p.build(), GTLS_OK);
  Bytes hello = stream_out(n.p.c.conn);
  size_t used = 0;
  ASSERT_EQ(gtls_conn_stream_feed(n.p.s.conn, hello.data(), hello.size(), n.p.now, &used), GTLS_OK);
  Bytes wire = stream_out(n.p.s.conn);
  Bytes sh = server_hello_in(wire);
  ASSERT_FALSE(sh.empty());
  /* The suite field of the ServerHello: header, version, random, session id. */
  const size_t at = 5 + 4 + 2 + 32 + 1 + sh[4 + 2 + 32];
  ASSERT_EQ(wire[at], 0x13);
  ASSERT_EQ(wire[at + 1], 0x01);
  wire[at + 1] = 0x02;   /* TLS_AES_256_GCM_SHA384: offered, and the wrong hash for the PSK */
  EXPECT_EQ(gtls_conn_stream_feed(n.p.c.conn, wire.data(), wire.size(), n.p.now, &used), GTLS_ERR_PROTOCOL);
  EXPECT_EQ(gtls_conn_alert(n.p.c.conn), GTLS_ALERT_ILLEGAL_PARAMETER);
  EXPECT_TRUE(gtls_conn_secrets_are_wiped(n.p.c.conn));
}

/* ------------------------------------------------------------------ rotation */

TEST(Resume, ANewKeySealsAndAnOldOneStillOpensUntilItExpires) {
  Env e;
  ASSERT_NO_FATAL_FAILURE(run_full(e.p));
  Held old_session;
  ASSERT_NO_FATAL_FAILURE(old_session.take(e.p));
  const GTLS_TicketKey k1 = tkey(1);
  EXPECT_EQ(Bytes(old_session.s->ticket, old_session.s->ticket + 16),
      Bytes(k1.name, k1.name + 16)) << "sealed by the first key";

  /* Rotation: the second key begins later and so seals; the first stays and opens. */
  Next n(e);
  n.p.keys = {tkey(1), tkey(2, kNow - 500, kNow + 1000000)};
  n.p.offer = old_session.s;
  ASSERT_NO_FATAL_FAILURE(run_full(n.p));
  expect_resumed(n.p, true);
  Held fresh;
  ASSERT_NO_FATAL_FAILURE(fresh.take(n.p));
  const GTLS_TicketKey k2 = tkey(2, kNow - 500, kNow + 1000000);
  EXPECT_EQ(Bytes(fresh.s->ticket, fresh.s->ticket + 16), Bytes(k2.name, k2.name + 16))
      << "the newest key seals";

  /* The order of the list does not matter. */
  Next m(e);
  m.p.keys = {tkey(2, kNow - 500, kNow + 1000000), tkey(1)};
  m.p.offer = old_session.s;
  ASSERT_NO_FATAL_FAILURE(run_full(m.p));
  expect_resumed(m.p, true);
  Held again;
  ASSERT_NO_FATAL_FAILURE(again.take(m.p));
  EXPECT_EQ(Bytes(again.s->ticket, again.s->ticket + 16), Bytes(k2.name, k2.name + 16));

  /* Both open the other's tickets while both are unexpired. */
  EXPECT_EQ(decision(e, fresh.s, [&](Pair & p) { p.keys = {tkey(1), tkey(2, kNow - 500, kNow + 1000000)}; }), 1);
  /* When the first expires, what it sealed no longer opens and what the second sealed does. */
  auto after = [](Pair & p) {
    p.keys = {tkey(1, kNow - 1000, kNow + 10), tkey(2, kNow - 500, kNow + 1000000)};
    p.now = kNow + 20;
  };
  EXPECT_EQ(decision(e, old_session.s, after, kNow + 20), 0);
  EXPECT_EQ(decision(e, fresh.s, after, kNow + 20), 1);
}

TEST(Resume, ASessionIssuedUnderAKeyOpensOnlyWhileThatKeyIsUnexpired) {
  Env e;
  e.p.keys = {tkey(1, kNow - 1000, kNow + 100)};
  ASSERT_NO_FATAL_FAILURE(run_full(e.p));
  Held h;
  ASSERT_NO_FATAL_FAILURE(h.take(e.p));
  auto keep = [](Pair & p) { p.keys = {tkey(1, kNow - 1000, kNow + 100)}; };
  EXPECT_EQ(decision(e, h.s, [&](Pair & p) { keep(p); p.now = kNow + 99; }, kNow + 99), 1);
  EXPECT_EQ(decision(e, h.s, [&](Pair & p) { keep(p); p.now = kNow + 100; }, kNow + 100), 0);
}

TEST(Resume, SeveralTicketsEachWithAPskOfItsOwn) {
  Env e;
  e.p.scfg.ticket_count = 3;
  ASSERT_NO_FATAL_FAILURE(run_full(e.p));
  ASSERT_EQ(gtls_conn_session_count(e.p.c.conn), 3u);
  Held a, b, c;
  ASSERT_NO_FATAL_FAILURE(a.take(e.p, 0));
  ASSERT_NO_FATAL_FAILURE(b.take(e.p, 1));
  ASSERT_NO_FATAL_FAILURE(c.take(e.p, 2));
  EXPECT_NE(Bytes(a.s->psk, a.s->psk + a.s->psk_len), Bytes(b.s->psk, b.s->psk + b.s->psk_len));
  EXPECT_NE(Bytes(b.s->psk, b.s->psk + b.s->psk_len), Bytes(c.s->psk, c.s->psk + c.s->psk_len));
  EXPECT_NE(Bytes(a.s->ticket, a.s->ticket + 20), Bytes(b.s->ticket, b.s->ticket + 20));
  for (Held * h : {&a, &b, &c}) {
    ASSERT_EQ(e.p.again(h->s), GTLS_OK);
    e.p.run();
    ASSERT_TRUE(e.p.connected());
    expect_resumed(e.p, true);
  }
  EXPECT_EQ(gtls_conn_session_count(e.p.c.conn), 3u);
}

TEST(Resume, TheLifetimeIsTheServersAndNeverMoreThanSevenDays) {
  Env e;
  e.p.scfg.ticket_lifetime = GTLS_TICKET_LIFETIME_MAX;
  ASSERT_NO_FATAL_FAILURE(run_full(e.p));
  Held h;
  ASSERT_NO_FATAL_FAILURE(h.take(e.p));
  GTLS_SessionInfo info;
  ASSERT_EQ(gtls_session_info(h.s, &info), GTLS_OK);
  EXPECT_EQ(info.lifetime, 604800u);
  EXPECT_EQ(info.expires, info.received + 604800);
  EXPECT_EQ(info.received, kNow);

  Env over;
  over.p.scfg.ticket_lifetime = GTLS_TICKET_LIFETIME_MAX + 1;
  EXPECT_EQ(over.p.build(), GTLS_ERR_INVALID);
}

/* ------------------------------------------------------- the client's checks */

TEST(Resume, ASessionIsRefusedForAnotherHostAnotherSuiteOrOnceItHasRunOut) {
  Env e;
  ASSERT_NO_FATAL_FAILURE(run_full(e.p));
  Held h;
  ASSERT_NO_FATAL_FAILURE(h.take(e.p));

  auto client = [&](const std::string & host, GTLS_Conn ** out, GTLS_Context ** ctx,
                    const GTLS_Suite * suites, size_t n) {
    GTLS_ContextConfig cfg;
    gtls_context_config_default(&cfg);
    cfg.trust = e.p.trust->store;
    cfg.suites = suites;
    cfg.suite_count = n;
    EXPECT_EQ(gtls_context_new(nullptr, &cfg, ctx), GTLS_OK);
    EXPECT_EQ(gtls_conn_new(*ctx, host.data(), host.size(), out), GTLS_OK);
  };
  GTLS_Context * ctx = nullptr;
  GTLS_Conn * c = nullptr;

  client("elsewhere.test", &c, &ctx, nullptr, 0);
  EXPECT_EQ(gtls_conn_set_session(c, h.s, kNow), GTLS_ERR_INVALID) << "another host";
  gtls_conn_free(c);
  gtls_context_free(ctx);

  client("examplf.test", &c, &ctx, nullptr, 0);
  EXPECT_EQ(gtls_conn_set_session(c, h.s, kNow), GTLS_ERR_INVALID) << "another host of the same length";
  gtls_conn_free(c);
  gtls_context_free(ctx);

  client("example.tes", &c, &ctx, nullptr, 0);
  EXPECT_EQ(gtls_conn_set_session(c, h.s, kNow), GTLS_ERR_INVALID) << "a prefix of the host";
  gtls_conn_free(c);
  gtls_context_free(ctx);

  client("example.testx", &c, &ctx, nullptr, 0);
  EXPECT_EQ(gtls_conn_set_session(c, h.s, kNow), GTLS_ERR_INVALID) << "the host with more after it";
  gtls_conn_free(c);
  gtls_context_free(ctx);

  client("EXAMPLE.test", &c, &ctx, nullptr, 0);
  EXPECT_EQ(gtls_conn_set_session(c, h.s, kNow), GTLS_OK) << "a host name differing in case is the same one";
  EXPECT_EQ(gtls_conn_set_session(c, h.s, kNow), GTLS_ERR_INVALID) << "only one session";
  gtls_conn_free(c);
  gtls_context_free(ctx);

  static const GTLS_Suite other[] = {GTLS_SUITE_AES_256_GCM_SHA384};
  ASSERT_EQ(h.s->suite, GTLS_SUITE_AES_128_GCM_SHA256);
  client(e.cred->name, &c, &ctx, other, 1);
  EXPECT_EQ(gtls_conn_set_session(c, h.s, kNow), GTLS_ERR_INVALID) << "a suite this connection does not offer";
  gtls_conn_free(c);
  gtls_context_free(ctx);

  client(e.cred->name, &c, &ctx, nullptr, 0);
  EXPECT_EQ(gtls_conn_set_session(c, h.s, kNow - 1), GTLS_ERR_INVALID) << "not received yet";
  EXPECT_EQ(gtls_conn_set_session(c, h.s, kNow + GTLS_TICKET_LIFETIME_DEFAULT), GTLS_ERR_INVALID)
      << "run out";
  EXPECT_EQ(gtls_conn_set_session(c, h.s, kNow + GTLS_TICKET_LIFETIME_DEFAULT - 1), GTLS_OK)
      << "the last second";
  EXPECT_EQ(gtls_conn_set_session(c, nullptr, kNow), GTLS_ERR_INVALID);
  ASSERT_EQ(gtls_conn_start(c), GTLS_OK);
  gtls_conn_free(c);
  gtls_context_free(ctx);

  client(e.cred->name, &c, &ctx, nullptr, 0);
  ASSERT_EQ(gtls_conn_start(c), GTLS_OK);
  EXPECT_EQ(gtls_conn_set_session(c, h.s, kNow), GTLS_ERR_INVALID) << "after start";
  gtls_conn_free(c);
  gtls_context_free(ctx);

  /* A server connection takes none, and holds none. */
  EXPECT_EQ(gtls_conn_set_session(e.p.s.conn, h.s, kNow), GTLS_ERR_INVALID);
  GTLS_Session * none = nullptr;
  EXPECT_EQ(gtls_conn_session(e.p.s.conn, 0, &none), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_session_count(e.p.s.conn), 0u);
  EXPECT_EQ(gtls_conn_session(e.p.c.conn, 1, &none), GTLS_ERR_INVALID) << "no such session";
}

TEST(Resume, AFailedConnectionHoldsNoSessions) {
  Env e;
  e.p.scfg.ticket_count = 2;
  ASSERT_NO_FATAL_FAILURE(run_full(e.p));
  ASSERT_EQ(gtls_conn_session_count(e.p.c.conn), 2u);
  /* A record that does not authenticate kills the connection. */
  Bytes junk = {23, 3, 3, 0, 20};
  junk.insert(junk.end(), 20, 0x42);
  size_t used = 0;
  EXPECT_NE(gtls_conn_stream_feed(e.p.c.conn, junk.data(), junk.size(), kNow, &used), GTLS_OK);
  ASSERT_TRUE(gtls_conn_is_failed(e.p.c.conn));
  EXPECT_EQ(gtls_conn_session_count(e.p.c.conn), 0u);
  GTLS_Session * none = nullptr;
  EXPECT_EQ(gtls_conn_session(e.p.c.conn, 0, &none), GTLS_ERR_FAILED);
}

TEST(Resume, TheOfferedSessionIsWipedOnceTheServerHelloHasDecided) {
  Env e;
  ASSERT_NO_FATAL_FAILURE(run_full(e.p));
  Held h;
  ASSERT_NO_FATAL_FAILURE(h.take(e.p));
  Next n(e);
  n.p.offer = h.s;
  ASSERT_EQ(n.p.build(), GTLS_OK);
  EXPECT_NE(n.p.c.conn->offer, nullptr);
  n.p.run();
  ASSERT_TRUE(n.p.connected());
  EXPECT_EQ(n.p.c.conn->offer, nullptr);
}

/* --------------------------------------------------------- the RFC's ticket */

TEST(Resume, TheTicketRfc8448SendsBecomesTheSessionItsResumedTraceStartedFrom) {
  Flow r(simple_trace());
  Vec resumed("resumed");
  r.start();
  r.take(GTLS_EPOCH_INITIAL);
  ASSERT_EQ(r.through_server_hello(), GTLS_OK);
  ASSERT_EQ(r.feed(GTLS_EPOCH_HANDSHAKE, r.v[simple_trace().flight()]), GTLS_OK);
  r.take(GTLS_EPOCH_HANDSHAKE);
  const Bytes nst = r.v["server.construct-a-newsessionticket-handshake-message.newsessionticket"];
  ASSERT_EQ(r.feed(GTLS_EPOCH_APPLICATION, nst), GTLS_OK);
  ASSERT_EQ(gtls_conn_session_count(r.conn), 1u);

  GTLS_Session * s = nullptr;
  ASSERT_EQ(gtls_conn_session(r.conn, 0, &s), GTLS_OK);
  EXPECT_EQ(Bytes(s->psk, s->psk + s->psk_len), resumed["client.extract-secret-early.ikm"])
      << "the PSK the resumed trace extracts its early secret from";
  EXPECT_EQ(s->ticket_len, 178u);
  EXPECT_EQ(Bytes(s->ticket, s->ticket + s->ticket_len),
      Bytes(nst.begin() + 4 + 4 + 4 + 1 + 2 + 2, nst.begin() + 4 + 4 + 4 + 1 + 2 + 2 + 178));
  EXPECT_EQ(s->lifetime, 30u);
  EXPECT_EQ(s->age_add, 0xfad6aac5u);
  EXPECT_EQ(s->max_early_data, 0x400u);
  EXPECT_EQ(s->suite, GTLS_SUITE_AES_128_GCM_SHA256);
  EXPECT_EQ(std::string(reinterpret_cast<const char *>(s->host), s->host_len), "server");
  EXPECT_EQ(s->received, r.now);
  gtls_session_free(s);

  /* The same, one byte at a time and twice. */
  ASSERT_EQ(r.feed(GTLS_EPOCH_APPLICATION, nst, 1), GTLS_OK);
  EXPECT_EQ(gtls_conn_session_count(r.conn), 2u);
}

TEST(Resume, ATicketWithALifetimeOfZeroIsNotKeptAndAMuchLongerOneIsCut) {
  Flow r(simple_trace());
  r.start();
  r.take(GTLS_EPOCH_INITIAL);
  ASSERT_EQ(r.through_server_hello(), GTLS_OK);
  ASSERT_EQ(r.feed(GTLS_EPOCH_HANDSHAKE, r.v[simple_trace().flight()]), GTLS_OK);
  Bytes nst = r.v["server.construct-a-newsessionticket-handshake-message.newsessionticket"];
  Bytes zero = nst;
  zero[4] = zero[5] = zero[6] = zero[7] = 0;
  ASSERT_EQ(r.feed(GTLS_EPOCH_APPLICATION, zero), GTLS_OK);
  EXPECT_EQ(gtls_conn_session_count(r.conn), 0u);
  EXPECT_EQ(r.conn->tickets, 1u) << "but it counts against the cap";
  Bytes long_lived = nst;
  long_lived[4] = 0xff;
  long_lived[5] = long_lived[6] = long_lived[7] = 0xff;
  ASSERT_EQ(r.feed(GTLS_EPOCH_APPLICATION, long_lived), GTLS_OK);
  ASSERT_EQ(gtls_conn_session_count(r.conn), 1u);
  GTLS_Session * s = nullptr;
  ASSERT_EQ(gtls_conn_session(r.conn, 0, &s), GTLS_OK);
  EXPECT_EQ(s->lifetime, GTLS_TICKET_LIFETIME_MAX);
  gtls_session_free(s);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
