/**
 * @file
 *
 * After a connection is freed, the secrets it held are zero: not in the
 * connection, not in anything the library allocated. The allocator shows
 * every block to a scan just before it is freed, and the scan looks for the
 * secrets the test knows (it picked the client's private key, and the
 * simulated server derived the same schedule).
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "sim.h"

#include <algorithm>

using namespace gtlstest;

namespace {

bool contains(const unsigned char * p, size_t n, const Bytes & needle) {
  if (needle.empty() || n < needle.size()) {
    return false;
  }
  return std::search(p, p + n, needle.begin(), needle.end()) != p + n;
}

struct Watch {
  std::vector<Bytes> secrets;
  int found = 0;
  void install(TestAlloc & a) {
    a.on_free = [this](const unsigned char * p, size_t n) {
      for (const Bytes & s : secrets) {
        if (contains(p, n, s)) {
          found++;
        }
      }
    };
  }
};

/** The client's private key and random, so that the test knows both. */
const Bytes kClientRandom(32, 0x61);
const Bytes kClientPrivate(32, 0x66);

}  // namespace

/* The scan has to be able to see what it looks for. */
TEST(WipeScanControl, FindsASecretThatWasLeftInAFreedBlock) {
  TestAlloc alloc;
  Watch watch;
  watch.secrets = {Bytes(32, 0x77)};
  watch.install(alloc);
  unsigned char * p = static_cast<unsigned char *>(alloc.a.malloc_fn(alloc.a.ctx, 100));
  std::memset(p + 10, 0x77, 32);
  alloc.a.free_fn(alloc.a.ctx, p);
  EXPECT_EQ(watch.found, 1);
  p = static_cast<unsigned char *>(alloc.a.malloc_fn(alloc.a.ctx, 100));
  std::memset(p, 0, 100);  /* the allocator may hand back the block just freed */
  std::memset(p + 10, 0x77, 31);  /* one short of the whole secret */
  alloc.a.free_fn(alloc.a.ctx, p);
  EXPECT_EQ(watch.found, 1);
}

TEST(Wipe, NoSecretReachesAFreedBlockAfterASuccessfulHandshake) {
  TestAlloc alloc;
  Watch watch;
  {
    World w;
    w.allocator = &alloc.a;
    w.build();
    ScriptedRandom rnd;
    rnd.chunks = {kClientRandom, kClientPrivate};
    gtls_conn_set_hooks(w.conn, ScriptedRandom::fn, &rnd, nullptr, nullptr);
    SimServer s(w.server_options());
    ASSERT_EQ(w.run(s), GTLS_OK);
    const GTLS_Schedule & k = s.sched;
    watch.secrets = {kClientPrivate, Bytes(k.handshake, k.handshake + 32),
        Bytes(k.master, k.master + 32), Bytes(k.c_hs, k.c_hs + 32),
        Bytes(k.s_hs, k.s_hs + 32), Bytes(k.c_ap, k.c_ap + 32),
        Bytes(k.s_ap, k.s_ap + 32)};
    watch.install(alloc);
    EXPECT_FALSE(gtls_conn_secrets_are_wiped(w.conn));
    /* Before the free, the connection really does hold them. */
    const unsigned char * raw = reinterpret_cast<const unsigned char *>(w.conn);
    EXPECT_TRUE(contains(raw, sizeof(GTLS_Conn), Bytes(k.c_ap, k.c_ap + 32)))
        << "so the scan below is looking for something that was there";
  }
  EXPECT_EQ(watch.found, 0) << "a secret was in a block when it was freed";
  EXPECT_EQ(alloc.live, 0);
}

TEST(Wipe, NoSecretReachesAFreedBlockWhenTheHandshakeFailsAtAnyMessage) {
  /* Fail at each of: ServerHello is fine and the flight is refused at
   * EncryptedExtensions, at Certificate, at CertificateVerify, at Finished. */
  for (int stage = 0; stage < 4; stage++) {
    TestAlloc alloc;
    Watch watch;
    {
      World w;
      w.allocator = &alloc.a;
      w.build();
      ScriptedRandom rnd;
      rnd.chunks = {kClientRandom, kClientPrivate};
      gtls_conn_set_hooks(w.conn, ScriptedRandom::fn, &rnd, nullptr, nullptr);
      SimOptions o = w.server_options();
      switch (stage) {
        case 0: o.ee_extras = {SimServer::ext(0x7a7a, Bytes{1})}; break;
        case 1: o.chain = {}; break;
        case 2: o.cv_wrong_transcript = true; break;
        default: o.bad_finished = true; break;
      }
      SimServer s(o);
      EXPECT_NE(w.run(s), GTLS_OK) << stage;
      EXPECT_TRUE(gtls_conn_secrets_are_wiped(w.conn)) << stage;
      const GTLS_Schedule & k = s.sched;
      watch.secrets = {kClientPrivate, Bytes(k.handshake, k.handshake + 32),
          Bytes(k.c_hs, k.c_hs + 32), Bytes(k.s_hs, k.s_hs + 32)};
      watch.install(alloc);
    }
    EXPECT_EQ(watch.found, 0) << "stage " << stage;
    EXPECT_EQ(alloc.live, 0) << "stage " << stage;
  }
}

TEST(Wipe, ThePrivateKeyIsGoneTheMomentServerHelloIsProcessed) {
  World w;
  w.build();
  ScriptedRandom rnd;
  rnd.chunks = {kClientRandom, kClientPrivate};
  gtls_conn_set_hooks(w.conn, ScriptedRandom::fn, &rnd, nullptr, nullptr);
  SimServer s(w.server_options());
  ASSERT_EQ(gtls_conn_start(w.conn), GTLS_OK);
  const unsigned char * raw = reinterpret_cast<const unsigned char *>(w.conn);
  EXPECT_TRUE(contains(raw, sizeof(GTLS_Conn), kClientPrivate)) << "held while it is needed";
  Bytes ch = w.out(GTLS_EPOCH_INITIAL);
  w.drain(GTLS_EPOCH_INITIAL);
  s.accept_hello(ch);
  ASSERT_EQ(w.feed(GTLS_EPOCH_INITIAL, s.sh_msg), GTLS_OK);
  EXPECT_FALSE(contains(raw, sizeof(GTLS_Conn), kClientPrivate)) << "and not a moment longer";
}

TEST(Wipe, ARetriedKeyShareReplacesAndWipesTheFirst) {
  World w;
  w.build();
  ScriptedRandom rnd;
  const Bytes second(32, 0x11);
  rnd.chunks = {kClientRandom, kClientPrivate, second};
  gtls_conn_set_hooks(w.conn, ScriptedRandom::fn, &rnd, nullptr, nullptr);
  SimOptions o = w.server_options();
  o.hrr = true;
  SimServer s(o);
  ASSERT_EQ(gtls_conn_start(w.conn), GTLS_OK);
  Bytes ch = w.out(GTLS_EPOCH_INITIAL);
  w.drain(GTLS_EPOCH_INITIAL);
  s.accept_hello(ch);
  ASSERT_EQ(w.feed(GTLS_EPOCH_INITIAL, s.hrr_msg), GTLS_OK);
  const unsigned char * raw = reinterpret_cast<const unsigned char *>(w.conn);
  EXPECT_FALSE(contains(raw, sizeof(GTLS_Conn), kClientPrivate))
      << "the X25519 key was for a group that was refused";
  EXPECT_TRUE(contains(raw, sizeof(GTLS_Conn), second));
}

TEST(Wipe, ASecretReadOutThroughTheApiIsTheCallersToWipe) {
  /* The API copies; it does not keep a second copy of its own for the
   * caller's buffer. What the caller holds is the caller's. */
  World w;
  w.build();
  SimServer s(w.server_options());
  ASSERT_EQ(w.run(s), GTLS_OK);
  Bytes buf(GTLS_HASH_MAX, 0);
  size_t n = 0;
  ASSERT_EQ(gtls_conn_secret(w.conn, GTLS_EPOCH_APPLICATION, GTLS_DIR_WRITE, buf.data(), buf.size(), &n),
      GTLS_OK);
  EXPECT_EQ(n, 32u);
  EXPECT_EQ(buf[n], 0) << "nothing written past the digest";
}

/* The other groups and the other hash: the P-256 and P-384 private keys, and
 * the 48-byte secrets of an AES-256-GCM-SHA384 handshake. */
TEST(Wipe, NoSecretReachesAFreedBlockForP256P384AndSha384) {
  struct Case {
    GTLS_Group group;
    GTLS_Suite suite;
    size_t priv_len;
  };
  const Case cases[] = {{GTLS_GROUP_SECP256R1, GTLS_SUITE_AES_128_GCM_SHA256, 32},
      {GTLS_GROUP_SECP384R1, GTLS_SUITE_AES_256_GCM_SHA384, 48},
      {GTLS_GROUP_SECP256R1, GTLS_SUITE_AES_256_GCM_SHA384, 32}};
  for (const Case & c : cases) {
    TestAlloc alloc;
    Watch watch;
    {
      World w;
      w.allocator = &alloc.a;
      GTLS_Group groups[1] = {c.group};
      w.cfg.groups = groups;
      w.cfg.group_count = 1;
      w.build();
      const Bytes priv(c.priv_len, 0x2d);
      ScriptedRandom rnd;
      rnd.chunks = {kClientRandom, priv};
      gtls_conn_set_hooks(w.conn, ScriptedRandom::fn, &rnd, nullptr, nullptr);
      SimOptions o = w.server_options();
      o.group = c.group;
      o.suite = c.suite;
      SimServer s(o);
      ASSERT_EQ(w.run(s), GTLS_OK);
      const GTLS_Schedule & k = s.sched;
      const size_t h = k.hlen;
      ASSERT_EQ(h, c.suite == GTLS_SUITE_AES_256_GCM_SHA384 ? 48u : 32u);
      watch.secrets = {priv, Bytes(k.handshake, k.handshake + h), Bytes(k.master, k.master + h),
          Bytes(k.c_hs, k.c_hs + h), Bytes(k.s_hs, k.s_hs + h), Bytes(k.c_ap, k.c_ap + h),
          Bytes(k.s_ap, k.s_ap + h)};
      watch.install(alloc);
      const unsigned char * raw = reinterpret_cast<const unsigned char *>(w.conn);
      EXPECT_TRUE(contains(raw, sizeof(GTLS_Conn), Bytes(k.c_ap, k.c_ap + h)))
          << "held until the free";
    }
    EXPECT_EQ(watch.found, 0) << "group " << c.group << " suite " << c.suite;
    EXPECT_EQ(alloc.live, 0);
  }
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
