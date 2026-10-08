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

#include "loop.h"

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

/* ------------------------------------------------- the server and the record layer */

namespace {

/** Every secret a connection holds that the test can name: the schedule, the record keys, and the traffic secrets. */
std::vector<Bytes> secrets_of(const GTLS_Conn * c) {
  std::vector<Bytes> out;
  const GTLS_Schedule & k = c->sec.schedule;
  const size_t h = k.hlen;
  if (h == 0) {
    return out;
  }
  for (const unsigned char * p : {k.handshake, k.master, k.c_hs, k.s_hs, k.c_ap, k.s_ap}) {
    out.push_back(Bytes(p, p + h));
  }
  if (c->sec.wr.active) {
    out.push_back(Bytes(c->sec.wr.key, c->sec.wr.key + gtls_suite_key_len(c->sec.wr.suite)));
    out.push_back(Bytes(c->sec.wr_secret, c->sec.wr_secret + h));
  }
  if (c->sec.rd.active) {
    out.push_back(Bytes(c->sec.rd.key, c->sec.rd.key + gtls_suite_key_len(c->sec.rd.suite)));
    out.push_back(Bytes(c->sec.rd_secret, c->sec.rd_secret + h));
  }
  return out;
}

}  // namespace

TEST(WipeStream, NoSecretOfEitherEndReachesAFreedBlock) {
  std::unique_ptr<Cred> cred = ed_cred();
  for (bool retry : {false, true}) {
    TestAlloc alloc;
    Watch watch;
    {
      Pair p(*cred);
      p.allocator = &alloc.a;
      GTLS_Group want = GTLS_GROUP_SECP256R1;
      if (retry) {
        p.scfg.groups = &want;
        p.scfg.group_count = 1;
      }
      ASSERT_EQ(p.build(), GTLS_OK);
      ScriptedRandom crnd, srnd;
      const Bytes cpriv(32, 0x71), spriv(32, 0x72);
      crnd.chunks = {Bytes(32, 0x61), cpriv, cpriv};
      srnd.chunks = {Bytes(32, 0x62), spriv, spriv};
      /* the connections were started by build(): redraw with scripted keys */
      gtls_conn_free(p.c.conn);
      gtls_conn_free(p.s.conn);
      p.c.conn = nullptr;
      p.s.conn = nullptr;
      ASSERT_EQ(gtls_conn_new(p.c.ctx, p.host.data(), p.host.size(), &p.c.conn), GTLS_OK);
      ASSERT_EQ(gtls_conn_new_server(p.s.ctx, &p.s.conn), GTLS_OK);
      gtls_conn_set_hooks(p.c.conn, ScriptedRandom::fn, &crnd, nullptr, nullptr);
      gtls_conn_set_hooks(p.s.conn, ScriptedRandom::fn, &srnd, nullptr, nullptr);
      ASSERT_EQ(gtls_conn_start(p.c.conn), GTLS_OK);
      ASSERT_EQ(gtls_conn_start(p.s.conn), GTLS_OK);
      p.run();
      ASSERT_TRUE(p.connected());
      p.send_all(p.c, p.s, pattern(3000, 1));
      ASSERT_EQ(gtls_conn_key_update(p.c.conn, 1), GTLS_OK);
      p.send_all(p.s, p.c, pattern(3000, 2));
      for (const Bytes & k : secrets_of(p.c.conn)) watch.secrets.push_back(k);
      for (const Bytes & k : secrets_of(p.s.conn)) watch.secrets.push_back(k);
      if (!retry) {
        watch.secrets.push_back(cpriv);
        watch.secrets.push_back(spriv);
      }
      watch.install(alloc);
      EXPECT_GE(watch.secrets.size(), 20u);
      const unsigned char * raw = reinterpret_cast<const unsigned char *>(p.s.conn);
      EXPECT_TRUE(contains(raw, sizeof(GTLS_Conn), Bytes(p.s.conn->sec.wr.key, p.s.conn->sec.wr.key + 16)))
          << "the scan looks for something that was there";
    }
    EXPECT_EQ(watch.found, 0) << (retry ? "retry" : "plain");
    EXPECT_EQ(alloc.live, 0);
  }
}

TEST(WipeStream, AServerThatFailsAtAnyStageHoldsNothingAfterwards) {
  std::unique_ptr<Cred> cred = ed_cred();
  /* stage 0: no ALPN overlap; 1: a refused ClientHello; 2: a tampered Finished;
   * 3: a truncated stream after the handshake; 4: a record that does not authenticate */
  for (int stage = 0; stage < 5; stage++) {
    TestAlloc alloc;
    Watch watch;
    {
      Pair p(*cred);
      p.allocator = &alloc.a;
      if (stage == 0) {
        p.salpn = {"h2"};
        p.calpn = {"spdy"};
      }
      ASSERT_EQ(p.build(), GTLS_OK);
      p.auto_read = true;
      if (stage == 1) {
        Bytes bad = {22, 3, 3, 0, 4, 1, 0, 0, 0};
        size_t used = 0;
        EXPECT_NE(gtls_conn_stream_feed(p.s.conn, bad.data(), bad.size(), kNow, &used), GTLS_OK);
      } else if (stage == 2) {
        Bytes ch = stream_out(p.c.conn);
        gtls_conn_stream_consume(p.c.conn, ch.size());
        size_t used = 0;
        ASSERT_EQ(gtls_conn_stream_feed(p.s.conn, ch.data(), ch.size(), kNow, &used), GTLS_OK);
        for (const Bytes & s : secrets_of(p.s.conn)) watch.secrets.push_back(s);
        Bytes junk(5 + 53, 0x42);
        junk[0] = 23;
        junk[1] = 3;
        junk[2] = 3;
        junk[3] = 0;
        junk[4] = 53;
        EXPECT_EQ(gtls_conn_stream_feed(p.s.conn, junk.data(), junk.size(), kNow, &used), GTLS_ERR_MISMATCH);
      } else {
        p.run();
        if (stage == 0) {
          EXPECT_TRUE(gtls_conn_is_failed(p.s.conn));
        } else {
          ASSERT_TRUE(p.connected());
          for (const Bytes & s : secrets_of(p.s.conn)) watch.secrets.push_back(s);
          for (const Bytes & s : secrets_of(p.c.conn)) watch.secrets.push_back(s);
          if (stage == 3) {
            EXPECT_EQ(gtls_conn_stream_eof(p.s.conn), GTLS_ERR_TRUNCATED);
          } else {
            Bytes junk(5 + 30, 0x42);
            junk[0] = 23;
            junk[1] = 3;
            junk[2] = 3;
            junk[3] = 0;
            junk[4] = 30;
            size_t used = 0;
            EXPECT_EQ(gtls_conn_stream_feed(p.s.conn, junk.data(), junk.size(), kNow, &used), GTLS_ERR_MISMATCH);
            EXPECT_TRUE(gtls_conn_secrets_are_wiped(p.s.conn));
          }
        }
      }
      EXPECT_TRUE(gtls_conn_is_failed(p.s.conn)) << stage;
      EXPECT_TRUE(gtls_conn_secrets_are_wiped(p.s.conn)) << stage;
      watch.install(alloc);
    }
    EXPECT_EQ(watch.found, 0) << "stage " << stage;
    EXPECT_EQ(alloc.live, 0) << "stage " << stage;
  }
}

TEST(WipeStream, PlaintextNotYetReadIsGoneAfterAFailureToo) {
  std::unique_ptr<Cred> cred = ed_cred();
  TestAlloc alloc;
  Watch watch;
  watch.secrets = {Bytes(64, 0x5e)};
  {
    Pair p(*cred);
    p.allocator = &alloc.a;
    ASSERT_EQ(p.build(), GTLS_OK);
    p.run();
    ASSERT_TRUE(p.connected());
    p.auto_read = false;
    size_t w = 0;
    ASSERT_EQ(gtls_conn_write(p.c.conn, watch.secrets[0].data(), 64, &w), GTLS_OK);
    p.run();
    ASSERT_GT(p.s.conn->app_in.len, 0u) << "it is waiting to be read";
    EXPECT_EQ(gtls_conn_stream_eof(p.s.conn), GTLS_ERR_TRUNCATED);
    unsigned char b[64];
    size_t n = 1;
    EXPECT_EQ(gtls_conn_read(p.s.conn, b, 64, &n), GTLS_ERR_FAILED) << "a failed connection discards what it held";
    watch.install(alloc);
  }
  EXPECT_EQ(watch.found, 0);
}



/* A resumed handshake: the PSK, the early secret it seeds, every secret
 * after it and the resumption secret and PSKs of the new tickets are gone
 * from every block the library frees, on success and on a refused binder. */

namespace {

GTLS_TicketKey wipe_key() {
  GTLS_TicketKey k;
  std::memset(&k, 0, sizeof k);
  std::memset(k.name, 0x31, sizeof k.name);
  std::memset(k.key, 0x32, sizeof k.key);
  k.not_before = kNow - 100;
  k.not_after = kNow + 100000;
  return k;
}

}  // namespace

TEST(WipeResume, NoSecretOfAResumedHandshakeReachesAFreedBlock) {
  std::unique_ptr<Cred> cred = ed_cred();
  GTLS_Session * session = nullptr;
  {
    Pair p1(*cred);
    p1.keys = {wipe_key()};
    ASSERT_EQ(p1.build(), GTLS_OK);
    p1.run();
    ASSERT_TRUE(p1.connected());
    ASSERT_EQ(gtls_conn_session(p1.c.conn, 0, &session), GTLS_OK);
  }
  const Bytes psk(session->psk, session->psk + session->psk_len);
  TestAlloc alloc;
  Watch watch;
  {
    Pair p2(*cred);
    p2.keys = {wipe_key()};
    p2.allocator = &alloc.a;
    p2.offer = session;
    ASSERT_EQ(p2.build(), GTLS_OK);
    p2.run();
    ASSERT_TRUE(p2.connected());
    ASSERT_EQ(gtls_conn_resumed(p2.c.conn), 1);
    watch.secrets.push_back(psk);
    for (GTLS_Conn * c : {p2.c.conn, p2.s.conn}) {
      for (GTLS_SecretId id : {GTLS_SECRET_EARLY, GTLS_SECRET_HANDSHAKE, GTLS_SECRET_MASTER,
               GTLS_SECRET_CLIENT_HS, GTLS_SECRET_SERVER_HS, GTLS_SECRET_CLIENT_AP,
               GTLS_SECRET_SERVER_AP}) {
        Bytes out(GTLS_HASH_MAX);
        size_t n = 0;
        ASSERT_EQ(gtls_conn_debug_secret(c, id, out.data(), out.size(), &n), GTLS_OK);
        out.resize(n);
        watch.secrets.push_back(out);
      }
      watch.secrets.push_back(Bytes(c->sec.schedule.res, c->sec.schedule.res + c->sec.schedule.hlen));
    }
    GTLS_Session * fresh = nullptr;
    ASSERT_EQ(gtls_conn_session(p2.c.conn, 0, &fresh), GTLS_OK);
    watch.secrets.push_back(Bytes(fresh->psk, fresh->psk + fresh->psk_len));
    gtls_session_free(fresh);
    EXPECT_TRUE(contains(reinterpret_cast<const unsigned char *>(p2.c.conn), sizeof(GTLS_Conn),
        Bytes(p2.c.conn->sec.schedule.early, p2.c.conn->sec.schedule.early + 32)))
        << "so the scan is looking for something that was there";
    watch.install(alloc);
  }
  EXPECT_EQ(watch.found, 0) << "a secret was in a block when it was freed";
  EXPECT_EQ(alloc.live, 0);
  gtls_session_free(session);
}

TEST(WipeResume, ARefusedBinderLeavesNoSecretBehindEither) {
  std::unique_ptr<Cred> cred = ed_cred();
  GTLS_Session * session = nullptr;
  {
    Pair p1(*cred);
    p1.keys = {wipe_key()};
    ASSERT_EQ(p1.build(), GTLS_OK);
    p1.run();
    ASSERT_EQ(gtls_conn_session(p1.c.conn, 0, &session), GTLS_OK);
  }
  TestAlloc alloc;
  Watch watch;
  watch.secrets.push_back(Bytes(session->psk, session->psk + session->psk_len));
  watch.install(alloc);
  {
    Pair p2(*cred);
    p2.keys = {wipe_key()};
    p2.allocator = &alloc.a;
    p2.offer = session;
    ASSERT_EQ(p2.build(), GTLS_OK);
    Bytes hello = stream_out(p2.c.conn);
    hello[hello.size() - 1] ^= 1;
    size_t used = 0;
    EXPECT_EQ(gtls_conn_stream_feed(p2.s.conn, hello.data(), hello.size(), kNow, &used), GTLS_ERR_MISMATCH);
    EXPECT_TRUE(gtls_conn_secrets_are_wiped(p2.s.conn));
  }
  EXPECT_EQ(watch.found, 0);
  EXPECT_EQ(alloc.live, 0);
  gtls_session_free(session);
}

TEST(WipeResume, AFreedSessionLeavesNeitherThePskNorTheTicketBehind) {
  TestAlloc alloc;
  Watch watch;
  GTLS_Session * s = gtls_session_alloc(&alloc.a, 64);
  ASSERT_NE(s, nullptr);
  s->suite = GTLS_SUITE_AES_128_GCM_SHA256;
  s->psk_len = 32;
  std::memset(s->psk, 0x5d, 32);
  std::memset(s->ticket, 0x6e, 64);
  watch.secrets = {Bytes(32, 0x5d), Bytes(64, 0x6e)};
  watch.install(alloc);
  gtls_session_free(s);
  EXPECT_EQ(watch.found, 0);
  EXPECT_EQ(alloc.live, 0);
  GTLS_Session * c = gtls_session_alloc(&alloc.a, 64);
  std::memset(c->psk, 0x5d, 32);
  watch.install(alloc);
  /* Control: a block that is freed without a wipe is seen by the scan. */
  unsigned char * leak = static_cast<unsigned char *>(alloc.a.malloc_fn(alloc.a.ctx, 64));
  std::memset(leak, 0x5d, 32);
  alloc.a.free_fn(alloc.a.ctx, leak);
  EXPECT_EQ(watch.found, 1);
  gtls_session_free(c);
  EXPECT_EQ(watch.found, 1) << "and the session's own free adds nothing";
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
