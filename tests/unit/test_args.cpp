/**
 * @file
 *
 * What the library refuses when it is called wrongly: null arguments, calls
 * out of order, a connection that has already failed, a context that cannot be
 * right, an output buffer that is already in error, a random source that
 * fails, and the internal functions' own argument checks. None of these is
 * reached by a handshake, which is why `make coverage` listed them; each is
 * one line the library is meant to keep, and the test is the proof that it
 * does.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "loop.h"

using namespace gtlstest;

/* ------------------------------------------------- the internal functions */

TEST(InternalArguments, TheTranscriptRefusesWhatCannotBe) {
  GTLS_Transcript t;
  unsigned char out[64];

  EXPECT_EQ(gtls_transcript_init(nullptr), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_transcript_update(nullptr, "x", 1), GTLS_ERR_INVALID);
  ASSERT_EQ(gtls_transcript_init(&t), GTLS_OK);
  EXPECT_EQ(gtls_transcript_update(&t, nullptr, 1), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_transcript_select(&t, GTLS_HASH_NONE), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_transcript_snapshot(nullptr, GTLS_HASH_SHA256, out), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_transcript_snapshot(&t, GTLS_HASH_NONE, out), GTLS_ERR_INVALID);
  ASSERT_EQ(gtls_transcript_select(&t, GTLS_HASH_SHA256), GTLS_OK);
  EXPECT_EQ(gtls_transcript_select(&t, GTLS_HASH_SHA256), GTLS_ERR_INVALID) << "the hash is chosen once";
  EXPECT_EQ(gtls_transcript_snapshot(&t, GTLS_HASH_SHA384, out), GTLS_ERR_INVALID) << "the one that was dropped";
  EXPECT_EQ(gtls_transcript_restart(nullptr, GTLS_HASH_SHA256), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_transcript_restart(&t, GTLS_HASH_NONE), GTLS_ERR_INVALID);
  gtls_transcript_wipe(&t);
}

TEST(InternalArguments, TheScheduleAndTheMacsRefuseWhatCannotBe) {
  GTLS_Schedule s;
  GTLS_MacScratch m;
  unsigned char b[64] = {0};
  unsigned char th[32] = {0};
  unsigned char psk[32] = {0};

  std::memset(&m, 0, sizeof m);
  EXPECT_EQ(gtls_schedule_early(nullptr, GTLS_HASH_SHA256), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_schedule_early(&s, GTLS_HASH_NONE), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_derive_secret(GTLS_HASH_SHA256, b, 32, "x", nullptr, b), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_resumption_psk(GTLS_HASH_SHA256, nullptr, "n", 1, b), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_resumption_psk(GTLS_HASH_SHA256, b, nullptr, 1, b), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_binder_compute(GTLS_HASH_SHA256, psk, 32, nullptr, b, &m), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_binder_compute(GTLS_HASH_SHA256, psk, 32, th, b, nullptr), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_binder_check(GTLS_HASH_NONE, psk, 32, th, b, 32, &m), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_binder_check(GTLS_HASH_SHA256, psk, 32, th, nullptr, 32, &m), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_finished_verify_data(GTLS_HASH_SHA256, nullptr, th, b, &m), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_finished_verify_data(GTLS_HASH_SHA256, psk, th, b, nullptr), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_finished_check(GTLS_HASH_NONE, psk, th, b, 32, &m), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_finished_check(GTLS_HASH_SHA256, psk, th, nullptr, 32, &m), GTLS_ERR_INVALID);
  EXPECT_TRUE(all_zero(&m, sizeof m));
}

TEST(InternalArguments, TheRecordLayerRefusesNullsAndAnOutputInError) {
  GTLS_RecordKeys k;
  GTLS_Buf out;
  unsigned char pt[32];
  size_t n = 0;
  unsigned inner = 0;
  unsigned char key[16] = {1};
  unsigned char iv[12] = {2};

  ASSERT_EQ(gtls_record_keys_from_raw(&k, GTLS_SUITE_AES_128_GCM_SHA256, key, iv, 0), GTLS_OK);
  EXPECT_EQ(gtls_record_open(nullptr, pt, pt, 20, 0, pt, &n, &inner), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_record_open(&k, nullptr, pt, 20, 0, pt, &n, &inner), GTLS_ERR_INVALID);
  gtls_buf_init(&out, nullptr, 1 << 16);
  ASSERT_EQ(gtls_buf_reserve(&out, 1024), GTLS_OK);   /* room, so only the error state can refuse */
  out.err = GTLS_ERR_OOM;
  EXPECT_EQ(gtls_record_plain(GTLS_CT_HANDSHAKE, 0x0303, "x", 1, &out), GTLS_ERR_OOM)
      << "a buffer that has failed stays failed";
  EXPECT_EQ(gtls_record_seal(&k, GTLS_CT_APPLICATION_DATA, "x", 1, 0, &out), GTLS_ERR_OOM);
  EXPECT_EQ(k.seq, 0u) << "and nothing was sealed";
  EXPECT_TRUE(all_zero(k.nonce, sizeof k.nonce));
  gtls_buf_free(&out);
}

TEST(InternalArguments, TheBufferReserveHasItsEdges) {
  GTLS_Buf b;

  gtls_buf_init(&b, nullptr, 100);
  EXPECT_EQ(gtls_buf_reserve(&b, 101), GTLS_ERR_LIMIT) << "past the cap";
  EXPECT_EQ(gtls_buf_reserve(&b, 10), GTLS_ERR_LIMIT) << "and a buffer in error stays in error";
  gtls_buf_free(&b);
  gtls_buf_init(&b, nullptr, 100);
  ASSERT_EQ(gtls_buf_reserve(&b, 50), GTLS_OK);
  EXPECT_EQ(b.cap, 50u);
  EXPECT_EQ(gtls_buf_reserve(&b, 20), GTLS_OK) << "room already";
  EXPECT_EQ(b.cap, 50u);
  gtls_buf_free(&b);
}

TEST(InternalArguments, ACapOfExtensionsAboveTheLibrarysIsClamped) {
  /* A cap above GTLS_EXT_MAX does not let the parser keep more than it has room for. */
  GTLS_Ext exts[GTLS_EXT_MAX];
  size_t count = 99;
  const unsigned char empty[2] = {0, 0};   /* an extensions block with nothing in it */
  GTLS_Reader r;
  gtls_reader_init(&r, empty, sizeof empty);
  EXPECT_EQ(gtls_msg_extensions(&r, 1000000u, exts, &count), GTLS_OK);
  EXPECT_EQ(count, 0u);
}

TEST(InternalArguments, EndOfEarlyDataBuildsIntoSomethingOrNothing) {
  EXPECT_EQ(gtls_msg_build_end_of_early_data(nullptr), GTLS_ERR_INVALID);
}

TEST(InternalArguments, TheChainCheckRefusesNothing) {
  EXPECT_EQ(gtls_verify_chain(nullptr, nullptr, nullptr, 0), GTLS_ERR_INVALID);
}

/* ------------------------------------------------------------ connections */

namespace {

/** A session a real handshake left, for the tests that need one to hand in. */
GTLS_Session * a_session() {
  std::unique_ptr<Cred> cred = ed_cred();
  Pair p(*cred);
  GTLS_TicketKey key;
  std::memset(&key, 0, sizeof key);
  for (unsigned i = 0; i < GTLS_TICKET_KEY_NAME_LEN; i++) key.name[i] = static_cast<unsigned char>(i + 1);
  for (unsigned i = 0; i < GTLS_TICKET_KEY_LEN; i++) key.key[i] = static_cast<unsigned char>(i * 3 + 1);
  key.not_before = kNow - 1000;
  key.not_after = kNow + 1000000;
  p.keys = {key};
  EXPECT_EQ(p.build(), GTLS_OK);
  p.run();
  GTLS_Session * s = nullptr;
  EXPECT_GT(gtls_conn_session_count(p.c.conn), 0u);
  EXPECT_EQ(gtls_conn_session(p.c.conn, 0, &s), GTLS_OK);
  return s;
}

struct FailingRandom {
  int calls = 0;
  int fail_on = 0;
  static GTLS_Result fn(void * user, void * out, size_t n) {
    FailingRandom * self = static_cast<FailingRandom *>(user);
    if (self->calls++ == self->fail_on) {
      return GTLS_ERR_IO;
    }
    std::memset(out, 0x42, n);
    return GTLS_OK;
  }
};

}  // namespace

TEST(ConnectionArguments, NullsAndOutOfOrderCallsAreRefused) {
  std::unique_ptr<Cred> cred = ed_cred();
  Pair p(*cred);
  ASSERT_EQ(p.build(), GTLS_OK);   /* both started */
  size_t w = 0;
  unsigned char buf[16];
  GTLS_EarlyStatus st = GTLS_EARLY_NONE;
  GTLS_SessionInfo info;
  GTLS_Session * s = nullptr;

  EXPECT_EQ(gtls_conn_start(nullptr), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_start_raw(nullptr, "x", 1, "y"), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_start_raw(p.s.conn, "x", 1, buf), GTLS_ERR_INVALID) << "a server has no ClientHello to bring";
  EXPECT_EQ(gtls_conn_start_raw(p.c.conn, "x", 1, buf), GTLS_ERR_INVALID) << "and a client already started has none";
  EXPECT_EQ(gtls_conn_write(nullptr, "x", 1, &w), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_write(p.c.conn, nullptr, 1, &w), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_read_early(nullptr, buf, sizeof buf, &w), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_early_status(nullptr, &st), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_early_resend(nullptr, buf, sizeof buf, &w), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_session_info(nullptr, &info), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_session(nullptr, 0, &s), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_session(p.c.conn, 0, nullptr), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_scratch_is_wiped(nullptr), 1);
  EXPECT_SCRATCH_WIPED(p.c.conn);
}

TEST(ConnectionArguments, AConnectionThatHasFailedAnswersFailedToEveryStart) {
  std::unique_ptr<Cred> cred = ed_cred();
  Pair p(*cred);
  ASSERT_EQ(p.build(), GTLS_OK);
  gtls_conn_free(p.c.conn);
  gtls_conn_free(p.s.conn);
  p.c.conn = nullptr;
  p.s.conn = nullptr;
  ASSERT_EQ(gtls_conn_new(p.c.ctx, p.host.data(), p.host.size(), &p.c.conn), GTLS_OK);
  ASSERT_EQ(gtls_conn_new_server(p.s.ctx, &p.s.conn), GTLS_OK);
  /* Failed before it was started: the library's own way of ending a connection. */
  gtls_conn_fail(p.c.conn, GTLS_ERR_INTERNAL, GTLS_ALERT_NONE);
  gtls_conn_fail(p.s.conn, GTLS_ERR_INTERNAL, GTLS_ALERT_NONE);
  EXPECT_EQ(gtls_conn_start(p.c.conn), GTLS_ERR_FAILED);
  EXPECT_EQ(gtls_conn_start(p.s.conn), GTLS_ERR_FAILED);
  EXPECT_EQ(gtls_stream_flush(p.c.conn), GTLS_ERR_FAILED);
  GTLS_Session * s = a_session();
  ASSERT_NE(s, nullptr);
  EXPECT_EQ(gtls_conn_set_session(p.c.conn, nullptr, 0), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_set_session(p.c.conn, s, kNow), GTLS_ERR_FAILED);
  gtls_session_free(s);
  EXPECT_TRUE(gtls_conn_secrets_are_wiped(p.c.conn));
}

TEST(ConnectionArguments, ARandomSourceThatFailsAtTheKeyFailsTheStart) {
  World w;
  w.build();
  FailingRandom r;
  r.fail_on = 1;   /* the hello's random is drawn first, then the private key */
  gtls_conn_set_hooks(w.conn, FailingRandom::fn, &r, nullptr, nullptr);
  EXPECT_EQ(gtls_conn_start(w.conn), GTLS_ERR_IO);
  EXPECT_TRUE(gtls_conn_is_failed(w.conn));
  EXPECT_TRUE(gtls_conn_secrets_are_wiped(w.conn));
}

TEST(ConnectionArguments, KeySharesRefuseWhatCannotBeOne) {
  World w;
  w.build();
  GTLS_KeyShare share;
  unsigned char out[GTLS_KX_MAX];
  size_t out_len = 0;
  unsigned char kx[97] = {4};

  EXPECT_EQ(gtls_conn_gen_share(w.conn, GTLS_GROUP_NONE, &share), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_shared_secret(w.conn, GTLS_GROUP_SECP384R1, kx, 96, out, &out_len), GTLS_ERR_PROTOCOL)
      << "a P-384 point is 97 bytes";
  kx[0] = 3;
  EXPECT_EQ(gtls_conn_shared_secret(w.conn, GTLS_GROUP_SECP384R1, kx, 97, out, &out_len), GTLS_ERR_PROTOCOL)
      << "and uncompressed";
  EXPECT_EQ(gtls_conn_shared_secret(w.conn, GTLS_GROUP_NONE, kx, 32, out, &out_len), GTLS_ERR_PROTOCOL);
}

TEST(ConnectionArguments, TheDebugAccessorsRefuseAWrongAskAndASmallBuffer) {
  World w;
  w.build();
  SimServer s(w.server_options());
  ASSERT_EQ(w.run(s), GTLS_OK);
  unsigned char b[64];
  size_t n = 0;

  EXPECT_EQ(gtls_conn_debug_secret(w.conn, static_cast<GTLS_SecretId>(99), b, sizeof b, &n), GTLS_ERR_INVALID);
  EXPECT_EQ(gtls_conn_debug_secret(w.conn, GTLS_SECRET_CLIENT_AP, b, 8, &n), GTLS_ERR_LIMIT);
  EXPECT_EQ(gtls_conn_debug_transcript(w.conn, b, 8, &n), GTLS_ERR_LIMIT);

  World started;
  started.build();
  ASSERT_EQ(gtls_conn_start(started.conn), GTLS_OK);
  EXPECT_EQ(gtls_conn_debug_transcript(started.conn, b, sizeof b, &n), GTLS_OK)
      << "before ServerHello the hash is not chosen and the SHA-256 one is given";
  EXPECT_EQ(n, 32u);
  EXPECT_EQ(gtls_conn_debug_transcript(started.conn, b, 31, &n), GTLS_ERR_LIMIT);
}

TEST(ConnectionArguments, AChainVerdictThatIsALimitIsADecodeError) {
  World w;
  w.build();
  FixedVerdict v;
  v.result = GTLS_ERR_LIMIT;
  gtls_conn_set_hooks(w.conn, nullptr, nullptr, FixedVerdict::fn, &v);
  SimServer s(w.server_options());
  EXPECT_EQ(w.run(s), GTLS_ERR_LIMIT);
  EXPECT_EQ(v.calls, 1);
  EXPECT_EQ(gtls_conn_alert(w.conn), GTLS_ALERT_DECODE_ERROR);
}

TEST(ConnectionArguments, ASessionBlobThatCannotBeAllocatedIsOom) {
  GTLS_Session * s = a_session();
  ASSERT_NE(s, nullptr);
  unsigned char blob[4096];
  size_t len = 0;
  ASSERT_EQ(gtls_session_serialize(s, blob, sizeof blob, &len), GTLS_OK);
  gtls_session_free(s);

  TestAlloc alloc;
  GTLS_Session * parsed = nullptr;
  alloc.fail_at = 0;
  EXPECT_EQ(gtls_session_parse(&alloc.a, nullptr, blob, len, &parsed), GTLS_ERR_OOM);
  EXPECT_EQ(parsed, nullptr);
  EXPECT_EQ(alloc.live, 0);
  alloc.fail_at = -1;
  ASSERT_EQ(gtls_session_parse(&alloc.a, nullptr, blob, len, &parsed), GTLS_OK);
  gtls_session_free(parsed);
  EXPECT_EQ(alloc.live, 0);
}

TEST(ConnectionArguments, AWriteStopsAtTheOutputCapAndTheCloseStillHasItsRoom) {
  std::unique_ptr<Cred> cred = ed_cred();
  Pair p(*cred);
  ASSERT_EQ(p.build(), GTLS_OK);
  p.run();
  ASSERT_TRUE(p.connected());
  /* One big write: the records that fit go out and the call says how many bytes that was. */
  const Bytes big = pattern(100000, 5);
  size_t w = 0;
  ASSERT_EQ(gtls_conn_write(p.c.conn, big.data(), big.size(), &w), GTLS_OK);
  EXPECT_GT(w, 0u);
  EXPECT_LT(w, big.size()) << "the output holds 65536 bytes of data and no more";
  /* Then one byte at a time until not even a byte fits (a one-byte record is 23). */
  size_t one = 1;
  for (int i = 0; i < 4000 && one != 0; i++) {
    one = 0;
    ASSERT_EQ(gtls_conn_write(p.c.conn, "x", 1, &one), GTLS_OK);
  }
  ASSERT_EQ(one, 0u);
  /* The buffer behind the output is larger than the cap on purpose (an alert and a
   * KeyUpdate must always fit), so a close on a full output still closes. */
  EXPECT_EQ(gtls_conn_close(p.c.conn), GTLS_OK);
  EXPECT_FALSE(gtls_conn_is_failed(p.c.conn));
  p.run();
  EXPECT_TRUE(gtls_conn_peer_closed(p.s.conn));
}

TEST(ConnectionArguments, AnEarlyWriteWithNothingToWriteToIsRefused) {
  size_t w = 0;
  EXPECT_EQ(gtls_conn_write_early(nullptr, "x", 1, &w), GTLS_ERR_INVALID);
}

/* ---------------------------------------------------------------- contexts */

TEST(ContextArguments, AContextRefusesWhatCannotBeRight) {
  std::unique_ptr<Cred> cred = ed_cred();
  {
    /* A complete server configuration with a role that is neither: without the
     * check it would be taken for a server, the identities being all it looks at. */
    Pair p(*cred);
    ASSERT_EQ(p.build(), GTLS_OK);
    GTLS_ContextConfig odd = p.scfg;
    GTLS_Context * ctx = nullptr;
    odd.role = static_cast<GTLS_Role>(99);
    EXPECT_EQ(gtls_context_new(nullptr, &odd, &ctx), GTLS_ERR_INVALID) << "a role that is neither";
    EXPECT_EQ(ctx, nullptr);
  }
  {
    Pair p(*cred);
    const GTLS_Group dup[] = {GTLS_GROUP_X25519, GTLS_GROUP_X25519};
    p.ccfg.groups = dup;
    p.ccfg.group_count = 2;
    EXPECT_EQ(p.build(), GTLS_ERR_INVALID) << "a group twice";
  }
  {
    Pair p(*cred);
    const GCERT_SigScheme dup[] = {GCERT_SIG_ED25519, GCERT_SIG_ED25519};
    p.ccfg.sig_algs = dup;
    p.ccfg.sig_alg_count = 2;
    EXPECT_EQ(p.build(), GTLS_ERR_INVALID) << "a signature scheme twice";
  }
  {
    Pair p(*cred);
    p.calpn = {nullptr};
    EXPECT_EQ(p.build(), GTLS_ERR_INVALID) << "an ALPN name that is not there";
  }
  {
    Pair p(*cred);
    p.names[0] = {nullptr};
    EXPECT_EQ(p.build(), GTLS_ERR_INVALID) << "a server name that is not there";
  }
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
