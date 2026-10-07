/**
 * @file
 *
 * Allocation failure at every allocation, and what is left behind.
 *
 * The allocator counts, and fails the Nth call. A whole handshake (with and
 * without a HelloRetryRequest) runs once per N, from the context's first
 * allocation to its last. At every N the result is out-of-memory and the
 * connection is failed, or the run finished because N was past the end;
 * and at every N, once everything is freed, no block is live.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "loop.h"

using namespace gtlstest;

namespace {

/** Run one whole handshake with the Nth allocation failing. Returns whether N was reached. */
bool run_with_failure_at(long n, bool hrr, bool alpn, TestAlloc & alloc, GTLS_Result * result) {
  alloc.count = 0;
  alloc.fail_at = n;
  World w;
  w.allocator = &alloc.a;
  if (alpn) {
    w.alpn = {"h2"};
  }
  /* World::build asserts on failure, and here failure is the point. */
  w.cfg.trust = w.trust->store;
  w.cfg.limits = &w.limits;
  if (alpn) {
    w.cfg.alpn = w.alpn.data();
    w.cfg.alpn_count = w.alpn.size();
  }
  GTLS_Result r = gtls_context_new(&alloc.a, &w.cfg, &w.ctx);
  if (r != GTLS_OK) {
    *result = r;
    EXPECT_EQ(w.ctx, nullptr) << "a failed context_new returns nothing to free";
    return true;
  }
  r = gtls_conn_new(w.ctx, w.host.data(), w.host.size(), &w.conn);
  if (r != GTLS_OK) {
    *result = r;
    EXPECT_EQ(w.conn, nullptr);
    return true;
  }
  SimOptions o = w.server_options();
  o.hrr = hrr;
  if (alpn) {
    o.alpn = Bytes{'h', '2'};
  }
  SimServer s(o);
  r = w.run(s);
  *result = r;
  if (r != GTLS_OK) {
    EXPECT_TRUE(gtls_conn_is_failed(w.conn));
    EXPECT_TRUE(gtls_conn_secrets_are_wiped(w.conn)) << "failure at allocation " << n;
  }
  return r != GTLS_OK || alloc.count > n;
}

}  // namespace

class AllocationSweep : public ::testing::TestWithParam<std::tuple<bool, bool>> {};

TEST_P(AllocationSweep, FailingEachAllocationLeaksNothingAndReportsOom) {
  const bool hrr = std::get<0>(GetParam());
  const bool alpn = std::get<1>(GetParam());
  /* The number of allocations on the clean run. */
  TestAlloc probe;
  GTLS_Result r = GTLS_ERR_INTERNAL;
  run_with_failure_at(-1, hrr, alpn, probe, &r);
  ASSERT_EQ(r, GTLS_OK);
  const long total = probe.count;
  EXPECT_EQ(probe.live, 0) << "even the clean run frees everything";
  ASSERT_GT(total, 5);
  ASSERT_LT(total, 200);

  long reached = 0;
  for (long n = 0; n < total; n++) {
    TestAlloc alloc;
    bool hit = run_with_failure_at(n, hrr, alpn, alloc, &r);
    EXPECT_TRUE(hit) << n;
    EXPECT_EQ(r, GTLS_ERR_OOM) << "allocation " << n << " of " << total
                               << " failed and the result was " << gtls_result_string(r);
    EXPECT_EQ(alloc.live, 0) << "allocation " << n << " leaked";
    reached++;
  }
  EXPECT_EQ(reached, total);
  /* One past the end: nothing fails, and it completes. */
  TestAlloc alloc;
  run_with_failure_at(total, hrr, alpn, alloc, &r);
  EXPECT_EQ(r, GTLS_OK);
  EXPECT_EQ(alloc.live, 0);
}

INSTANTIATE_TEST_SUITE_P(Flows, AllocationSweep,
    ::testing::Combine(::testing::Bool(), ::testing::Bool()),
    [](const ::testing::TestParamInfo<std::tuple<bool, bool>> & info) {
      return std::string(std::get<0>(info.param) ? "Retry" : "Plain") +
          (std::get<1>(info.param) ? "Alpn" : "NoAlpn");
    });

/* The same, for the server role, the record layer and everything the stream
 * interface allocates: both contexts (one with identities), both
 * connections, the handshake, data both ways, a key update, and a close. */

namespace {

struct StreamRun {
  GTLS_Result create = GTLS_OK;   /* what a creation call returned, if one failed */
  bool both_connected = false;
  bool any_oom = false;           /* a connection failed for lack of memory */
  bool clean = false;             /* everything that was asked for happened */
};

StreamRun stream_with_failure_at(long n, TestAlloc & alloc, Cred & cred, bool retry) {
  StreamRun out;
  alloc.count = 0;
  alloc.fail_at = n;
  Pair p(cred);
  p.allocator = &alloc.a;
  p.calpn = {"h2"};
  p.salpn = {"h2", "http/1.1"};
  GTLS_Group want = GTLS_GROUP_SECP256R1;
  if (retry) {
    p.scfg.groups = &want;
    p.scfg.group_count = 1;
  }
  out.create = p.build();
  if (out.create != GTLS_OK) {
    return out;
  }
  p.run();
  out.both_connected = p.connected();
  size_t w = 0;
  if (out.both_connected) {
    Bytes data = pattern(40000, 3);
    GTLS_Result r1 = gtls_conn_write(p.c.conn, data.data(), data.size(), &w);
    p.run();
    GTLS_Result r2 = gtls_conn_write(p.s.conn, data.data(), 500, &w);
    GTLS_Result r3 = gtls_conn_key_update(p.s.conn, 1);
    p.run();
    GTLS_Result r4 = gtls_conn_close(p.c.conn);
    p.run();
    out.clean = r1 == GTLS_OK && r2 == GTLS_OK && r3 == GTLS_OK && r4 == GTLS_OK &&
        p.s.got.size() == data.size() && p.c.got.size() == 500 && gtls_conn_peer_closed(p.s.conn);
  }
  for (GTLS_Conn * c : {p.c.conn, p.s.conn}) {
    if (gtls_conn_is_failed(c)) {
      out.any_oom |= gtls_conn_failure(c) == GTLS_ERR_OOM;
      EXPECT_TRUE(gtls_conn_secrets_are_wiped(c)) << "failure at allocation " << n;
    }
  }
  return out;
}

}  // namespace

class StreamAllocationSweep : public ::testing::TestWithParam<bool> {};

TEST_P(StreamAllocationSweep, FailingEachAllocationLeaksNothingAndIsNeverSilent) {
  const bool retry = GetParam();
  std::unique_ptr<Cred> cred = ed_cred();
  TestAlloc probe;
  StreamRun clean = stream_with_failure_at(-1, probe, *cred, retry);
  ASSERT_EQ(clean.create, GTLS_OK);
  ASSERT_TRUE(clean.clean);
  EXPECT_EQ(probe.live, 0) << "the clean run frees everything";
  const long total = probe.count;
  ASSERT_GT(total, 20);
  ASSERT_LT(total, 600);
  for (long n = 0; n < total; n++) {
    TestAlloc alloc;
    StreamRun r = stream_with_failure_at(n, alloc, *cred, retry);
    EXPECT_EQ(alloc.live, 0) << "allocation " << n << " of " << total << " leaked";
    /* Either a call said out-of-memory, or a connection failed for it. The
     * one way to be silent is to have run clean over a failed allocation. */
    EXPECT_FALSE(r.clean) << "allocation " << n << " failed and nothing noticed";
    if (r.create != GTLS_OK) {
      EXPECT_EQ(r.create, GTLS_ERR_OOM) << n;
    } else {
      /* A connection said out-of-memory: not internal error, not a protocol
       * failure, not a handshake that went on without a block it asked for. */
      EXPECT_TRUE(r.any_oom) << "allocation " << n << " failed and no connection reported out-of-memory";
    }
  }
  TestAlloc past;
  StreamRun after = stream_with_failure_at(total, past, *cred, retry);
  EXPECT_TRUE(after.clean);
  EXPECT_EQ(past.live, 0);
}

INSTANTIATE_TEST_SUITE_P(Flows, StreamAllocationSweep, ::testing::Bool(),
    [](const ::testing::TestParamInfo<bool> & info) { return info.param ? "Retry" : "Plain"; });

TEST(StreamAllocationSweepControl, AServerContextThatFailsPartwayLeavesNothing) {
  std::unique_ptr<Cred> a = ed_cred("a.test");
  std::unique_ptr<Cred> b = ed_cred("b.test");
  TestAlloc probe;
  Pair probe_pair(std::vector<Cred *>{a.get(), b.get()});
  probe_pair.allocator = &probe.a;
  ASSERT_EQ(probe_pair.build(), GTLS_OK);
  const long total = probe.count;
  for (long n = 0; n < total; n++) {
    TestAlloc alloc;
    {
      Pair p(std::vector<Cred *>{a.get(), b.get()});
      p.allocator = &alloc.a;
      alloc.fail_at = n;
      GTLS_Result r = p.build();
      EXPECT_EQ(r, GTLS_ERR_OOM) << n;
    }
    EXPECT_EQ(alloc.live, 0) << "allocation " << n << " of " << total;
  }
}

/* The sweep above counts allocations through the context's allocator. A
 * control for the sweep itself: an allocator that fails and a leak that the
 * counter would notice. */
TEST(AllocationSweepControl, TheAllocatorSeesALeakAndAFailure) {
  TestAlloc a;
  void * p = a.a.malloc_fn(a.a.ctx, 10);
  ASSERT_NE(p, nullptr);
  EXPECT_EQ(a.live, 1) << "a block not freed is visible";
  a.a.free_fn(a.a.ctx, p);
  EXPECT_EQ(a.live, 0);
  a.count = 0;
  a.fail_at = 1;
  EXPECT_NE(a.a.malloc_fn(a.a.ctx, 1), nullptr);
  EXPECT_EQ(a.a.malloc_fn(a.a.ctx, 1), nullptr) << "the second one fails";
  a.fail_at = -1;
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
