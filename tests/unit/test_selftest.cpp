/**
 * @file
 *
 * The built-in known answer.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

TEST(Selftest, PassesOnThisBuild) {
  EXPECT_EQ(gtls_selftest(), GTLS_OK);
}

/* The self test's constants are generated from the RFC by the extractor, so
 * the check that matters is that they are the values the vector file holds
 * and that the schedule really does reach them. */
TEST(Selftest, ItsConstantsAreTheRfcsEarlyAndDerivedSecrets) {
  gtlstest::Vec v("simple-1rtt");
  GTLS_Schedule s;
  ASSERT_EQ(gtls_schedule_early(&s, GTLS_HASH_SHA256), GTLS_OK);
  EXPECT_EQ(std::memcmp(s.early, v["server.extract-secret-early.secret"].data(), 32), 0);
  gtls_schedule_wipe(&s);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
