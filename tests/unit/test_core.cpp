/**
 * @file
 *
 * Results, limits, version and allocator: the contract files every library
 * in the suite has (CONVENTIONS.md section 5).
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/tls/libver.h>

#include <set>
#include <string>

/* GTLS_RESULT_COUNT closes the enum so a test can check the string table is
 * complete. A new result without a string falls through to "Unknown error". */
TEST(Result, EveryCodeHasItsOwnString) {
  std::set<std::string> seen;
  for (int i = 0; i < GTLS_RESULT_COUNT; i++) {
    const char * s = gtls_result_string(static_cast<GTLS_Result>(i));
    ASSERT_NE(s, nullptr);
    EXPECT_STRNE(s, "Unknown error") << "result " << i;
    EXPECT_TRUE(seen.insert(s).second) << "result " << i << " shares a string";
  }
}

TEST(Result, OutOfRangeIsUnknownNotUndefined) {
  EXPECT_STREQ(gtls_result_string(GTLS_RESULT_COUNT), "Unknown error");
  EXPECT_STREQ(gtls_result_string(static_cast<GTLS_Result>(-1)), "Unknown error");
}

TEST(Result, ZeroIsSuccess) {
  EXPECT_EQ(GTLS_OK, 0);
  EXPECT_STREQ(gtls_result_string(GTLS_OK), "No error");
}

/* The suite's vocabulary is the first nine, in this order, and the library's
 * own refusals come after: the numbers are part of what a caller may log. */
TEST(Result, SuiteVocabularyComesFirstInTheSuitesOrder) {
  EXPECT_EQ(GTLS_ERR_IO, 1);
  EXPECT_EQ(GTLS_ERR_FORMAT, 2);
  EXPECT_EQ(GTLS_ERR_UNSUPPORTED, 3);
  EXPECT_EQ(GTLS_ERR_LIMIT, 4);
  EXPECT_EQ(GTLS_ERR_CORRUPT, 5);
  EXPECT_EQ(GTLS_ERR_OOM, 6);
  EXPECT_EQ(GTLS_ERR_INVALID, 7);
  EXPECT_EQ(GTLS_ERR_INTERNAL, 8);
  EXPECT_EQ(GTLS_ERR_MISMATCH, 9);
}

TEST(Limits, DefaultsAreEveryFieldNonzero) {
  GTLS_Limits limits;
  std::memset(&limits, 0, sizeof limits);
  gtls_limits_default(&limits);
  const uint32_t * f = reinterpret_cast<const uint32_t *>(&limits);
  for (size_t i = 0; i < sizeof limits / sizeof *f; i++) {
    EXPECT_NE(f[i], 0u) << "field " << i;
  }
  EXPECT_EQ(limits.max_handshake_message, GTLS_HANDSHAKE_MESSAGE_DEFAULT);
}

TEST(Limits, NullDefaultIsIgnored) {
  gtls_limits_default(nullptr);
}

TEST(Limits, ZeroFieldsResolveToTheDefaultAndSetOnesStay) {
  GTLS_Limits in;
  GTLS_Limits out;
  GTLS_Limits defaults;
  std::memset(&in, 0, sizeof in);
  in.max_certificates = 3;
  gtls_limits_default(&defaults);
  gtls_limits_resolve(&in, &out);
  EXPECT_EQ(out.max_certificates, 3u);
  EXPECT_EQ(out.max_extensions, defaults.max_extensions);
  gtls_limits_resolve(nullptr, &out);
  EXPECT_EQ(out.max_certificates, defaults.max_certificates);
}

TEST(Version, StringMatchesTheGeneratedHeader) {
  EXPECT_STREQ(gtls_version_string(), GTLS_VERSION_STRING);
  EXPECT_EQ(gtls_version_number(), GTLS_VERSION_NUMBER);
  EXPECT_EQ(GTLS_VERSION_NUMBER,
      GTLS_MAKE_VERSION(GTLS_VERSION_MAJOR, GTLS_VERSION_MINOR,
          GTLS_VERSION_PATCH));
}

TEST(Allocator, DefaultIsCutils) {
  const GTLS_Allocator * allocator = gtls_allocator_default();
  ASSERT_NE(allocator, nullptr);
  EXPECT_EQ(allocator, gcu_allocator_default());
}

TEST(SecurityResult, SameMembersAsSecurityInTheSameOrder) {
  for (int i = 0; i < GSEC_RESULT_COUNT; i++) {
    EXPECT_EQ(static_cast<int>(gtls_from_gsec(static_cast<GSEC_Result>(i))), i)
        << "result " << i;
    EXPECT_STREQ(gtls_result_string(gtls_from_gsec(static_cast<GSEC_Result>(i))),
        i == GSEC_OK ? "No error" : gtls_result_string(static_cast<GTLS_Result>(i)));
  }
}

TEST(SecurityResult, AValueInNeitherEnumIsNotSuccess) {
  EXPECT_EQ(gtls_from_gsec(GSEC_RESULT_COUNT), GTLS_ERR_INTERNAL);
  EXPECT_EQ(gtls_from_gsec(static_cast<GSEC_Result>(-1)), GTLS_ERR_INTERNAL);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
