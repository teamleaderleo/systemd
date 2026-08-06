/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "oomd-managed-oom-message.h"
#include "strv.h"
#include "tests.h"

static int parse_text(const char *text, OomdManagedOOMMessageBatch *ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
        int r;

        assert(text);
        assert(ret);

        r = sd_json_parse(text, SD_JSON_PARSE_MUST_BE_OBJECT, &parameters, NULL, NULL);
        if (r < 0)
                return r;

        return oomd_managed_oom_message_batch_parse(parameters, ret);
}

static void assert_parse_error(const char *text, int expected) {
        _cleanup_(oomd_managed_oom_message_batch_donep) OomdManagedOOMMessageBatch batch = {};

        ASSERT_ERROR(parse_text(text, &batch), expected);
        ASSERT_EQ(batch.n_items, 0U);
}

TEST(empty_report_is_a_valid_owned_batch) {
        _cleanup_(oomd_managed_oom_message_batch_donep) OomdManagedOOMMessageBatch batch = {};

        ASSERT_OK(parse_text("{\"cgroups\":[]}", &batch));
        ASSERT_EQ(batch.n_items, 0U);
}

TEST(valid_report_is_typed_and_independent_of_json_storage) {
        _cleanup_(oomd_managed_oom_message_batch_donep) OomdManagedOOMMessageBatch batch = {};

        ASSERT_OK(parse_text(
                          "{\"cgroups\":["
                          "{\"mode\":\"kill\",\"path\":\"/user.slice/user-4711.slice\",\"property\":\"ManagedOOMMemoryPressure\",\"limit\":7000,\"duration\":5000000},"
                          "{\"mode\":\"kill\",\"path\":\"/user.slice/user-4711.slice\",\"property\":\"ManagedOOMSwap\"},"
                          "{\"mode\":\"kill\",\"path\":\"/user.slice/user-4711.slice\",\"property\":\"OOMRules\",\"rules\":[\"desktop\",\"batch\"]}"
                          "]}",
                          &batch));

        ASSERT_EQ(batch.n_items, 3U);
        ASSERT_EQ(batch.items[0].mode, MANAGED_OOM_KILL);
        ASSERT_EQ(batch.items[0].property, OOMD_POLICY_MEMORY_PRESSURE);
        ASSERT_STREQ(batch.items[0].path, "/user.slice/user-4711.slice");
        ASSERT_EQ(batch.items[0].limit, 7000U);
        ASSERT_EQ(batch.items[0].duration, UINT64_C(5000000));

        ASSERT_EQ(batch.items[1].property, OOMD_POLICY_SWAP);
        ASSERT_EQ(batch.items[1].limit, 0U);
        ASSERT_EQ(batch.items[1].duration, USEC_INFINITY);

        ASSERT_EQ(batch.items[2].property, OOMD_POLICY_RULES);
        ASSERT_EQ(strv_length(batch.items[2].rules), 2U);
        ASSERT_STREQ(batch.items[2].rules[0], "desktop");
        ASSERT_STREQ(batch.items[2].rules[1], "batch");
}

TEST(empty_path_is_canonical_root) {
        _cleanup_(oomd_managed_oom_message_batch_donep) OomdManagedOOMMessageBatch batch = {};

        ASSERT_OK(parse_text(
                          "{\"cgroups\":[{\"mode\":\"kill\",\"path\":\"\",\"property\":\"ManagedOOMSwap\"}]}",
                          &batch));
        ASSERT_EQ(batch.n_items, 1U);
        ASSERT_STREQ(batch.items[0].path, "/");
}

TEST(root_aliases_are_duplicate_policy_keys) {
        assert_parse_error(
                        "{\"cgroups\":["
                        "{\"mode\":\"kill\",\"path\":\"\",\"property\":\"ManagedOOMSwap\"},"
                        "{\"mode\":\"auto\",\"path\":\"/\",\"property\":\"ManagedOOMSwap\"}"
                        "]}",
                        EEXIST);
}

TEST(malformed_later_element_rejects_the_whole_batch) {
        assert_parse_error(
                        "{\"cgroups\":["
                        "{\"mode\":\"kill\",\"path\":\"/a.slice\",\"property\":\"ManagedOOMSwap\"},"
                        "{\"mode\":\"kill\",\"path\":\"/b.slice\",\"property\":\"ManagedOOMMemoryPressure\",\"limit\":\"bad\"}"
                        "]}",
                        EINVAL);
}

TEST(non_object_element_is_fatal_for_the_message) {
        assert_parse_error(
                        "{\"cgroups\":[{\"mode\":\"kill\",\"path\":\"/a.slice\",\"property\":\"ManagedOOMSwap\"},null]}",
                        EINVAL);
}

TEST(unknown_property_is_fatal_for_the_message) {
        assert_parse_error(
                        "{\"cgroups\":[{\"mode\":\"kill\",\"path\":\"/a.slice\",\"property\":\"ManagedOOMFuture\"}]}",
                        EINVAL);
}

TEST(unknown_fields_are_not_silently_accepted) {
        assert_parse_error(
                        "{\"cgroups\":[],\"future\":true}",
                        EINVAL);
        assert_parse_error(
                        "{\"cgroups\":[{\"mode\":\"kill\",\"path\":\"/a.slice\",\"property\":\"ManagedOOMSwap\",\"future\":true}]}",
                        EINVAL);
}

TEST(non_normalized_or_relative_paths_are_rejected) {
        assert_parse_error(
                        "{\"cgroups\":[{\"mode\":\"kill\",\"path\":\"/a.slice/../b.slice\",\"property\":\"ManagedOOMSwap\"}]}",
                        EINVAL);
        assert_parse_error(
                        "{\"cgroups\":[{\"mode\":\"kill\",\"path\":\"a.slice\",\"property\":\"ManagedOOMSwap\"}]}",
                        EINVAL);
}

TEST(duplicate_property_path_keys_are_rejected) {
        assert_parse_error(
                        "{\"cgroups\":["
                        "{\"mode\":\"kill\",\"path\":\"/a.slice\",\"property\":\"ManagedOOMMemoryPressure\",\"limit\":7000},"
                        "{\"mode\":\"auto\",\"path\":\"/a.slice\",\"property\":\"ManagedOOMMemoryPressure\"}"
                        "]}",
                        EEXIST);
}

TEST(rules_require_consistent_mode_and_property) {
        assert_parse_error(
                        "{\"cgroups\":[{\"mode\":\"kill\",\"path\":\"/a.slice\",\"property\":\"OOMRules\"}]}",
                        EINVAL);
        assert_parse_error(
                        "{\"cgroups\":[{\"mode\":\"auto\",\"path\":\"/a.slice\",\"property\":\"OOMRules\",\"rules\":[\"desktop\"]}]}",
                        EINVAL);
        assert_parse_error(
                        "{\"cgroups\":[{\"mode\":\"kill\",\"path\":\"/a.slice\",\"property\":\"ManagedOOMSwap\",\"rules\":[\"desktop\"]}]}",
                        EINVAL);
}

TEST(missing_or_wrong_cgroups_field_is_rejected) {
        assert_parse_error("{}", EINVAL);
        assert_parse_error("{\"cgroups\":{}}", EINVAL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
