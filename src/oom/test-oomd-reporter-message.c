/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "oomd-reporter-adapter.h"
#include "oomd-reporter-message.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

#define TEST_PATH "/user.slice/user-4711.slice/user@4711.service"

static const OomdReporterAuthority user_authority = {
        .kind = OOMD_REPORTER_USER_MANAGER,
        .uid = 4711,
};

static void parse_parameters(const char *text, sd_json_variant **ret) {
        assert(text);
        assert(ret);

        ASSERT_OK(sd_json_parse(text, SD_JSON_PARSE_MUST_BE_OBJECT, ret, NULL, NULL));
}

TEST(empty_report_is_an_explicit_empty_snapshot) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
        _cleanup_(oomd_reporter_message_freep) OomdReporterMessage *message = NULL;

        parse_parameters("{\"cgroups\":[]}", &parameters);
        ASSERT_OK(oomd_reporter_message_parse(parameters, &message));
        ASSERT_EQ(oomd_reporter_message_size(message), 0U);
        assert_se(!oomd_reporter_message_entries(message));
}

TEST(valid_message_is_owned_and_normalized) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
        _cleanup_(oomd_reporter_message_freep) OomdReporterMessage *message = NULL;
        const OomdPolicySnapshotEntry *entries;

        parse_parameters(
                        "{\"cgroups\":["
                        "{\"mode\":\"kill\",\"path\":\"\",\"property\":\"ManagedOOMMemoryPressure\",\"limit\":5000,\"duration\":2000000},"
                        "{\"mode\":\"auto\",\"path\":\"/swap.slice\",\"property\":\"ManagedOOMSwap\"},"
                        "{\"mode\":\"kill\",\"path\":\"/rules.slice\",\"property\":\"OOMRules\",\"rules\":[\"desktop\",\"desktop\",\"batch\"]}"
                        "]}",
                        &parameters);

        ASSERT_OK(oomd_reporter_message_parse(parameters, &message));
        ASSERT_EQ(oomd_reporter_message_size(message), 3U);

        entries = oomd_reporter_message_entries(message);
        assert_se(entries);

        ASSERT_EQ(entries[0].property, OOMD_POLICY_MEMORY_PRESSURE);
        assert_se(streq(entries[0].path, "/"));
        assert_se(entries[0].value);
        ASSERT_EQ(entries[0].value->pressure_limit, 5000U);
        ASSERT_EQ(entries[0].value->pressure_duration_usec, 2000000U);

        ASSERT_EQ(entries[1].property, OOMD_POLICY_SWAP);
        assert_se(streq(entries[1].path, "/swap.slice"));
        assert_se(!entries[1].value);

        ASSERT_EQ(entries[2].property, OOMD_POLICY_RULES);
        assert_se(entries[2].value);
        ASSERT_EQ(strv_length(entries[2].value->rules), 2U);
        assert_se(streq(entries[2].value->rules[0], "desktop"));
        assert_se(streq(entries[2].value->rules[1], "batch"));
}

TEST(auto_with_configured_pressure_fields_is_a_withdrawal) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
        _cleanup_(oomd_reporter_message_freep) OomdReporterMessage *message = NULL;
        const OomdPolicySnapshotEntry *entries;

        parse_parameters(
                        "{\"cgroups\":[{"
                        "\"mode\":\"auto\","
                        "\"path\":\"/x\","
                        "\"property\":\"ManagedOOMMemoryPressure\","
                        "\"limit\":5000,"
                        "\"duration\":2000000"
                        "}]}",
                        &parameters);

        ASSERT_OK(oomd_reporter_message_parse(parameters, &message));
        ASSERT_EQ(oomd_reporter_message_size(message), 1U);
        entries = oomd_reporter_message_entries(message);
        assert_se(entries);
        ASSERT_EQ(entries[0].property, OOMD_POLICY_MEMORY_PRESSURE);
        assert_se(streq(entries[0].path, "/x"));
        assert_se(!entries[0].value);
}

TEST(malformed_later_element_rejects_the_complete_message) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
        _cleanup_(oomd_reporter_message_freep) OomdReporterMessage *message = NULL;

        parse_parameters(
                        "{\"cgroups\":["
                        "{\"mode\":\"kill\",\"path\":\"/valid.slice\",\"property\":\"ManagedOOMSwap\"},"
                        "{\"mode\":\"kill\",\"path\":\"/missing-property.slice\"}"
                        "]}",
                        &parameters);

        ASSERT_LT(oomd_reporter_message_parse(parameters, &message), 0);
        assert_se(!message);
}

TEST(non_object_element_is_rejected) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
        _cleanup_(oomd_reporter_message_freep) OomdReporterMessage *message = NULL;

        parse_parameters("{\"cgroups\":[42]}", &parameters);
        ASSERT_ERROR(oomd_reporter_message_parse(parameters, &message), EINVAL);
        assert_se(!message);
}

TEST(unknown_or_incompatible_fields_are_rejected) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *unknown_property = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *unknown_field = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *swap_payload = NULL;
        _cleanup_(oomd_reporter_message_freep) OomdReporterMessage *message = NULL;

        parse_parameters(
                        "{\"cgroups\":[{\"mode\":\"kill\",\"path\":\"/x\",\"property\":\"Unknown\"}]}",
                        &unknown_property);
        ASSERT_ERROR(oomd_reporter_message_parse(unknown_property, &message), EINVAL);
        assert_se(!message);

        parse_parameters(
                        "{\"cgroups\":[{\"mode\":\"kill\",\"path\":\"/x\",\"property\":\"ManagedOOMSwap\",\"extra\":true}]}",
                        &unknown_field);
        ASSERT_LT(oomd_reporter_message_parse(unknown_field, &message), 0);
        assert_se(!message);

        parse_parameters(
                        "{\"cgroups\":[{\"mode\":\"kill\",\"path\":\"/x\",\"property\":\"ManagedOOMSwap\",\"limit\":1}]}",
                        &swap_payload);
        ASSERT_ERROR(oomd_reporter_message_parse(swap_payload, &message), EINVAL);
        assert_se(!message);
}

TEST(parse_failure_clears_the_output_pointer) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
        _cleanup_(oomd_reporter_message_freep) OomdReporterMessage *message = (OomdReporterMessage*) UINT_TO_PTR(1);

        parse_parameters("{\"cgroups\":[42]}", &parameters);
        ASSERT_ERROR(oomd_reporter_message_parse(parameters, &message), EINVAL);
        assert_se(!message);
}

TEST(duplicate_property_path_keys_are_rejected) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
        _cleanup_(oomd_reporter_message_freep) OomdReporterMessage *message = NULL;

        parse_parameters(
                        "{\"cgroups\":["
                        "{\"mode\":\"kill\",\"path\":\"\",\"property\":\"ManagedOOMSwap\"},"
                        "{\"mode\":\"auto\",\"path\":\"/\",\"property\":\"ManagedOOMSwap\"}"
                        "]}",
                        &parameters);

        ASSERT_ERROR(oomd_reporter_message_parse(parameters, &message), EEXIST);
        assert_se(!message);
}

TEST(non_normalized_or_relative_paths_are_rejected) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *non_normalized = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *relative = NULL;
        _cleanup_(oomd_reporter_message_freep) OomdReporterMessage *message = NULL;

        parse_parameters(
                        "{\"cgroups\":[{\"mode\":\"kill\",\"path\":\"/a/../b\",\"property\":\"ManagedOOMSwap\"}]}",
                        &non_normalized);
        ASSERT_ERROR(oomd_reporter_message_parse(non_normalized, &message), EINVAL);
        assert_se(!message);

        parse_parameters(
                        "{\"cgroups\":[{\"mode\":\"kill\",\"path\":\"relative\",\"property\":\"ManagedOOMSwap\"}]}",
                        &relative);
        ASSERT_ERROR(oomd_reporter_message_parse(relative, &message), EINVAL);
        assert_se(!message);
}

TEST(parsed_snapshot_commits_through_the_adapter_once) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
        _cleanup_(oomd_reporter_message_freep) OomdReporterMessage *message = NULL;
        _cleanup_(oomd_reporter_adapter_freep) OomdReporterAdapter *adapter = NULL;
        _cleanup_(oomd_policy_decision_donep) OomdPolicyDecision decision = {};
        OomdReporterAdapterEvent event;
        OomdReporterSession session;

        parse_parameters(
                        "{\"cgroups\":[{\"mode\":\"kill\",\"path\":\"" TEST_PATH "\",\"property\":\"ManagedOOMMemoryPressure\",\"limit\":6500}]}",
                        &parameters);
        ASSERT_OK(oomd_reporter_message_parse(parameters, &message));

        ASSERT_OK(oomd_reporter_adapter_new(&adapter));
        ASSERT_OK(oomd_reporter_adapter_connect(adapter, 1, user_authority, &session, &event));
        ASSERT_OK(oomd_reporter_adapter_first_snapshot(
                          adapter,
                          1,
                          oomd_reporter_message_entries(message),
                          oomd_reporter_message_size(message),
                          &event));

        ASSERT_EQ(oomd_reporter_adapter_get_effective(
                          adapter,
                          OOMD_POLICY_MEMORY_PRESSURE,
                          TEST_PATH,
                          &decision), 1);
        ASSERT_EQ(decision.value.pressure_limit, 6500U);
        ASSERT_GT(session.generation, 0U);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
