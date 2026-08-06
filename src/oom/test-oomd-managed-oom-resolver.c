/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "oomd-managed-oom-resolver.h"
#include "strv.h"
#include "tests.h"

typedef struct AuthorizationState {
        size_t calls;
        const char *deny_path;
} AuthorizationState;

static const OomdReporterAuthority user_authority = {
        .kind = OOMD_REPORTER_USER_MANAGER,
        .uid = 4711,
};

static const OomdReporterAuthority system_authority = {
        .kind = OOMD_REPORTER_SYSTEM_MANAGER,
        .uid = 0,
};

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

static int authorize_path(uid_t uid, const char *path, void *userdata) {
        AuthorizationState *state = ASSERT_PTR(userdata);

        ASSERT_EQ(uid, 4711U);
        state->calls++;

        if (state->deny_path && streq(path, state->deny_path))
                return -EPERM;

        return 0;
}

TEST(empty_user_snapshot_needs_no_authorizer) {
        _cleanup_(oomd_managed_oom_message_batch_donep) OomdManagedOOMMessageBatch messages = {};
        _cleanup_(oomd_managed_oom_policy_batch_donep) OomdManagedOOMPolicyBatch policy = {};

        ASSERT_OK(parse_text("{\"cgroups\":[]}", &messages));
        ASSERT_OK(oomd_managed_oom_policy_batch_resolve(
                          &messages, user_authority, NULL, NULL, NULL, &policy));
        ASSERT_EQ(policy.n_entries, 0U);
}

TEST(all_user_paths_are_authorized_before_output) {
        _cleanup_(oomd_managed_oom_message_batch_donep) OomdManagedOOMMessageBatch messages = {};
        _cleanup_(oomd_managed_oom_policy_batch_donep) OomdManagedOOMPolicyBatch policy = {};
        AuthorizationState state = { .deny_path = "/b.slice" };

        ASSERT_OK(parse_text(
                          "{\"cgroups\":["
                          "{\"mode\":\"kill\",\"path\":\"/a.slice\",\"property\":\"ManagedOOMSwap\"},"
                          "{\"mode\":\"kill\",\"path\":\"/b.slice\",\"property\":\"ManagedOOMSwap\"}"
                          "]}",
                          &messages));

        ASSERT_ERROR(oomd_managed_oom_policy_batch_resolve(
                             &messages, user_authority, NULL, authorize_path, &state, &policy), EPERM);
        ASSERT_EQ(state.calls, 2U);
        ASSERT_EQ(policy.n_entries, 0U);
        assert_se(!policy.entries && !policy.paths && !policy.values);
}

TEST(default_pressure_tuple_is_resolved) {
        _cleanup_(oomd_managed_oom_message_batch_donep) OomdManagedOOMMessageBatch messages = {};
        _cleanup_(oomd_managed_oom_policy_batch_donep) OomdManagedOOMPolicyBatch policy = {};
        AuthorizationState state = {};
        OomdManagedOOMDefaults defaults = {
                .pressure_limit = 6000,
                .pressure_duration_usec = 30 * USEC_PER_SEC,
        };

        ASSERT_OK(parse_text(
                          "{\"cgroups\":[{\"mode\":\"kill\",\"path\":\"/a.slice\",\"property\":\"ManagedOOMMemoryPressure\"}]}",
                          &messages));
        ASSERT_OK(oomd_managed_oom_policy_batch_resolve(
                          &messages, user_authority, &defaults, authorize_path, &state, &policy));

        ASSERT_EQ(state.calls, 1U);
        ASSERT_EQ(policy.n_entries, 1U);
        ASSERT_EQ(policy.entries[0].property, OOMD_POLICY_MEMORY_PRESSURE);
        ASSERT_STREQ(policy.entries[0].path, "/a.slice");
        ASSERT_EQ(policy.entries[0].value->pressure_limit, 6000U);
        ASSERT_EQ(policy.entries[0].value->pressure_duration_usec, 30 * USEC_PER_SEC);
}

TEST(zero_pressure_limit_default_is_usable) {
        _cleanup_(oomd_managed_oom_message_batch_donep) OomdManagedOOMMessageBatch messages = {};
        _cleanup_(oomd_managed_oom_policy_batch_donep) OomdManagedOOMPolicyBatch policy = {};
        OomdManagedOOMDefaults defaults = {
                .pressure_limit = 0,
                .pressure_duration_usec = 30 * USEC_PER_SEC,
        };

        ASSERT_OK(parse_text(
                          "{\"cgroups\":[{\"mode\":\"kill\",\"path\":\"/a.slice\",\"property\":\"ManagedOOMMemoryPressure\"}]}",
                          &messages));
        ASSERT_OK(oomd_managed_oom_policy_batch_resolve(
                          &messages, system_authority, &defaults, NULL, NULL, &policy));
        ASSERT_EQ(policy.entries[0].value->pressure_limit, 0U);
        ASSERT_EQ(policy.entries[0].value->pressure_duration_usec, 30 * USEC_PER_SEC);
}

TEST(explicit_pressure_tuple_needs_no_defaults) {
        _cleanup_(oomd_managed_oom_message_batch_donep) OomdManagedOOMMessageBatch messages = {};
        _cleanup_(oomd_managed_oom_policy_batch_donep) OomdManagedOOMPolicyBatch policy = {};

        ASSERT_OK(parse_text(
                          "{\"cgroups\":[{\"mode\":\"kill\",\"path\":\"/a.slice\",\"property\":\"ManagedOOMMemoryPressure\",\"limit\":7200,\"duration\":9000000}]}",
                          &messages));
        ASSERT_OK(oomd_managed_oom_policy_batch_resolve(
                          &messages, system_authority, NULL, NULL, NULL, &policy));

        ASSERT_EQ(policy.entries[0].value->pressure_limit, 7200U);
        ASSERT_EQ(policy.entries[0].value->pressure_duration_usec, UINT64_C(9000000));
}

TEST(missing_or_infinite_defaults_are_rejected_before_authorization) {
        _cleanup_(oomd_managed_oom_message_batch_donep) OomdManagedOOMMessageBatch messages = {};
        _cleanup_(oomd_managed_oom_policy_batch_donep) OomdManagedOOMPolicyBatch policy = {};
        AuthorizationState state = {};
        OomdManagedOOMDefaults unusable = {
                .pressure_limit = 6000,
                .pressure_duration_usec = USEC_INFINITY,
        };

        ASSERT_OK(parse_text(
                          "{\"cgroups\":[{\"mode\":\"kill\",\"path\":\"/a.slice\",\"property\":\"ManagedOOMMemoryPressure\"}]}",
                          &messages));
        ASSERT_ERROR(oomd_managed_oom_policy_batch_resolve(
                             &messages, user_authority, NULL, authorize_path, &state, &policy), EINVAL);
        ASSERT_EQ(state.calls, 0U);
        ASSERT_ERROR(oomd_managed_oom_policy_batch_resolve(
                             &messages, user_authority, &unusable, authorize_path, &state, &policy), EINVAL);
        ASSERT_EQ(state.calls, 0U);
}

TEST(auto_is_a_source_specific_withdrawal) {
        _cleanup_(oomd_managed_oom_message_batch_donep) OomdManagedOOMMessageBatch messages = {};
        _cleanup_(oomd_managed_oom_policy_batch_donep) OomdManagedOOMPolicyBatch policy = {};
        AuthorizationState state = {};

        ASSERT_OK(parse_text(
                          "{\"cgroups\":[{\"mode\":\"auto\",\"path\":\"/a.slice\",\"property\":\"ManagedOOMMemoryPressure\",\"limit\":7000,\"duration\":5000000}]}",
                          &messages));
        ASSERT_OK(oomd_managed_oom_policy_batch_resolve(
                          &messages, user_authority, NULL, authorize_path, &state, &policy));

        ASSERT_EQ(state.calls, 1U);
        ASSERT_EQ(policy.n_entries, 1U);
        ASSERT_NULL(policy.entries[0].value);
}

TEST(policy_batch_owns_paths_and_rules) {
        _cleanup_(oomd_managed_oom_message_batch_donep) OomdManagedOOMMessageBatch messages = {};
        _cleanup_(oomd_managed_oom_policy_batch_donep) OomdManagedOOMPolicyBatch policy = {};

        ASSERT_OK(parse_text(
                          "{\"cgroups\":[{\"mode\":\"kill\",\"path\":\"/a.slice\",\"property\":\"OOMRules\",\"rules\":[\"desktop\",\"batch\"]}]}",
                          &messages));
        ASSERT_OK(oomd_managed_oom_policy_batch_resolve(
                          &messages, system_authority, NULL, NULL, NULL, &policy));

        oomd_managed_oom_message_batch_done(&messages);

        ASSERT_STREQ(policy.entries[0].path, "/a.slice");
        ASSERT_EQ(strv_length(policy.entries[0].value->rules), 2U);
        ASSERT_STREQ(policy.entries[0].value->rules[0], "desktop");
        ASSERT_STREQ(policy.entries[0].value->rules[1], "batch");
}

TEST(system_authority_bypasses_user_path_authorizer) {
        _cleanup_(oomd_managed_oom_message_batch_donep) OomdManagedOOMMessageBatch messages = {};
        _cleanup_(oomd_managed_oom_policy_batch_donep) OomdManagedOOMPolicyBatch policy = {};
        AuthorizationState state = { .deny_path = "/a.slice" };

        ASSERT_OK(parse_text(
                          "{\"cgroups\":[{\"mode\":\"kill\",\"path\":\"/a.slice\",\"property\":\"ManagedOOMSwap\"}]}",
                          &messages));
        ASSERT_OK(oomd_managed_oom_policy_batch_resolve(
                          &messages, system_authority, NULL, authorize_path, &state, &policy));
        ASSERT_EQ(state.calls, 0U);
        ASSERT_EQ(policy.n_entries, 1U);
}

TEST(nonempty_user_batch_requires_authorizer) {
        _cleanup_(oomd_managed_oom_message_batch_donep) OomdManagedOOMMessageBatch messages = {};
        _cleanup_(oomd_managed_oom_policy_batch_donep) OomdManagedOOMPolicyBatch policy = {};

        ASSERT_OK(parse_text(
                          "{\"cgroups\":[{\"mode\":\"kill\",\"path\":\"/a.slice\",\"property\":\"ManagedOOMSwap\"}]}",
                          &messages));
        ASSERT_ERROR(oomd_managed_oom_policy_batch_resolve(
                             &messages, user_authority, NULL, NULL, NULL, &policy), EINVAL);
        ASSERT_EQ(policy.n_entries, 0U);
}

TEST(forged_duplicate_typed_keys_are_rejected_before_authorization) {
        _cleanup_(oomd_managed_oom_policy_batch_donep) OomdManagedOOMPolicyBatch policy = {};
        AuthorizationState state = {};
        OomdManagedOOMMessage items[] = {
                {
                        .mode = MANAGED_OOM_KILL,
                        .property = OOMD_POLICY_SWAP,
                        .path = (char*) "/a.slice",
                        .duration = USEC_INFINITY,
                },
                {
                        .mode = MANAGED_OOM_AUTO,
                        .property = OOMD_POLICY_SWAP,
                        .path = (char*) "/a.slice",
                        .duration = USEC_INFINITY,
                },
        };
        OomdManagedOOMMessageBatch messages = {
                .items = items,
                .n_items = ELEMENTSOF(items),
        };

        ASSERT_ERROR(oomd_managed_oom_policy_batch_resolve(
                             &messages, user_authority, NULL, authorize_path, &state, &policy), EEXIST);
        ASSERT_EQ(state.calls, 0U);
        ASSERT_EQ(policy.n_entries, 0U);
}

TEST(failure_releases_a_prior_valid_output_batch) {
        _cleanup_(oomd_managed_oom_message_batch_donep) OomdManagedOOMMessageBatch messages = {};
        _cleanup_(oomd_managed_oom_policy_batch_donep) OomdManagedOOMPolicyBatch policy = {};

        ASSERT_OK(parse_text(
                          "{\"cgroups\":[{\"mode\":\"kill\",\"path\":\"/a.slice\",\"property\":\"ManagedOOMSwap\"}]}",
                          &messages));
        ASSERT_OK(oomd_managed_oom_policy_batch_resolve(
                          &messages, system_authority, NULL, NULL, NULL, &policy));
        ASSERT_EQ(policy.n_entries, 1U);
        assert_se(policy.entries && policy.paths && policy.values);

        ASSERT_ERROR(oomd_managed_oom_policy_batch_resolve(
                             &messages, user_authority, NULL, NULL, NULL, &policy), EINVAL);
        ASSERT_EQ(policy.n_entries, 0U);
        assert_se(!policy.entries && !policy.paths && !policy.values);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
