/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "oomd-managed-oom-resolver.h"
#include "oomd-reporter-adapter.h"
#include "string-util.h"
#include "tests.h"

#define DEFAULT_PATH "/user.slice/user-4711.slice/default.scope"
#define EXPLICIT_PATH "/user.slice/user-4711.slice/explicit.scope"
#define SWAP_PATH "/user.slice/user-4711.slice/swap.scope"
#define RULES_PATH "/user.slice/user-4711.slice/rules.scope"
#define WITHDRAW_PATH "/user.slice/user-4711.slice/withdraw.scope"
#define FOREIGN_PATH "/user.slice/user-9999.slice/foreign.scope"
#define ERROR_PATH "/user.slice/user-4711.slice/gone.scope"

static const OomdReporterAuthority user_authority = {
        .kind = OOMD_REPORTER_USER_MANAGER,
        .uid = 4711,
};

static const OomdReporterAuthority system_authority = {
        .kind = OOMD_REPORTER_SYSTEM_MANAGER,
        .uid = 0,
};

static const OomdManagedOOMDefaults defaults = {
        .memory_pressure_limit_permyriad = 6000,
        .memory_pressure_duration_usec = 30 * USEC_PER_SEC,
};

typedef struct OwnerFixture {
        uid_t owner;
        const char *foreign_path;
        const char *error_path;
        unsigned calls;
} OwnerFixture;

static int owner_lookup(const char *path, uid_t *ret_owner, void *userdata) {
        OwnerFixture *fixture = ASSERT_PTR(userdata);

        assert(path);
        assert(ret_owner);

        fixture->calls++;
        if (fixture->error_path && streq(path, fixture->error_path))
                return -ENOENT;

        *ret_owner = fixture->foreign_path && streq(path, fixture->foreign_path) ? 9999 : fixture->owner;
        return 0;
}

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

TEST(user_resolution_authorizes_all_and_resolves_defaults) {
        _cleanup_(oomd_managed_oom_message_batch_donep) OomdManagedOOMMessageBatch message = {};
        _cleanup_(oomd_managed_oom_policy_batch_freep) OomdManagedOOMPolicyBatch *policy = NULL;
        OwnerFixture fixture = { .owner = 4711 };
        const OomdPolicySnapshotEntry *entries;

        ASSERT_OK(parse_text(
                          "{\"cgroups\":["
                          "{\"mode\":\"kill\",\"path\":\"" DEFAULT_PATH "\",\"property\":\"ManagedOOMMemoryPressure\"},"
                          "{\"mode\":\"kill\",\"path\":\"" EXPLICIT_PATH "\",\"property\":\"ManagedOOMMemoryPressure\",\"limit\":4294967295,\"duration\":5000000},"
                          "{\"mode\":\"kill\",\"path\":\"" SWAP_PATH "\",\"property\":\"ManagedOOMSwap\"},"
                          "{\"mode\":\"kill\",\"path\":\"" RULES_PATH "\",\"property\":\"OOMRules\",\"rules\":[\"desktop\",\"batch\"]},"
                          "{\"mode\":\"auto\",\"path\":\"" WITHDRAW_PATH "\",\"property\":\"ManagedOOMSwap\"}"
                          "]}",
                          &message));

        ASSERT_OK(oomd_managed_oom_policy_batch_resolve(
                          &message,
                          user_authority,
                          &defaults,
                          owner_lookup,
                          &fixture,
                          &policy));
        ASSERT_EQ(fixture.calls, 5U);
        ASSERT_EQ(oomd_managed_oom_policy_batch_size(policy), 5U);

        entries = oomd_managed_oom_policy_batch_entries(policy);
        assert_se(entries);

        ASSERT_EQ(entries[0].property, OOMD_POLICY_MEMORY_PRESSURE);
        ASSERT_EQ(entries[0].value->pressure_limit, 6000U);
        ASSERT_EQ(entries[0].value->pressure_duration_usec, 30 * USEC_PER_SEC);

        ASSERT_EQ(entries[1].property, OOMD_POLICY_MEMORY_PRESSURE);
        ASSERT_EQ(entries[1].value->pressure_limit, 10000U);
        ASSERT_EQ(entries[1].value->pressure_duration_usec, UINT64_C(5000000));

        ASSERT_EQ(entries[2].property, OOMD_POLICY_SWAP);
        assert_se(entries[2].value);
        ASSERT_EQ(entries[2].value->pressure_limit, 0U);
        ASSERT_EQ(entries[2].value->pressure_duration_usec, 0U);

        ASSERT_EQ(entries[3].property, OOMD_POLICY_RULES);
        ASSERT_EQ(strv_length(entries[3].value->rules), 2U);
        ASSERT_STREQ(entries[3].value->rules[0], "desktop");
        ASSERT_STREQ(entries[3].value->rules[1], "batch");

        ASSERT_EQ(entries[4].property, OOMD_POLICY_SWAP);
        assert_se(!entries[4].value);

        oomd_managed_oom_message_batch_done(&message);
        ASSERT_STREQ(entries[0].path, DEFAULT_PATH);
        ASSERT_STREQ(entries[3].value->rules[1], "batch");
}

TEST(late_authorization_failure_is_atomic_and_clears_prior_output) {
        _cleanup_(oomd_managed_oom_message_batch_donep) OomdManagedOOMMessageBatch message = {};
        _cleanup_(oomd_managed_oom_policy_batch_freep) OomdManagedOOMPolicyBatch *policy = NULL;
        OwnerFixture fixture = { .owner = 4711 };

        ASSERT_OK(parse_text(
                          "{\"cgroups\":[{\"mode\":\"kill\",\"path\":\"" SWAP_PATH "\",\"property\":\"ManagedOOMSwap\"}]}",
                          &message));
        ASSERT_OK(oomd_managed_oom_policy_batch_resolve(
                          &message, user_authority, &defaults, owner_lookup, &fixture, &policy));
        assert_se(policy);

        oomd_managed_oom_message_batch_done(&message);
        ASSERT_OK(parse_text(
                          "{\"cgroups\":["
                          "{\"mode\":\"kill\",\"path\":\"" SWAP_PATH "\",\"property\":\"ManagedOOMSwap\"},"
                          "{\"mode\":\"kill\",\"path\":\"" FOREIGN_PATH "\",\"property\":\"ManagedOOMSwap\"}"
                          "]}",
                          &message));

        fixture = (OwnerFixture) {
                .owner = 4711,
                .foreign_path = FOREIGN_PATH,
        };
        ASSERT_ERROR(oomd_managed_oom_policy_batch_resolve(
                             &message, user_authority, &defaults, owner_lookup, &fixture, &policy),
                     EPERM);
        ASSERT_EQ(fixture.calls, 2U);
        assert_se(!policy);
}

TEST(owner_lookup_error_is_propagated_without_output) {
        _cleanup_(oomd_managed_oom_message_batch_donep) OomdManagedOOMMessageBatch message = {};
        _cleanup_(oomd_managed_oom_policy_batch_freep) OomdManagedOOMPolicyBatch *policy = NULL;
        OwnerFixture fixture = {
                .owner = 4711,
                .error_path = ERROR_PATH,
        };

        ASSERT_OK(parse_text(
                          "{\"cgroups\":[{\"mode\":\"kill\",\"path\":\"" ERROR_PATH "\",\"property\":\"ManagedOOMSwap\"}]}",
                          &message));
        ASSERT_ERROR(oomd_managed_oom_policy_batch_resolve(
                             &message, user_authority, &defaults, owner_lookup, &fixture, &policy),
                     ENOENT);
        ASSERT_EQ(fixture.calls, 1U);
        assert_se(!policy);
}

TEST(system_authority_bypasses_owner_lookup) {
        _cleanup_(oomd_managed_oom_message_batch_donep) OomdManagedOOMMessageBatch message = {};
        _cleanup_(oomd_managed_oom_policy_batch_freep) OomdManagedOOMPolicyBatch *policy = NULL;

        ASSERT_OK(parse_text(
                          "{\"cgroups\":[{\"mode\":\"kill\",\"path\":\"" FOREIGN_PATH "\",\"property\":\"ManagedOOMSwap\"}]}",
                          &message));
        ASSERT_OK(oomd_managed_oom_policy_batch_resolve(
                          &message, system_authority, &defaults, NULL, NULL, &policy));
        ASSERT_EQ(oomd_managed_oom_policy_batch_size(policy), 1U);
}

TEST(user_authority_requires_owner_lookup) {
        _cleanup_(oomd_managed_oom_message_batch_donep) OomdManagedOOMMessageBatch message = {};
        _cleanup_(oomd_managed_oom_policy_batch_freep) OomdManagedOOMPolicyBatch *policy = NULL;

        ASSERT_OK(parse_text("{\"cgroups\":[]}", &message));
        ASSERT_ERROR(oomd_managed_oom_policy_batch_resolve(
                             &message, user_authority, &defaults, NULL, NULL, &policy),
                     EINVAL);
        assert_se(!policy);
}

TEST(invalid_defaults_fail_before_authorization) {
        _cleanup_(oomd_managed_oom_message_batch_donep) OomdManagedOOMMessageBatch message = {};
        _cleanup_(oomd_managed_oom_policy_batch_freep) OomdManagedOOMPolicyBatch *policy = NULL;
        OwnerFixture fixture = { .owner = 4711 };
        OomdManagedOOMDefaults invalid_limit = defaults;
        OomdManagedOOMDefaults invalid_duration = defaults;

        invalid_limit.memory_pressure_limit_permyriad = 10001;
        invalid_duration.memory_pressure_duration_usec = USEC_INFINITY;

        ASSERT_OK(parse_text(
                          "{\"cgroups\":[{\"mode\":\"kill\",\"path\":\"" DEFAULT_PATH "\",\"property\":\"ManagedOOMMemoryPressure\"}]}",
                          &message));

        ASSERT_ERROR(oomd_managed_oom_policy_batch_resolve(
                             &message, user_authority, &invalid_limit, owner_lookup, &fixture, &policy),
                     EINVAL);
        ASSERT_ERROR(oomd_managed_oom_policy_batch_resolve(
                             &message, user_authority, &invalid_duration, owner_lookup, &fixture, &policy),
                     EINVAL);
        ASSERT_EQ(fixture.calls, 0U);
        assert_se(!policy);
}

TEST(empty_message_resolves_without_owner_reads) {
        _cleanup_(oomd_managed_oom_message_batch_donep) OomdManagedOOMMessageBatch message = {};
        _cleanup_(oomd_managed_oom_policy_batch_freep) OomdManagedOOMPolicyBatch *policy = NULL;
        OwnerFixture fixture = { .owner = 4711 };

        ASSERT_OK(parse_text("{\"cgroups\":[]}", &message));
        ASSERT_OK(oomd_managed_oom_policy_batch_resolve(
                          &message, user_authority, &defaults, owner_lookup, &fixture, &policy));
        ASSERT_EQ(fixture.calls, 0U);
        ASSERT_EQ(oomd_managed_oom_policy_batch_size(policy), 0U);
}

TEST(resolved_batch_applies_through_one_adapter_snapshot) {
        _cleanup_(oomd_managed_oom_message_batch_donep) OomdManagedOOMMessageBatch message = {};
        _cleanup_(oomd_managed_oom_policy_batch_freep) OomdManagedOOMPolicyBatch *policy = NULL;
        _cleanup_(oomd_reporter_adapter_freep) OomdReporterAdapter *adapter = NULL;
        _cleanup_(oomd_policy_decision_donep) OomdPolicyDecision decision = {};
        OwnerFixture fixture = { .owner = 4711 };
        OomdReporterAdapterEvent event;
        OomdReporterSession session;

        ASSERT_OK(parse_text(
                          "{\"cgroups\":[{\"mode\":\"kill\",\"path\":\"" DEFAULT_PATH "\",\"property\":\"ManagedOOMMemoryPressure\"}]}",
                          &message));
        ASSERT_OK(oomd_managed_oom_policy_batch_resolve(
                          &message, user_authority, &defaults, owner_lookup, &fixture, &policy));

        ASSERT_OK(oomd_reporter_adapter_new(&adapter));
        ASSERT_OK(oomd_reporter_adapter_connect(adapter, 1, user_authority, &session, &event));
        ASSERT_OK(oomd_reporter_adapter_first_snapshot(
                          adapter,
                          1,
                          oomd_managed_oom_policy_batch_entries(policy),
                          oomd_managed_oom_policy_batch_size(policy),
                          &event));

        ASSERT_EQ(oomd_reporter_adapter_get_effective(
                          adapter,
                          OOMD_POLICY_MEMORY_PRESSURE,
                          DEFAULT_PATH,
                          &decision), 1);
        ASSERT_EQ(decision.value.pressure_limit, 6000U);
        ASSERT_EQ(decision.value.pressure_duration_usec, 30 * USEC_PER_SEC);
        ASSERT_GT(session.generation, 0U);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
