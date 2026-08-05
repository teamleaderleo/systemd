/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "oomd-reporter-adapter.h"
#include "tests.h"

#define TEST_PATH "/user.slice/user-4711.slice/user@4711.service"

static const OomdReporterAuthority user_authority = {
        .kind = OOMD_REPORTER_USER_MANAGER,
        .uid = 4711,
};

static OomdReporterSession connect_and_activate(
                OomdReporterAdapter *adapter,
                OomdReporterLinkId link_id,
                uint32_t pressure_limit,
                bool with_swap) {

        OomdReporterAdapterEvent event;
        OomdReporterSession session;
        OomdPolicyValue pressure = { .pressure_limit = pressure_limit };
        OomdPolicyValue swap = {};
        OomdPolicySnapshotEntry entries[] = {
                { OOMD_POLICY_MEMORY_PRESSURE, TEST_PATH, &pressure },
                { OOMD_POLICY_SWAP, TEST_PATH, &swap },
        };

        ASSERT_OK(oomd_reporter_adapter_connect(
                          adapter, link_id, user_authority, &session, &event));
        ASSERT_OK(oomd_reporter_adapter_first_snapshot(
                          adapter, link_id, entries, with_swap ? ELEMENTSOF(entries) : 1, &event));
        return session;
}

static uint32_t effective_pressure(OomdReporterAdapter *adapter) {
        _cleanup_(oomd_policy_decision_donep) OomdPolicyDecision decision = {};

        ASSERT_EQ(oomd_reporter_adapter_get_effective(
                          adapter, OOMD_POLICY_MEMORY_PRESSURE, TEST_PATH, &decision), 1);
        return decision.value.pressure_limit;
}

static int has_effective(OomdReporterAdapter *adapter, OomdPolicyProperty property) {
        _cleanup_(oomd_policy_decision_donep) OomdPolicyDecision decision = {};

        return oomd_reporter_adapter_get_effective(adapter, property, TEST_PATH, &decision);
}

TEST(batch_updates_commit_together) {
        _cleanup_(oomd_reporter_adapter_freep) OomdReporterAdapter *adapter = NULL;
        OomdPolicyValue pressure = { .pressure_limit = 7100 };
        OomdPolicyValue swap = {};
        OomdPolicySnapshotEntry entries[] = {
                { OOMD_POLICY_MEMORY_PRESSURE, TEST_PATH, &pressure },
                { OOMD_POLICY_SWAP, TEST_PATH, &swap },
        };

        ASSERT_OK(oomd_reporter_adapter_new(&adapter));
        (void) connect_and_activate(adapter, 1, 7000, false);

        ASSERT_OK(oomd_reporter_adapter_apply_updates(
                          adapter, 1, entries, ELEMENTSOF(entries)));
        ASSERT_EQ(effective_pressure(adapter), 7100U);
        ASSERT_EQ(has_effective(adapter, OOMD_POLICY_SWAP), 1);
        ASSERT_EQ(oomd_reporter_adapter_size(adapter), 2U);
}

TEST(invalid_later_update_rolls_back_earlier_update) {
        _cleanup_(oomd_reporter_adapter_freep) OomdReporterAdapter *adapter = NULL;
        char *rules[] = { (char*) "desktop", NULL };
        OomdPolicyValue pressure = { .pressure_limit = 7100 };
        OomdPolicyValue invalid_rules = {
                .pressure_limit = 1,
                .rules = rules,
        };
        OomdPolicySnapshotEntry entries[] = {
                { OOMD_POLICY_MEMORY_PRESSURE, TEST_PATH, &pressure },
                { OOMD_POLICY_RULES, TEST_PATH, &invalid_rules },
        };

        ASSERT_OK(oomd_reporter_adapter_new(&adapter));
        (void) connect_and_activate(adapter, 1, 7000, false);

        ASSERT_ERROR(oomd_reporter_adapter_apply_updates(
                             adapter, 1, entries, ELEMENTSOF(entries)), EINVAL);
        ASSERT_EQ(effective_pressure(adapter), 7000U);
        ASSERT_EQ(has_effective(adapter, OOMD_POLICY_RULES), 0);
        ASSERT_EQ(oomd_reporter_adapter_size(adapter), 1U);
}

TEST(duplicate_update_keys_are_rejected_atomically) {
        _cleanup_(oomd_reporter_adapter_freep) OomdReporterAdapter *adapter = NULL;
        OomdPolicyValue first = { .pressure_limit = 7100 };
        OomdPolicyValue second = { .pressure_limit = 7200 };
        OomdPolicySnapshotEntry entries[] = {
                { OOMD_POLICY_MEMORY_PRESSURE, TEST_PATH, &first },
                { OOMD_POLICY_MEMORY_PRESSURE, TEST_PATH, &second },
        };

        ASSERT_OK(oomd_reporter_adapter_new(&adapter));
        (void) connect_and_activate(adapter, 1, 7000, false);

        ASSERT_ERROR(oomd_reporter_adapter_apply_updates(
                             adapter, 1, entries, ELEMENTSOF(entries)), EEXIST);
        ASSERT_EQ(effective_pressure(adapter), 7000U);
        ASSERT_EQ(oomd_reporter_adapter_size(adapter), 1U);
}

TEST(batch_withdrawals_commit_together) {
        _cleanup_(oomd_reporter_adapter_freep) OomdReporterAdapter *adapter = NULL;
        OomdPolicySnapshotEntry entries[] = {
                { OOMD_POLICY_MEMORY_PRESSURE, TEST_PATH, NULL },
                { OOMD_POLICY_SWAP, TEST_PATH, NULL },
        };

        ASSERT_OK(oomd_reporter_adapter_new(&adapter));
        (void) connect_and_activate(adapter, 1, 7000, true);
        ASSERT_EQ(oomd_reporter_adapter_size(adapter), 2U);

        ASSERT_OK(oomd_reporter_adapter_apply_updates(
                          adapter, 1, entries, ELEMENTSOF(entries)));
        ASSERT_EQ(has_effective(adapter, OOMD_POLICY_MEMORY_PRESSURE), 0);
        ASSERT_EQ(has_effective(adapter, OOMD_POLICY_SWAP), 0);
        ASSERT_EQ(oomd_reporter_adapter_size(adapter), 0U);
}

TEST(empty_update_array_is_an_active_generation_noop) {
        _cleanup_(oomd_reporter_adapter_freep) OomdReporterAdapter *adapter = NULL;

        ASSERT_OK(oomd_reporter_adapter_new(&adapter));
        (void) connect_and_activate(adapter, 1, 7000, false);

        ASSERT_OK(oomd_reporter_adapter_apply_updates(adapter, 1, NULL, 0));
        ASSERT_EQ(effective_pressure(adapter), 7000U);
        ASSERT_EQ(oomd_reporter_adapter_size(adapter), 1U);
}

TEST(null_path_is_rejected_without_state_change) {
        _cleanup_(oomd_reporter_adapter_freep) OomdReporterAdapter *adapter = NULL;
        OomdPolicyValue pressure = { .pressure_limit = 7100 };
        OomdPolicySnapshotEntry entries[] = {
                { OOMD_POLICY_MEMORY_PRESSURE, NULL, &pressure },
        };

        ASSERT_OK(oomd_reporter_adapter_new(&adapter));
        (void) connect_and_activate(adapter, 1, 7000, false);

        ASSERT_ERROR(oomd_reporter_adapter_apply_updates(
                             adapter, 1, entries, ELEMENTSOF(entries)), EINVAL);
        ASSERT_EQ(effective_pressure(adapter), 7000U);
        ASSERT_EQ(oomd_reporter_adapter_size(adapter), 1U);
}

TEST(pending_generation_cannot_apply_update_array) {
        _cleanup_(oomd_reporter_adapter_freep) OomdReporterAdapter *adapter = NULL;
        OomdReporterAdapterEvent event;
        OomdReporterSession pending;
        OomdPolicyValue pressure = { .pressure_limit = 7100 };
        OomdPolicySnapshotEntry entries[] = {
                { OOMD_POLICY_MEMORY_PRESSURE, TEST_PATH, &pressure },
        };

        ASSERT_OK(oomd_reporter_adapter_new(&adapter));
        (void) connect_and_activate(adapter, 1, 7000, false);
        ASSERT_OK(oomd_reporter_adapter_connect(
                          adapter, 2, user_authority, &pending, &event));

        ASSERT_ERROR(oomd_reporter_adapter_apply_updates(
                             adapter, 2, entries, ELEMENTSOF(entries)), ESTALE);
        ASSERT_EQ(effective_pressure(adapter), 7000U);
        ASSERT_GT(pending.generation, 0U);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
