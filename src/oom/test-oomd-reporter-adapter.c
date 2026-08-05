/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "oomd-reporter-adapter.h"
#include "tests.h"

#define TEST_PATH "/user.slice/user-4711.slice/user@4711.service"

static const OomdReporterAuthority user_authority = {
        .kind = OOMD_REPORTER_USER_MANAGER,
        .uid = 4711,
};

static OomdPolicyValue pressure(uint32_t limit) {
        return (OomdPolicyValue) { .pressure_limit = limit };
}

static uint32_t effective_pressure(OomdReporterAdapter *adapter) {
        _cleanup_(oomd_policy_decision_donep) OomdPolicyDecision decision = {};

        ASSERT_EQ(oomd_reporter_adapter_get_effective(
                          adapter, OOMD_POLICY_MEMORY_PRESSURE, TEST_PATH, &decision), 1);
        return decision.value.pressure_limit;
}

static OomdReporterSession connect_link(
                OomdReporterAdapter *adapter,
                OomdReporterLinkId link_id,
                OomdReporterAdapterTimerAction expected_action) {

        OomdReporterAdapterEvent event;
        OomdReporterSession session;

        ASSERT_OK(oomd_reporter_adapter_connect(
                          adapter, link_id, user_authority, &session, &event));
        ASSERT_EQ(event.timer_action, expected_action);
        ASSERT_GT(session.generation, 0U);
        return session;
}

static void first_pressure(
                OomdReporterAdapter *adapter,
                OomdReporterLinkId link_id,
                uint32_t limit,
                OomdReporterAdapterTimerAction expected_action) {

        OomdPolicyValue value = pressure(limit);
        OomdPolicySnapshotEntry entries[] = {
                { OOMD_POLICY_MEMORY_PRESSURE, TEST_PATH, &value },
        };
        OomdReporterAdapterEvent event;

        ASSERT_OK(oomd_reporter_adapter_first_snapshot(
                          adapter, link_id, entries, ELEMENTSOF(entries), &event));
        ASSERT_EQ(event.timer_action, expected_action);
}

TEST(explicit_empty_first_snapshot_initializes_link) {
        _cleanup_(oomd_reporter_adapter_freep) OomdReporterAdapter *adapter = NULL;
        OomdReporterAdapterEvent event;
        OomdReporterSession session;
        OomdPolicyDecision decision = {};

        ASSERT_OK(oomd_reporter_adapter_new(&adapter));
        session = connect_link(adapter, 1, OOMD_REPORTER_ADAPTER_TIMER_NO_ACTION);
        ASSERT_OK(oomd_reporter_adapter_first_snapshot(adapter, 1, NULL, 0, &event));
        ASSERT_EQ(event.timer_action, OOMD_REPORTER_ADAPTER_TIMER_NO_ACTION);
        ASSERT_EQ(oomd_reporter_adapter_size(adapter), 0U);
        ASSERT_EQ(oomd_reporter_adapter_get_effective(
                          adapter, OOMD_POLICY_MEMORY_PRESSURE, TEST_PATH, &decision), 0);

        OomdPolicyValue value = pressure(7000);
        ASSERT_OK(oomd_reporter_adapter_update(
                          adapter, 1, OOMD_POLICY_MEMORY_PRESSURE, TEST_PATH, &value));
        ASSERT_EQ(effective_pressure(adapter), 7000U);
        ASSERT_GT(session.generation, 0U);
}

TEST(active_continues_while_pending_waits_for_first_snapshot) {
        _cleanup_(oomd_reporter_adapter_freep) OomdReporterAdapter *adapter = NULL;
        OomdReporterAdapterEvent event;
        OomdReporterSession first, second;
        OomdPolicyValue active_update = pressure(7100);
        OomdPolicyValue pending_update = pressure(7200);

        ASSERT_OK(oomd_reporter_adapter_new(&adapter));
        first = connect_link(adapter, 1, OOMD_REPORTER_ADAPTER_TIMER_NO_ACTION);
        first_pressure(adapter, 1, 7000, OOMD_REPORTER_ADAPTER_TIMER_NO_ACTION);
        second = connect_link(adapter, 2, OOMD_REPORTER_ADAPTER_TIMER_NO_ACTION);

        ASSERT_OK(oomd_reporter_adapter_update(
                          adapter, 1, OOMD_POLICY_MEMORY_PRESSURE, TEST_PATH, &active_update));
        ASSERT_ERROR(oomd_reporter_adapter_update(
                             adapter, 2, OOMD_POLICY_MEMORY_PRESSURE, TEST_PATH, &pending_update), ESTALE);
        ASSERT_EQ(effective_pressure(adapter), 7100U);

        first_pressure(adapter, 2, 6000, OOMD_REPORTER_ADAPTER_TIMER_NO_ACTION);
        ASSERT_EQ(effective_pressure(adapter), 6000U);
        ASSERT_ERROR(oomd_reporter_adapter_update(
                             adapter, 1, OOMD_POLICY_MEMORY_PRESSURE, TEST_PATH, &active_update), ESTALE);
        ASSERT_LT(first.generation, second.generation);
        ASSERT_OK(oomd_reporter_adapter_disconnect(adapter, 1, &event));
        ASSERT_EQ(event.timer_action, OOMD_REPORTER_ADAPTER_TIMER_NO_ACTION);
}

TEST(active_disconnect_arms_grace_and_snapshot_cancels_it) {
        _cleanup_(oomd_reporter_adapter_freep) OomdReporterAdapter *adapter = NULL;
        OomdReporterAdapterEvent event;
        OomdReporterSession second;

        ASSERT_OK(oomd_reporter_adapter_new(&adapter));
        (void) connect_link(adapter, 1, OOMD_REPORTER_ADAPTER_TIMER_NO_ACTION);
        first_pressure(adapter, 1, 7000, OOMD_REPORTER_ADAPTER_TIMER_NO_ACTION);
        second = connect_link(adapter, 2, OOMD_REPORTER_ADAPTER_TIMER_NO_ACTION);

        ASSERT_OK(oomd_reporter_adapter_disconnect(adapter, 1, &event));
        ASSERT_EQ(event.timer_action, OOMD_REPORTER_ADAPTER_TIMER_ARM_OR_REPLACE_GRACE);
        ASSERT_EQ(event.grace_session.generation, second.generation);
        ASSERT_EQ(effective_pressure(adapter), 7000U);

        first_pressure(adapter, 2, 6000, OOMD_REPORTER_ADAPTER_TIMER_CANCEL_GRACE);
        ASSERT_EQ(effective_pressure(adapter), 6000U);
        ASSERT_OK(oomd_reporter_adapter_expire_grace(adapter, second));
        ASSERT_EQ(effective_pressure(adapter), 6000U);
}

TEST(grace_expiry_withdraws_old_policy_and_late_snapshot_promotes) {
        _cleanup_(oomd_reporter_adapter_freep) OomdReporterAdapter *adapter = NULL;
        OomdReporterAdapterEvent event;
        OomdReporterSession second;
        OomdPolicyDecision decision = {};

        ASSERT_OK(oomd_reporter_adapter_new(&adapter));
        (void) connect_link(adapter, 1, OOMD_REPORTER_ADAPTER_TIMER_NO_ACTION);
        first_pressure(adapter, 1, 7000, OOMD_REPORTER_ADAPTER_TIMER_NO_ACTION);
        second = connect_link(adapter, 2, OOMD_REPORTER_ADAPTER_TIMER_NO_ACTION);
        ASSERT_OK(oomd_reporter_adapter_disconnect(adapter, 1, &event));
        ASSERT_EQ(event.timer_action, OOMD_REPORTER_ADAPTER_TIMER_ARM_OR_REPLACE_GRACE);

        ASSERT_OK(oomd_reporter_adapter_expire_grace(adapter, second));
        ASSERT_EQ(oomd_reporter_adapter_size(adapter), 0U);
        ASSERT_EQ(oomd_reporter_adapter_get_effective(
                          adapter, OOMD_POLICY_MEMORY_PRESSURE, TEST_PATH, &decision), 0);

        first_pressure(adapter, 2, 6000, OOMD_REPORTER_ADAPTER_TIMER_NO_ACTION);
        ASSERT_EQ(effective_pressure(adapter), 6000U);
}

TEST(newer_pending_link_replaces_grace_token) {
        _cleanup_(oomd_reporter_adapter_freep) OomdReporterAdapter *adapter = NULL;
        OomdReporterAdapterEvent event;
        OomdReporterSession first_pending, second_pending;

        ASSERT_OK(oomd_reporter_adapter_new(&adapter));
        (void) connect_link(adapter, 1, OOMD_REPORTER_ADAPTER_TIMER_NO_ACTION);
        first_pressure(adapter, 1, 7000, OOMD_REPORTER_ADAPTER_TIMER_NO_ACTION);
        first_pending = connect_link(adapter, 2, OOMD_REPORTER_ADAPTER_TIMER_NO_ACTION);
        ASSERT_OK(oomd_reporter_adapter_disconnect(adapter, 1, &event));
        ASSERT_EQ(event.grace_session.generation, first_pending.generation);

        second_pending = connect_link(
                        adapter, 3, OOMD_REPORTER_ADAPTER_TIMER_ARM_OR_REPLACE_GRACE);
        ASSERT_GT(second_pending.generation, first_pending.generation);

        ASSERT_OK(oomd_reporter_adapter_expire_grace(adapter, first_pending));
        ASSERT_EQ(effective_pressure(adapter), 7000U);
        ASSERT_OK(oomd_reporter_adapter_expire_grace(adapter, second_pending));
        ASSERT_EQ(oomd_reporter_adapter_size(adapter), 0U);

        first_pressure(adapter, 3, 6000, OOMD_REPORTER_ADAPTER_TIMER_NO_ACTION);
        ASSERT_EQ(effective_pressure(adapter), 6000U);
}

TEST(pending_disconnect_preserves_connected_active) {
        _cleanup_(oomd_reporter_adapter_freep) OomdReporterAdapter *adapter = NULL;
        OomdReporterAdapterEvent event;
        OomdPolicyValue update = pressure(7200);

        ASSERT_OK(oomd_reporter_adapter_new(&adapter));
        (void) connect_link(adapter, 1, OOMD_REPORTER_ADAPTER_TIMER_NO_ACTION);
        first_pressure(adapter, 1, 7000, OOMD_REPORTER_ADAPTER_TIMER_NO_ACTION);
        (void) connect_link(adapter, 2, OOMD_REPORTER_ADAPTER_TIMER_NO_ACTION);

        ASSERT_OK(oomd_reporter_adapter_disconnect(adapter, 2, &event));
        ASSERT_EQ(event.timer_action, OOMD_REPORTER_ADAPTER_TIMER_NO_ACTION);
        ASSERT_OK(oomd_reporter_adapter_update(
                          adapter, 1, OOMD_POLICY_MEMORY_PRESSURE, TEST_PATH, &update));
        ASSERT_EQ(effective_pressure(adapter), 7200U);
}

TEST(pending_disconnect_after_active_disconnect_withdraws_and_cancels) {
        _cleanup_(oomd_reporter_adapter_freep) OomdReporterAdapter *adapter = NULL;
        OomdReporterAdapterEvent event;

        ASSERT_OK(oomd_reporter_adapter_new(&adapter));
        (void) connect_link(adapter, 1, OOMD_REPORTER_ADAPTER_TIMER_NO_ACTION);
        first_pressure(adapter, 1, 7000, OOMD_REPORTER_ADAPTER_TIMER_NO_ACTION);
        (void) connect_link(adapter, 2, OOMD_REPORTER_ADAPTER_TIMER_NO_ACTION);

        ASSERT_OK(oomd_reporter_adapter_disconnect(adapter, 1, &event));
        ASSERT_EQ(event.timer_action, OOMD_REPORTER_ADAPTER_TIMER_ARM_OR_REPLACE_GRACE);
        ASSERT_OK(oomd_reporter_adapter_disconnect(adapter, 2, &event));
        ASSERT_EQ(event.timer_action, OOMD_REPORTER_ADAPTER_TIMER_CANCEL_GRACE);
        ASSERT_EQ(oomd_reporter_adapter_size(adapter), 0U);
}

TEST(stale_pending_snapshot_and_duplicate_link_are_rejected) {
        _cleanup_(oomd_reporter_adapter_freep) OomdReporterAdapter *adapter = NULL;
        OomdReporterAdapterEvent event;
        OomdReporterSession session;
        OomdPolicyValue value = pressure(6000);
        OomdPolicySnapshotEntry entries[] = {
                { OOMD_POLICY_MEMORY_PRESSURE, TEST_PATH, &value },
        };

        ASSERT_OK(oomd_reporter_adapter_new(&adapter));
        session = connect_link(adapter, 1, OOMD_REPORTER_ADAPTER_TIMER_NO_ACTION);
        ASSERT_ERROR(oomd_reporter_adapter_connect(
                             adapter, 1, user_authority, &session, &event), EEXIST);
        (void) connect_link(adapter, 2, OOMD_REPORTER_ADAPTER_TIMER_NO_ACTION);
        ASSERT_ERROR(oomd_reporter_adapter_first_snapshot(
                             adapter, 1, entries, ELEMENTSOF(entries), &event), ESTALE);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
