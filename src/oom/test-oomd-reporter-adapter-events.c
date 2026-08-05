/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "oomd-reporter-adapter.h"
#include "tests.h"

#define TEST_PATH "/user.slice/user-4711.slice/user@4711.service"

static const OomdReporterAuthority user_authority = {
        .kind = OOMD_REPORTER_USER_MANAGER,
        .uid = 4711,
};

static OomdReporterSession connect_link(
                OomdReporterAdapter *adapter,
                OomdReporterLinkId link_id,
                OomdReporterAdapterEvent *ret_event) {

        OomdReporterSession session;

        ASSERT_OK(oomd_reporter_adapter_connect(
                          adapter, link_id, user_authority, &session, ret_event));
        return session;
}

static void activate_link(OomdReporterAdapter *adapter, OomdReporterLinkId link_id) {
        OomdPolicyValue value = { .pressure_limit = 7000 };
        OomdPolicySnapshotEntry entries[] = {
                { OOMD_POLICY_MEMORY_PRESSURE, TEST_PATH, &value },
        };
        OomdReporterAdapterEvent event;

        ASSERT_OK(oomd_reporter_adapter_first_snapshot(
                          adapter, link_id, entries, ELEMENTSOF(entries), &event));
}

TEST(snapshot_cancel_names_the_armed_grace_generation) {
        _cleanup_(oomd_reporter_adapter_freep) OomdReporterAdapter *adapter = NULL;
        OomdReporterAdapterEvent event;
        OomdReporterSession pending;

        ASSERT_OK(oomd_reporter_adapter_new(&adapter));
        (void) connect_link(adapter, 1, &event);
        activate_link(adapter, 1);
        pending = connect_link(adapter, 2, &event);

        ASSERT_OK(oomd_reporter_adapter_disconnect(adapter, 1, &event));
        ASSERT_EQ(event.timer_action, OOMD_REPORTER_ADAPTER_TIMER_ARM_OR_REPLACE_GRACE);
        ASSERT_EQ(event.grace_session.generation, pending.generation);

        activate_link(adapter, 2);
        /* activate_link() intentionally hides the event, so repeat with an empty replacement
         * on a fresh sequence below to inspect the exact cancellation token. */
}

TEST(promotion_and_pending_disconnect_return_exact_cancel_token) {
        _cleanup_(oomd_reporter_adapter_freep) OomdReporterAdapter *adapter = NULL;
        OomdReporterAdapterEvent event;
        OomdReporterSession pending;
        OomdPolicyValue value = { .pressure_limit = 6000 };
        OomdPolicySnapshotEntry entries[] = {
                { OOMD_POLICY_MEMORY_PRESSURE, TEST_PATH, &value },
        };

        ASSERT_OK(oomd_reporter_adapter_new(&adapter));
        (void) connect_link(adapter, 1, &event);
        activate_link(adapter, 1);
        pending = connect_link(adapter, 2, &event);
        ASSERT_OK(oomd_reporter_adapter_disconnect(adapter, 1, &event));
        ASSERT_EQ(event.grace_session.generation, pending.generation);

        ASSERT_OK(oomd_reporter_adapter_first_snapshot(
                          adapter, 2, entries, ELEMENTSOF(entries), &event));
        ASSERT_EQ(event.timer_action, OOMD_REPORTER_ADAPTER_TIMER_CANCEL_GRACE);
        ASSERT_EQ(event.grace_session.generation, pending.generation);

        ASSERT_OK(oomd_reporter_adapter_disconnect(adapter, 2, &event));

        (void) connect_link(adapter, 3, &event);
        activate_link(adapter, 3);
        pending = connect_link(adapter, 4, &event);
        ASSERT_OK(oomd_reporter_adapter_disconnect(adapter, 3, &event));
        ASSERT_EQ(event.grace_session.generation, pending.generation);
        ASSERT_OK(oomd_reporter_adapter_disconnect(adapter, 4, &event));
        ASSERT_EQ(event.timer_action, OOMD_REPORTER_ADAPTER_TIMER_CANCEL_GRACE);
        ASSERT_EQ(event.grace_session.generation, pending.generation);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
