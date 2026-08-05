/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "oomd-reporter-adapter.h"
#include "tests.h"

#define TEST_PATH "/user.slice/user-4711.slice/user@4711.service"

static const OomdReporterAuthority user_authority = {
        .kind = OOMD_REPORTER_USER_MANAGER,
        .uid = 4711,
};

static void activate_link(
                OomdReporterAdapter *adapter,
                OomdReporterLinkId link_id,
                uint32_t limit) {

        OomdReporterAdapterEvent event;
        OomdPolicyValue value = { .pressure_limit = limit };
        OomdPolicySnapshotEntry entries[] = {
                { OOMD_POLICY_MEMORY_PRESSURE, TEST_PATH, &value },
        };

        ASSERT_OK(oomd_reporter_adapter_first_snapshot(
                          adapter, link_id, entries, ELEMENTSOF(entries), &event));
}

TEST(disconnected_link_id_can_be_reused_with_a_new_generation) {
        _cleanup_(oomd_reporter_adapter_freep) OomdReporterAdapter *adapter = NULL;
        OomdReporterAdapterEvent event;
        OomdReporterSession first, second;

        ASSERT_OK(oomd_reporter_adapter_new(&adapter));
        ASSERT_OK(oomd_reporter_adapter_connect(
                          adapter, 1, user_authority, &first, &event));
        activate_link(adapter, 1, 7000);
        ASSERT_OK(oomd_reporter_adapter_disconnect(adapter, 1, &event));

        ASSERT_OK(oomd_reporter_adapter_connect(
                          adapter, 1, user_authority, &second, &event));
        ASSERT_GT(second.generation, first.generation);
        activate_link(adapter, 1, 6000);
}

TEST(disconnected_active_id_remains_reserved_until_grace_resolves) {
        _cleanup_(oomd_reporter_adapter_freep) OomdReporterAdapter *adapter = NULL;
        OomdReporterAdapterEvent event;
        OomdReporterSession active, pending, reused;

        ASSERT_OK(oomd_reporter_adapter_new(&adapter));
        ASSERT_OK(oomd_reporter_adapter_connect(
                          adapter, 1, user_authority, &active, &event));
        activate_link(adapter, 1, 7000);
        ASSERT_OK(oomd_reporter_adapter_connect(
                          adapter, 2, user_authority, &pending, &event));

        ASSERT_OK(oomd_reporter_adapter_disconnect(adapter, 1, &event));
        ASSERT_EQ(event.timer_action, OOMD_REPORTER_ADAPTER_TIMER_ARM_OR_REPLACE_GRACE);
        ASSERT_ERROR(oomd_reporter_adapter_connect(
                             adapter, 1, user_authority, &reused, &event), EEXIST);

        ASSERT_OK(oomd_reporter_adapter_expire_grace(adapter, pending));
        ASSERT_OK(oomd_reporter_adapter_connect(
                          adapter, 1, user_authority, &reused, &event));
        ASSERT_GT(reused.generation, active.generation);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
