/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "oomd-reporter-adapter.h"
#include "tests.h"

#define TEST_PATH "/user.slice/user-4711.slice/user@4711.service"

static const OomdReporterAuthority user_authority = {
        .kind = OOMD_REPORTER_USER_MANAGER,
        .uid = 4711,
};

TEST(disconnected_link_id_can_be_reused_with_a_new_generation) {
        _cleanup_(oomd_reporter_adapter_freep) OomdReporterAdapter *adapter = NULL;
        OomdReporterAdapterEvent event;
        OomdReporterSession first, second;
        OomdPolicyValue first_value = { .pressure_limit = 7000 };
        OomdPolicyValue second_value = { .pressure_limit = 6000 };
        OomdPolicySnapshotEntry first_entries[] = {
                { OOMD_POLICY_MEMORY_PRESSURE, TEST_PATH, &first_value },
        };
        OomdPolicySnapshotEntry second_entries[] = {
                { OOMD_POLICY_MEMORY_PRESSURE, TEST_PATH, &second_value },
        };

        ASSERT_OK(oomd_reporter_adapter_new(&adapter));
        ASSERT_OK(oomd_reporter_adapter_connect(
                          adapter, 1, user_authority, &first, &event));
        ASSERT_OK(oomd_reporter_adapter_first_snapshot(
                          adapter, 1, first_entries, ELEMENTSOF(first_entries), &event));
        ASSERT_OK(oomd_reporter_adapter_disconnect(adapter, 1, &event));

        ASSERT_OK(oomd_reporter_adapter_connect(
                          adapter, 1, user_authority, &second, &event));
        ASSERT_GT(second.generation, first.generation);
        ASSERT_OK(oomd_reporter_adapter_first_snapshot(
                          adapter, 1, second_entries, ELEMENTSOF(second_entries), &event));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
