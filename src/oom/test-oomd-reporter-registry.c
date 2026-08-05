/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "oomd-reporter-registry.h"
#include "tests.h"

#define PATH "/user.slice/user-4711.slice/user@4711.service"

static const OomdReporterAuthority user_authority = {
        .kind = OOMD_REPORTER_USER_MANAGER,
        .uid = 4711,
};

static const OomdReporterAuthority system_authority = {
        .kind = OOMD_REPORTER_SYSTEM_MANAGER,
        .uid = 0,
};

static OomdReporterSession begin_session(
                OomdReporterRegistry *registry,
                OomdReporterAuthority authority) {

        OomdReporterSession session;

        ASSERT_OK(oomd_reporter_registry_begin(registry, authority, &session));
        ASSERT_GT(session.generation, 0U);
        return session;
}

static OomdReporterSession activate_pressure(
                OomdReporterRegistry *registry,
                OomdReporterAuthority authority,
                uint32_t limit) {

        OomdPolicyValue value = { .pressure_limit = limit };
        OomdPolicySnapshotEntry entries[] = {
                { OOMD_POLICY_MEMORY_PRESSURE, PATH, &value },
        };
        OomdReporterSession session;

        session = begin_session(registry, authority);
        ASSERT_OK(oomd_reporter_registry_replace_snapshot(registry, session, entries, ELEMENTSOF(entries)));
        return session;
}

static uint32_t effective_pressure(OomdReporterRegistry *registry) {
        _cleanup_(oomd_policy_decision_donep) OomdPolicyDecision decision = {};

        ASSERT_EQ(oomd_reporter_registry_get_effective(
                          registry, OOMD_POLICY_MEMORY_PRESSURE, PATH, &decision), 1);
        return decision.value.pressure_limit;
}

TEST(failed_replacement_keeps_old_generation_and_policy) {
        _cleanup_(oomd_reporter_registry_freep) OomdReporterRegistry *registry = NULL;
        char *rules[] = { (char*) "desktop", NULL };
        OomdPolicyValue invalid = {
                .pressure_limit = 1,
                .rules = rules,
        };
        OomdPolicySnapshotEntry entries[] = {
                { OOMD_POLICY_RULES, PATH, &invalid },
        };
        OomdPolicyValue update = { .pressure_limit = 7100 };
        OomdReporterSession first, second;

        ASSERT_OK(oomd_reporter_registry_new(&registry));
        first = activate_pressure(registry, user_authority, 7000);
        second = begin_session(registry, user_authority);

        ASSERT_ERROR(oomd_reporter_registry_replace_snapshot(
                             registry, second, entries, ELEMENTSOF(entries)), EINVAL);
        ASSERT_EQ(effective_pressure(registry), 7000U);
        ASSERT_OK(oomd_reporter_registry_update(
                          registry, first, OOMD_POLICY_MEMORY_PRESSURE, PATH, &update));
        ASSERT_ERROR(oomd_reporter_registry_update(
                             registry, second, OOMD_POLICY_MEMORY_PRESSURE, PATH, &update), ESTALE);
        ASSERT_EQ(effective_pressure(registry), 7100U);
}

TEST(connected_active_remains_writable_while_replacement_is_pending) {
        _cleanup_(oomd_reporter_registry_freep) OomdReporterRegistry *registry = NULL;
        OomdPolicyValue active_update = { .pressure_limit = 7100 };
        OomdPolicyValue pending_update = { .pressure_limit = 7200 };
        OomdPolicyValue replacement = { .pressure_limit = 6000 };
        OomdPolicySnapshotEntry entries[] = {
                { OOMD_POLICY_MEMORY_PRESSURE, PATH, &replacement },
        };
        OomdReporterSession first, second;

        ASSERT_OK(oomd_reporter_registry_new(&registry));
        first = activate_pressure(registry, user_authority, 7000);
        second = begin_session(registry, user_authority);

        ASSERT_OK(oomd_reporter_registry_update(
                          registry, first, OOMD_POLICY_MEMORY_PRESSURE, PATH, &active_update));
        ASSERT_ERROR(oomd_reporter_registry_update(
                             registry, second, OOMD_POLICY_MEMORY_PRESSURE, PATH, &pending_update), ESTALE);
        ASSERT_EQ(effective_pressure(registry), 7100U);

        ASSERT_OK(oomd_reporter_registry_replace_snapshot(
                          registry, second, entries, ELEMENTSOF(entries)));
        ASSERT_EQ(effective_pressure(registry), 6000U);
        ASSERT_ERROR(oomd_reporter_registry_update(
                             registry, first, OOMD_POLICY_MEMORY_PRESSURE, PATH, &active_update), ESTALE);
}

TEST(valid_replacement_promotes_new_generation) {
        _cleanup_(oomd_reporter_registry_freep) OomdReporterRegistry *registry = NULL;
        OomdPolicyValue stale_update = { .pressure_limit = 7200 };
        OomdPolicyValue current_update = { .pressure_limit = 6100 };
        OomdPolicyValue replacement = { .pressure_limit = 6000 };
        OomdPolicySnapshotEntry entries[] = {
                { OOMD_POLICY_MEMORY_PRESSURE, PATH, &replacement },
        };
        OomdReporterSession first, second;

        ASSERT_OK(oomd_reporter_registry_new(&registry));
        first = activate_pressure(registry, user_authority, 7000);
        second = begin_session(registry, user_authority);

        ASSERT_OK(oomd_reporter_registry_replace_snapshot(
                          registry, second, entries, ELEMENTSOF(entries)));
        ASSERT_EQ(effective_pressure(registry), 6000U);
        ASSERT_ERROR(oomd_reporter_registry_update(
                             registry, first, OOMD_POLICY_MEMORY_PRESSURE, PATH, &stale_update), ESTALE);
        ASSERT_OK(oomd_reporter_registry_update(
                          registry, second, OOMD_POLICY_MEMORY_PRESSURE, PATH, &current_update));
        ASSERT_EQ(effective_pressure(registry), 6100U);
}

TEST(empty_replacement_snapshot_withdraws_old_authority_state) {
        _cleanup_(oomd_reporter_registry_freep) OomdReporterRegistry *registry = NULL;
        OomdPolicyDecision decision = {};
        OomdReporterSession first, second;

        ASSERT_OK(oomd_reporter_registry_new(&registry));
        first = activate_pressure(registry, user_authority, 7000);
        second = begin_session(registry, user_authority);

        ASSERT_OK(oomd_reporter_registry_replace_snapshot(registry, second, NULL, 0));
        ASSERT_EQ(oomd_reporter_registry_size(registry), 0U);
        ASSERT_EQ(oomd_reporter_registry_get_effective(
                          registry, OOMD_POLICY_MEMORY_PRESSURE, PATH, &decision), 0);
        ASSERT_ERROR(oomd_reporter_registry_update(
                             registry, first, OOMD_POLICY_MEMORY_PRESSURE, PATH, NULL), ESTALE);
}

TEST(current_disconnect_without_replacement_withdraws_policy) {
        _cleanup_(oomd_reporter_registry_freep) OomdReporterRegistry *registry = NULL;
        OomdReporterSession session;

        ASSERT_OK(oomd_reporter_registry_new(&registry));
        session = activate_pressure(registry, user_authority, 7000);
        ASSERT_OK(oomd_reporter_registry_disconnect(registry, session));
        ASSERT_EQ(oomd_reporter_registry_size(registry), 0U);
}

TEST(old_disconnect_with_pending_retains_until_pending_disconnect) {
        _cleanup_(oomd_reporter_registry_freep) OomdReporterRegistry *registry = NULL;
        OomdPolicyValue update = { .pressure_limit = 7100 };
        OomdReporterSession first, second;

        ASSERT_OK(oomd_reporter_registry_new(&registry));
        first = activate_pressure(registry, user_authority, 7000);
        second = begin_session(registry, user_authority);

        ASSERT_OK(oomd_reporter_registry_disconnect(registry, first));
        ASSERT_EQ(effective_pressure(registry), 7000U);
        ASSERT_ERROR(oomd_reporter_registry_update(
                             registry, first, OOMD_POLICY_MEMORY_PRESSURE, PATH, &update), ESTALE);
        ASSERT_ERROR(oomd_reporter_registry_update(
                             registry, second, OOMD_POLICY_MEMORY_PRESSURE, PATH, &update), ESTALE);

        ASSERT_OK(oomd_reporter_registry_disconnect(registry, second));
        ASSERT_EQ(oomd_reporter_registry_size(registry), 0U);
}

TEST(pending_disconnect_does_not_remove_connected_active_policy) {
        _cleanup_(oomd_reporter_registry_freep) OomdReporterRegistry *registry = NULL;
        OomdPolicyValue update = { .pressure_limit = 7200 };
        OomdReporterSession first, second;

        ASSERT_OK(oomd_reporter_registry_new(&registry));
        first = activate_pressure(registry, user_authority, 7000);
        second = begin_session(registry, user_authority);

        ASSERT_OK(oomd_reporter_registry_disconnect(registry, second));
        ASSERT_EQ(effective_pressure(registry), 7000U);
        ASSERT_OK(oomd_reporter_registry_update(
                          registry, first, OOMD_POLICY_MEMORY_PRESSURE, PATH, &update));
        ASSERT_EQ(effective_pressure(registry), 7200U);
}

TEST(late_old_disconnect_cannot_erase_new_policy) {
        _cleanup_(oomd_reporter_registry_freep) OomdReporterRegistry *registry = NULL;
        OomdPolicyValue replacement = { .pressure_limit = 6000 };
        OomdPolicySnapshotEntry entries[] = {
                { OOMD_POLICY_MEMORY_PRESSURE, PATH, &replacement },
        };
        OomdReporterSession first, second;

        ASSERT_OK(oomd_reporter_registry_new(&registry));
        first = activate_pressure(registry, user_authority, 7000);
        second = begin_session(registry, user_authority);
        ASSERT_OK(oomd_reporter_registry_replace_snapshot(
                          registry, second, entries, ELEMENTSOF(entries)));

        ASSERT_OK(oomd_reporter_registry_disconnect(registry, first));
        ASSERT_EQ(effective_pressure(registry), 6000U);
}

TEST(system_disconnect_reveals_active_user_policy) {
        _cleanup_(oomd_reporter_registry_freep) OomdReporterRegistry *registry = NULL;
        OomdReporterSession system, user;

        ASSERT_OK(oomd_reporter_registry_new(&registry));
        user = activate_pressure(registry, user_authority, 7000);
        system = activate_pressure(registry, system_authority, 5000);
        ASSERT_EQ(effective_pressure(registry), 5000U);

        ASSERT_OK(oomd_reporter_registry_disconnect(registry, system));
        ASSERT_EQ(effective_pressure(registry), 7000U);

        ASSERT_OK(oomd_reporter_registry_disconnect(registry, user));
        ASSERT_EQ(oomd_reporter_registry_size(registry), 0U);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
