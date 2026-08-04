/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "oomd-reporter-lifecycle.h"
#include "tests.h"

#define TEST_PATH "/user.slice/user-4711.slice/user@4711.service"

static const OomdReporterAuthority user_authority = {
        .kind = OOMD_REPORTER_USER_MANAGER,
        .uid = 4711,
};

static OomdReporterSession begin_session(OomdReporterLifecycle *lifecycle) {
        OomdReporterSession session;

        ASSERT_OK(oomd_reporter_lifecycle_begin(lifecycle, user_authority, &session));
        ASSERT_GT(session.generation, 0U);
        return session;
}

static OomdReporterSession activate_session(OomdReporterLifecycle *lifecycle) {
        OomdReporterLifecycleTransition transition;
        OomdReporterSession session;

        session = begin_session(lifecycle);
        ASSERT_OK(oomd_reporter_lifecycle_prepare_snapshot(lifecycle, session, &transition));
        ASSERT_EQ(transition.kind, OOMD_REPORTER_LIFECYCLE_TRANSITION_SNAPSHOT);
        ASSERT_EQ(transition.action, OOMD_REPORTER_LIFECYCLE_REPLACE_SNAPSHOT);
        ASSERT_OK(oomd_reporter_lifecycle_commit(lifecycle, &transition));
        ASSERT_EQ(oomd_reporter_lifecycle_accepts_incremental(lifecycle, session), 1);
        return session;
}

TEST(pending_generation_requires_initial_snapshot) {
        _cleanup_(oomd_reporter_lifecycle_freep) OomdReporterLifecycle *lifecycle = NULL;
        OomdReporterLifecycleTransition transition;
        OomdReporterSession session;

        ASSERT_OK(oomd_reporter_lifecycle_new(&lifecycle));
        session = begin_session(lifecycle);
        ASSERT_EQ(oomd_reporter_lifecycle_accepts_incremental(lifecycle, session), 0);
        ASSERT_OK(oomd_reporter_lifecycle_prepare_snapshot(lifecycle, session, &transition));
        ASSERT_EQ(transition.action, OOMD_REPORTER_LIFECYCLE_REPLACE_SNAPSHOT);
        ASSERT_OK(oomd_reporter_lifecycle_commit(lifecycle, &transition));
        ASSERT_EQ(oomd_reporter_lifecycle_accepts_incremental(lifecycle, session), 1);
}

TEST(uncommitted_snapshot_keeps_old_generation_active) {
        _cleanup_(oomd_reporter_lifecycle_freep) OomdReporterLifecycle *lifecycle = NULL;
        OomdReporterLifecycleTransition transition;
        OomdReporterSession first, second;

        ASSERT_OK(oomd_reporter_lifecycle_new(&lifecycle));
        first = activate_session(lifecycle);
        second = begin_session(lifecycle);

        ASSERT_OK(oomd_reporter_lifecycle_prepare_snapshot(lifecycle, second, &transition));
        ASSERT_EQ(oomd_reporter_lifecycle_accepts_incremental(lifecycle, first), 1);
        ASSERT_EQ(oomd_reporter_lifecycle_accepts_incremental(lifecycle, second), 0);

        /* A failed policy-store replacement simply leaves this transition uncommitted. */
        ASSERT_EQ(oomd_reporter_lifecycle_accepts_incremental(lifecycle, first), 1);
}

TEST(new_snapshot_replaces_old_generation) {
        _cleanup_(oomd_reporter_lifecycle_freep) OomdReporterLifecycle *lifecycle = NULL;
        OomdReporterLifecycleTransition transition;
        OomdReporterSession first, second;

        ASSERT_OK(oomd_reporter_lifecycle_new(&lifecycle));
        first = activate_session(lifecycle);
        second = begin_session(lifecycle);

        ASSERT_OK(oomd_reporter_lifecycle_prepare_snapshot(lifecycle, second, &transition));
        ASSERT_OK(oomd_reporter_lifecycle_commit(lifecycle, &transition));
        ASSERT_EQ(oomd_reporter_lifecycle_accepts_incremental(lifecycle, first), 0);
        ASSERT_EQ(oomd_reporter_lifecycle_accepts_incremental(lifecycle, second), 1);
}

TEST(active_disconnect_with_pending_retains_policy) {
        _cleanup_(oomd_reporter_lifecycle_freep) OomdReporterLifecycle *lifecycle = NULL;
        OomdReporterLifecycleTransition transition;
        OomdReporterSession first, second;

        ASSERT_OK(oomd_reporter_lifecycle_new(&lifecycle));
        first = activate_session(lifecycle);
        second = begin_session(lifecycle);

        ASSERT_OK(oomd_reporter_lifecycle_prepare_disconnect(lifecycle, first, &transition));
        ASSERT_EQ(transition.kind, OOMD_REPORTER_LIFECYCLE_TRANSITION_DISCONNECT_ACTIVE);
        ASSERT_EQ(transition.action, OOMD_REPORTER_LIFECYCLE_NO_ACTION);
        ASSERT_OK(oomd_reporter_lifecycle_commit(lifecycle, &transition));
        ASSERT_EQ(oomd_reporter_lifecycle_accepts_incremental(lifecycle, first), 0);

        ASSERT_OK(oomd_reporter_lifecycle_prepare_snapshot(lifecycle, second, &transition));
        ASSERT_EQ(transition.action, OOMD_REPORTER_LIFECYCLE_REPLACE_SNAPSHOT);
        ASSERT_OK(oomd_reporter_lifecycle_commit(lifecycle, &transition));
        ASSERT_EQ(oomd_reporter_lifecycle_accepts_incremental(lifecycle, second), 1);
}

TEST(active_then_pending_disconnect_withdraws_retained_policy) {
        _cleanup_(oomd_reporter_lifecycle_freep) OomdReporterLifecycle *lifecycle = NULL;
        OomdReporterLifecycleTransition transition;
        OomdReporterSession first, second;

        ASSERT_OK(oomd_reporter_lifecycle_new(&lifecycle));
        first = activate_session(lifecycle);
        second = begin_session(lifecycle);

        ASSERT_OK(oomd_reporter_lifecycle_prepare_disconnect(lifecycle, first, &transition));
        ASSERT_EQ(transition.action, OOMD_REPORTER_LIFECYCLE_NO_ACTION);
        ASSERT_OK(oomd_reporter_lifecycle_commit(lifecycle, &transition));

        ASSERT_OK(oomd_reporter_lifecycle_prepare_disconnect(lifecycle, second, &transition));
        ASSERT_EQ(transition.kind, OOMD_REPORTER_LIFECYCLE_TRANSITION_DISCONNECT_PENDING);
        ASSERT_EQ(transition.action, OOMD_REPORTER_LIFECYCLE_WITHDRAW_AUTHORITY);
        ASSERT_OK(oomd_reporter_lifecycle_commit(lifecycle, &transition));
        ASSERT_EQ(oomd_reporter_lifecycle_accepts_incremental(lifecycle, first), 0);
}

TEST(pending_disconnect_does_not_withdraw_connected_active_policy) {
        _cleanup_(oomd_reporter_lifecycle_freep) OomdReporterLifecycle *lifecycle = NULL;
        OomdReporterLifecycleTransition transition;
        OomdReporterSession first, second;

        ASSERT_OK(oomd_reporter_lifecycle_new(&lifecycle));
        first = activate_session(lifecycle);
        second = begin_session(lifecycle);

        ASSERT_OK(oomd_reporter_lifecycle_prepare_disconnect(lifecycle, second, &transition));
        ASSERT_EQ(transition.kind, OOMD_REPORTER_LIFECYCLE_TRANSITION_DISCONNECT_PENDING);
        ASSERT_EQ(transition.action, OOMD_REPORTER_LIFECYCLE_NO_ACTION);
        ASSERT_OK(oomd_reporter_lifecycle_commit(lifecycle, &transition));
        ASSERT_EQ(oomd_reporter_lifecycle_accepts_incremental(lifecycle, first), 1);
}

TEST(active_disconnect_without_pending_withdraws_authority) {
        _cleanup_(oomd_reporter_lifecycle_freep) OomdReporterLifecycle *lifecycle = NULL;
        OomdReporterLifecycleTransition transition;
        OomdReporterSession session;

        ASSERT_OK(oomd_reporter_lifecycle_new(&lifecycle));
        session = activate_session(lifecycle);

        ASSERT_OK(oomd_reporter_lifecycle_prepare_disconnect(lifecycle, session, &transition));
        ASSERT_EQ(transition.kind, OOMD_REPORTER_LIFECYCLE_TRANSITION_DISCONNECT_ACTIVE);
        ASSERT_EQ(transition.action, OOMD_REPORTER_LIFECYCLE_WITHDRAW_AUTHORITY);
        ASSERT_OK(oomd_reporter_lifecycle_commit(lifecycle, &transition));
        ASSERT_EQ(oomd_reporter_lifecycle_accepts_incremental(lifecycle, session), 0);
}

TEST(late_old_disconnect_cannot_erase_new_generation) {
        _cleanup_(oomd_reporter_lifecycle_freep) OomdReporterLifecycle *lifecycle = NULL;
        OomdReporterLifecycleTransition transition;
        OomdReporterSession first, second;

        ASSERT_OK(oomd_reporter_lifecycle_new(&lifecycle));
        first = activate_session(lifecycle);
        second = begin_session(lifecycle);
        ASSERT_OK(oomd_reporter_lifecycle_prepare_snapshot(lifecycle, second, &transition));
        ASSERT_OK(oomd_reporter_lifecycle_commit(lifecycle, &transition));

        ASSERT_OK(oomd_reporter_lifecycle_prepare_disconnect(lifecycle, first, &transition));
        ASSERT_EQ(transition.kind, OOMD_REPORTER_LIFECYCLE_TRANSITION_NONE);
        ASSERT_EQ(transition.action, OOMD_REPORTER_LIFECYCLE_NO_ACTION);
        ASSERT_OK(oomd_reporter_lifecycle_commit(lifecycle, &transition));
        ASSERT_EQ(oomd_reporter_lifecycle_accepts_incremental(lifecycle, second), 1);
}

TEST(newer_pending_generation_supersedes_older_pending_snapshot) {
        _cleanup_(oomd_reporter_lifecycle_freep) OomdReporterLifecycle *lifecycle = NULL;
        OomdReporterLifecycleTransition transition;
        OomdReporterSession first, second;

        ASSERT_OK(oomd_reporter_lifecycle_new(&lifecycle));
        first = begin_session(lifecycle);
        second = begin_session(lifecycle);
        ASSERT_GT(second.generation, first.generation);

        ASSERT_ERROR(oomd_reporter_lifecycle_prepare_snapshot(lifecycle, first, &transition), ESTALE);
        ASSERT_OK(oomd_reporter_lifecycle_prepare_snapshot(lifecycle, second, &transition));
        ASSERT_OK(oomd_reporter_lifecycle_commit(lifecycle, &transition));
        ASSERT_EQ(oomd_reporter_lifecycle_accepts_incremental(lifecycle, second), 1);
}

TEST(stale_prepared_transition_cannot_commit_after_newer_begin) {
        _cleanup_(oomd_reporter_lifecycle_freep) OomdReporterLifecycle *lifecycle = NULL;
        OomdReporterLifecycleTransition transition;
        OomdReporterSession first;

        ASSERT_OK(oomd_reporter_lifecycle_new(&lifecycle));
        first = begin_session(lifecycle);
        ASSERT_OK(oomd_reporter_lifecycle_prepare_snapshot(lifecycle, first, &transition));
        (void) begin_session(lifecycle);
        ASSERT_ERROR(oomd_reporter_lifecycle_commit(lifecycle, &transition), ESTALE);
}

TEST(non_root_system_authority_is_rejected_by_both_layers) {
        _cleanup_(oomd_policy_store_freep) OomdPolicyStore *store = NULL;
        _cleanup_(oomd_reporter_lifecycle_freep) OomdReporterLifecycle *lifecycle = NULL;
        OomdReporterAuthority invalid = {
                .kind = OOMD_REPORTER_SYSTEM_MANAGER,
                .uid = 4711,
        };
        OomdReporterSession session;
        OomdPolicyValue value = { .pressure_limit = 5000 };

        ASSERT_OK(oomd_policy_store_new(&store));
        ASSERT_OK(oomd_reporter_lifecycle_new(&lifecycle));
        ASSERT_ERROR(oomd_policy_store_update(store, invalid, OOMD_POLICY_MEMORY_PRESSURE, TEST_PATH, &value), EINVAL);
        ASSERT_ERROR(oomd_reporter_lifecycle_begin(lifecycle, invalid, &session), EINVAL);
}

TEST(root_user_manager_remains_distinct_and_valid) {
        _cleanup_(oomd_policy_decision_donep) OomdPolicyDecision decision = {};
        _cleanup_(oomd_policy_store_freep) OomdPolicyStore *store = NULL;
        _cleanup_(oomd_reporter_lifecycle_freep) OomdReporterLifecycle *lifecycle = NULL;
        OomdReporterAuthority root_user = {
                .kind = OOMD_REPORTER_USER_MANAGER,
                .uid = 0,
        };
        OomdReporterSession session;
        OomdPolicyValue value = { .pressure_limit = 7000 };

        ASSERT_OK(oomd_policy_store_new(&store));
        ASSERT_OK(oomd_reporter_lifecycle_new(&lifecycle));
        ASSERT_OK(oomd_policy_store_update(store, root_user, OOMD_POLICY_MEMORY_PRESSURE, TEST_PATH, &value));
        ASSERT_EQ(oomd_policy_store_get_effective(store, OOMD_POLICY_MEMORY_PRESSURE, TEST_PATH, &decision), 1);
        ASSERT_EQ(decision.authority.kind, OOMD_REPORTER_USER_MANAGER);
        ASSERT_EQ(decision.authority.uid, 0U);
        ASSERT_OK(oomd_reporter_lifecycle_begin(lifecycle, root_user, &session));
        ASSERT_GT(session.generation, 0U);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
