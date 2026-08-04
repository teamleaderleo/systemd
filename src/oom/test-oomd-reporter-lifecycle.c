/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "oomd-reporter-lifecycle.h"
#include "tests.h"

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

DEFINE_TEST_MAIN(LOG_DEBUG);
