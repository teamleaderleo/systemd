/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "oomd-policy.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

#define PATH "/user.slice/user-4711.slice/user@4711.service"
#define OTHER_PATH "/user.slice/user-4711.slice/session-1.scope"

static const OomdReporterAuthority system_authority = {
        .kind = OOMD_REPORTER_SYSTEM_MANAGER,
        .uid = 0,
};

static const OomdReporterAuthority user_authority = {
        .kind = OOMD_REPORTER_USER_MANAGER,
        .uid = 4711,
};

TEST(system_policy_has_precedence_as_complete_tuple) {
        _cleanup_(oomd_policy_decision_donep) OomdPolicyDecision decision = {};
        _cleanup_(oomd_policy_store_freep) OomdPolicyStore *store = NULL;
        OomdPolicyValue system = {
                .pressure_limit = 5000,
                .pressure_duration_usec = 30 * USEC_PER_SEC,
        };
        OomdPolicyValue user = {
                .pressure_limit = 7000,
                .pressure_duration_usec = 5 * USEC_PER_SEC,
        };

        ASSERT_OK(oomd_policy_store_new(&store));
        ASSERT_OK(oomd_policy_store_update(store, user_authority, OOMD_POLICY_MEMORY_PRESSURE, PATH, &user));
        ASSERT_OK(oomd_policy_store_update(store, system_authority, OOMD_POLICY_MEMORY_PRESSURE, PATH, &system));
        ASSERT_EQ(oomd_policy_store_get_effective(store, OOMD_POLICY_MEMORY_PRESSURE, PATH, &decision), 1);
        ASSERT_EQ(decision.authority.kind, OOMD_REPORTER_SYSTEM_MANAGER);
        ASSERT_EQ(decision.authority.uid, 0U);
        ASSERT_EQ(decision.value.pressure_limit, 5000U);
        ASSERT_EQ(decision.value.pressure_duration_usec, 30 * USEC_PER_SEC);
}

TEST(user_withdrawal_does_not_remove_system_policy) {
        _cleanup_(oomd_policy_decision_donep) OomdPolicyDecision decision = {};
        _cleanup_(oomd_policy_store_freep) OomdPolicyStore *store = NULL;
        OomdPolicyValue system = { .pressure_limit = 5000 };
        OomdPolicyValue user = { .pressure_limit = 7000 };

        ASSERT_OK(oomd_policy_store_new(&store));
        ASSERT_OK(oomd_policy_store_update(store, system_authority, OOMD_POLICY_MEMORY_PRESSURE, PATH, &system));
        ASSERT_OK(oomd_policy_store_update(store, user_authority, OOMD_POLICY_MEMORY_PRESSURE, PATH, &user));
        ASSERT_OK(oomd_policy_store_update(store, user_authority, OOMD_POLICY_MEMORY_PRESSURE, PATH, NULL));
        ASSERT_EQ(oomd_policy_store_get_effective(store, OOMD_POLICY_MEMORY_PRESSURE, PATH, &decision), 1);
        ASSERT_EQ(decision.authority.kind, OOMD_REPORTER_SYSTEM_MANAGER);
        ASSERT_EQ(decision.value.pressure_limit, 5000U);
}

TEST(system_withdrawal_reveals_existing_user_policy) {
        _cleanup_(oomd_policy_decision_donep) OomdPolicyDecision decision = {};
        _cleanup_(oomd_policy_store_freep) OomdPolicyStore *store = NULL;
        OomdPolicyValue system = { .pressure_limit = 5000 };
        OomdPolicyValue user = { .pressure_limit = 7000 };

        ASSERT_OK(oomd_policy_store_new(&store));
        ASSERT_OK(oomd_policy_store_update(store, user_authority, OOMD_POLICY_MEMORY_PRESSURE, PATH, &user));
        ASSERT_OK(oomd_policy_store_update(store, system_authority, OOMD_POLICY_MEMORY_PRESSURE, PATH, &system));
        ASSERT_OK(oomd_policy_store_update(store, system_authority, OOMD_POLICY_MEMORY_PRESSURE, PATH, NULL));
        ASSERT_EQ(oomd_policy_store_get_effective(store, OOMD_POLICY_MEMORY_PRESSURE, PATH, &decision), 1);
        ASSERT_EQ(decision.authority.kind, OOMD_REPORTER_USER_MANAGER);
        ASSERT_EQ(decision.authority.uid, 4711U);
        ASSERT_EQ(decision.value.pressure_limit, 7000U);
}

TEST(snapshot_replaces_complete_authority_state) {
        _cleanup_(oomd_policy_decision_donep) OomdPolicyDecision decision = {};
        _cleanup_(oomd_policy_store_freep) OomdPolicyStore *store = NULL;
        OomdPolicyValue old = { .pressure_limit = 7000 };
        OomdPolicyValue replacement = { .pressure_limit = 6500 };
        OomdPolicySnapshotEntry snapshot[] = {
                { OOMD_POLICY_MEMORY_PRESSURE, PATH, &replacement },
        };

        ASSERT_OK(oomd_policy_store_new(&store));
        ASSERT_OK(oomd_policy_store_update(store, user_authority, OOMD_POLICY_MEMORY_PRESSURE, PATH, &old));
        ASSERT_OK(oomd_policy_store_replace_snapshot(store, user_authority, snapshot, ELEMENTSOF(snapshot)));
        ASSERT_EQ(oomd_policy_store_size(store), 1U);
        ASSERT_EQ(oomd_policy_store_get_effective(store, OOMD_POLICY_MEMORY_PRESSURE, PATH, &decision), 1);
        ASSERT_EQ(decision.value.pressure_limit, 6500U);
}

TEST(empty_snapshot_withdraws_old_authority_state) {
        _cleanup_(oomd_policy_store_freep) OomdPolicyStore *store = NULL;
        OomdPolicyValue user = { .pressure_limit = 7000 };
        OomdPolicyDecision decision = {};

        ASSERT_OK(oomd_policy_store_new(&store));
        ASSERT_OK(oomd_policy_store_update(store, user_authority, OOMD_POLICY_MEMORY_PRESSURE, PATH, &user));
        ASSERT_OK(oomd_policy_store_replace_snapshot(store, user_authority, NULL, 0));
        ASSERT_EQ(oomd_policy_store_size(store), 0U);
        ASSERT_EQ(oomd_policy_store_get_effective(store, OOMD_POLICY_MEMORY_PRESSURE, PATH, &decision), 0);
}

TEST(duplicate_snapshot_is_rejected_atomically) {
        _cleanup_(oomd_policy_decision_donep) OomdPolicyDecision decision = {};
        _cleanup_(oomd_policy_store_freep) OomdPolicyStore *store = NULL;
        OomdPolicyValue original = { .pressure_limit = 7000 };
        OomdPolicyValue first = { .pressure_limit = 6500 };
        OomdPolicyValue second = { .pressure_limit = 6000 };
        OomdPolicySnapshotEntry invalid[] = {
                { OOMD_POLICY_MEMORY_PRESSURE, PATH, &first },
                { OOMD_POLICY_MEMORY_PRESSURE, PATH, &second },
        };

        ASSERT_OK(oomd_policy_store_new(&store));
        ASSERT_OK(oomd_policy_store_update(store, user_authority, OOMD_POLICY_MEMORY_PRESSURE, PATH, &original));
        ASSERT_ERROR(oomd_policy_store_replace_snapshot(store, user_authority, invalid, ELEMENTSOF(invalid)), EEXIST);
        ASSERT_EQ(oomd_policy_store_size(store), 1U);
        ASSERT_EQ(oomd_policy_store_get_effective(store, OOMD_POLICY_MEMORY_PRESSURE, PATH, &decision), 1);
        ASSERT_EQ(decision.value.pressure_limit, 7000U);
}

TEST(rules_are_selected_as_one_complete_list) {
        _cleanup_(oomd_policy_decision_donep) OomdPolicyDecision decision = {};
        _cleanup_(oomd_policy_store_freep) OomdPolicyStore *store = NULL;
        char *system_rules[] = { (char*) "system-default", NULL };
        char *user_rules[] = { (char*) "desktop", (char*) "interactive", NULL };
        OomdPolicyValue system = { .rules = system_rules };
        OomdPolicyValue user = { .rules = user_rules };

        ASSERT_OK(oomd_policy_store_new(&store));
        ASSERT_OK(oomd_policy_store_update(store, user_authority, OOMD_POLICY_RULES, PATH, &user));
        ASSERT_OK(oomd_policy_store_update(store, system_authority, OOMD_POLICY_RULES, PATH, &system));
        ASSERT_EQ(oomd_policy_store_get_effective(store, OOMD_POLICY_RULES, PATH, &decision), 1);
        ASSERT_TRUE(strv_equal(decision.value.rules, STRV_MAKE("system-default")));
}

TEST(equal_rank_different_user_authorities_are_ambiguous) {
        _cleanup_(oomd_policy_store_freep) OomdPolicyStore *store = NULL;
        OomdReporterAuthority other = {
                .kind = OOMD_REPORTER_USER_MANAGER,
                .uid = 4712,
        };
        OomdPolicyValue a = { .pressure_limit = 7000 };
        OomdPolicyValue b = { .pressure_limit = 6000 };
        OomdPolicyDecision decision = {};

        ASSERT_OK(oomd_policy_store_new(&store));
        ASSERT_OK(oomd_policy_store_update(store, user_authority, OOMD_POLICY_MEMORY_PRESSURE, PATH, &a));
        ASSERT_OK(oomd_policy_store_update(store, other, OOMD_POLICY_MEMORY_PRESSURE, PATH, &b));
        ASSERT_ERROR(oomd_policy_store_get_effective(store, OOMD_POLICY_MEMORY_PRESSURE, PATH, &decision), ENOTUNIQ);
}

TEST(higher_rank_policy_resolves_earlier_user_ambiguity) {
        _cleanup_(oomd_policy_decision_donep) OomdPolicyDecision decision = {};
        _cleanup_(oomd_policy_store_freep) OomdPolicyStore *store = NULL;
        OomdReporterAuthority other = {
                .kind = OOMD_REPORTER_USER_MANAGER,
                .uid = 4712,
        };
        OomdPolicyValue first_user = { .pressure_limit = 7000 };
        OomdPolicyValue second_user = { .pressure_limit = 6000 };
        OomdPolicyValue system = { .pressure_limit = 5000 };

        ASSERT_OK(oomd_policy_store_new(&store));
        ASSERT_OK(oomd_policy_store_update(store, user_authority, OOMD_POLICY_MEMORY_PRESSURE, PATH, &first_user));
        ASSERT_OK(oomd_policy_store_update(store, other, OOMD_POLICY_MEMORY_PRESSURE, PATH, &second_user));
        ASSERT_OK(oomd_policy_store_update(store, system_authority, OOMD_POLICY_MEMORY_PRESSURE, PATH, &system));
        ASSERT_EQ(oomd_policy_store_get_effective(store, OOMD_POLICY_MEMORY_PRESSURE, PATH, &decision), 1);
        ASSERT_EQ(decision.authority.kind, OOMD_REPORTER_SYSTEM_MANAGER);
        ASSERT_EQ(decision.authority.uid, 0U);
        ASSERT_EQ(decision.value.pressure_limit, 5000U);
}

TEST(invalid_incremental_value_is_rejected_atomically) {
        _cleanup_(oomd_policy_decision_donep) OomdPolicyDecision decision = {};
        _cleanup_(oomd_policy_store_freep) OomdPolicyStore *store = NULL;
        char *unexpected_rules[] = { (char*) "not-a-pressure-field", NULL };
        OomdPolicyValue original = { .pressure_limit = 7000 };
        OomdPolicyValue invalid = {
                .pressure_limit = 6500,
                .rules = unexpected_rules,
        };

        ASSERT_OK(oomd_policy_store_new(&store));
        ASSERT_OK(oomd_policy_store_update(store, user_authority, OOMD_POLICY_MEMORY_PRESSURE, PATH, &original));
        ASSERT_ERROR(oomd_policy_store_update(store, user_authority, OOMD_POLICY_MEMORY_PRESSURE, PATH, &invalid), EINVAL);
        ASSERT_EQ(oomd_policy_store_size(store), 1U);
        ASSERT_EQ(oomd_policy_store_get_effective(store, OOMD_POLICY_MEMORY_PRESSURE, PATH, &decision), 1);
        ASSERT_EQ(decision.value.pressure_limit, 7000U);
}

TEST(invalid_snapshot_value_is_rejected_atomically) {
        _cleanup_(oomd_policy_decision_donep) OomdPolicyDecision decision = {};
        _cleanup_(oomd_policy_store_freep) OomdPolicyStore *store = NULL;
        char *rules[] = { (char*) "desktop", NULL };
        OomdPolicyValue original = { .pressure_limit = 7000 };
        OomdPolicyValue replacement = { .pressure_limit = 6500 };
        OomdPolicyValue invalid_rules = {
                .pressure_limit = 1,
                .rules = rules,
        };
        OomdPolicySnapshotEntry invalid[] = {
                { OOMD_POLICY_MEMORY_PRESSURE, PATH, &replacement },
                { OOMD_POLICY_RULES, OTHER_PATH, &invalid_rules },
        };

        ASSERT_OK(oomd_policy_store_new(&store));
        ASSERT_OK(oomd_policy_store_update(store, user_authority, OOMD_POLICY_MEMORY_PRESSURE, PATH, &original));
        ASSERT_ERROR(oomd_policy_store_replace_snapshot(store, user_authority, invalid, ELEMENTSOF(invalid)), EINVAL);
        ASSERT_EQ(oomd_policy_store_size(store), 1U);
        ASSERT_EQ(oomd_policy_store_get_effective(store, OOMD_POLICY_MEMORY_PRESSURE, PATH, &decision), 1);
        ASSERT_EQ(decision.value.pressure_limit, 7000U);
}

TEST(empty_rules_value_is_rejected) {
        _cleanup_(oomd_policy_store_freep) OomdPolicyStore *store = NULL;
        OomdPolicyValue empty = {};

        ASSERT_OK(oomd_policy_store_new(&store));
        ASSERT_ERROR(oomd_policy_store_update(store, user_authority, OOMD_POLICY_RULES, PATH, &empty), EINVAL);
        ASSERT_EQ(oomd_policy_store_size(store), 0U);
}

TEST(swap_policy_accepts_empty_value) {
        _cleanup_(oomd_policy_decision_donep) OomdPolicyDecision decision = {};
        _cleanup_(oomd_policy_store_freep) OomdPolicyStore *store = NULL;
        OomdPolicyValue swap = {};

        ASSERT_OK(oomd_policy_store_new(&store));
        ASSERT_OK(oomd_policy_store_update(store, user_authority, OOMD_POLICY_SWAP, PATH, &swap));
        ASSERT_EQ(oomd_policy_store_get_effective(store, OOMD_POLICY_SWAP, PATH, &decision), 1);
        ASSERT_EQ(decision.authority.kind, OOMD_REPORTER_USER_MANAGER);
        ASSERT_EQ(decision.value.pressure_limit, 0U);
        ASSERT_EQ(decision.value.pressure_duration_usec, 0U);
        ASSERT_TRUE(strv_isempty(decision.value.rules));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
