/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef struct Session {
        uint64_t generation;
} Session;

typedef struct WireState {
        uint64_t last_generation;
        uint64_t active_generation;
        uint64_t pending_generation;
        uint64_t grace_generation;
        bool active_connected;
        bool pending_connected;
        bool grace_armed;
        int policy;
} WireState;

static Session begin(WireState *s) {
        assert(s);
        assert(s->last_generation < UINT64_MAX);

        s->pending_generation = ++s->last_generation;
        s->pending_connected = true;

        /* If policy is being retained for a disconnected active generation,
         * superseding an older pending connection must move the compatibility
         * grace to the new pending generation. Otherwise the old timer becomes
         * stale and the retained policy can survive forever. */
        if (s->active_generation != 0 && !s->active_connected) {
                s->grace_armed = true;
                s->grace_generation = s->pending_generation;
        } else {
                s->grace_armed = false;
                s->grace_generation = 0;
        }

        return (Session) { .generation = s->pending_generation };
}

static bool pending_matches(const WireState *s, Session session) {
        return s->pending_connected && s->pending_generation == session.generation;
}

static bool active_matches(const WireState *s, Session session) {
        return s->active_generation == session.generation;
}

/* New protocol: the first message is a complete authoritative snapshot.
 * policy == 0 represents an explicit empty snapshot. */
static int complete_snapshot(WireState *s, Session session, int policy) {
        if (!pending_matches(s, session))
                return -1;

        s->policy = policy;
        s->active_generation = s->pending_generation;
        s->active_connected = true;
        s->pending_generation = 0;
        s->pending_connected = false;
        s->grace_generation = 0;
        s->grace_armed = false;
        return 0;
}

/* Legacy compatibility: the old client sends a complete non-empty set on
 * reconnect, but cannot represent an empty set. The first legacy report can
 * therefore promote a pending generation only when it actually arrives. */
static int legacy_first_report(WireState *s, Session session, int policy) {
        if (policy == 0 || !pending_matches(s, session))
                return -1;

        return complete_snapshot(s, session, policy);
}

static void disconnect(WireState *s, Session session) {
        if (pending_matches(s, session)) {
                s->pending_generation = 0;
                s->pending_connected = false;
                s->grace_generation = 0;
                s->grace_armed = false;

                if (s->active_generation != 0 && !s->active_connected) {
                        s->active_generation = 0;
                        s->policy = 0;
                }
                return;
        }

        if (!active_matches(s, session))
                return;

        if (!s->pending_connected) {
                s->active_generation = 0;
                s->active_connected = false;
                s->policy = 0;
                return;
        }

        /* Preserve the old contribution briefly while a replacement session
         * is pending. A legacy-empty reconnect otherwise has no wire message. */
        s->active_connected = false;
        s->grace_generation = s->pending_generation;
        s->grace_armed = true;
}

static void expire_legacy_grace(WireState *s, uint64_t generation) {
        if (!s->grace_armed ||
            s->grace_generation != generation ||
            !s->pending_connected ||
            s->pending_generation != generation)
                return;

        s->grace_armed = false;
        s->grace_generation = 0;

        if (s->active_generation != 0 && !s->active_connected) {
                s->active_generation = 0;
                s->policy = 0;
        }
}

static Session seed_active(WireState *s, int policy) {
        Session session = begin(s);
        assert(complete_snapshot(s, session, policy) == 0);
        return session;
}

static void test_new_empty_snapshot_is_authoritative(void) {
        WireState s = {};
        Session old = seed_active(&s, 11);
        Session replacement = begin(&s);

        assert(complete_snapshot(&s, replacement, 0) == 0);
        assert(s.policy == 0);
        assert(s.active_generation == replacement.generation);
        disconnect(&s, old);
        assert(s.active_generation == replacement.generation);
}

static void test_new_snapshot_preserves_continuity_after_disconnect(void) {
        WireState s = {};
        Session old = seed_active(&s, 11);
        Session replacement = begin(&s);

        disconnect(&s, old);
        assert(s.policy == 11);
        assert(s.grace_armed);
        assert(complete_snapshot(&s, replacement, 22) == 0);
        assert(s.policy == 22);
        assert(!s.grace_armed);
}

static void test_legacy_nonempty_first_report_promotes(void) {
        WireState s = {};
        Session old = seed_active(&s, 11);
        Session replacement = begin(&s);

        assert(legacy_first_report(&s, replacement, 22) == 0);
        assert(s.policy == 22);
        disconnect(&s, old);
        assert(s.policy == 22);
}

static void test_legacy_empty_reconnect_withdraws_after_grace(void) {
        WireState s = {};
        Session old = seed_active(&s, 11);
        Session replacement = begin(&s);

        disconnect(&s, old);
        assert(s.policy == 11);
        expire_legacy_grace(&s, replacement.generation);
        assert(s.policy == 0);
        assert(s.active_generation == 0);
        assert(s.pending_generation == replacement.generation);
}

static void test_late_legacy_report_after_grace_promotes(void) {
        WireState s = {};
        Session old = seed_active(&s, 11);
        Session replacement = begin(&s);

        disconnect(&s, old);
        expire_legacy_grace(&s, replacement.generation);
        assert(s.policy == 0);
        assert(s.active_generation == 0);
        assert(s.pending_generation == replacement.generation);

        assert(legacy_first_report(&s, replacement, 22) == 0);
        assert(s.policy == 22);
        assert(s.active_generation == replacement.generation);
        assert(s.pending_generation == 0);
}

static void test_stale_grace_cannot_erase_new_snapshot(void) {
        WireState s = {};
        Session old = seed_active(&s, 11);
        Session replacement = begin(&s);
        uint64_t stale_timer = replacement.generation;

        disconnect(&s, old);
        assert(complete_snapshot(&s, replacement, 22) == 0);
        expire_legacy_grace(&s, stale_timer);
        assert(s.policy == 22);
        assert(s.active_generation == replacement.generation);
}

static void test_newer_pending_generation_rekeys_grace(void) {
        WireState s = {};
        Session old = seed_active(&s, 11);
        Session first = begin(&s);

        disconnect(&s, old);
        assert(s.grace_armed);
        assert(s.grace_generation == first.generation);

        Session second = begin(&s);
        assert(second.generation > first.generation);
        assert(s.grace_armed);
        assert(s.grace_generation == second.generation);

        expire_legacy_grace(&s, first.generation);
        assert(s.policy == 11);
        assert(s.pending_generation == second.generation);

        expire_legacy_grace(&s, second.generation);
        assert(s.policy == 0);
        assert(s.active_generation == 0);
        assert(s.pending_generation == second.generation);
}

static void test_pending_disconnect_after_old_disconnect_withdraws(void) {
        WireState s = {};
        Session old = seed_active(&s, 11);
        Session replacement = begin(&s);

        disconnect(&s, old);
        disconnect(&s, replacement);
        assert(s.policy == 0);
        assert(s.active_generation == 0);
        assert(s.pending_generation == 0);
}

static void test_pending_disconnect_while_old_active_retains(void) {
        WireState s = {};
        (void) seed_active(&s, 11);
        Session replacement = begin(&s);

        disconnect(&s, replacement);
        assert(s.policy == 11);
        assert(s.active_connected);
        assert(s.pending_generation == 0);
}

static void test_active_disconnect_without_replacement_withdraws(void) {
        WireState s = {};
        Session active = seed_active(&s, 11);

        disconnect(&s, active);
        assert(s.policy == 0);
        assert(s.active_generation == 0);
}

static void test_stale_disconnect_is_ignored(void) {
        WireState s = {};
        Session old = seed_active(&s, 11);
        Session replacement = begin(&s);

        assert(complete_snapshot(&s, replacement, 22) == 0);
        disconnect(&s, old);
        assert(s.policy == 22);
        assert(s.active_generation == replacement.generation);
}

int main(void) {
        test_new_empty_snapshot_is_authoritative();
        test_new_snapshot_preserves_continuity_after_disconnect();
        test_legacy_nonempty_first_report_promotes();
        test_legacy_empty_reconnect_withdraws_after_grace();
        test_late_legacy_report_after_grace_promotes();
        test_stale_grace_cannot_erase_new_snapshot();
        test_newer_pending_generation_rekeys_grace();
        test_pending_disconnect_after_old_disconnect_withdraws();
        test_pending_disconnect_while_old_active_retains();
        test_active_disconnect_without_replacement_withdraws();
        test_stale_disconnect_is_ignored();

        puts("FIELDWORK_OOMD_WIRE_INIT_COMPAT=PASSED");
        return 0;
}
