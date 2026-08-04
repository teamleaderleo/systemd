/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "oomd-reporter-lifecycle.h"
#include "user-util.h"

typedef struct OomdReporterLifecycleState {
        OomdReporterAuthority authority;
        uint64_t last_generation;
        uint64_t active_generation;
        uint64_t pending_generation;
        bool active_connected;
        bool pending_connected;
} OomdReporterLifecycleState;

struct OomdReporterLifecycle {
        OomdReporterLifecycleState *states;
        size_t n_states;
};

static bool authority_valid(OomdReporterAuthority authority) {
        return authority.kind >= 0 &&
               authority.kind < _OOMD_REPORTER_KIND_MAX &&
               uid_is_valid(authority.uid);
}

static bool authority_equal(OomdReporterAuthority a, OomdReporterAuthority b) {
        return a.kind == b.kind && a.uid == b.uid;
}

static OomdReporterLifecycleState *find_state(
                OomdReporterLifecycle *lifecycle,
                OomdReporterAuthority authority) {

        assert(lifecycle);

        FOREACH_ARRAY(state, lifecycle->states, lifecycle->n_states)
                if (authority_equal(state->authority, authority))
                        return state;

        return NULL;
}

static int ensure_state(
                OomdReporterLifecycle *lifecycle,
                OomdReporterAuthority authority,
                OomdReporterLifecycleState **ret) {

        OomdReporterLifecycleState *state, *states;

        assert(lifecycle);
        assert(ret);

        state = find_state(lifecycle, authority);
        if (state) {
                *ret = state;
                return 0;
        }

        states = reallocarray(lifecycle->states, lifecycle->n_states + 1, sizeof(*states));
        if (!states)
                return -ENOMEM;

        lifecycle->states = states;
        state = lifecycle->states + lifecycle->n_states++;
        *state = (OomdReporterLifecycleState) {
                .authority = authority,
        };

        *ret = state;
        return 0;
}

OomdReporterLifecycle *oomd_reporter_lifecycle_free(OomdReporterLifecycle *lifecycle) {
        if (!lifecycle)
                return NULL;

        free(lifecycle->states);
        return mfree(lifecycle);
}

int oomd_reporter_lifecycle_new(OomdReporterLifecycle **ret) {
        _cleanup_(oomd_reporter_lifecycle_freep) OomdReporterLifecycle *lifecycle = NULL;

        assert(ret);

        lifecycle = new0(OomdReporterLifecycle, 1);
        if (!lifecycle)
                return -ENOMEM;

        *ret = TAKE_PTR(lifecycle);
        return 0;
}

int oomd_reporter_lifecycle_begin(
                OomdReporterLifecycle *lifecycle,
                OomdReporterAuthority authority,
                OomdReporterSession *ret_session) {

        OomdReporterLifecycleState *state;
        int r;

        assert(lifecycle);
        assert(ret_session);

        if (!authority_valid(authority))
                return -EINVAL;

        r = ensure_state(lifecycle, authority, &state);
        if (r < 0)
                return r;
        if (state->last_generation == UINT64_MAX)
                return -EOVERFLOW;

        state->pending_generation = ++state->last_generation;
        state->pending_connected = true;
        *ret_session = (OomdReporterSession) {
                .authority = authority,
                .generation = state->pending_generation,
        };
        return 0;
}

int oomd_reporter_lifecycle_prepare_snapshot(
                OomdReporterLifecycle *lifecycle,
                OomdReporterSession session,
                OomdReporterLifecycleTransition *ret_transition) {

        OomdReporterLifecycleState *state;

        assert(lifecycle);
        assert(ret_transition);

        if (!authority_valid(session.authority) || session.generation == 0)
                return -EINVAL;

        state = find_state(lifecycle, session.authority);
        if (!state ||
            !state->pending_connected ||
            state->pending_generation != session.generation)
                return -ESTALE;

        *ret_transition = (OomdReporterLifecycleTransition) {
                .kind = OOMD_REPORTER_LIFECYCLE_TRANSITION_SNAPSHOT,
                .action = OOMD_REPORTER_LIFECYCLE_REPLACE_SNAPSHOT,
                .session = session,
        };
        return 0;
}

int oomd_reporter_lifecycle_prepare_disconnect(
                OomdReporterLifecycle *lifecycle,
                OomdReporterSession session,
                OomdReporterLifecycleTransition *ret_transition) {

        OomdReporterLifecycleState *state;

        assert(lifecycle);
        assert(ret_transition);

        if (!authority_valid(session.authority) || session.generation == 0)
                return -EINVAL;

        *ret_transition = (OomdReporterLifecycleTransition) {
                .kind = OOMD_REPORTER_LIFECYCLE_TRANSITION_NONE,
                .action = OOMD_REPORTER_LIFECYCLE_NO_ACTION,
                .session = session,
        };

        state = find_state(lifecycle, session.authority);
        if (!state)
                return 0;

        if (state->pending_connected && state->pending_generation == session.generation) {
                ret_transition->kind = OOMD_REPORTER_LIFECYCLE_TRANSITION_DISCONNECT_PENDING;
                if (state->active_generation != 0 && !state->active_connected)
                        ret_transition->action = OOMD_REPORTER_LIFECYCLE_WITHDRAW_AUTHORITY;
                return 0;
        }

        if (state->active_generation == session.generation) {
                ret_transition->kind = OOMD_REPORTER_LIFECYCLE_TRANSITION_DISCONNECT_ACTIVE;
                if (!state->pending_connected)
                        ret_transition->action = OOMD_REPORTER_LIFECYCLE_WITHDRAW_AUTHORITY;
                return 0;
        }

        return 0;
}

int oomd_reporter_lifecycle_commit(
                OomdReporterLifecycle *lifecycle,
                const OomdReporterLifecycleTransition *transition) {

        OomdReporterLifecycleState *state;

        assert(lifecycle);
        assert(transition);

        if (transition->kind == OOMD_REPORTER_LIFECYCLE_TRANSITION_NONE)
                return 0;
        if (!authority_valid(transition->session.authority) || transition->session.generation == 0)
                return -EINVAL;

        state = find_state(lifecycle, transition->session.authority);
        if (!state)
                return -ESTALE;

        switch (transition->kind) {
        case OOMD_REPORTER_LIFECYCLE_TRANSITION_SNAPSHOT:
                if (transition->action != OOMD_REPORTER_LIFECYCLE_REPLACE_SNAPSHOT ||
                    !state->pending_connected ||
                    state->pending_generation != transition->session.generation)
                        return -ESTALE;

                state->active_generation = state->pending_generation;
                state->active_connected = true;
                state->pending_generation = 0;
                state->pending_connected = false;
                return 0;

        case OOMD_REPORTER_LIFECYCLE_TRANSITION_DISCONNECT_PENDING:
                if (!state->pending_connected ||
                    state->pending_generation != transition->session.generation)
                        return -ESTALE;
                if (transition->action == OOMD_REPORTER_LIFECYCLE_WITHDRAW_AUTHORITY) {
                        if (state->active_generation == 0 || state->active_connected)
                                return -ESTALE;
                        state->active_generation = 0;
                } else if (transition->action != OOMD_REPORTER_LIFECYCLE_NO_ACTION)
                        return -EINVAL;

                state->pending_generation = 0;
                state->pending_connected = false;
                return 0;

        case OOMD_REPORTER_LIFECYCLE_TRANSITION_DISCONNECT_ACTIVE:
                if (state->active_generation != transition->session.generation)
                        return -ESTALE;
                if (state->pending_connected) {
                        if (transition->action != OOMD_REPORTER_LIFECYCLE_NO_ACTION)
                                return -ESTALE;
                        state->active_connected = false;
                } else {
                        if (transition->action != OOMD_REPORTER_LIFECYCLE_WITHDRAW_AUTHORITY)
                                return -ESTALE;
                        state->active_generation = 0;
                        state->active_connected = false;
                }
                return 0;

        default:
                return -EINVAL;
        }
}

int oomd_reporter_lifecycle_accepts_incremental(
                OomdReporterLifecycle *lifecycle,
                OomdReporterSession session) {

        OomdReporterLifecycleState *state;

        assert(lifecycle);

        if (!authority_valid(session.authority) || session.generation == 0)
                return -EINVAL;

        state = find_state(lifecycle, session.authority);
        return state &&
               state->active_connected &&
               state->active_generation == session.generation;
}
