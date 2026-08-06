/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef enum Kind { SYSTEM_MANAGER, USER_MANAGER } Kind;
typedef struct Authority { Kind kind; uint32_t uid; } Authority;
typedef struct Session { Authority authority; uint64_t token; } Session;

typedef struct State {
        Authority authority;
        uint64_t active, pending;
        bool active_connected, pending_connected, policy;
} State;

typedef struct Registry {
        State *states;
        size_t n_states;
        uint64_t last_token;
} Registry;

static bool authority_valid(Authority a) {
        return a.kind == USER_MANAGER || (a.kind == SYSTEM_MANAGER && a.uid == 0);
}

static bool authority_equal(Authority a, Authority b) {
        return a.kind == b.kind && a.uid == b.uid;
}

static State *find_state(Registry *r, Authority a) {
        size_t i;

        for (i = 0; i < r->n_states; i++)
                if (authority_equal(r->states[i].authority, a))
                        return &r->states[i];
        return NULL;
}

static State *ensure_state(Registry *r, Authority a) {
        State *s, *p;

        s = find_state(r, a);
        if (s)
                return s;

        p = realloc(r->states, (r->n_states + 1) * sizeof(*p));
        if (!p)
                return NULL;

        r->states = p;
        s = &r->states[r->n_states++];
        *s = (State) { .authority = a };
        return s;
}

static void collect(Registry *r, State *s) {
        size_t i;

        if (s->active != 0 || s->pending != 0)
                return;

        i = (size_t)(s - r->states);
        assert(i < r->n_states);
        r->states[i] = r->states[r->n_states - 1];
        if (--r->n_states == 0) {
                free(r->states);
                r->states = NULL;
        }
}

static int begin(Registry *r, Authority a, Session *ret) {
        State *s;
        uint64_t token;

        if (!authority_valid(a))
                return -1;
        if (r->last_token == UINT64_MAX)
                return -2;

        token = r->last_token + 1;
        s = ensure_state(r, a);
        if (!s)
                return -3;

        r->last_token = token;
        s->pending = token;
        s->pending_connected = true;
        *ret = (Session) { .authority = a, .token = token };
        return 0;
}

static int snapshot(Registry *r, Session session, bool policy) {
        State *s;

        if (!authority_valid(session.authority) || session.token == 0)
                return -1;

        s = find_state(r, session.authority);
        if (!s || !s->pending_connected || s->pending != session.token)
                return -2;

        s->policy = policy;
        s->active = s->pending;
        s->active_connected = true;
        s->pending = 0;
        s->pending_connected = false;
        return 0;
}

static bool accepts_update(Registry *r, Session session) {
        State *s;

        s = find_state(r, session.authority);
        return authority_valid(session.authority) &&
               session.token != 0 &&
               s &&
               s->active_connected &&
               s->active == session.token;
}

static int disconnect(Registry *r, Session session) {
        State *s;

        if (!authority_valid(session.authority) || session.token == 0)
                return -1;

        s = find_state(r, session.authority);
        if (!s)
                return 0;

        if (s->pending_connected && s->pending == session.token) {
                s->pending = 0;
                s->pending_connected = false;
                if (s->active != 0 && !s->active_connected) {
                        s->active = 0;
                        s->policy = false;
                }
                collect(r, s);
                return 0;
        }

        if (s->active == session.token) {
                if (s->pending_connected)
                        s->active_connected = false;
                else {
                        s->active = 0;
                        s->active_connected = false;
                        s->policy = false;
                        collect(r, s);
                }
        }

        return 0;
}

static bool has_policy(Registry *r, Authority a) {
        State *s = find_state(r, a);
        return s && s->policy;
}

static void done(Registry *r) {
        free(r->states);
        *r = (Registry) {0};
}

int main(void) {
        Authority user = { USER_MANAGER, 4711 };
        Authority other = { USER_MANAGER, 4712 };
        Authority system = { SYSTEM_MANAGER, 0 };
        Registry r = {0};
        Session active, pending, old, fresh, a, b, c, stale;
        uint32_t uid;

        /* Active disconnect withdraws and collects dormant authority state. */
        assert(begin(&r, user, &active) == 0);
        assert(snapshot(&r, active, true) == 0);
        assert(disconnect(&r, active) == 0);
        assert(r.n_states == 0 && !has_policy(&r, user));

        /* Recreating one authority gets a globally fresh token. */
        old = active;
        assert(begin(&r, user, &fresh) == 0);
        assert(fresh.token > old.token);
        assert(snapshot(&r, old, true) == -2);
        assert(!accepts_update(&r, old));
        assert(disconnect(&r, old) == 0);
        assert(snapshot(&r, fresh, true) == 0);
        assert(r.n_states == 1);
        assert(disconnect(&r, fresh) == 0);

        /* UID churn is bounded by live sessions, not historical authorities. */
        for (uid = 1; uid <= 10000; uid++) {
                Authority churn = { USER_MANAGER, uid };
                assert(begin(&r, churn, &a) == 0);
                assert(snapshot(&r, a, true) == 0);
                assert(disconnect(&r, a) == 0);
                assert(r.n_states == 0);
        }

        /* Pending disconnect leaves a connected active session untouched. */
        assert(begin(&r, user, &active) == 0);
        assert(snapshot(&r, active, true) == 0);
        assert(begin(&r, user, &pending) == 0);
        assert(disconnect(&r, pending) == 0);
        assert(accepts_update(&r, active) && has_policy(&r, user));

        /* Pending snapshot can promote after old active disconnects. */
        assert(begin(&r, user, &pending) == 0);
        assert(disconnect(&r, active) == 0);
        assert(!accepts_update(&r, active) && has_policy(&r, user));
        assert(snapshot(&r, pending, false) == 0);
        assert(accepts_update(&r, pending) && !has_policy(&r, user));
        assert(disconnect(&r, pending) == 0);

        /* If both old active and pending replacement disconnect, collect. */
        assert(begin(&r, user, &active) == 0);
        assert(snapshot(&r, active, true) == 0);
        assert(begin(&r, user, &pending) == 0);
        assert(disconnect(&r, active) == 0);
        assert(has_policy(&r, user));
        assert(disconnect(&r, pending) == 0);
        assert(r.n_states == 0 && !has_policy(&r, user));

        /* Tokens are globally unique across authorities. */
        assert(begin(&r, user, &a) == 0);
        assert(begin(&r, other, &b) == 0);
        assert(begin(&r, system, &c) == 0);
        assert(a.token < b.token && b.token < c.token);
        done(&r);

        /* A newer pending connection invalidates the older pending token. */
        assert(begin(&r, user, &stale) == 0);
        assert(begin(&r, user, &fresh) == 0);
        assert(fresh.token > stale.token);
        assert(snapshot(&r, stale, true) == -2);
        assert(disconnect(&r, stale) == 0);
        assert(snapshot(&r, fresh, true) == 0);
        assert(disconnect(&r, fresh) == 0);

        /* Exhaustion fails before allocating an authority state. */
        r.last_token = UINT64_MAX;
        assert(begin(&r, user, &a) == -2);
        assert(r.n_states == 0 && r.states == NULL);
        r.last_token = 0;

        /* A stale disconnect after collection is a no-op and cannot recreate. */
        assert(begin(&r, user, &stale) == 0);
        assert(disconnect(&r, stale) == 0);
        assert(r.n_states == 0);
        assert(disconnect(&r, stale) == 0);
        assert(r.n_states == 0);

        done(&r);
        puts("FIELDWORK_OOMD_SESSION_TOKEN_GC=PASSED");
        return 0;
}
