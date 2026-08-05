/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "oomd-reporter-adapter.h"
#include "user-util.h"

typedef struct OomdReporterLinkState {
        OomdReporterLinkId id;
        OomdReporterSession session;
        bool initialized;
} OomdReporterLinkState;

typedef struct OomdReporterAuthorityState {
        OomdReporterAuthority authority;
        OomdReporterLinkId active_link_id;
        OomdReporterLinkId pending_link_id;
        bool active_connected;
        bool grace_armed;
        OomdReporterSession grace_session;
} OomdReporterAuthorityState;

struct OomdReporterAdapter {
        OomdReporterRegistry *registry;
        OomdReporterLinkState *links;
        size_t n_links;
        OomdReporterAuthorityState *authorities;
        size_t n_authorities;
};

static bool authority_valid(OomdReporterAuthority authority) {
        switch (authority.kind) {
        case OOMD_REPORTER_USER_MANAGER:
                return uid_is_valid(authority.uid);
        case OOMD_REPORTER_SYSTEM_MANAGER:
                return authority.uid == 0;
        default:
                return false;
        }
}

static bool authority_equal(OomdReporterAuthority a, OomdReporterAuthority b) {
        return a.kind == b.kind && a.uid == b.uid;
}

static bool session_equal(OomdReporterSession a, OomdReporterSession b) {
        return authority_equal(a.authority, b.authority) && a.generation == b.generation;
}

static OomdReporterLinkState *find_link(OomdReporterAdapter *adapter, OomdReporterLinkId link_id) {
        assert(adapter);

        FOREACH_ARRAY(link, adapter->links, adapter->n_links)
                if (link->id == link_id)
                        return link;

        return NULL;
}

static void remove_link(OomdReporterAdapter *adapter, OomdReporterLinkId link_id) {
        assert(adapter);

        for (size_t i = 0; i < adapter->n_links; i++)
                if (adapter->links[i].id == link_id) {
                        adapter->links[i] = adapter->links[--adapter->n_links];
                        return;
                }

        assert_not_reached();
}

static OomdReporterAuthorityState *find_authority(
                OomdReporterAdapter *adapter,
                OomdReporterAuthority authority) {

        assert(adapter);

        FOREACH_ARRAY(state, adapter->authorities, adapter->n_authorities)
                if (authority_equal(state->authority, authority))
                        return state;

        return NULL;
}

static void event_reset(OomdReporterAdapterEvent *event) {
        assert(event);
        *event = (OomdReporterAdapterEvent) {
                .timer_action = OOMD_REPORTER_ADAPTER_TIMER_NO_ACTION,
        };
}

static void event_arm(OomdReporterAdapterEvent *event, OomdReporterSession session) {
        assert(event);

        event->timer_action = OOMD_REPORTER_ADAPTER_TIMER_ARM_OR_REPLACE_GRACE;
        event->grace_session = session;
}

static void event_cancel(OomdReporterAdapterEvent *event, OomdReporterSession session) {
        assert(event);

        event->timer_action = OOMD_REPORTER_ADAPTER_TIMER_CANCEL_GRACE;
        event->grace_session = session;
}

OomdReporterAdapter *oomd_reporter_adapter_free(OomdReporterAdapter *adapter) {
        if (!adapter)
                return NULL;

        oomd_reporter_registry_free(adapter->registry);
        free(adapter->links);
        free(adapter->authorities);
        return mfree(adapter);
}

int oomd_reporter_adapter_new(OomdReporterAdapter **ret) {
        _cleanup_(oomd_reporter_adapter_freep) OomdReporterAdapter *adapter = NULL;
        int r;

        assert(ret);

        adapter = new0(OomdReporterAdapter, 1);
        if (!adapter)
                return -ENOMEM;

        r = oomd_reporter_registry_new(&adapter->registry);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(adapter);
        return 0;
}

int oomd_reporter_adapter_connect(
                OomdReporterAdapter *adapter,
                OomdReporterLinkId link_id,
                OomdReporterAuthority authority,
                OomdReporterSession *ret_session,
                OomdReporterAdapterEvent *ret_event) {

        OomdReporterAuthorityState *state;
        OomdReporterAuthorityState *authorities;
        OomdReporterLinkState *links;
        OomdReporterSession session;
        bool new_authority;
        int r;

        assert(adapter);
        assert(ret_session);
        assert(ret_event);

        event_reset(ret_event);

        if (link_id == 0 || !authority_valid(authority))
                return -EINVAL;
        if (find_link(adapter, link_id))
                return -EEXIST;

        state = find_authority(adapter, authority);
        new_authority = !state;

        links = reallocarray(adapter->links, adapter->n_links + 1, sizeof(*links));
        if (!links)
                return -ENOMEM;
        adapter->links = links;

        if (new_authority) {
                authorities = reallocarray(
                                adapter->authorities,
                                adapter->n_authorities + 1,
                                sizeof(*authorities));
                if (!authorities)
                        return -ENOMEM;
                adapter->authorities = authorities;
        }

        r = oomd_reporter_registry_begin(adapter->registry, authority, &session);
        if (r < 0)
                return r;

        if (new_authority) {
                state = adapter->authorities + adapter->n_authorities++;
                *state = (OomdReporterAuthorityState) {
                        .authority = authority,
                };
        } else
                state = find_authority(adapter, authority);

        adapter->links[adapter->n_links++] = (OomdReporterLinkState) {
                .id = link_id,
                .session = session,
        };

        state->pending_link_id = link_id;
        if (state->active_link_id != 0 && !state->active_connected) {
                state->grace_armed = true;
                state->grace_session = session;
                event_arm(ret_event, session);
        }

        *ret_session = session;
        return 0;
}

int oomd_reporter_adapter_first_snapshot(
                OomdReporterAdapter *adapter,
                OomdReporterLinkId link_id,
                const OomdPolicySnapshotEntry *entries,
                size_t n_entries,
                OomdReporterAdapterEvent *ret_event) {

        OomdReporterAuthorityState *state;
        OomdReporterLinkState *link;
        OomdReporterSession cancelled_grace = {};
        bool cancel_grace;
        int r;

        assert(adapter);
        assert(entries || n_entries == 0);
        assert(ret_event);

        event_reset(ret_event);

        link = find_link(adapter, link_id);
        if (!link)
                return -ESTALE;
        if (link->initialized)
                return -EALREADY;

        state = find_authority(adapter, link->session.authority);
        if (!state || state->pending_link_id != link_id)
                return -ESTALE;

        cancel_grace = state->grace_armed;
        if (cancel_grace)
                cancelled_grace = state->grace_session;

        r = oomd_reporter_registry_replace_snapshot(
                        adapter->registry, link->session, entries, n_entries);
        if (r < 0)
                return r;

        link->initialized = true;
        state->active_link_id = link_id;
        state->active_connected = true;
        state->pending_link_id = 0;
        state->grace_armed = false;
        state->grace_session = (OomdReporterSession) {};

        if (cancel_grace)
                event_cancel(ret_event, cancelled_grace);

        return 0;
}

int oomd_reporter_adapter_update(
                OomdReporterAdapter *adapter,
                OomdReporterLinkId link_id,
                OomdPolicyProperty property,
                const char *path,
                const OomdPolicyValue *value) {

        OomdReporterLinkState *link;

        assert(adapter);

        link = find_link(adapter, link_id);
        if (!link || !link->initialized)
                return -ESTALE;

        return oomd_reporter_registry_update(
                        adapter->registry, link->session, property, path, value);
}

int oomd_reporter_adapter_disconnect(
                OomdReporterAdapter *adapter,
                OomdReporterLinkId link_id,
                OomdReporterAdapterEvent *ret_event) {

        OomdReporterAuthorityState *state;
        OomdReporterLinkState *link, *pending;
        OomdReporterSession session, pending_session = {}, cancelled_grace = {};
        bool was_active, was_pending;
        int r;

        assert(adapter);
        assert(ret_event);

        event_reset(ret_event);

        link = find_link(adapter, link_id);
        if (!link)
                return 0;

        session = link->session;
        state = find_authority(adapter, session.authority);
        assert(state);

        was_active = state->active_link_id == link_id;
        was_pending = state->pending_link_id == link_id;

        if (was_active && state->pending_link_id != 0) {
                pending = find_link(adapter, state->pending_link_id);
                assert(pending);
                pending_session = pending->session;
        }
        if (state->grace_armed)
                cancelled_grace = state->grace_session;

        r = oomd_reporter_registry_disconnect(adapter->registry, session);
        if (r < 0)
                return r;

        if (was_pending) {
                state->pending_link_id = 0;

                if (state->active_link_id != 0 && !state->active_connected) {
                        state->active_link_id = 0;
                        if (state->grace_armed)
                                event_cancel(ret_event, cancelled_grace);
                }

                state->grace_armed = false;
                state->grace_session = (OomdReporterSession) {};
                remove_link(adapter, link_id);
                return 0;
        }

        if (!was_active) {
                remove_link(adapter, link_id);
                return 0;
        }

        state->active_connected = false;
        if (state->pending_link_id == 0) {
                state->active_link_id = 0;
                state->grace_armed = false;
                state->grace_session = (OomdReporterSession) {};
                remove_link(adapter, link_id);
                return 0;
        }

        state->grace_armed = true;
        state->grace_session = pending_session;
        event_arm(ret_event, pending_session);
        remove_link(adapter, link_id);
        return 0;
}

int oomd_reporter_adapter_expire_grace(
                OomdReporterAdapter *adapter,
                OomdReporterSession grace_session) {

        OomdReporterAuthorityState *state;
        OomdReporterLinkState *pending;
        int r;

        assert(adapter);

        state = find_authority(adapter, grace_session.authority);
        if (!state ||
            !state->grace_armed ||
            !session_equal(state->grace_session, grace_session) ||
            state->pending_link_id == 0)
                return 0;

        pending = find_link(adapter, state->pending_link_id);
        if (!pending || !session_equal(pending->session, grace_session))
                return 0;

        r = oomd_reporter_registry_expire_pending_grace(adapter->registry, grace_session);
        if (r < 0)
                return r;

        state->active_link_id = 0;
        state->active_connected = false;
        state->grace_armed = false;
        state->grace_session = (OomdReporterSession) {};
        return 0;
}

int oomd_reporter_adapter_get_effective(
                OomdReporterAdapter *adapter,
                OomdPolicyProperty property,
                const char *path,
                OomdPolicyDecision *ret) {

        assert(adapter);

        return oomd_reporter_registry_get_effective(adapter->registry, property, path, ret);
}

size_t oomd_reporter_adapter_size(OomdReporterAdapter *adapter) {
        assert(adapter);

        return oomd_reporter_registry_size(adapter->registry);
}
