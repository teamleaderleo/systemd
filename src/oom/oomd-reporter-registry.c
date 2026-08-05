/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "oomd-reporter-registry.h"

struct OomdReporterRegistry {
        OomdPolicyStore *policy;
        OomdReporterLifecycle *lifecycle;
};

OomdReporterRegistry *oomd_reporter_registry_free(OomdReporterRegistry *registry) {
        if (!registry)
                return NULL;

        oomd_policy_store_free(registry->policy);
        oomd_reporter_lifecycle_free(registry->lifecycle);
        return mfree(registry);
}

int oomd_reporter_registry_new(OomdReporterRegistry **ret) {
        _cleanup_(oomd_reporter_registry_freep) OomdReporterRegistry *registry = NULL;
        int r;

        assert(ret);

        registry = new0(OomdReporterRegistry, 1);
        if (!registry)
                return -ENOMEM;

        r = oomd_policy_store_new(&registry->policy);
        if (r < 0)
                return r;

        r = oomd_reporter_lifecycle_new(&registry->lifecycle);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(registry);
        return 0;
}

int oomd_reporter_registry_begin(
                OomdReporterRegistry *registry,
                OomdReporterAuthority authority,
                OomdReporterSession *ret_session) {

        assert(registry);

        return oomd_reporter_lifecycle_begin(registry->lifecycle, authority, ret_session);
}

int oomd_reporter_registry_replace_snapshot(
                OomdReporterRegistry *registry,
                OomdReporterSession session,
                const OomdPolicySnapshotEntry *entries,
                size_t n_entries) {

        OomdReporterLifecycleTransition transition;
        int r;

        assert(registry);
        assert(entries || n_entries == 0);

        r = oomd_reporter_lifecycle_prepare_snapshot(registry->lifecycle, session, &transition);
        if (r < 0)
                return r;

        r = oomd_policy_store_replace_snapshot(registry->policy, session.authority, entries, n_entries);
        if (r < 0)
                return r;

        /* The registry owns both components and does not expose the lifecycle object,
         * hence nothing can invalidate a prepared transition between these two calls. */
        r = oomd_reporter_lifecycle_commit(registry->lifecycle, &transition);
        assert(r >= 0);
        return r;
}

int oomd_reporter_registry_update(
                OomdReporterRegistry *registry,
                OomdReporterSession session,
                OomdPolicyProperty property,
                const char *path,
                const OomdPolicyValue *value) {

        int r;

        assert(registry);

        r = oomd_reporter_lifecycle_accepts_incremental(registry->lifecycle, session);
        if (r < 0)
                return r;
        if (r == 0)
                return -ESTALE;

        return oomd_policy_store_update(registry->policy, session.authority, property, path, value);
}

int oomd_reporter_registry_disconnect(
                OomdReporterRegistry *registry,
                OomdReporterSession session) {

        OomdReporterLifecycleTransition transition;
        int r;

        assert(registry);

        r = oomd_reporter_lifecycle_prepare_disconnect(registry->lifecycle, session, &transition);
        if (r < 0)
                return r;

        if (transition.action == OOMD_REPORTER_LIFECYCLE_WITHDRAW_AUTHORITY) {
                r = oomd_policy_store_replace_snapshot(registry->policy, session.authority, NULL, 0);
                if (r < 0)
                        return r;
        }

        r = oomd_reporter_lifecycle_commit(registry->lifecycle, &transition);
        assert(r >= 0);
        return r;
}

int oomd_reporter_registry_expire_pending_grace(
                OomdReporterRegistry *registry,
                OomdReporterSession pending_session) {

        OomdReporterLifecycleTransition transition;
        int r;

        assert(registry);

        r = oomd_reporter_lifecycle_prepare_grace_expiry(
                        registry->lifecycle, pending_session, &transition);
        if (r < 0)
                return r;

        if (transition.action == OOMD_REPORTER_LIFECYCLE_WITHDRAW_AUTHORITY) {
                r = oomd_policy_store_replace_snapshot(
                                registry->policy, pending_session.authority, NULL, 0);
                if (r < 0)
                        return r;
        }

        r = oomd_reporter_lifecycle_commit(registry->lifecycle, &transition);
        assert(r >= 0);
        return r;
}

int oomd_reporter_registry_get_effective(
                OomdReporterRegistry *registry,
                OomdPolicyProperty property,
                const char *path,
                OomdPolicyDecision *ret) {

        assert(registry);

        return oomd_policy_store_get_effective(registry->policy, property, path, ret);
}

size_t oomd_reporter_registry_size(OomdReporterRegistry *registry) {
        assert(registry);

        return oomd_policy_store_size(registry->policy);
}
