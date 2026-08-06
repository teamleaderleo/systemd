/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdbool.h>

#include "alloc-util.h"
#include "oomd-managed-oom-resolver.h"
#include "path-util.h"
#include "percent-util.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"

struct OomdManagedOOMPolicyBatch {
        OomdPolicySnapshotEntry *entries;
        OomdPolicyValue *values;
        char **paths;
        size_t n_entries;
};

static bool authority_valid(OomdReporterAuthority authority) {
        switch (authority.kind) {
        case OOMD_REPORTER_SYSTEM_MANAGER:
                return authority.uid == 0;
        case OOMD_REPORTER_USER_MANAGER:
                return uid_is_valid(authority.uid);
        default:
                return false;
        }
}

static bool defaults_valid(const OomdManagedOOMDefaults *defaults) {
        return defaults &&
               defaults->memory_pressure_limit_permyriad <= 10000U &&
               defaults->memory_pressure_duration_usec != USEC_INFINITY;
}

static bool same_message_key(
                const OomdManagedOOMMessage *a,
                OomdPolicyProperty property,
                const char *path) {

        assert(a);
        assert(path);

        return a->property == property && streq(a->path, path);
}

static int validate_message(const OomdManagedOOMMessageBatch *message) {
        assert(message);
        assert(message->items || message->n_items == 0);

        for (size_t i = 0; i < message->n_items; i++) {
                const OomdManagedOOMMessage *item = message->items + i;

                if (!item->path || !path_is_absolute(item->path) || !path_is_normalized(item->path))
                        return -EINVAL;
                if (item->property < 0 || item->property >= _OOMD_POLICY_PROPERTY_MAX)
                        return -EINVAL;
                if (!IN_SET(item->mode, MANAGED_OOM_AUTO, MANAGED_OOM_KILL))
                        return -EINVAL;
                if (item->mode == MANAGED_OOM_KILL &&
                    item->property == OOMD_POLICY_RULES &&
                    strv_isempty(item->rules))
                        return -EINVAL;

                for (size_t j = 0; j < i; j++)
                        if (same_message_key(message->items + j, item->property, item->path))
                                return -EEXIST;
        }

        return 0;
}

static int authorize_message(
                const OomdManagedOOMMessageBatch *message,
                OomdReporterAuthority authority,
                OomdManagedOOMOwnerLookup owner_lookup,
                void *owner_userdata) {

        assert(message);
        assert(message->items || message->n_items == 0);

        if (authority.kind == OOMD_REPORTER_SYSTEM_MANAGER || message->n_items == 0)
                return 0;
        if (!owner_lookup)
                return -EINVAL;

        FOREACH_ARRAY(item, message->items, message->n_items) {
                uid_t owner;
                int r;

                r = owner_lookup(item->path, &owner, owner_userdata);
                if (r < 0)
                        return r;
                if (owner != authority.uid)
                        return -EPERM;
        }

        return 0;
}

OomdManagedOOMPolicyBatch *oomd_managed_oom_policy_batch_free(OomdManagedOOMPolicyBatch *batch) {
        if (!batch)
                return NULL;

        for (size_t i = 0; i < batch->n_entries; i++) {
                free(batch->paths[i]);
                oomd_policy_value_done(batch->values + i);
        }

        free(batch->entries);
        free(batch->values);
        free(batch->paths);
        return mfree(batch);
}

int oomd_managed_oom_policy_batch_resolve(
                const OomdManagedOOMMessageBatch *message,
                OomdReporterAuthority authority,
                const OomdManagedOOMDefaults *defaults,
                OomdManagedOOMOwnerLookup owner_lookup,
                void *owner_userdata,
                OomdManagedOOMPolicyBatch **ret) {

        _cleanup_(oomd_managed_oom_policy_batch_freep) OomdManagedOOMPolicyBatch *batch = NULL;
        int r;

        assert(message);
        assert(message->items || message->n_items == 0);
        assert(ret);

        *ret = oomd_managed_oom_policy_batch_free(*ret);

        if (!authority_valid(authority) || !defaults_valid(defaults))
                return -EINVAL;

        r = validate_message(message);
        if (r < 0)
                return r;

        r = authorize_message(message, authority, owner_lookup, owner_userdata);
        if (r < 0)
                return r;

        batch = new0(OomdManagedOOMPolicyBatch, 1);
        if (!batch)
                return -ENOMEM;

        batch->entries = new0(OomdPolicySnapshotEntry, message->n_items);
        batch->values = new0(OomdPolicyValue, message->n_items);
        batch->paths = new0(char*, message->n_items);
        if (message->n_items > 0 && (!batch->entries || !batch->values || !batch->paths))
                return -ENOMEM;

        FOREACH_ARRAY(item, message->items, message->n_items) {
                _cleanup_(oomd_policy_value_donep) OomdPolicyValue value = {};
                _cleanup_free_ char *path = NULL;
                size_t i = batch->n_entries;
                bool withdrawal;

                path = strdup(item->path);
                if (!path)
                        return -ENOMEM;

                withdrawal = item->mode == MANAGED_OOM_AUTO;
                if (!withdrawal)
                        switch (item->property) {
                        case OOMD_POLICY_SWAP:
                                break;

                        case OOMD_POLICY_MEMORY_PRESSURE:
                                value.pressure_limit = item->limit > 0 ?
                                                       UINT32_SCALE_TO_PERMYRIAD(item->limit) :
                                                       defaults->memory_pressure_limit_permyriad;
                                value.pressure_duration_usec = item->duration != USEC_INFINITY ?
                                                               item->duration :
                                                               defaults->memory_pressure_duration_usec;
                                break;

                        case OOMD_POLICY_RULES:
                                value.rules = strv_copy(item->rules);
                                if (!value.rules)
                                        return -ENOMEM;
                                break;

                        default:
                                assert_not_reached();
                        }

                batch->paths[i] = TAKE_PTR(path);
                batch->values[i] = value;
                value = (OomdPolicyValue) {};
                batch->entries[i] = (OomdPolicySnapshotEntry) {
                        .property = item->property,
                        .path = batch->paths[i],
                        .value = withdrawal ? NULL : batch->values + i,
                };
                batch->n_entries++;
        }

        *ret = TAKE_PTR(batch);
        return 0;
}

const OomdPolicySnapshotEntry *oomd_managed_oom_policy_batch_entries(const OomdManagedOOMPolicyBatch *batch) {
        assert(batch);

        return batch->entries;
}

size_t oomd_managed_oom_policy_batch_size(const OomdManagedOOMPolicyBatch *batch) {
        assert(batch);

        return batch->n_entries;
}
