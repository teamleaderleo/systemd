/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#include "alloc-util.h"
#include "oomd-managed-oom-resolver.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"

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

static bool property_valid(OomdPolicyProperty property) {
        return property >= 0 && property < _OOMD_POLICY_PROPERTY_MAX;
}

static int validate_message(const OomdManagedOOMMessage *message) {
        assert(message);

        if (message->mode != MANAGED_OOM_AUTO && message->mode != MANAGED_OOM_KILL)
                return -EINVAL;
        if (!property_valid(message->property))
                return -EINVAL;
        if (!message->path || !path_is_absolute(message->path) || !path_is_normalized(message->path))
                return -EINVAL;

        if (message->property == OOMD_POLICY_RULES) {
                if (message->mode == MANAGED_OOM_KILL && strv_isempty(message->rules))
                        return -EINVAL;
                if (message->mode == MANAGED_OOM_AUTO && !strv_isempty(message->rules))
                        return -EINVAL;
        } else if (!strv_isempty(message->rules))
                return -EINVAL;

        return 0;
}

static bool same_message_key(const OomdManagedOOMMessage *a, const OomdManagedOOMMessage *b) {
        assert(a);
        assert(b);

        return a->property == b->property && streq(a->path, b->path);
}

static int validate_defaults(
                const OomdManagedOOMMessageBatch *messages,
                const OomdManagedOOMDefaults *defaults) {

        assert(messages);

        FOREACH_ARRAY(message, messages->items, messages->n_items) {
                if (message->mode != MANAGED_OOM_KILL ||
                    message->property != OOMD_POLICY_MEMORY_PRESSURE)
                        continue;

                if (message->limit == 0 && !defaults)
                        return -EINVAL;
                if (message->duration == USEC_INFINITY &&
                    (!defaults || defaults->pressure_duration_usec == USEC_INFINITY))
                        return -EINVAL;
        }

        return 0;
}

void oomd_managed_oom_policy_batch_done(OomdManagedOOMPolicyBatch *batch) {
        if (!batch)
                return;

        FOREACH_ARRAY(value, batch->values, batch->n_entries)
                oomd_policy_value_done(value);
        STRV_FOREACH(path, batch->paths)
                free(*path);

        free(batch->entries);
        free(batch->paths);
        free(batch->values);
        *batch = (OomdManagedOOMPolicyBatch) {};
}

int oomd_managed_oom_policy_batch_resolve(
                const OomdManagedOOMMessageBatch *messages,
                OomdReporterAuthority authority,
                const OomdManagedOOMDefaults *defaults,
                OomdManagedOOMAuthorizePath authorize_path,
                void *authorize_userdata,
                OomdManagedOOMPolicyBatch *ret) {

        _cleanup_(oomd_managed_oom_policy_batch_donep) OomdManagedOOMPolicyBatch batch = {};
        int r;

        assert(messages);
        assert(messages->items || messages->n_items == 0);
        assert(ret);

        oomd_managed_oom_policy_batch_done(ret);

        if (!authority_valid(authority))
                return -EINVAL;

        for (size_t i = 0; i < messages->n_items; i++) {
                r = validate_message(messages->items + i);
                if (r < 0)
                        return r;

                for (size_t j = 0; j < i; j++)
                        if (same_message_key(messages->items + j, messages->items + i))
                                return -EEXIST;
        }

        r = validate_defaults(messages, defaults);
        if (r < 0)
                return r;

        if (authority.kind == OOMD_REPORTER_USER_MANAGER && messages->n_items > 0) {
                if (!authorize_path)
                        return -EINVAL;

                FOREACH_ARRAY(message, messages->items, messages->n_items) {
                        r = authorize_path(authority.uid, message->path, authorize_userdata);
                        if (r < 0)
                                return r;
                }
        }

        if (messages->n_items > SIZE_MAX / sizeof(OomdPolicySnapshotEntry) ||
            messages->n_items > SIZE_MAX / sizeof(OomdPolicyValue) ||
            messages->n_items >= SIZE_MAX / sizeof(char*))
                return -EOVERFLOW;

        batch.entries = new0(OomdPolicySnapshotEntry, messages->n_items);
        batch.paths = new0(char*, messages->n_items + 1);
        batch.values = new0(OomdPolicyValue, messages->n_items);
        if ((!batch.entries || !batch.paths || !batch.values) && messages->n_items > 0)
                return -ENOMEM;
        batch.n_entries = messages->n_items;

        for (size_t i = 0; i < messages->n_items; i++) {
                const OomdManagedOOMMessage *message = messages->items + i;
                OomdPolicyValue *value = batch.values + i;

                batch.paths[i] = strdup(message->path);
                if (!batch.paths[i])
                        return -ENOMEM;

                if (message->mode == MANAGED_OOM_KILL)
                        switch (message->property) {
                        case OOMD_POLICY_SWAP:
                                break;

                        case OOMD_POLICY_MEMORY_PRESSURE:
                                value->pressure_limit = message->limit > 0 ?
                                        message->limit : defaults->pressure_limit;
                                value->pressure_duration_usec = message->duration != USEC_INFINITY ?
                                        message->duration : defaults->pressure_duration_usec;
                                break;

                        case OOMD_POLICY_RULES:
                                value->rules = strv_copy(message->rules);
                                if (!value->rules)
                                        return -ENOMEM;
                                break;

                        default:
                                assert_not_reached();
                        }

                batch.entries[i] = (OomdPolicySnapshotEntry) {
                        .property = message->property,
                        .path = batch.paths[i],
                        .value = message->mode == MANAGED_OOM_KILL ? value : NULL,
                };
        }

        *ret = batch;
        batch = (OomdManagedOOMPolicyBatch) {};
        return 0;
}
