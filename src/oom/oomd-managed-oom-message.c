/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#include "alloc-util.h"
#include "json-util.h"
#include "oomd-managed-oom-message.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"

typedef struct ManagedOOMWireMessage {
        ManagedOOMMode mode;
        char *path;
        char *property;
        uint32_t limit;
        usec_t duration;
        char **rules;
} ManagedOOMWireMessage;

typedef struct ManagedOOMEnvelope {
        sd_json_variant *cgroups;
} ManagedOOMEnvelope;

static void managed_oom_wire_message_done(ManagedOOMWireMessage *message) {
        if (!message)
                return;

        free(message->path);
        free(message->property);
        strv_free(message->rules);
        *message = (ManagedOOMWireMessage) {};
}

static JSON_DISPATCH_ENUM_DEFINE(dispatch_managed_oom_mode, ManagedOOMMode, managed_oom_mode_from_string);

static int property_from_string(const char *property, OomdPolicyProperty *ret) {
        assert(property);
        assert(ret);

        if (streq(property, "ManagedOOMSwap"))
                *ret = OOMD_POLICY_SWAP;
        else if (streq(property, "ManagedOOMMemoryPressure"))
                *ret = OOMD_POLICY_MEMORY_PRESSURE;
        else if (streq(property, "OOMRules"))
                *ret = OOMD_POLICY_RULES;
        else
                return -EINVAL;

        return 0;
}

static int validate_property_value(
                const ManagedOOMWireMessage *message,
                OomdPolicyProperty property,
                bool has_limit,
                bool has_duration,
                bool has_rules) {

        assert(message);

        /* Current senders can include configured pressure metadata while reporting auto. The
         * receiver has always treated auto as a withdrawal and ignored the remaining fields. */
        if (message->mode == MANAGED_OOM_AUTO)
                return 0;

        assert(message->mode == MANAGED_OOM_KILL);

        switch (property) {
        case OOMD_POLICY_SWAP:
                return has_limit || has_duration || has_rules ? -EINVAL : 0;

        case OOMD_POLICY_MEMORY_PRESSURE:
                return has_rules ? -EINVAL : 0;

        case OOMD_POLICY_RULES:
                return has_limit || has_duration || strv_isempty(message->rules) ? -EINVAL : 0;

        default:
                assert_not_reached();
        }
}

static bool same_message_key(
                const OomdManagedOOMMessage *a,
                OomdPolicyProperty property,
                const char *path) {

        assert(a);
        assert(path);

        return a->property == property && streq(a->path, path);
}

void oomd_managed_oom_message_batch_done(OomdManagedOOMMessageBatch *batch) {
        if (!batch)
                return;

        FOREACH_ARRAY(item, batch->items, batch->n_items) {
                free(item->path);
                strv_free(item->rules);
        }
        free(batch->items);
        *batch = (OomdManagedOOMMessageBatch) {};
}

int oomd_managed_oom_message_batch_parse(
                sd_json_variant *parameters,
                OomdManagedOOMMessageBatch *ret) {

        _cleanup_(oomd_managed_oom_message_batch_donep) OomdManagedOOMMessageBatch batch = {};
        ManagedOOMEnvelope envelope = {};
        size_t n_items;
        int r;

        static const sd_json_dispatch_field envelope_dispatch_table[] = {
                { "cgroups", SD_JSON_VARIANT_ARRAY, sd_json_dispatch_variant_noref, offsetof(ManagedOOMEnvelope, cgroups), SD_JSON_MANDATORY },
                {},
        };
        static const sd_json_dispatch_field message_dispatch_table[] = {
                { "mode",     SD_JSON_VARIANT_STRING,        dispatch_managed_oom_mode, offsetof(ManagedOOMWireMessage, mode),     SD_JSON_MANDATORY },
                { "path",     SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,   offsetof(ManagedOOMWireMessage, path),     SD_JSON_MANDATORY },
                { "property", SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,   offsetof(ManagedOOMWireMessage, property), SD_JSON_MANDATORY },
                { "limit",    _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint32,   offsetof(ManagedOOMWireMessage, limit),    0                 },
                { "duration", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,   offsetof(ManagedOOMWireMessage, duration), 0                 },
                { "rules",    _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_strv,     offsetof(ManagedOOMWireMessage, rules),    0                 },
                {},
        };

        assert(parameters);
        assert(ret);

        *ret = (OomdManagedOOMMessageBatch) {};

        if (!sd_json_variant_is_object(parameters))
                return -EINVAL;

        r = sd_json_dispatch(parameters, envelope_dispatch_table, SD_JSON_STRICT, &envelope);
        if (r < 0)
                return r;

        n_items = sd_json_variant_elements(envelope.cgroups);
        if (n_items > SIZE_MAX / sizeof(OomdManagedOOMMessage))
                return -EOVERFLOW;

        batch.items = new0(OomdManagedOOMMessage, n_items);
        if (!batch.items && n_items > 0)
                return -ENOMEM;

        for (size_t i = 0; i < n_items; i++) {
                _cleanup_(managed_oom_wire_message_done) ManagedOOMWireMessage message = {
                        .duration = USEC_INFINITY,
                };
                bool has_duration, has_limit, has_rules;
                OomdPolicyProperty property;
                sd_json_variant *element;

                element = sd_json_variant_by_index(envelope.cgroups, i);
                if (!sd_json_variant_is_object(element))
                        return -EINVAL;

                r = sd_json_dispatch(element, message_dispatch_table, SD_JSON_STRICT, &message);
                if (r < 0)
                        return r;

                if (isempty(message.path)) {
                        free(message.path);
                        message.path = strdup("/");
                        if (!message.path)
                                return -ENOMEM;
                }

                if (!path_is_absolute(message.path) || !path_is_normalized(message.path))
                        return -EINVAL;

                r = property_from_string(message.property, &property);
                if (r < 0)
                        return r;

                has_limit = sd_json_variant_by_key(element, "limit") != NULL;
                has_duration = sd_json_variant_by_key(element, "duration") != NULL;
                has_rules = sd_json_variant_by_key(element, "rules") != NULL;

                r = validate_property_value(&message, property, has_limit, has_duration, has_rules);
                if (r < 0)
                        return r;

                for (size_t j = 0; j < i; j++)
                        if (same_message_key(batch.items + j, property, message.path))
                                return -EEXIST;

                if (message.mode == MANAGED_OOM_AUTO) {
                        message.limit = 0;
                        message.duration = USEC_INFINITY;
                        message.rules = strv_free(message.rules);
                } else if (property == OOMD_POLICY_RULES)
                        strv_uniq(message.rules);

                batch.items[i] = (OomdManagedOOMMessage) {
                        .mode = message.mode,
                        .property = property,
                        .path = TAKE_PTR(message.path),
                        .limit = message.limit,
                        .duration = message.duration,
                        .rules = TAKE_PTR(message.rules),
                };
                batch.n_items++;
        }

        *ret = batch;
        batch = (OomdManagedOOMMessageBatch) {};
        return 0;
}
