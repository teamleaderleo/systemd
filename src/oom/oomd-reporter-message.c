/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "oomd-reporter-message.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"

struct OomdReporterMessage {
        OomdPolicySnapshotEntry *entries;
        OomdPolicyValue *values;
        char **paths;
        size_t n_entries;
};

typedef struct RawManagedOOMParameters {
        sd_json_variant *cgroups;
} RawManagedOOMParameters;

typedef struct RawManagedOOMMessage {
        char *mode;
        char *path;
        char *property;
        uint32_t limit;
        usec_t duration;
        char **rules;
} RawManagedOOMMessage;

static void raw_managed_oom_message_done(RawManagedOOMMessage *message) {
        if (!message)
                return;

        free(message->mode);
        free(message->path);
        free(message->property);
        message->rules = strv_free(message->rules);
        *message = (RawManagedOOMMessage) {};
}

static int policy_property_from_string(const char *property, OomdPolicyProperty *ret) {
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

OomdReporterMessage *oomd_reporter_message_free(OomdReporterMessage *message) {
        if (!message)
                return NULL;

        for (size_t i = 0; i < message->n_entries; i++) {
                free(message->paths[i]);
                oomd_policy_value_done(message->values + i);
        }

        free(message->entries);
        free(message->values);
        free(message->paths);
        return mfree(message);
}

int oomd_reporter_message_parse(
                sd_json_variant *parameters,
                OomdReporterMessage **ret) {

        _cleanup_(oomd_reporter_message_freep) OomdReporterMessage *message = NULL;
        RawManagedOOMParameters raw_parameters = {};
        size_t n_entries;
        int r;

        static const sd_json_dispatch_field parameters_dispatch_table[] = {
                { "cgroups", SD_JSON_VARIANT_ARRAY, sd_json_dispatch_variant_noref, offsetof(RawManagedOOMParameters, cgroups), SD_JSON_MANDATORY },
                {},
        };
        static const sd_json_dispatch_field message_dispatch_table[] = {
                { "mode",     SD_JSON_VARIANT_STRING,        sd_json_dispatch_string, offsetof(RawManagedOOMMessage, mode),     SD_JSON_MANDATORY },
                { "path",     SD_JSON_VARIANT_STRING,        sd_json_dispatch_string, offsetof(RawManagedOOMMessage, path),     SD_JSON_MANDATORY },
                { "property", SD_JSON_VARIANT_STRING,        sd_json_dispatch_string, offsetof(RawManagedOOMMessage, property), SD_JSON_MANDATORY },
                { "limit",    _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint32, offsetof(RawManagedOOMMessage, limit),    0                 },
                { "duration", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(RawManagedOOMMessage, duration), 0                 },
                { "rules",    _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_strv,   offsetof(RawManagedOOMMessage, rules),    0                 },
                {},
        };

        assert(parameters);
        assert(ret);

        r = sd_json_dispatch(parameters, parameters_dispatch_table, SD_JSON_STRICT, &raw_parameters);
        if (r < 0)
                return r;

        n_entries = sd_json_variant_elements(raw_parameters.cgroups);

        message = new0(OomdReporterMessage, 1);
        if (!message)
                return -ENOMEM;

        message->entries = new0(OomdPolicySnapshotEntry, n_entries);
        message->values = new0(OomdPolicyValue, n_entries);
        message->paths = new0(char*, n_entries);
        if (n_entries > 0 && (!message->entries || !message->values || !message->paths))
                return -ENOMEM;
        message->n_entries = n_entries;

        for (size_t i = 0; i < n_entries; i++) {
                _cleanup_(raw_managed_oom_message_done) RawManagedOOMMessage raw = {
                        .duration = USEC_INFINITY,
                };
                _cleanup_free_ char *path = NULL;
                sd_json_variant *element;
                OomdPolicyProperty property;
                bool has_duration, has_limit, has_rules, is_auto, is_kill;

                element = sd_json_variant_by_index(raw_parameters.cgroups, i);
                if (!sd_json_variant_is_object(element))
                        return -EINVAL;

                r = sd_json_dispatch(element, message_dispatch_table, SD_JSON_STRICT, &raw);
                if (r < 0)
                        return r;

                is_auto = streq(raw.mode, "auto");
                is_kill = streq(raw.mode, "kill");
                if (!is_auto && !is_kill)
                        return -EINVAL;

                r = policy_property_from_string(raw.property, &property);
                if (r < 0)
                        return r;

                if (!path_is_absolute(empty_to_root(raw.path)) ||
                    !path_is_normalized(empty_to_root(raw.path)))
                        return -EINVAL;

                path = strdup(empty_to_root(raw.path));
                if (!path)
                        return -ENOMEM;

                for (size_t j = 0; j < i; j++)
                        if (message->entries[j].property == property && streq(message->paths[j], path))
                                return -EEXIST;

                has_limit = sd_json_variant_by_key(element, "limit");
                has_duration = sd_json_variant_by_key(element, "duration");
                has_rules = sd_json_variant_by_key(element, "rules");

                message->paths[i] = TAKE_PTR(path);
                message->entries[i] = (OomdPolicySnapshotEntry) {
                        .property = property,
                        .path = message->paths[i],
                };

                if (is_auto) {
                        if (has_limit || has_duration || has_rules)
                                return -EINVAL;

                        continue;
                }

                switch (property) {
                case OOMD_POLICY_SWAP:
                        if (has_limit || has_duration || has_rules)
                                return -EINVAL;
                        break;

                case OOMD_POLICY_MEMORY_PRESSURE:
                        if (has_rules)
                                return -EINVAL;

                        message->values[i].pressure_limit = raw.limit;
                        message->values[i].pressure_duration_usec = raw.duration;
                        break;

                case OOMD_POLICY_RULES:
                        if (has_limit || has_duration || strv_isempty(raw.rules))
                                return -EINVAL;

                        strv_uniq(raw.rules);
                        message->values[i].rules = TAKE_PTR(raw.rules);
                        break;

                default:
                        assert_not_reached();
                }

                message->entries[i].value = message->values + i;
        }

        *ret = TAKE_PTR(message);
        return 0;
}

const OomdPolicySnapshotEntry *oomd_reporter_message_entries(const OomdReporterMessage *message) {
        assert(message);

        return message->entries;
}

size_t oomd_reporter_message_size(const OomdReporterMessage *message) {
        assert(message);

        return message->n_entries;
}
