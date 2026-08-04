/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "oomd-policy.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"

typedef struct OomdPolicyContribution {
        OomdReporterAuthority authority;
        OomdPolicyProperty property;
        char *path;
        OomdPolicyValue value;
} OomdPolicyContribution;

struct OomdPolicyStore {
        OomdPolicyContribution *items;
        size_t n_items;
};

void oomd_policy_value_done(OomdPolicyValue *value) {
        if (!value)
                return;

        value->rules = strv_free(value->rules);
        *value = (OomdPolicyValue) {};
}

void oomd_policy_decision_done(OomdPolicyDecision *decision) {
        if (!decision)
                return;

        oomd_policy_value_done(&decision->value);
        *decision = (OomdPolicyDecision) {};
}

static void contribution_done(OomdPolicyContribution *item) {
        if (!item)
                return;

        free(item->path);
        oomd_policy_value_done(&item->value);
        *item = (OomdPolicyContribution) {};
}

static void contribution_array_free(OomdPolicyContribution *items, size_t n_items) {
        FOREACH_ARRAY(item, items, n_items)
                contribution_done(item);
        free(items);
}

static bool authority_valid(OomdReporterAuthority authority) {
        return authority.kind >= 0 && authority.kind < _OOMD_REPORTER_KIND_MAX && uid_is_valid(authority.uid);
}

static bool property_valid(OomdPolicyProperty property) {
        return property >= 0 && property < _OOMD_POLICY_PROPERTY_MAX;
}

static bool value_valid_for_property(OomdPolicyProperty property, const OomdPolicyValue *value) {
        assert(value);

        switch (property) {
        case OOMD_POLICY_SWAP:
                return value->pressure_limit == 0 &&
                       value->pressure_duration_usec == 0 &&
                       strv_isempty(value->rules);

        case OOMD_POLICY_MEMORY_PRESSURE:
                return strv_isempty(value->rules);

        case OOMD_POLICY_RULES:
                return value->pressure_limit == 0 &&
                       value->pressure_duration_usec == 0 &&
                       !strv_isempty(value->rules);

        default:
                return false;
        }
}

static int value_copy(OomdPolicyValue *ret, const OomdPolicyValue *value) {
        _cleanup_strv_free_ char **rules = NULL;

        assert(ret);
        assert(value);

        rules = strv_copy(value->rules);
        if (value->rules && !rules)
                return -ENOMEM;

        *ret = (OomdPolicyValue) {
                .pressure_limit = value->pressure_limit,
                .pressure_duration_usec = value->pressure_duration_usec,
                .rules = TAKE_PTR(rules),
        };
        return 0;
}

static int contribution_copy(OomdPolicyContribution *ret, const OomdPolicyContribution *item) {
        int r;

        assert(ret);
        assert(item);

        *ret = (OomdPolicyContribution) {
                .authority = item->authority,
                .property = item->property,
                .path = strdup(item->path),
        };
        if (!ret->path)
                return -ENOMEM;

        r = value_copy(&ret->value, &item->value);
        if (r < 0) {
                contribution_done(ret);
                return r;
        }

        return 0;
}

static int contribution_from_parts(
                OomdPolicyContribution *ret,
                OomdReporterAuthority authority,
                OomdPolicyProperty property,
                const char *path,
                const OomdPolicyValue *value) {

        int r;

        assert(ret);

        if (!authority_valid(authority) ||
            !property_valid(property) ||
            !value ||
            !value_valid_for_property(property, value))
                return -EINVAL;
        if (!path_is_absolute(path) || !path_is_normalized(path))
                return -EINVAL;

        *ret = (OomdPolicyContribution) {
                .authority = authority,
                .property = property,
                .path = strdup(path),
        };
        if (!ret->path)
                return -ENOMEM;

        r = value_copy(&ret->value, value);
        if (r < 0) {
                contribution_done(ret);
                return r;
        }

        return 0;
}

static bool same_key(
                const OomdPolicyContribution *item,
                OomdReporterAuthority authority,
                OomdPolicyProperty property,
                const char *path) {

        return item->authority.kind == authority.kind &&
               item->authority.uid == authority.uid &&
               item->property == property &&
               streq(item->path, path);
}

static int append_copy(
                OomdPolicyContribution *items,
                size_t capacity,
                size_t *n_items,
                const OomdPolicyContribution *source) {

        int r;

        assert(items || capacity == 0);
        assert(n_items);
        assert(*n_items < capacity);

        r = contribution_copy(items + *n_items, source);
        if (r < 0)
                return r;

        (*n_items)++;
        return 0;
}

OomdPolicyStore *oomd_policy_store_free(OomdPolicyStore *store) {
        if (!store)
                return NULL;

        contribution_array_free(store->items, store->n_items);
        return mfree(store);
}

int oomd_policy_store_new(OomdPolicyStore **ret) {
        _cleanup_(oomd_policy_store_freep) OomdPolicyStore *store = NULL;

        assert(ret);

        store = new0(OomdPolicyStore, 1);
        if (!store)
                return -ENOMEM;

        *ret = TAKE_PTR(store);
        return 0;
}

int oomd_policy_store_update(
                OomdPolicyStore *store,
                OomdReporterAuthority authority,
                OomdPolicyProperty property,
                const char *path,
                const OomdPolicyValue *value) {

        _cleanup_free_ OomdPolicyContribution *candidate = NULL;
        size_t capacity, n_candidate = 0;
        int r;

        assert(store);

        if (!authority_valid(authority) || !property_valid(property))
                return -EINVAL;
        if (!path_is_absolute(path) || !path_is_normalized(path))
                return -EINVAL;

        capacity = store->n_items + !!value;
        candidate = new0(OomdPolicyContribution, capacity);
        if (!candidate && capacity > 0)
                return -ENOMEM;

        FOREACH_ARRAY(item, store->items, store->n_items) {
                if (same_key(item, authority, property, path))
                        continue;

                r = append_copy(candidate, capacity, &n_candidate, item);
                if (r < 0)
                        goto fail;
        }

        if (value) {
                r = contribution_from_parts(candidate + n_candidate, authority, property, path, value);
                if (r < 0)
                        goto fail;
                n_candidate++;
        }

        contribution_array_free(store->items, store->n_items);
        store->items = TAKE_PTR(candidate);
        store->n_items = n_candidate;
        return 0;

fail:
        contribution_array_free(TAKE_PTR(candidate), n_candidate);
        return r;
}

int oomd_policy_store_replace_snapshot(
                OomdPolicyStore *store,
                OomdReporterAuthority authority,
                const OomdPolicySnapshotEntry *entries,
                size_t n_entries) {

        _cleanup_free_ OomdPolicyContribution *candidate = NULL;
        size_t keep = 0, n_candidate = 0;
        int r;

        assert(store);
        assert(entries || n_entries == 0);

        if (!authority_valid(authority))
                return -EINVAL;

        FOREACH_ARRAY(item, store->items, store->n_items)
                if (item->authority.kind != authority.kind || item->authority.uid != authority.uid)
                        keep++;

        candidate = new0(OomdPolicyContribution, keep + n_entries);
        if (!candidate && keep + n_entries > 0)
                return -ENOMEM;

        FOREACH_ARRAY(item, store->items, store->n_items) {
                if (item->authority.kind == authority.kind && item->authority.uid == authority.uid)
                        continue;

                r = append_copy(candidate, keep + n_entries, &n_candidate, item);
                if (r < 0)
                        goto fail;
        }

        FOREACH_ARRAY(entry, entries, n_entries) {
                for (size_t i = keep; i < n_candidate; i++)
                        if (candidate[i].property == entry->property && streq(candidate[i].path, entry->path)) {
                                r = -EEXIST;
                                goto fail;
                        }

                r = contribution_from_parts(
                                candidate + n_candidate,
                                authority,
                                entry->property,
                                entry->path,
                                entry->value);
                if (r < 0)
                        goto fail;
                n_candidate++;
        }

        contribution_array_free(store->items, store->n_items);
        store->items = TAKE_PTR(candidate);
        store->n_items = n_candidate;
        return 0;

fail:
        contribution_array_free(TAKE_PTR(candidate), n_candidate);
        return r;
}

static int reporter_rank(OomdReporterKind kind) {
        return kind == OOMD_REPORTER_SYSTEM_MANAGER ? 1 : 0;
}

int oomd_policy_store_get_effective(
                const OomdPolicyStore *store,
                OomdPolicyProperty property,
                const char *path,
                OomdPolicyDecision *ret) {

        const OomdPolicyContribution *selected = NULL;
        bool ambiguous = false;
        int r, selected_rank = -1;

        assert(store);
        assert(ret);

        if (!property_valid(property) || !path_is_absolute(path) || !path_is_normalized(path))
                return -EINVAL;

        FOREACH_ARRAY(item, store->items, store->n_items) {
                int rank;

                if (item->property != property || !streq(item->path, path))
                        continue;

                rank = reporter_rank(item->authority.kind);
                if (!selected || rank > selected_rank) {
                        selected = item;
                        selected_rank = rank;
                        ambiguous = false;
                        continue;
                }

                if (rank == selected_rank && item->authority.uid != selected->authority.uid)
                        ambiguous = true;
        }

        if (!selected)
                return 0;
        if (ambiguous)
                return -ENOTUNIQ;

        *ret = (OomdPolicyDecision) { .authority = selected->authority };
        r = value_copy(&ret->value, &selected->value);
        if (r < 0) {
                oomd_policy_decision_done(ret);
                return r;
        }

        return 1;
}

size_t oomd_policy_store_size(const OomdPolicyStore *store) {
        assert(store);

        return store->n_items;
}
