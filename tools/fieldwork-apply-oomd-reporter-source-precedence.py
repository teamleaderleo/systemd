#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Apply the bounded reporter-source precedence prototype to a systemd checkout.

The prototype keeps system-manager and user-manager ManagedOOM contributions
separate, then derives the existing effective cgroup maps with system-manager
precedence. It is intentionally limited to policy ownership; reporter
connection lifetime cleanup is a follow-up patch.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

MANAGER_FIELDS_ANCHOR = """        Hashmap *monitored_rules_cgroup_contexts;
        Hashmap *monitored_rules_cgroup_contexts_candidates;

        OomdSystemContext system_context;
"""

MANAGER_FIELDS_REPLACEMENT = """        Hashmap *monitored_rules_cgroup_contexts;
        Hashmap *monitored_rules_cgroup_contexts_candidates;

        /* Source contributions are kept separate from the effective maps above.
         * PID 1 is authoritative when both manager classes report the same path. */
        Hashmap *system_managed_oom_swap_cgroup_contexts;
        Hashmap *system_managed_oom_mem_pressure_cgroup_contexts;
        Hashmap *system_managed_oom_rules_cgroup_contexts;
        Hashmap *user_managed_oom_swap_cgroup_contexts;
        Hashmap *user_managed_oom_mem_pressure_cgroup_contexts;
        Hashmap *user_managed_oom_rules_cgroup_contexts;

        OomdSystemContext system_context;
"""

PROCESS_BLOCK = r'''typedef enum ManagedOOMReporter {
        MANAGED_OOM_REPORTER_SYSTEM,
        MANAGED_OOM_REPORTER_USER,
} ManagedOOMReporter;

static Hashmap* manager_get_managed_oom_contribution_hashmap(
                Manager *m,
                ManagedOOMReporter reporter,
                const char *property) {

        assert(m);
        assert(property);

        if (streq(property, "ManagedOOMSwap"))
                return reporter == MANAGED_OOM_REPORTER_SYSTEM ?
                        m->system_managed_oom_swap_cgroup_contexts :
                        m->user_managed_oom_swap_cgroup_contexts;
        if (streq(property, "ManagedOOMMemoryPressure"))
                return reporter == MANAGED_OOM_REPORTER_SYSTEM ?
                        m->system_managed_oom_mem_pressure_cgroup_contexts :
                        m->user_managed_oom_mem_pressure_cgroup_contexts;
        if (streq(property, "OOMRules"))
                return reporter == MANAGED_OOM_REPORTER_SYSTEM ?
                        m->system_managed_oom_rules_cgroup_contexts :
                        m->user_managed_oom_rules_cgroup_contexts;

        return NULL;
}

static Hashmap* manager_get_managed_oom_effective_hashmap(Manager *m, const char *property) {
        assert(m);
        assert(property);

        if (streq(property, "ManagedOOMSwap"))
                return m->monitored_swap_cgroup_contexts;
        if (streq(property, "ManagedOOMMemoryPressure"))
                return m->monitored_mem_pressure_cgroup_contexts;
        if (streq(property, "OOMRules"))
                return m->monitored_rules_cgroup_contexts;

        return NULL;
}

static void manager_clear_ruleset_start_times(Manager *m, const char *path) {
        OomdRuleset *ruleset;

        assert(m);
        assert(path);

        HASHMAP_FOREACH(ruleset, m->rulesets) {
                _cleanup_free_ char *key = NULL;

                free(hashmap_remove2(ruleset->start_times, path, (void **) &key));
        }
}

static int manager_recompute_managed_oom_effective(
                Manager *m,
                const char *property,
                const char *path) {

        _cleanup_strv_free_ char **rules = NULL;
        OomdCGroupContext *ctx, *selected, *system_ctx, *user_ctx;
        Hashmap *effective_hm, *system_hm, *user_hm;
        int r;

        assert(m);
        assert(property);
        assert(path);

        path = empty_to_root(path);
        effective_hm = ASSERT_PTR(manager_get_managed_oom_effective_hashmap(m, property));
        system_hm = ASSERT_PTR(manager_get_managed_oom_contribution_hashmap(
                        m, MANAGED_OOM_REPORTER_SYSTEM, property));
        user_hm = ASSERT_PTR(manager_get_managed_oom_contribution_hashmap(
                        m, MANAGED_OOM_REPORTER_USER, property));

        system_ctx = hashmap_get(system_hm, path);
        user_ctx = hashmap_get(user_hm, path);
        selected = system_ctx ?: user_ctx;
        ctx = hashmap_get(effective_hm, path);

        if (!selected) {
                if (streq(property, "OOMRules"))
                        manager_clear_ruleset_start_times(m, path);

                (void) oomd_cgroup_context_unref(hashmap_remove(effective_hm, path));
                return 0;
        }

        if (!ctx) {
                r = oomd_insert_cgroup_context(NULL, effective_hm, path);
                if (r < 0)
                        return r;

                ctx = ASSERT_PTR(hashmap_get(effective_hm, path));
        }

        if (streq(property, "ManagedOOMMemoryPressure")) {
                if (ctx->mem_pressure_limit != selected->mem_pressure_limit ||
                    ctx->mem_pressure_duration_usec != selected->mem_pressure_duration_usec)
                        ctx->mem_pressure_limit_hit_start = 0;

                ctx->mem_pressure_limit = selected->mem_pressure_limit;
                ctx->mem_pressure_duration_usec = selected->mem_pressure_duration_usec;
        } else if (streq(property, "OOMRules")) {
                rules = strv_copy(selected->rules);
                if (selected->rules && !rules)
                        return -ENOMEM;

                STRV_FOREACH(old_rule, ctx->rules) {
                        OomdRuleset *dropped;
                        _cleanup_free_ char *key = NULL;

                        if (strv_contains(rules, *old_rule))
                                continue;

                        dropped = hashmap_get(m->rulesets, *old_rule);
                        if (!dropped)
                                continue;

                        free(hashmap_remove2(dropped->start_times, path, (void **) &key));
                }

                strv_free_and_replace(ctx->rules, rules);
        }

        return 0;
}

static int process_managed_oom_message(
                Manager *m,
                ManagedOOMReporter reporter,
                uid_t uid,
                sd_json_variant *parameters) {

        sd_json_variant *c, *cgroups;
        int r;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "mode",     SD_JSON_VARIANT_STRING,        dispatch_managed_oom_mode, offsetof(ManagedOOMMessage, mode),     SD_JSON_MANDATORY },
                { "path",     SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,   offsetof(ManagedOOMMessage, path),     SD_JSON_MANDATORY },
                { "property", SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,   offsetof(ManagedOOMMessage, property), SD_JSON_MANDATORY },
                { "limit",    _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint32,   offsetof(ManagedOOMMessage, limit),    0                 },
                { "duration", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,   offsetof(ManagedOOMMessage, duration), 0                 },
                { "rules",    _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_strv,     offsetof(ManagedOOMMessage, rules),    0                 },
                {},
        };

        assert(m);
        assert(parameters);

        cgroups = sd_json_variant_by_key(parameters, "cgroups");
        if (!cgroups)
                return -EINVAL;

        /* Skip malformed elements and keep processing in case the others are good. */
        JSON_VARIANT_ARRAY_FOREACH(c, cgroups) {
                _cleanup_(managed_oom_message_destroy) ManagedOOMMessage message = {
                        .duration = USEC_INFINITY,
                };
                OomdCGroupContext *ctx;
                Hashmap *contribution_hm;
                loadavg_t limit;
                usec_t duration;

                if (!sd_json_variant_is_object(c))
                        continue;

                r = sd_json_dispatch(c, dispatch_table, 0, &message);
                if (r == -ENOMEM)
                        return r;
                if (r < 0)
                        continue;

                if (!path_is_normalized(empty_to_root(message.path))) {
                        log_debug("Received non-normalized cgroup path '%s', ignoring.", message.path);
                        continue;
                }

                if (uid != 0) {
                        uid_t cg_uid;

                        r = cg_path_get_owner_uid(message.path, &cg_uid);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to get cgroup %s owner uid: %m", message.path);
                                continue;
                        }

                        if (uid != cg_uid)
                                return log_error_errno(SYNTHETIC_ERRNO(EPERM),
                                                       "cgroup path owner UID does not match sender uid "
                                                       "(" UID_FMT " != " UID_FMT ")", uid, cg_uid);
                }

                contribution_hm = manager_get_managed_oom_contribution_hashmap(m, reporter, message.property);
                if (!contribution_hm) {
                        log_debug("Unknown property '%s', ignoring.", message.property);
                        continue;
                }

                if (message.mode == MANAGED_OOM_AUTO) {
                        (void) oomd_cgroup_context_unref(hashmap_remove(
                                        contribution_hm, empty_to_root(message.path)));

                        r = manager_recompute_managed_oom_effective(m, message.property, message.path);
                        if (r == -ENOMEM)
                                return r;
                        if (r < 0)
                                log_debug_errno(r, "Failed to recompute ManagedOOM policy for %s, ignoring: %m", message.path);
                        continue;
                }

                limit = m->default_mem_pressure_limit;
                if (streq(message.property, "ManagedOOMMemoryPressure") && message.limit > 0) {
                        int permyriad = UINT32_SCALE_TO_PERMYRIAD(message.limit);

                        r = store_loadavg_fixed_point(permyriad / 100LU, permyriad % 100LU, &limit);
                        if (r < 0)
                                continue;
                }

                if (streq(message.property, "ManagedOOMMemoryPressure") && message.duration != USEC_INFINITY)
                        duration = message.duration;
                else
                        duration = m->default_mem_pressure_duration_usec;

                if (streq(message.property, "OOMRules") && strv_isempty(message.rules))
                        continue;

                ctx = hashmap_get(contribution_hm, empty_to_root(message.path));
                if (!ctx) {
                        r = oomd_insert_cgroup_context(NULL, contribution_hm, message.path);
                        if (r == -ENOMEM)
                                return r;
                        if (r < 0) {
                                log_debug_errno(r, "Failed to insert ManagedOOM contribution, ignoring: %m");
                                continue;
                        }

                        ctx = ASSERT_PTR(hashmap_get(contribution_hm, empty_to_root(message.path)));
                }

                if (streq(message.property, "ManagedOOMMemoryPressure")) {
                        ctx->mem_pressure_limit = limit;
                        ctx->mem_pressure_duration_usec = duration;
                } else if (streq(message.property, "OOMRules")) {
                        strv_free_and_replace(ctx->rules, message.rules);
                        strv_uniq(ctx->rules);

                        STRV_FOREACH(rule, ctx->rules)
                                if (!hashmap_contains(m->rulesets, *rule))
                                        log_warning("Cgroup %s references undefined ruleset '%s', it will be ignored.",
                                                    ctx->path, *rule);
                }

                r = manager_recompute_managed_oom_effective(m, message.property, message.path);
                if (r == -ENOMEM)
                        return r;
                if (r < 0)
                        log_debug_errno(r, "Failed to recompute ManagedOOM policy for %s, ignoring: %m", message.path);
        }

        r = sd_event_source_set_enabled(m->swap_context_event_source,
                                        hashmap_isempty(m->monitored_swap_cgroup_contexts) ? SD_EVENT_OFF : SD_EVENT_ON);
        if (r < 0)
                return log_error_errno(r, "Failed to toggle enabled state of swap context source: %m");

        r = sd_event_source_set_enabled(m->rules_context_event_source,
                                        hashmap_isempty(m->monitored_rules_cgroup_contexts) ? SD_EVENT_OFF : SD_EVENT_ON);
        if (r < 0)
                return log_error_errno(r, "Failed to toggle enabled state of rules context source: %m");

        return 0;
}
'''

FREE_ANCHOR = """        hashmap_free(m->monitored_rules_cgroup_contexts);
        hashmap_free(m->monitored_rules_cgroup_contexts_candidates);

        set_free(m->kill_states);
"""

FREE_REPLACEMENT = """        hashmap_free(m->monitored_rules_cgroup_contexts);
        hashmap_free(m->monitored_rules_cgroup_contexts_candidates);

        hashmap_free(m->system_managed_oom_swap_cgroup_contexts);
        hashmap_free(m->system_managed_oom_mem_pressure_cgroup_contexts);
        hashmap_free(m->system_managed_oom_rules_cgroup_contexts);
        hashmap_free(m->user_managed_oom_swap_cgroup_contexts);
        hashmap_free(m->user_managed_oom_mem_pressure_cgroup_contexts);
        hashmap_free(m->user_managed_oom_rules_cgroup_contexts);

        set_free(m->kill_states);
"""

INIT_ANCHOR = """        m->monitored_rules_cgroup_contexts_candidates = hashmap_new(&oomd_cgroup_ctx_hash_ops);
        if (!m->monitored_rules_cgroup_contexts_candidates)
                return -ENOMEM;

        *ret = TAKE_PTR(m);
"""

INIT_REPLACEMENT = """        m->monitored_rules_cgroup_contexts_candidates = hashmap_new(&oomd_cgroup_ctx_hash_ops);
        if (!m->monitored_rules_cgroup_contexts_candidates)
                return -ENOMEM;

        m->system_managed_oom_swap_cgroup_contexts = hashmap_new(&oomd_cgroup_ctx_hash_ops);
        if (!m->system_managed_oom_swap_cgroup_contexts)
                return -ENOMEM;

        m->system_managed_oom_mem_pressure_cgroup_contexts = hashmap_new(&oomd_cgroup_ctx_hash_ops);
        if (!m->system_managed_oom_mem_pressure_cgroup_contexts)
                return -ENOMEM;

        m->system_managed_oom_rules_cgroup_contexts = hashmap_new(&oomd_cgroup_ctx_hash_ops);
        if (!m->system_managed_oom_rules_cgroup_contexts)
                return -ENOMEM;

        m->user_managed_oom_swap_cgroup_contexts = hashmap_new(&oomd_cgroup_ctx_hash_ops);
        if (!m->user_managed_oom_swap_cgroup_contexts)
                return -ENOMEM;

        m->user_managed_oom_mem_pressure_cgroup_contexts = hashmap_new(&oomd_cgroup_ctx_hash_ops);
        if (!m->user_managed_oom_mem_pressure_cgroup_contexts)
                return -ENOMEM;

        m->user_managed_oom_rules_cgroup_contexts = hashmap_new(&oomd_cgroup_ctx_hash_ops);
        if (!m->user_managed_oom_rules_cgroup_contexts)
                return -ENOMEM;

        *ret = TAKE_PTR(m);
"""

OLD_CALL = "return process_managed_oom_message(m, uid, parameters);"
USER_CALL = "return process_managed_oom_message(m, MANAGED_OOM_REPORTER_USER, uid, parameters);"
SYSTEM_CALL = "r = process_managed_oom_message(m, MANAGED_OOM_REPORTER_SYSTEM, uid, parameters);"


def replace_exact(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise ValueError(f"{label}: expected one anchor, found {count}")
    return source.replace(old, new)


def patch_header(path: pathlib.Path) -> None:
    source = path.read_text(encoding="utf-8")
    source = replace_exact(source, MANAGER_FIELDS_ANCHOR, MANAGER_FIELDS_REPLACEMENT, "manager fields")
    path.write_text(source, encoding="utf-8")


def patch_manager(path: pathlib.Path) -> None:
    source = path.read_text(encoding="utf-8")

    start_marker = "static int process_managed_oom_message(Manager *m, uid_t uid, sd_json_variant *parameters) {"
    end_marker = "\nstatic int process_managed_oom_request("
    start = source.find(start_marker)
    end = source.find(end_marker, start)
    if start < 0 or end < 0:
        raise ValueError("process_managed_oom_message block anchors were not found")

    source = source[:start] + PROCESS_BLOCK + source[end:]

    if source.count(OLD_CALL) != 2:
        raise ValueError(f"expected two process calls, found {source.count(OLD_CALL)}")
    source = source.replace(OLD_CALL, USER_CALL, 1)
    source = source.replace(OLD_CALL, SYSTEM_CALL, 1)

    source = replace_exact(source, FREE_ANCHOR, FREE_REPLACEMENT, "manager free")
    source = replace_exact(source, INIT_ANCHOR, INIT_REPLACEMENT, "manager init")
    path.write_text(source, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=pathlib.Path)
    args = parser.parse_args()

    root = args.source.resolve()
    try:
        patch_header(root / "src/oom/oomd-manager.h")
        patch_manager(root / "src/oom/oomd-manager.c")
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        print(f"failed to apply reporter source precedence prototype: {exc}", file=sys.stderr)
        return 2

    print("applied reporter source precedence prototype")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
