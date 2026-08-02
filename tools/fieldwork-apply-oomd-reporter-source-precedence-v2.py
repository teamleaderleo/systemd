#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Run the reporter-source prototype injector with corrected, atomic semantics."""

from __future__ import annotations

import importlib.util
import pathlib
import sys


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise ValueError(f"{label}: expected one exact anchor, found {count}")
    return source.replace(old, new, 1)


def make_atomic(block: str) -> str:
    block = replace_once(
        block,
        """typedef enum ManagedOOMReporter {
        MANAGED_OOM_REPORTER_SYSTEM,
        MANAGED_OOM_REPORTER_USER,
} ManagedOOMReporter;
""",
        """typedef enum ManagedOOMReporter {
        MANAGED_OOM_REPORTER_SYSTEM,
        MANAGED_OOM_REPORTER_USER,
        _MANAGED_OOM_REPORTER_INVALID = -EINVAL,
} ManagedOOMReporter;
""",
        "reporter enum",
    )

    block = replace_once(
        block,
        """static int manager_recompute_managed_oom_effective(
                Manager *m,
                const char *property,
                const char *path) {
""",
        """static int manager_recompute_managed_oom_effective(
                Manager *m,
                const char *property,
                const char *path,
                ManagedOOMReporter ignored_reporter) {
""",
        "recompute signature",
    )

    block = replace_once(
        block,
        """        system_ctx = hashmap_get(system_hm, path);
        user_ctx = hashmap_get(user_hm, path);
        selected = system_ctx ?: user_ctx;
""",
        """        system_ctx = ignored_reporter == MANAGED_OOM_REPORTER_SYSTEM ? NULL : hashmap_get(system_hm, path);
        user_ctx = ignored_reporter == MANAGED_OOM_REPORTER_USER ? NULL : hashmap_get(user_hm, path);
        selected = system_ctx ?: user_ctx;
""",
        "staged reporter withdrawal",
    )

    block = replace_once(
        block,
        """        if (!ctx) {
                r = oomd_insert_cgroup_context(NULL, effective_hm, path);
                if (r < 0)
                        return r;

                ctx = ASSERT_PTR(hashmap_get(effective_hm, path));
        }

        if (streq(property, \"ManagedOOMMemoryPressure\")) {
                if (ctx->mem_pressure_limit != selected->mem_pressure_limit ||
                    ctx->mem_pressure_duration_usec != selected->mem_pressure_duration_usec)
                        ctx->mem_pressure_limit_hit_start = 0;

                ctx->mem_pressure_limit = selected->mem_pressure_limit;
                ctx->mem_pressure_duration_usec = selected->mem_pressure_duration_usec;
        } else if (streq(property, \"OOMRules\")) {
                rules = strv_copy(selected->rules);
                if (selected->rules && !rules)
                        return -ENOMEM;

                STRV_FOREACH(old_rule, ctx->rules) {
""",
        """        /* Complete all fallible rule-list allocation before mutating the effective map. */
        if (streq(property, \"OOMRules\")) {
                rules = strv_copy(selected->rules);
                if (selected->rules && !rules)
                        return -ENOMEM;
        }

        if (!ctx) {
                r = oomd_insert_cgroup_context(NULL, effective_hm, path);
                if (r < 0)
                        return r;

                ctx = ASSERT_PTR(hashmap_get(effective_hm, path));
        }

        if (streq(property, \"ManagedOOMMemoryPressure\")) {
                if (ctx->mem_pressure_limit != selected->mem_pressure_limit ||
                    ctx->mem_pressure_duration_usec != selected->mem_pressure_duration_usec)
                        ctx->mem_pressure_limit_hit_start = 0;

                ctx->mem_pressure_limit = selected->mem_pressure_limit;
                ctx->mem_pressure_duration_usec = selected->mem_pressure_duration_usec;
        } else if (streq(property, \"OOMRules\")) {
                STRV_FOREACH(old_rule, ctx->rules) {
""",
        "preallocate effective rules",
    )

    block = replace_once(
        block,
        """                OomdCGroupContext *ctx;
                Hashmap *contribution_hm;
                loadavg_t limit;
                usec_t duration;
""",
        """                _cleanup_strv_free_ char **previous_rules = NULL;
                OomdCGroupContext *ctx;
                Hashmap *contribution_hm;
                bool contribution_inserted = false;
                loadavg_t limit, previous_limit = {};
                usec_t duration, previous_duration = USEC_INFINITY;
""",
        "transaction snapshots",
    )

    block = replace_once(
        block,
        """                if (message.mode == MANAGED_OOM_AUTO) {
                        (void) oomd_cgroup_context_unref(hashmap_remove(
                                        contribution_hm, empty_to_root(message.path)));

                        r = manager_recompute_managed_oom_effective(m, message.property, message.path);
                        if (r == -ENOMEM)
                                return r;
                        if (r < 0)
                                log_debug_errno(r, \"Failed to recompute ManagedOOM policy for %s, ignoring: %m\", message.path);
                        continue;
                }
""",
        """                if (message.mode == MANAGED_OOM_AUTO) {
                        /* Stage effective state while the old source contribution is still present,
                         * then remove the source only after the fallible recomputation succeeds. */
                        r = manager_recompute_managed_oom_effective(
                                        m, message.property, message.path, reporter);
                        if (r == -ENOMEM)
                                return r;
                        if (r < 0) {
                                log_debug_errno(r, \"Failed to recompute ManagedOOM policy for %s, ignoring: %m\", message.path);
                                continue;
                        }

                        (void) oomd_cgroup_context_unref(hashmap_remove(
                                        contribution_hm, empty_to_root(message.path)));
                        continue;
                }
""",
        "atomic auto withdrawal",
    )

    block = replace_once(
        block,
        """                ctx = hashmap_get(contribution_hm, empty_to_root(message.path));
                if (!ctx) {
                        r = oomd_insert_cgroup_context(NULL, contribution_hm, message.path);
                        if (r == -ENOMEM)
                                return r;
                        if (r < 0) {
                                log_debug_errno(r, \"Failed to insert ManagedOOM contribution, ignoring: %m\");
                                continue;
                        }

                        ctx = ASSERT_PTR(hashmap_get(contribution_hm, empty_to_root(message.path)));
                }

                if (streq(message.property, \"ManagedOOMMemoryPressure\")) {
                        ctx->mem_pressure_limit = limit;
                        ctx->mem_pressure_duration_usec = duration;
                } else if (streq(message.property, \"OOMRules\")) {
                        strv_free_and_replace(ctx->rules, message.rules);
                        strv_uniq(ctx->rules);

                        STRV_FOREACH(rule, ctx->rules)
                                if (!hashmap_contains(m->rulesets, *rule))
                                        log_warning(\"Cgroup %s references undefined ruleset '%s', it will be ignored.\",
                                                    ctx->path, *rule);
                }

                r = manager_recompute_managed_oom_effective(m, message.property, message.path);
                if (r == -ENOMEM)
                        return r;
                if (r < 0)
                        log_debug_errno(r, \"Failed to recompute ManagedOOM policy for %s, ignoring: %m\", message.path);
""",
        """                ctx = hashmap_get(contribution_hm, empty_to_root(message.path));
                if (!ctx) {
                        r = oomd_insert_cgroup_context(NULL, contribution_hm, message.path);
                        if (r == -ENOMEM)
                                return r;
                        if (r < 0) {
                                log_debug_errno(r, \"Failed to insert ManagedOOM contribution, ignoring: %m\");
                                continue;
                        }

                        contribution_inserted = true;
                        ctx = ASSERT_PTR(hashmap_get(contribution_hm, empty_to_root(message.path)));
                } else if (streq(message.property, \"ManagedOOMMemoryPressure\")) {
                        previous_limit = ctx->mem_pressure_limit;
                        previous_duration = ctx->mem_pressure_duration_usec;
                } else if (streq(message.property, \"OOMRules\"))
                        previous_rules = TAKE_PTR(ctx->rules);

                if (streq(message.property, \"ManagedOOMMemoryPressure\")) {
                        ctx->mem_pressure_limit = limit;
                        ctx->mem_pressure_duration_usec = duration;
                } else if (streq(message.property, \"OOMRules\")) {
                        strv_free_and_replace(ctx->rules, message.rules);
                        strv_uniq(ctx->rules);

                        STRV_FOREACH(rule, ctx->rules)
                                if (!hashmap_contains(m->rulesets, *rule))
                                        log_warning(\"Cgroup %s references undefined ruleset '%s', it will be ignored.\",
                                                    ctx->path, *rule);
                }

                r = manager_recompute_managed_oom_effective(
                                m, message.property, message.path, _MANAGED_OOM_REPORTER_INVALID);
                if (r < 0) {
                        /* Publish contribution and effective state as one transaction. */
                        if (contribution_inserted)
                                (void) oomd_cgroup_context_unref(hashmap_remove(
                                                contribution_hm, empty_to_root(message.path)));
                        else if (streq(message.property, \"ManagedOOMMemoryPressure\")) {
                                ctx->mem_pressure_limit = previous_limit;
                                ctx->mem_pressure_duration_usec = previous_duration;
                        } else if (streq(message.property, \"OOMRules\"))
                                strv_free_and_replace(ctx->rules, previous_rules);

                        if (r == -ENOMEM)
                                return r;

                        log_debug_errno(r, \"Failed to recompute ManagedOOM policy for %s, ignoring: %m\", message.path);
                        continue;
                }
""",
        "atomic explicit contribution",
    )

    return block


def main() -> int:
    implementation = pathlib.Path(__file__).with_name(
        "fieldwork-apply-oomd-reporter-source-precedence.py"
    )
    spec = importlib.util.spec_from_file_location(
        "fieldwork_oomd_source_precedence_impl", implementation
    )
    if spec is None or spec.loader is None:
        print(f"failed to load injector: {implementation}", file=sys.stderr)
        return 2

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    # Current oomd-manager.c has one return-site and one assignment-site. Match
    # their common call expression while preserving each surrounding prefix.
    module.OLD_CALL = "process_managed_oom_message(m, uid, parameters);"
    module.USER_CALL = (
        "process_managed_oom_message("
        "m, MANAGED_OOM_REPORTER_USER, uid, parameters);"
    )
    module.SYSTEM_CALL = (
        "process_managed_oom_message("
        "m, MANAGED_OOM_REPORTER_SYSTEM, uid, parameters);"
    )

    try:
        module.PROCESS_BLOCK = make_atomic(module.PROCESS_BLOCK)
    except ValueError as exc:
        print(f"failed to harden reporter-source prototype: {exc}", file=sys.stderr)
        return 2

    return module.main()


if __name__ == "__main__":
    raise SystemExit(main())
