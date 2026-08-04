/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "macro.h"
#include "time-util.h"
#include "user-util.h"

typedef enum OomdReporterKind {
        OOMD_REPORTER_USER_MANAGER,
        OOMD_REPORTER_SYSTEM_MANAGER,
        _OOMD_REPORTER_KIND_MAX,
        _OOMD_REPORTER_KIND_INVALID = -EINVAL,
} OomdReporterKind;

typedef enum OomdPolicyProperty {
        OOMD_POLICY_SWAP,
        OOMD_POLICY_MEMORY_PRESSURE,
        OOMD_POLICY_RULES,
        _OOMD_POLICY_PROPERTY_MAX,
        _OOMD_POLICY_PROPERTY_INVALID = -EINVAL,
} OomdPolicyProperty;

typedef struct OomdReporterAuthority {
        OomdReporterKind kind;
        uid_t uid;
} OomdReporterAuthority;

typedef struct OomdPolicyValue {
        uint32_t pressure_limit;
        usec_t pressure_duration_usec;
        char **rules;
} OomdPolicyValue;

typedef struct OomdPolicyDecision {
        OomdReporterAuthority authority;
        OomdPolicyValue value;
} OomdPolicyDecision;

typedef struct OomdPolicySnapshotEntry {
        OomdPolicyProperty property;
        const char *path;
        const OomdPolicyValue *value;
} OomdPolicySnapshotEntry;

typedef struct OomdPolicyStore OomdPolicyStore;

void oomd_policy_value_done(OomdPolicyValue *value);
void oomd_policy_decision_done(OomdPolicyDecision *decision);

OomdPolicyStore *oomd_policy_store_free(OomdPolicyStore *store);
int oomd_policy_store_new(OomdPolicyStore **ret);

int oomd_policy_store_update(
                OomdPolicyStore *store,
                OomdReporterAuthority authority,
                OomdPolicyProperty property,
                const char *path,
                const OomdPolicyValue *value);

int oomd_policy_store_replace_snapshot(
                OomdPolicyStore *store,
                OomdReporterAuthority authority,
                const OomdPolicySnapshotEntry *entries,
                size_t n_entries);

int oomd_policy_store_get_effective(
                const OomdPolicyStore *store,
                OomdPolicyProperty property,
                const char *path,
                OomdPolicyDecision *ret);

size_t oomd_policy_store_size(const OomdPolicyStore *store);

DEFINE_TRIVIAL_CLEANUP_FUNC(OomdPolicyStore*, oomd_policy_store_free);

static inline void oomd_policy_value_donep(OomdPolicyValue *value) {
        oomd_policy_value_done(value);
}

static inline void oomd_policy_decision_donep(OomdPolicyDecision *decision) {
        oomd_policy_decision_done(decision);
}
