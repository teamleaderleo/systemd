/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "oomd-managed-oom-message.h"
#include "oomd-policy.h"
#include "time-util.h"

typedef struct OomdManagedOOMDefaults {
        uint32_t memory_pressure_limit_permyriad;
        usec_t memory_pressure_duration_usec;
} OomdManagedOOMDefaults;

typedef int (*OomdManagedOOMOwnerLookup)(
                const char *path,
                uid_t *ret_owner,
                void *userdata);

typedef struct OomdManagedOOMPolicyBatch OomdManagedOOMPolicyBatch;

OomdManagedOOMPolicyBatch *oomd_managed_oom_policy_batch_free(OomdManagedOOMPolicyBatch *batch);

int oomd_managed_oom_policy_batch_resolve(
                const OomdManagedOOMMessageBatch *message,
                OomdReporterAuthority authority,
                const OomdManagedOOMDefaults *defaults,
                OomdManagedOOMOwnerLookup owner_lookup,
                void *owner_userdata,
                OomdManagedOOMPolicyBatch **ret);

const OomdPolicySnapshotEntry *oomd_managed_oom_policy_batch_entries(const OomdManagedOOMPolicyBatch *batch);
size_t oomd_managed_oom_policy_batch_size(const OomdManagedOOMPolicyBatch *batch);

DEFINE_TRIVIAL_CLEANUP_FUNC(OomdManagedOOMPolicyBatch*, oomd_managed_oom_policy_batch_free);
