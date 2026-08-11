/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "oomd-managed-oom-message.h"
#include "oomd-policy.h"
#include "time-util.h"

typedef struct OomdManagedOOMDefaults {
        uint32_t pressure_limit;
        usec_t pressure_duration_usec;
} OomdManagedOOMDefaults;

typedef int (*OomdManagedOOMAuthorizePath)(
                uid_t uid,
                const char *path,
                void *userdata);

typedef struct OomdManagedOOMPolicyBatch {
        OomdPolicySnapshotEntry *entries;
        char **paths;
        OomdPolicyValue *values;
        size_t n_entries;
} OomdManagedOOMPolicyBatch;

void oomd_managed_oom_policy_batch_done(OomdManagedOOMPolicyBatch *batch);

int oomd_managed_oom_policy_batch_resolve(
                const OomdManagedOOMMessageBatch *messages,
                OomdReporterAuthority authority,
                const OomdManagedOOMDefaults *defaults,
                OomdManagedOOMAuthorizePath authorize_path,
                void *authorize_userdata,
                OomdManagedOOMPolicyBatch *ret);

static inline void oomd_managed_oom_policy_batch_donep(OomdManagedOOMPolicyBatch *batch) {
        oomd_managed_oom_policy_batch_done(batch);
}
