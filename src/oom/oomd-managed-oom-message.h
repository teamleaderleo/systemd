/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "cgroup-util.h"
#include "macro.h"
#include "oomd-policy.h"
#include "sd-json.h"
#include "time-util.h"

typedef struct OomdManagedOOMMessage {
        ManagedOOMMode mode;
        OomdPolicyProperty property;
        char *path;
        uint32_t limit;
        usec_t duration;
        char **rules;
} OomdManagedOOMMessage;

typedef struct OomdManagedOOMMessageBatch {
        OomdManagedOOMMessage *items;
        size_t n_items;
} OomdManagedOOMMessageBatch;

void oomd_managed_oom_message_batch_done(OomdManagedOOMMessageBatch *batch);

int oomd_managed_oom_message_batch_parse(
                sd_json_variant *parameters,
                OomdManagedOOMMessageBatch *ret);

static inline void oomd_managed_oom_message_batch_donep(OomdManagedOOMMessageBatch *batch) {
        oomd_managed_oom_message_batch_done(batch);
}
