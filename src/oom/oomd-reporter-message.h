/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>

#include "sd-json.h"

#include "oomd-policy.h"

typedef struct OomdReporterMessage OomdReporterMessage;

OomdReporterMessage *oomd_reporter_message_free(OomdReporterMessage *message);

int oomd_reporter_message_parse(
                sd_json_variant *parameters,
                OomdReporterMessage **ret);

const OomdPolicySnapshotEntry *oomd_reporter_message_entries(const OomdReporterMessage *message);
size_t oomd_reporter_message_size(const OomdReporterMessage *message);

DEFINE_TRIVIAL_CLEANUP_FUNC(OomdReporterMessage*, oomd_reporter_message_free);
