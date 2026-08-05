/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "oomd-policy.h"
#include "oomd-reporter-lifecycle.h"

typedef struct OomdReporterRegistry OomdReporterRegistry;

OomdReporterRegistry *oomd_reporter_registry_free(OomdReporterRegistry *registry);
int oomd_reporter_registry_new(OomdReporterRegistry **ret);

int oomd_reporter_registry_begin(
                OomdReporterRegistry *registry,
                OomdReporterAuthority authority,
                OomdReporterSession *ret_session);

int oomd_reporter_registry_replace_snapshot(
                OomdReporterRegistry *registry,
                OomdReporterSession session,
                const OomdPolicySnapshotEntry *entries,
                size_t n_entries);

int oomd_reporter_registry_update(
                OomdReporterRegistry *registry,
                OomdReporterSession session,
                OomdPolicyProperty property,
                const char *path,
                const OomdPolicyValue *value);

int oomd_reporter_registry_disconnect(
                OomdReporterRegistry *registry,
                OomdReporterSession session);

int oomd_reporter_registry_expire_pending_grace(
                OomdReporterRegistry *registry,
                OomdReporterSession pending_session);

int oomd_reporter_registry_get_effective(
                OomdReporterRegistry *registry,
                OomdPolicyProperty property,
                const char *path,
                OomdPolicyDecision *ret);

size_t oomd_reporter_registry_size(OomdReporterRegistry *registry);

DEFINE_TRIVIAL_CLEANUP_FUNC(OomdReporterRegistry*, oomd_reporter_registry_free);
