/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>

#include "oomd-reporter-registry.h"

typedef uint64_t OomdReporterLinkId;

typedef enum OomdReporterAdapterTimerAction {
        OOMD_REPORTER_ADAPTER_TIMER_NO_ACTION,
        OOMD_REPORTER_ADAPTER_TIMER_ARM_OR_REPLACE_GRACE,
        OOMD_REPORTER_ADAPTER_TIMER_CANCEL_GRACE,
        _OOMD_REPORTER_ADAPTER_TIMER_ACTION_MAX,
        _OOMD_REPORTER_ADAPTER_TIMER_ACTION_INVALID = -EINVAL,
} OomdReporterAdapterTimerAction;

typedef struct OomdReporterAdapterEvent {
        OomdReporterAdapterTimerAction timer_action;
        OomdReporterSession grace_session;
} OomdReporterAdapterEvent;

typedef struct OomdReporterAdapter OomdReporterAdapter;

OomdReporterAdapter *oomd_reporter_adapter_free(OomdReporterAdapter *adapter);
int oomd_reporter_adapter_new(OomdReporterAdapter **ret);

int oomd_reporter_adapter_connect(
                OomdReporterAdapter *adapter,
                OomdReporterLinkId link_id,
                OomdReporterAuthority authority,
                OomdReporterSession *ret_session,
                OomdReporterAdapterEvent *ret_event);

int oomd_reporter_adapter_first_snapshot(
                OomdReporterAdapter *adapter,
                OomdReporterLinkId link_id,
                const OomdPolicySnapshotEntry *entries,
                size_t n_entries,
                OomdReporterAdapterEvent *ret_event);

int oomd_reporter_adapter_update(
                OomdReporterAdapter *adapter,
                OomdReporterLinkId link_id,
                OomdPolicyProperty property,
                const char *path,
                const OomdPolicyValue *value);

int oomd_reporter_adapter_disconnect(
                OomdReporterAdapter *adapter,
                OomdReporterLinkId link_id,
                OomdReporterAdapterEvent *ret_event);

int oomd_reporter_adapter_expire_grace(
                OomdReporterAdapter *adapter,
                OomdReporterSession grace_session);

int oomd_reporter_adapter_get_effective(
                OomdReporterAdapter *adapter,
                OomdPolicyProperty property,
                const char *path,
                OomdPolicyDecision *ret);

size_t oomd_reporter_adapter_size(OomdReporterAdapter *adapter);

DEFINE_TRIVIAL_CLEANUP_FUNC(OomdReporterAdapter*, oomd_reporter_adapter_free);
