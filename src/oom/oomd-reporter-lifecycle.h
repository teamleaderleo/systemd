/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "oomd-policy.h"

typedef enum OomdReporterLifecycleAction {
        OOMD_REPORTER_LIFECYCLE_NO_ACTION,
        OOMD_REPORTER_LIFECYCLE_REPLACE_SNAPSHOT,
        OOMD_REPORTER_LIFECYCLE_WITHDRAW_AUTHORITY,
        _OOMD_REPORTER_LIFECYCLE_ACTION_MAX,
        _OOMD_REPORTER_LIFECYCLE_ACTION_INVALID = -EINVAL,
} OomdReporterLifecycleAction;

typedef enum OomdReporterLifecycleTransitionKind {
        OOMD_REPORTER_LIFECYCLE_TRANSITION_NONE,
        OOMD_REPORTER_LIFECYCLE_TRANSITION_SNAPSHOT,
        OOMD_REPORTER_LIFECYCLE_TRANSITION_DISCONNECT_PENDING,
        OOMD_REPORTER_LIFECYCLE_TRANSITION_DISCONNECT_ACTIVE,
        OOMD_REPORTER_LIFECYCLE_TRANSITION_EXPIRE_PENDING_GRACE,
        _OOMD_REPORTER_LIFECYCLE_TRANSITION_KIND_MAX,
        _OOMD_REPORTER_LIFECYCLE_TRANSITION_KIND_INVALID = -EINVAL,
} OomdReporterLifecycleTransitionKind;

typedef struct OomdReporterSession {
        OomdReporterAuthority authority;
        uint64_t generation;
} OomdReporterSession;

typedef struct OomdReporterLifecycleTransition {
        OomdReporterLifecycleTransitionKind kind;
        OomdReporterLifecycleAction action;
        OomdReporterSession session;
} OomdReporterLifecycleTransition;

typedef struct OomdReporterLifecycle OomdReporterLifecycle;

OomdReporterLifecycle *oomd_reporter_lifecycle_free(OomdReporterLifecycle *lifecycle);
int oomd_reporter_lifecycle_new(OomdReporterLifecycle **ret);

int oomd_reporter_lifecycle_begin(
                OomdReporterLifecycle *lifecycle,
                OomdReporterAuthority authority,
                OomdReporterSession *ret_session);

int oomd_reporter_lifecycle_prepare_snapshot(
                OomdReporterLifecycle *lifecycle,
                OomdReporterSession session,
                OomdReporterLifecycleTransition *ret_transition);

int oomd_reporter_lifecycle_prepare_disconnect(
                OomdReporterLifecycle *lifecycle,
                OomdReporterSession session,
                OomdReporterLifecycleTransition *ret_transition);

int oomd_reporter_lifecycle_prepare_grace_expiry(
                OomdReporterLifecycle *lifecycle,
                OomdReporterSession pending_session,
                OomdReporterLifecycleTransition *ret_transition);

int oomd_reporter_lifecycle_commit(
                OomdReporterLifecycle *lifecycle,
                const OomdReporterLifecycleTransition *transition);

int oomd_reporter_lifecycle_accepts_incremental(
                OomdReporterLifecycle *lifecycle,
                OomdReporterSession session);

size_t oomd_reporter_lifecycle_size(OomdReporterLifecycle *lifecycle);

DEFINE_TRIVIAL_CLEANUP_FUNC(OomdReporterLifecycle*, oomd_reporter_lifecycle_free);
