#!/usr/bin/env python3
"""Inject temporary reporter-identity logging into systemd-oomd.

This is controlled-fork evidence tooling, not a proposed product patch.
"""

from __future__ import annotations

import argparse
from pathlib import Path


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one exact match, found {count}")
    return source.replace(old, new, 1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    args = parser.parse_args()

    path = args.source
    text = path.read_text(encoding="utf-8")

    text = replace_once(
        text,
        "static int process_managed_oom_message(Manager *m, uid_t uid, sd_json_variant *parameters) {",
        "static int process_managed_oom_message(\n"
        "                Manager *m,\n"
        "                const char *reporter,\n"
        "                uid_t uid,\n"
        "                pid_t pid,\n"
        "                sd_json_variant *parameters) {",
        "process signature",
    )

    anchor = """                else {
                        log_debug(\"Unknown property '%s', ignoring.\", message.property);
                        continue;
                }

                if (message.mode == MANAGED_OOM_AUTO) {
"""
    replacement = """                else {
                        log_debug(\"Unknown property '%s', ignoring.\", message.property);
                        continue;
                }

                log_notice(\"FIELDWORK_MANAGED_OOM reporter=%s uid=%u pid=%d property=%s mode=%s path=%s limit=%u duration=%llu\",
                           reporter,
                           (unsigned) uid,
                           (int) pid,
                           message.property,
                           managed_oom_mode_to_string(message.mode),
                           empty_to_root(message.path),
                           (unsigned) message.limit,
                           (unsigned long long) message.duration);

                if (message.mode == MANAGED_OOM_AUTO) {
"""
    text = replace_once(text, anchor, replacement, "receive trace anchor")

    text = replace_once(
        text,
        """        Manager *m = ASSERT_PTR(userdata);
        uid_t uid;
        int r;

        r = sd_varlink_get_peer_uid(link, &uid);
        if (r < 0)
                return log_error_errno(r, \"Failed to get varlink peer uid: %m\");

        return process_managed_oom_message(m, uid, parameters);
""",
        """        Manager *m = ASSERT_PTR(userdata);
        pid_t pid;
        uid_t uid;
        int r;

        r = sd_varlink_get_peer_uid(link, &uid);
        if (r < 0)
                return log_error_errno(r, \"Failed to get varlink peer uid: %m\");

        r = sd_varlink_get_peer_pid(link, &pid);
        if (r < 0)
                return log_error_errno(r, \"Failed to get varlink peer pid: %m\");

        return process_managed_oom_message(m, \"user-manager\", uid, pid, parameters);
""",
        "user request boundary",
    )

    text = replace_once(
        text,
        """        Manager *m = ASSERT_PTR(userdata);
        uid_t uid;
        int r;

        if (error_id) {
""",
        """        Manager *m = ASSERT_PTR(userdata);
        pid_t pid;
        uid_t uid;
        int r;

        if (error_id) {
""",
        "system reply declarations",
    )

    text = replace_once(
        text,
        """        r = process_managed_oom_message(m, uid, parameters);

finish:
""",
        """        r = sd_varlink_get_peer_pid(link, &pid);
        if (r < 0) {
                log_error_errno(r, \"Failed to get varlink peer pid: %m\");
                goto finish;
        }

        r = process_managed_oom_message(m, \"system-manager\", uid, pid, parameters);

finish:
""",
        "system reply boundary",
    )

    path.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
