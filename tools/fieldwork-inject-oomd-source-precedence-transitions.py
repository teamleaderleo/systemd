#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Inject a focused ManagedOOM source-precedence transition testcase."""

from __future__ import annotations

import argparse
import pathlib
import sys

FUNCTION = r'''
testcase_managed_oom_reporter_source_precedence() {
    local block uid user_service_path

    uid="$(id -u testuser)"
    user_service_path="/user.slice/user-${uid}.slice/user@${uid}.service"

    oomctl_source_block_for_path() {
        oomctl | awk -v target="$1" '
            $1 == "Path:" {
                if (found)
                    exit
                found = ($2 == target)
            }
            found { print }
        '
    }

    wait_for_source_limit() {
        local expected="$1"

        for _ in {1..60}; do
            block="$(oomctl_source_block_for_path "$user_service_path")"
            if [[ -n "$block" ]] && grep -Fq "Memory Pressure Limit: $expected" <<<"$block"; then
                printf '%s\n' "$block"
                return 0
            fi
            sleep 1
        done

        echo "Expected $user_service_path at pressure limit $expected" >&2
        printf '%s\n' "$block" >&2
        return 1
    }

    wait_for_source_absence() {
        for _ in {1..60}; do
            block="$(oomctl_source_block_for_path "$user_service_path")"
            [[ -z "$block" ]] && return 0
            sleep 1
        done

        echo "Expected $user_service_path to leave the monitored set" >&2
        printf '%s\n' "$block" >&2
        return 1
    }

    cleanup_source_precedence_probe() {
        systemctl --machine "testuser@.host" --user set-property --runtime -- \
            -.slice ManagedOOMMemoryPressure=auto || true
        systemctl set-property --runtime "user@${uid}.service" \
            ManagedOOMMemoryPressure=auto || true
        loginctl disable-linger testuser || true
    }
    trap cleanup_source_precedence_probe RETURN

    loginctl enable-linger testuser
    systemctl start "user@${uid}.service"

    # PID 1 establishes the authoritative complete tuple.
    systemctl set-property --runtime "user@${uid}.service" \
        ManagedOOMMemoryPressure=kill \
        ManagedOOMMemoryPressureLimit=50%
    wait_for_source_limit 50.00%

    # The nested user manager reports a conflicting tuple for the same kernel
    # cgroup through its root -.slice. PID 1 must remain effective.
    systemctl --machine "testuser@.host" --user set-property --runtime -- \
        -.slice \
        ManagedOOMMemoryPressure=kill \
        ManagedOOMMemoryPressureLimit=70%
    wait_for_source_limit 50.00%

    # Withdrawing only PID 1's contribution must reveal the already-live user
    # contribution without requiring another message from the user manager.
    systemctl set-property --runtime "user@${uid}.service" \
        ManagedOOMMemoryPressure=auto
    wait_for_source_limit 70.00%

    # Withdrawing the final contribution removes the effective path.
    systemctl --machine "testuser@.host" --user set-property --runtime -- \
        -.slice ManagedOOMMemoryPressure=auto
    wait_for_source_absence

    echo "FIELDWORK_OOMD_SOURCE_PRECEDENCE=PASSED"
}
'''.strip("\n")

ANCHOR = "\nrun_testcases\n\ntouch /testok\n"
MARKER = "testcase_managed_oom_reporter_source_precedence()"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=pathlib.Path)
    args = parser.parse_args()

    path = args.path
    source = path.read_text(encoding="utf-8")

    if MARKER in source:
        print(f"source-precedence probe already present in {path}")
        return 0
    if source.count(ANCHOR) != 1:
        print(
            f"expected one TEST-55-OOMD anchor, found {source.count(ANCHOR)}",
            file=sys.stderr,
        )
        return 2

    updated = source.replace(ANCHOR, f"\n{FUNCTION}\n\nrun_testcases\n\ntouch /testok\n")
    path.write_text(updated, encoding="utf-8")
    print(f"injected source-precedence transition probe into {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
