#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Inject a focused current-main regression probe into TEST-55-OOMD.sh.

This file is retained only on the controlled Linux Fieldwork fork. It modifies
an exact checkout during CI so the baseline runtime failure can be captured
before a product policy is selected.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

FUNCTION = r'''
testcase_user_manager_reload_preserves_system_oomd_registration() {
    local active_enter_after active_enter_before after block cursor
    local nrestarts_after nrestarts_before outcome property_after property_before
    local uid user_service_path

    uid="$(id -u testuser)"
    user_service_path="/user.slice/user-${uid}.slice/user@${uid}.service"

    oomctl_block_for_path() {
        oomctl | awk -v target="$1" '
            $1 == "Path:" {
                if (found)
                    exit
                found = ($2 == target)
            }
            found { print }
        '
    }

    cleanup_reporter_collision_probe() {
        rm -f /run/systemd/system/user@.service.d/zz-fieldwork-oomd-reporter-collision.conf
        systemctl daemon-reload || true
        loginctl disable-linger testuser || true
    }
    trap cleanup_reporter_collision_probe RETURN

    mkdir -p /run/systemd/system/user@.service.d/
    cat >/run/systemd/system/user@.service.d/zz-fieldwork-oomd-reporter-collision.conf <<'EOF'
[Service]
ManagedOOMMemoryPressure=kill
ManagedOOMMemoryPressureLimit=50%
EOF

    systemctl daemon-reload
    loginctl enable-linger testuser
    systemctl start "user@${uid}.service"

    block=
    for _ in {1..60}; do
        block="$(oomctl_block_for_path "$user_service_path")"
        [[ -n "$block" ]] && break
        sleep 1
    done

    if [[ -z "$block" ]]; then
        echo "FIELDWORK_OOMD_REPORTER_COLLISION=CONTROL_FAILURE"
        echo "FIELDWORK_REASON=system-registration-never-appeared"
        return 1
    fi

    echo "FIELDWORK_OOMD_BEFORE_BEGIN"
    printf '%s\n' "$block"
    echo "FIELDWORK_OOMD_BEFORE_END"

    assert_in 'Memory Pressure Limit: 50.00%' "$block"
    active_enter_before="$(systemctl show "user@${uid}.service" -P ActiveEnterTimestampMonotonic)"
    nrestarts_before="$(systemctl show "user@${uid}.service" -P NRestarts)"
    property_before="$(systemctl show "user@${uid}.service" -P ManagedOOMMemoryPressure)"

    cursor="$(journalctl -n 0 --show-cursor | sed -n 's/^-- cursor: //p')"
    systemctl --machine "testuser@.host" --user log-level debug
    systemctl --machine "testuser@.host" --user daemon-reload

    outcome=not-reproduced
    for after in 1 5 10; do
        sleep "$after"
        block="$(oomctl_block_for_path "$user_service_path")"
        echo "FIELDWORK_OOMD_AFTER_${after}_BEGIN"
        printf '%s\n' "$block"
        echo "FIELDWORK_OOMD_AFTER_${after}_END"
        if [[ -z "$block" ]]; then
            outcome=reproduced
            break
        fi
    done

    active_enter_after="$(systemctl show "user@${uid}.service" -P ActiveEnterTimestampMonotonic)"
    nrestarts_after="$(systemctl show "user@${uid}.service" -P NRestarts)"
    property_after="$(systemctl show "user@${uid}.service" -P ManagedOOMMemoryPressure)"

    echo "FIELDWORK_CONTROL_ACTIVE_ENTER_BEFORE=$active_enter_before"
    echo "FIELDWORK_CONTROL_ACTIVE_ENTER_AFTER=$active_enter_after"
    echo "FIELDWORK_CONTROL_NRESTARTS_BEFORE=$nrestarts_before"
    echo "FIELDWORK_CONTROL_NRESTARTS_AFTER=$nrestarts_after"
    echo "FIELDWORK_CONTROL_PROPERTY_BEFORE=$property_before"
    echo "FIELDWORK_CONTROL_PROPERTY_AFTER=$property_after"

    journalctl --sync
    echo "FIELDWORK_RELOAD_JOURNAL_BEGIN"
    journalctl --after-cursor="$cursor" \
        -u systemd-oomd.service \
        -u "user@${uid}.service" \
        -o short-monotonic --no-pager || true
    echo "FIELDWORK_RELOAD_JOURNAL_END"

    if [[ "$active_enter_before" != "$active_enter_after" ||
          "$nrestarts_before" != "$nrestarts_after" ||
          "$property_before" != "kill" ||
          "$property_after" != "kill" ]]; then
        echo "FIELDWORK_OOMD_REPORTER_COLLISION=CONTROL_FAILURE"
        echo "FIELDWORK_REASON=service-identity-or-policy-changed"
        return 1
    fi

    if [[ "$outcome" == reproduced ]]; then
        echo "FIELDWORK_OOMD_REPORTER_COLLISION=REPRODUCED"
        return 1
    fi

    echo "FIELDWORK_OOMD_REPORTER_COLLISION=NOT_REPRODUCED"
    return 0
}
'''.strip("\n")

ANCHOR = "\nrun_testcases\n\ntouch /testok\n"
MARKER = "testcase_user_manager_reload_preserves_system_oomd_registration()"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=pathlib.Path)
    args = parser.parse_args()

    path = args.path
    source = path.read_text(encoding="utf-8")

    if MARKER in source:
        print(f"probe already present in {path}")
        return 0
    if source.count(ANCHOR) != 1:
        print(f"expected one TEST-55-OOMD anchor, found {source.count(ANCHOR)}", file=sys.stderr)
        return 2

    updated = source.replace(ANCHOR, f"\n{FUNCTION}\n\nrun_testcases\n\ntouch /testok\n")
    path.write_text(updated, encoding="utf-8")
    print(f"injected reporter-collision probe into {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
