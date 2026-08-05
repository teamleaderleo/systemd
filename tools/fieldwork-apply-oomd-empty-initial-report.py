#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

from __future__ import annotations

import argparse
from pathlib import Path

FUNCTION_START = "static int manager_varlink_send_managed_oom_initial(Manager *m) {"
FUNCTION_END = "\n}\n\nstatic int manager_varlink_managed_oom_connect(Manager *m);"
OLD_CALL = "r = build_managed_oom_cgroups_json(m, /* allow_empty= */ false, &v);"
NEW_CALL = "r = build_managed_oom_cgroups_json(m, /* allow_empty= */ true, &v);"
SEND_CALL = (
    'return sd_varlink_send(m->managed_oom_varlink, '
    '"io.systemd.oom.ReportManagedOOMCGroups", v);'
)


def function_region(text: str) -> tuple[int, int, str]:
    start = text.find(FUNCTION_START)
    if start < 0:
        raise SystemExit("initial ManagedOOM sender function anchor not found")

    end = text.find(FUNCTION_END, start)
    if end < 0:
        raise SystemExit("initial ManagedOOM sender function end anchor not found")

    end += len("\n}\n")
    return start, end, text[start:end]


def apply(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    start, end, region = function_region(text)

    if text.count(OLD_CALL) != 1:
        raise SystemExit(
            f"expected exactly one old allow_empty anchor, found {text.count(OLD_CALL)}"
        )
    if OLD_CALL not in region:
        raise SystemExit("old allow_empty anchor is outside the initial sender")
    if NEW_CALL in region:
        raise SystemExit("initial sender already uses allow_empty=true")
    if SEND_CALL not in region:
        raise SystemExit("existing ReportManagedOOMCGroups send call drifted")

    updated_region = region.replace(OLD_CALL, NEW_CALL, 1)
    updated = text[:start] + updated_region + text[end:]

    if updated_region.count(NEW_CALL) != 1 or OLD_CALL in updated_region:
        raise SystemExit("post-apply initial-sender invariant failed")

    path.write_text(updated, encoding="utf-8")
    print(f"FIELDWORK_OOMD_EMPTY_INITIAL_REPORT_APPLIED={path}")


def verify(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    _, _, region = function_region(text)

    if OLD_CALL in region:
        raise SystemExit("old allow_empty=false anchor remains in the initial sender")
    if region.count(NEW_CALL) != 1:
        raise SystemExit("allow_empty=true is not unique within the initial sender")
    if SEND_CALL not in region:
        raise SystemExit("existing ReportManagedOOMCGroups send call drifted")

    print(f"FIELDWORK_OOMD_EMPTY_INITIAL_REPORT_VERIFIED={path}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()

    if args.verify:
        verify(args.path)
    else:
        apply(args.path)


if __name__ == "__main__":
    main()
