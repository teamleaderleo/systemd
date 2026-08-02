#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Run the reporter-source prototype injector with corrected call anchors."""

from __future__ import annotations

import importlib.util
import pathlib
import sys


def main() -> int:
    implementation = pathlib.Path(__file__).with_name(
        "fieldwork-apply-oomd-reporter-source-precedence.py"
    )
    spec = importlib.util.spec_from_file_location(
        "fieldwork_oomd_source_precedence_impl", implementation
    )
    if spec is None or spec.loader is None:
        print(f"failed to load injector: {implementation}", file=sys.stderr)
        return 2

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    # Current oomd-manager.c has one return-site and one assignment-site. Match
    # their common call expression while preserving each surrounding prefix.
    module.OLD_CALL = "process_managed_oom_message(m, uid, parameters);"
    module.USER_CALL = (
        "process_managed_oom_message("
        "m, MANAGED_OOM_REPORTER_USER, uid, parameters);"
    )
    module.SYSTEM_CALL = (
        "process_managed_oom_message("
        "m, MANAGED_OOM_REPORTER_SYSTEM, uid, parameters);"
    )

    return module.main()


if __name__ == "__main__":
    raise SystemExit(main())
