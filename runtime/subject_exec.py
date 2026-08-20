#!/usr/bin/env python3
from __future__ import annotations

import os
import sys

import sandbox as runtime


def main() -> int:
    if os.geteuid() != 0:
        print("subject attachment requires root inside the disposable environment", file=sys.stderr)
        return 1
    if len(sys.argv) < 4 or sys.argv[2] != "--":
        print("usage: subject_exec.py <sandbox-id> -- <command> [args...]", file=sys.stderr)
        return 2
    sandbox_id = sys.argv[1]
    if not runtime.SANDBOX_PATTERN.fullmatch(sandbox_id):
        print("invalid sandbox-id", file=sys.stderr)
        return 2
    meta = runtime.load_meta(sandbox_id)
    if meta is None or meta.get("state") not in {"ready", "completed"}:
        print("subject attachment requires a ready or completed sandbox", file=sys.stderr)
        return 1
    command = runtime.unprivileged_command(
        int(meta["subject_uid"]),
        int(meta["subject_gid"]),
        str(meta["subject_namespace"]),
        sys.argv[3:],
    )
    environment = {
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "RANGE_SANDBOX_ID": sandbox_id,
    }
    os.execvpe(command[0], command, environment)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
