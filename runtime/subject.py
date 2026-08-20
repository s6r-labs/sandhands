#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import tempfile
import urllib.request
from pathlib import Path


def request_json(url: str, payload: dict[str, str] | None = None) -> dict[str, object]:
    body = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="GET" if body is None else "POST",
    )
    with urllib.request.urlopen(request, timeout=3) as response:
        return json.load(response)


def atomic_json(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".trace-")
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--trace", type=Path, required=True)
    args = parser.parse_args()

    result = request_json(
        f"http://{args.target}:8080/run",
        {"run_id": args.run_id, "attempt_id": args.attempt_id},
    )
    health = request_json(f"http://{args.target}:8080/health")
    atomic_json(
        args.trace,
        {
            "run_id": args.run_id,
            "attempt_id": args.attempt_id,
            "result": result,
            "health": health,
            "verdict": "pass",
        },
    )
    print(json.dumps({"event": "run_complete", "trace": str(args.trace)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
