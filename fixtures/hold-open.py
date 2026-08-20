#!/usr/bin/env python3
"""Keep one target connection open so reset can prove it was invalidated."""

from __future__ import annotations

import argparse
import json
import socket
import sys


def emit(event: str, **details: object) -> None:
    print(json.dumps({"event": event, **details}, sort_keys=True), flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()

    connection = socket.create_connection((args.host, args.port), args.timeout)
    connection.settimeout(args.timeout)
    connection.sendall(b"PING\n")
    initial = connection.recv(4096)
    if initial != b"PONG\n":
        emit("protocol_error", response=initial.decode(errors="replace"))
        return 2

    emit("connected")
    if sys.stdin.readline().strip() != "probe":
        emit("control_error")
        return 2

    try:
        connection.sendall(b"PING\n")
        response = connection.recv(4096)
    except OSError as error:
        emit("connection_invalidated", error=type(error).__name__)
        return 0

    if response:
        emit("connection_still_usable", response=response.decode(errors="replace"))
        return 1

    emit("connection_invalidated", error="eof")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

