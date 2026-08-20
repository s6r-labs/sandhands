#!/usr/bin/env python3
from __future__ import annotations

import signal


def stop(signum: int, frame: object) -> None:
    raise SystemExit(0)


def main() -> int:
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while True:
        signal.pause()


if __name__ == "__main__":
    raise SystemExit(main())
