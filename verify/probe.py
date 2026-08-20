#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import subprocess
import urllib.request


def result(reachable: bool, **details: object) -> None:
    print(json.dumps({"reachable": reachable, **details}, sort_keys=True), flush=True)


def dns_query() -> bytes:
    name = b"\x07invalid\x04test\x00"
    return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + name + b"\x00\x01\x00\x01"


def http_probe(host: str, port: int, timeout: float) -> None:
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/health", timeout=timeout) as response:
            body = response.read(4096)
        result(True, protocol="http", response=json.loads(body))
    except BaseException as error:
        result(False, protocol="http", error=type(error).__name__)


def tcp_probe(host: str, port: int, timeout: float) -> None:
    try:
        with socket.create_connection((host, port), timeout):
            pass
        result(True, protocol="tcp")
    except OSError as error:
        result(False, protocol="tcp", error=type(error).__name__)


def dns_udp_probe(host: str, port: int, timeout: float) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(dns_query(), (host, port))
        response, _ = sock.recvfrom(4096)
        result(bool(response), protocol="dns-udp")
    except OSError as error:
        result(False, protocol="dns-udp", error=type(error).__name__)
    finally:
        sock.close()


def dns_tcp_probe(host: str, port: int, timeout: float) -> None:
    query = dns_query()
    try:
        with socket.create_connection((host, port), timeout) as connection:
            connection.settimeout(timeout)
            connection.sendall(struct.pack("!H", len(query)) + query)
            header = connection.recv(2)
            if len(header) != 2:
                result(False, protocol="dns-tcp", error="short_response")
                return
            size = struct.unpack("!H", header)[0]
            response = connection.recv(size)
        result(bool(response), protocol="dns-tcp")
    except OSError as error:
        result(False, protocol="dns-tcp", error=type(error).__name__)


def identity_probe() -> None:
    capabilities = "unknown"
    for line in open("/proc/self/status"):
        if line.startswith("CapEff:"):
            capabilities = line.split(":", 1)[1].strip()
            break
    result(
        True,
        protocol="identity",
        uid=os.geteuid(),
        gid=os.getegid(),
        effective_capabilities=capabilities,
        sudo_works=subprocess.run(
            ["sudo", "-n", "true"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        ).returncode
        == 0,
        engine_socket_present=os.path.exists("/var/run/docker.sock"),
        evidence_writable=os.access("/var/lib/range-interview/evidence", os.W_OK),
    )


def readable_probe(path: str) -> None:
    result(True, protocol="filesystem", path=path, readable=os.access(path, os.R_OK))


def writable_probe(path: str) -> None:
    parent = os.path.dirname(path) or "."
    writable = os.access(path, os.W_OK) or os.access(parent, os.W_OK)
    result(True, protocol="filesystem", path=path, writable=writable)


def signal_probe(pid: int) -> None:
    try:
        os.kill(pid, 0)
        permitted = True
        error = None
    except OSError as exception:
        permitted = False
        error = type(exception).__name__
    result(True, protocol="process", pid=pid, signal_permitted=permitted, error=error)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode",
        choices=["http", "tcp", "dns-udp", "dns-tcp", "identity", "readable", "writable", "signal"],
    )
    parser.add_argument("host", nargs="?")
    parser.add_argument("port", nargs="?", type=int)
    parser.add_argument("--timeout", type=float, default=0.75)
    args = parser.parse_args()

    if args.mode == "identity":
        identity_probe()
        return 0
    if args.mode == "readable":
        if args.host is None:
            parser.error("path is required for a readable probe")
        readable_probe(args.host)
        return 0
    if args.mode == "writable":
        if args.host is None:
            parser.error("path is required for a writable probe")
        writable_probe(args.host)
        return 0
    if args.mode == "signal":
        if args.host is None:
            parser.error("pid is required for a signal probe")
        signal_probe(int(args.host))
        return 0
    if args.host is None or args.port is None:
        parser.error("host and port are required for a connectivity probe")
    if args.mode == "http":
        http_probe(args.host, args.port, args.timeout)
    elif args.mode == "tcp":
        tcp_probe(args.host, args.port, args.timeout)
    elif args.mode == "dns-udp":
        dns_udp_probe(args.host, args.port, args.timeout)
    else:
        dns_tcp_probe(args.host, args.port, args.timeout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
