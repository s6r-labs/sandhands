#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import socket
import socketserver
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    label = "fixture"

    def do_GET(self) -> None:
        body = json.dumps({"service": self.label, "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class ManagementHandler(Handler):
    label = "management"


class EgressHandler(Handler):
    label = "forbidden-egress"


class TCPDNS(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        length = self.request.recv(2)
        if len(length) != 2:
            return
        size = struct.unpack("!H", length)[0]
        query = self.request.recv(size)
        response = dns_response(query)
        self.request.sendall(struct.pack("!H", len(response)) + response)


def dns_response(query: bytes) -> bytes:
    if len(query) < 12:
        return query
    return query[:2] + b"\x81\x83" + query[4:6] + b"\x00\x00\x00\x00\x00\x00" + query[12:]


def serve_udp(host: str, port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    while True:
        query, address = sock.recvfrom(4096)
        sock.sendto(dns_response(query), address)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--management-port", type=int, default=9000)
    parser.add_argument("--egress-port", type=int, default=8081)
    parser.add_argument("--dns-port", type=int, default=5353)
    args = parser.parse_args()

    servers = [
        ThreadingHTTPServer((args.host, args.management_port), ManagementHandler),
        ThreadingHTTPServer((args.host, args.egress_port), EgressHandler),
        socketserver.ThreadingTCPServer((args.host, args.dns_port), TCPDNS),
    ]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    threading.Thread(target=serve_udp, args=(args.host, args.dns_port), daemon=True).start()
    threading.Event().wait()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
