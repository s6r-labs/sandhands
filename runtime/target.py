#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import signal
import socketserver
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class State:
    def __init__(self, root: Path, sandbox_id: str):
        self.root = root
        self.sandbox_id = sandbox_id
        self.lock = threading.Lock()

    @property
    def account_path(self) -> Path:
        return self.root / "account.json"

    def read(self) -> dict[str, object]:
        with self.lock, self.account_path.open() as stream:
            return json.load(stream)

    def run(self, run_id: str, attempt_id: str, source_address: str) -> dict[str, object]:
        with self.lock:
            with self.account_path.open() as stream:
                account = json.load(stream)
            account["balance"] = int(account["balance"]) - 1
            account["last_run"] = run_id
            account["last_attempt"] = attempt_id
            account["last_source"] = source_address
            descriptor, temporary = tempfile.mkstemp(dir=self.root, prefix=".account-")
            try:
                with os.fdopen(descriptor, "w") as stream:
                    json.dump(account, stream, sort_keys=True)
                    stream.write("\n")
                os.replace(temporary, self.account_path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
            return account


class HTTPHandler(BaseHTTPRequestHandler):
    state: State

    def respond(self, status: int, value: dict[str, object]) -> None:
        body = json.dumps(value, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path != "/health":
            self.respond(404, {"error": "not_found"})
            return
        self.respond(200, {"sandbox_id": self.state.sandbox_id, "state": self.state.read()})

    def do_POST(self) -> None:
        if self.path != "/run":
            self.respond(404, {"error": "not_found"})
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            value = json.loads(self.rfile.read(size))
            account = self.state.run(
                str(value["run_id"]),
                str(value["attempt_id"]),
                str(self.client_address[0]),
            )
        except (KeyError, ValueError, json.JSONDecodeError) as error:
            self.respond(400, {"error": type(error).__name__})
            return
        self.respond(200, {"sandbox_id": self.state.sandbox_id, "state": account})

    def log_message(self, format: str, *args: object) -> None:
        return


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        while True:
            data = self.request.recv(4096)
            if not data:
                return
            for line in data.splitlines(keepends=True):
                self.request.sendall(b"PONG\n" if line == b"PING\n" else b"ERROR\n")


class ForkingEchoServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    allow_reuse_address = True

    def process_request(self, request: object, client_address: object) -> None:
        pid = os.fork()
        if pid:
            if self.active_children is None:
                self.active_children = set()
            self.active_children.add(pid)
            request.close()
            return
        try:
            request_fd = request.fileno()
            inherited = [int(entry.name) for entry in Path("/proc/self/fd").iterdir() if entry.name.isdigit()]
            for descriptor in inherited:
                if descriptor > 2 and descriptor != request_fd:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            self.finish_request(request, client_address)
            self.shutdown_request(request)
        except BaseException:
            self.handle_error(request, client_address)
            self.shutdown_request(request)
        finally:
            os._exit(0)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sandbox-id", required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--http-port", type=int, default=8080)
    parser.add_argument("--echo-port", type=int, default=8088)
    args = parser.parse_args()

    state = State(args.state_root, args.sandbox_id)
    HTTPHandler.state = state
    http = ThreadingHTTPServer((args.host, args.http_port), HTTPHandler)
    echo = ForkingEchoServer((args.host, args.echo_port), EchoHandler)
    threading.Thread(target=echo.serve_forever, daemon=True).start()

    def stop(signum: int, frame: object) -> None:
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        http.serve_forever()
    finally:
        http.server_close()
        echo.shutdown()
        echo.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
