#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import secrets
import select
import subprocess
import sys
from pathlib import Path
from typing import Any

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
SANDBOX = ROOT / "bin/sandbox"
SUBJECT = ROOT / "bin/subject"
PROBE = ROOT / "verify/probe.py"
SCHEMA = json.loads((ROOT / "schemas/run-record.schema.json").read_text())
MANIFEST = ROOT / "fixtures/baseline/manifest.sha256"
SESSION = secrets.token_hex(4)
SANDBOXES = (f"verify-a-{SESSION}", f"verify-b-{SESSION}")
FAULT_SANDBOX = f"verify-fault-{SESSION}"
RUNS = tuple(f"run-{secrets.token_hex(8)}" for _ in range(3))
ATTEMPTS = tuple(f"try-{secrets.token_hex(8)}" for _ in range(3))
SENTINEL_TABLE = f"range_interview_s_{SESSION}"
SENTINEL_PATH = Path(f"/run/range-interview/sentinel-{SESSION}")
FORBIDDEN_CAPABILITIES = (1 << 12) | (1 << 21)


class VerificationError(RuntimeError):
    pass


class Reporter:
    def __init__(self) -> None:
        self.results: list[dict[str, object]] = []

    def check(self, name: str, passed: bool, detail: str) -> None:
        value = {"check": name, "result": "pass" if passed else "fail", "detail": detail}
        self.results.append(value)
        print(json.dumps(value, sort_keys=True), flush=True)

    def has(self, name: str) -> bool:
        return any(value["check"] == name for value in self.results)

    def finish(self) -> int:
        failed = [str(value["check"]) for value in self.results if value["result"] == "fail"]
        print(
            json.dumps(
                {
                    "status": "pass" if not failed else "fail",
                    "failed_checks": failed,
                    "note": "formal evaluation uses an external checker and varied contract-conforming inputs",
                },
                sort_keys=True,
            ),
            flush=True,
        )
        return 0 if not failed else 1


def command(
    arguments: list[str],
    *,
    check: bool = False,
    timeout: float = 15,
    environment: dict[str, str] | None = None,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        check=check,
        text=True,
        capture_output=True,
        timeout=timeout,
        env=environment,
        cwd=cwd,
    )


def parse_json(output: str) -> dict[str, Any]:
    lines = [line for line in output.splitlines() if line.strip()]
    if not lines:
        raise VerificationError("command emitted no JSON")
    value = json.loads(lines[-1])
    if not isinstance(value, dict):
        raise VerificationError("command JSON is not an object")
    return value


def sandbox(operation: str, *arguments: str, expect: int = 0, environment: dict[str, str] | None = None) -> dict[str, Any]:
    completed = command([str(SANDBOX), operation, *arguments], timeout=12, environment=environment)
    if completed.returncode != expect:
        raise VerificationError(
            f"sandbox {operation} returned {completed.returncode}, expected {expect}: {completed.stderr.strip()}"
        )
    stream = completed.stdout if completed.stdout.strip() else completed.stderr
    return parse_json(stream)


def status(sandbox_id: str) -> dict[str, Any]:
    return sandbox("status", sandbox_id)


def subject_probe(sandbox_id: str, mode: str, host: str | None = None, port: int | None = None) -> dict[str, Any]:
    arguments = [str(SUBJECT), sandbox_id, "--", "python3", str(PROBE), mode]
    if host is not None:
        arguments.append(host)
    if port is not None:
        arguments.append(str(port))
    completed = command(arguments, timeout=4)
    if completed.returncode != 0:
        raise VerificationError(f"subject probe failed: {completed.stderr.strip()}")
    return parse_json(completed.stdout)


def inventory() -> dict[str, tuple[str, ...]]:
    namespaces = []
    result = command(["ip", "netns", "list"])
    for line in result.stdout.splitlines():
        name = line.split()[0]
        if name.startswith("ri-") and name != "ri-fixture":
            namespaces.append(name)

    links = []
    result = command(["ip", "-o", "link", "show"])
    for line in result.stdout.splitlines():
        name = line.split(":", 2)[1].strip().split("@")[0]
        if name.startswith("ri-") and name not in {"ri-hfixture", "ri-pfixture"}:
            links.append(name)

    cgroups = []
    root = Path("/sys/fs/cgroup/range-interview/sandboxes")
    if root.exists():
        cgroups = [path.name for path in root.iterdir() if path.is_dir()]

    runtime_sandboxes = []
    root = Path("/run/range-interview/sandboxes")
    if root.exists():
        runtime_sandboxes = [path.name for path in root.iterdir() if path.is_dir()]

    state_sandboxes = []
    root = Path("/var/lib/range-interview/state")
    if root.exists():
        state_sandboxes = [path.name for path in root.iterdir() if path.is_dir()]

    return {
        "namespaces": tuple(sorted(namespaces)),
        "links": tuple(sorted(links)),
        "cgroups": tuple(sorted(cgroups)),
        "runtime_sandboxes": tuple(sorted(runtime_sandboxes)),
        "state_sandboxes": tuple(sorted(state_sandboxes)),
    }


def parallel_sandbox(operation: str, calls: list[tuple[str, ...]]) -> list[subprocess.CompletedProcess[str]]:
    processes = [
        subprocess.Popen(
            [str(SANDBOX), operation, *arguments],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for arguments in calls
    ]
    completed = []
    for process in processes:
        stdout, stderr = process.communicate(timeout=12)
        completed.append(subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr))
    return completed


def verify_state(meta: dict[str, Any], run_id: str, attempt_id: str) -> bool:
    path = Path(str(meta["operator_state_root"])) / "account.json"
    value = json.loads(path.read_text())
    return (
        value.get("balance") == 99
        and value.get("status") == "active"
        and value.get("last_run") == run_id
        and value.get("last_attempt") == attempt_id
        and value.get("last_source") == meta["subject_scope"]["ipv4_address"]
    )


def verify_manifest(meta: dict[str, Any]) -> bool:
    completed = command(["sha256sum", "--check", str(MANIFEST)], cwd=Path(str(meta["operator_state_root"])))
    return completed.returncode == 0


def state_path(meta: dict[str, Any]) -> Path:
    return Path(str(meta["operator_state_root"])) / "account.json"


def state_sha256(meta: dict[str, Any]) -> str:
    return hashlib.sha256(state_path(meta).read_bytes()).hexdigest()


def record_is_independent(
    record: dict[str, Any],
    meta: dict[str, Any],
    run_id: str,
    attempt_id: str,
    expected_state_sha256: str,
) -> bool:
    try:
        jsonschema.validate(record, SCHEMA)
    except jsonschema.ValidationError:
        return False
    expected_identity = {
        "run_id": run_id,
        "attempt_id": attempt_id,
        "sandbox_id": meta["sandbox_id"],
        "sandbox_generation": meta["sandbox_generation"],
        "reset_generation": meta["reset_generation"],
    }
    if any(record.get(field) != value for field, value in expected_identity.items()):
        return False
    if record.get("baseline_sha256") != hashlib.sha256(MANIFEST.read_bytes()).hexdigest():
        return False
    expected_observation = {**expected_identity, "state_sha256": expected_state_sha256}
    for observation in record.get("observations", []):
        vantage = str(observation.get("vantage", "")).lower()
        if (
            observation.get("kind") == "protected_state"
            and observation.get("result") == "pass"
            and "subject" not in vantage
            and isinstance(observation.get("details"), dict)
            and all(observation["details"].get(field) == value for field, value in expected_observation.items())
        ):
            return record.get("verdict") == "pass"
    return False


def record_artifact(result: dict[str, Any]) -> tuple[Path, dict[str, Any], bytes] | None:
    path_value = result.get("record")
    record = result.get("run_record")
    if not isinstance(path_value, str) or not isinstance(record, dict):
        return None
    path = Path(path_value)
    if not path.is_absolute():
        return None
    try:
        resolved = path.resolve(strict=True)
        allowed_roots = (Path("/run/range-interview"), Path("/var/lib/range-interview"))
        if path != resolved or not resolved.is_file():
            return None
        if not any(resolved.is_relative_to(root) and resolved != root for root in allowed_roots):
            return None
        payload = resolved.read_bytes()
        if json.loads(payload) != record:
            return None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return resolved, record, payload


def artifact_unchanged(artifact: tuple[Path, dict[str, Any], bytes] | None) -> bool:
    if artifact is None:
        return False
    path, record, payload = artifact
    try:
        return path.resolve(strict=True) == path and path.read_bytes() == payload and json.loads(payload) == record
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False


def subject_cannot_write_artifact(sandbox_id: str, artifact: tuple[Path, dict[str, Any], bytes] | None) -> bool:
    if artifact is None:
        return False
    observation = subject_probe(sandbox_id, "writable", str(artifact[0]))
    return observation.get("writable") is False


def process_identity(pid: int) -> tuple[int, int] | None:
    try:
        value = Path(f"/proc/{pid}/stat").read_text()
        close = value.rfind(")")
        if close < 0:
            return None
        fields_after_comm = value[close + 2 :].split()
        return pid, int(fields_after_comm[19])
    except (FileNotFoundError, IndexError, PermissionError, ValueError):
        return None


def process_identity_alive(identity: tuple[int, int]) -> bool:
    return process_identity(identity[0]) == identity


def forbidden_capabilities_clear(value: object) -> bool:
    try:
        return int(str(value), 16) & FORBIDDEN_CAPABILITIES == 0
    except ValueError:
        return False


def subject_scope_valid(meta: dict[str, Any]) -> bool:
    scope = meta.get("subject_scope")
    if not isinstance(scope, dict):
        return False
    try:
        pid = int(scope["anchor_pid"])
        if process_identity(pid) != (pid, int(scope["pid_start_time"])):
            return False
        if Path(f"/proc/{pid}/ns/net").stat().st_ino != int(scope["netns_inode"]):
            return False
        cgroup = Path(str(scope["cgroup_path"])).resolve(strict=True)
        delegated = Path("/sys/fs/cgroup/range-interview").resolve(strict=True)
        if not cgroup.is_relative_to(delegated) or cgroup == delegated:
            return False
        relative_cgroup = "/" + str(cgroup.relative_to(Path("/sys/fs/cgroup")))
        memberships = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
        if f"0::{relative_cgroup}" not in memberships:
            return False

        uid: int | None = None
        gid: int | None = None
        capabilities: str | None = None
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("Uid:"):
                uid = int(line.split()[1])
            elif line.startswith("Gid:"):
                gid = int(line.split()[1])
            elif line.startswith("CapEff:"):
                capabilities = line.split(":", 1)[1].strip()
        if (
            uid is None
            or gid is None
            or capabilities is None
            or uid == 0
            or uid != int(scope["uid"])
            or gid != int(scope["gid"])
            or not forbidden_capabilities_clear(capabilities)
        ):
            return False

        observed = command(
            ["nsenter", "--target", str(pid), "--net", "ip", "-j", "-4", "address", "show"],
            timeout=2,
        )
        addresses = {
            info.get("local")
            for interface in json.loads(observed.stdout)
            for info in interface.get("addr_info", [])
            if info.get("family") == "inet"
        }
        return observed.returncode == 0 and scope.get("ipv4_address") in addresses
    except (FileNotFoundError, KeyError, OSError, PermissionError, TypeError, ValueError, json.JSONDecodeError):
        return False


def target_cgroup(pid: int) -> Path:
    try:
        memberships = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
    except (FileNotFoundError, PermissionError) as error:
        raise VerificationError("target cgroup is unavailable") from error
    for membership in memberships:
        hierarchy, controllers, relative = membership.split(":", 2)
        if hierarchy == "0" and controllers == "":
            path = (Path("/sys/fs/cgroup") / relative.lstrip("/")).resolve()
            delegated = Path("/sys/fs/cgroup/range-interview").resolve()
            if not path.is_relative_to(delegated):
                raise VerificationError("target is outside the delegated cgroup scope")
            return path
    raise VerificationError("target has no cgroup v2 membership")


def process_tree(root_pid: int) -> set[int]:
    parents: dict[int, int] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            for line in (entry / "status").read_text().splitlines():
                if line.startswith("PPid:"):
                    parents[int(entry.name)] = int(line.split()[1])
                    break
        except (FileNotFoundError, PermissionError, ValueError):
            continue
    owned = {root_pid}
    while True:
        descendants = {pid for pid, parent in parents.items() if parent in owned}
        expanded = owned | descendants
        if expanded == owned:
            return owned
        owned = expanded


def target_scope_processes(meta: dict[str, Any]) -> set[tuple[int, int]]:
    target_pid = int(meta["target_process"]["pid"])
    pids = process_tree(target_pid)
    cgroup = target_cgroup(target_pid)
    process_files = [cgroup / "cgroup.procs", *cgroup.rglob("cgroup.procs")]
    for process_file in process_files:
        try:
            pids.update(int(value) for value in process_file.read_text().splitlines())
        except (FileNotFoundError, PermissionError, ValueError):
            continue
    identities: set[tuple[int, int]] = set()
    for pid in pids:
        identity = process_identity(pid)
        if identity is not None:
            identities.add(identity)
    return identities


def target_credentials(meta: dict[str, Any]) -> tuple[int, str]:
    pid = int(meta["target_process"]["pid"])
    uid: int | None = None
    capabilities: str | None = None
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("Uid:"):
            uid = int(line.split()[1])
        elif line.startswith("CapEff:"):
            capabilities = line.split(":", 1)[1].strip()
    if uid is None or capabilities is None:
        raise VerificationError("target credentials are unavailable")
    return uid, capabilities


def diagnostic_available(meta: dict[str, Any]) -> bool:
    value = meta.get("diagnostics")
    if not isinstance(value, str):
        return False
    path = Path(value)
    return path.is_file() and path.stat().st_size > 0


def start_hold_open(meta: dict[str, Any]) -> subprocess.Popen[str]:
    endpoint = meta["target_endpoint"]
    process = subprocess.Popen(
        [
            str(SUBJECT),
            str(meta["sandbox_id"]),
            "--",
            "python3",
            str(ROOT / "fixtures/hold-open.py"),
            str(endpoint["address"]),
            str(endpoint["hold_open_port"]),
        ],
        text=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    readable, _, _ = select.select([process.stdout], [], [], 4)
    if not readable:
        process.kill()
        process.wait()
        raise VerificationError("hold-open fixture did not connect")
    event = parse_json(process.stdout.readline())
    if event.get("event") != "connected":
        process.kill()
        process.wait()
        raise VerificationError(f"hold-open fixture failed: {event}")
    return process


def finish_hold_open(process: subprocess.Popen[str]) -> tuple[bool, str]:
    assert process.stdin is not None and process.stdout is not None
    process.stdin.write("probe\n")
    process.stdin.flush()
    stdout, stderr = process.communicate(timeout=4)
    events = [json.loads(line) for line in stdout.splitlines() if line.strip()]
    invalidated = process.returncode == 0 and any(
        value.get("event") == "connection_invalidated" for value in events
    )
    return invalidated, stderr.strip() or json.dumps(events, sort_keys=True)


def create_sentinel() -> tuple[Path, str, subprocess.Popen[bytes]]:
    content = hashlib.sha256(os.urandom(32)).hexdigest()
    SENTINEL_PATH.write_text(content)
    SENTINEL_PATH.chmod(0o600)
    command(["nft", "add", "table", "inet", SENTINEL_TABLE], check=True)
    process = subprocess.Popen(["sleep", "120"])
    return SENTINEL_PATH, content, process


def sentinel_intact(path: Path, content: str, process: subprocess.Popen[bytes]) -> bool:
    table = command(["nft", "list", "table", "inet", SENTINEL_TABLE])
    return path.exists() and path.read_text() == content and process.poll() is None and table.returncode == 0


def cleanup_sentinel(path: Path | None, process: subprocess.Popen[bytes] | None) -> None:
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    if path is not None:
        path.unlink(missing_ok=True)
    command(["nft", "delete", "table", "inet", SENTINEL_TABLE])


def main() -> int:
    if os.geteuid() != 0:
        print("public verification must run through bin/verify", file=sys.stderr)
        return 2

    reporter = Reporter()
    sentinel_path: Path | None = None
    sentinel_process: subprocess.Popen[bytes] | None = None
    initial_inventory = inventory()
    hold: subprocess.Popen[str] | None = None
    sentinel_content = ""

    try:
        for sandbox_id in (*SANDBOXES, FAULT_SANDBOX):
            if status(sandbox_id).get("state") != "absent":
                raise VerificationError(f"reserved verifier sandbox is not absent: {sandbox_id}")

        sentinel_path = SENTINEL_PATH
        sentinel_path, sentinel_content, sentinel_process = create_sentinel()
        created = parallel_sandbox("create", [(SANDBOXES[0],), (SANDBOXES[1],)])
        concurrency_ok = all(value.returncode == 0 for value in created)
        meta_a, meta_b = status(SANDBOXES[0]), status(SANDBOXES[1])
        concurrency_ok = concurrency_ok and meta_a.get("state") == meta_b.get("state") == "ready"
        concurrency_ok = concurrency_ok and all(
            isinstance(meta.get("sandbox_generation"), int) and meta["sandbox_generation"] > 0
            for meta in (meta_a, meta_b)
        )
        concurrency_ok = concurrency_ok and subject_scope_valid(meta_a) and subject_scope_valid(meta_b)
        concurrency_ok = concurrency_ok and all(
            meta_a["subject_scope"][field] != meta_b["subject_scope"][field]
            for field in ("anchor_pid", "cgroup_path")
        )
        concurrency_ok = concurrency_ok and sandbox("wait-ready", SANDBOXES[0]).get("state") == "ready"
        concurrency_ok = concurrency_ok and sandbox("wait-ready", SANDBOXES[1]).get("state") == "ready"
        concurrency_ok = concurrency_ok and verify_manifest(meta_a) and verify_manifest(meta_b)
        reporter.check("concurrent-lifecycle", concurrency_ok, "two sandboxes created with distinct identities")

        identity_a = subject_probe(SANDBOXES[0], "identity")
        identity_b = subject_probe(SANDBOXES[1], "identity")
        target_a = target_credentials(meta_a)
        target_b = target_credentials(meta_b)
        identity_ok = (
            identity_a.get("uid") == meta_a["subject_attachment"]["uid"]
            and identity_b.get("uid") == meta_b["subject_attachment"]["uid"]
            and identity_a.get("uid") != 0
            and identity_b.get("uid") != 0
            and identity_a.get("gid") == meta_a["subject_attachment"]["gid"]
            and identity_b.get("gid") == meta_b["subject_attachment"]["gid"]
            and identity_a.get("uid") == meta_a["subject_scope"]["uid"]
            and identity_b.get("uid") == meta_b["subject_scope"]["uid"]
            and identity_a.get("gid") == meta_a["subject_scope"]["gid"]
            and identity_b.get("gid") == meta_b["subject_scope"]["gid"]
            and forbidden_capabilities_clear(identity_a.get("effective_capabilities"))
            and forbidden_capabilities_clear(identity_b.get("effective_capabilities"))
            and identity_a.get("sudo_works") is False
            and identity_b.get("sudo_works") is False
            and identity_a.get("engine_socket_present") is False
            and identity_b.get("engine_socket_present") is False
            and identity_a.get("evidence_writable") is False
            and identity_b.get("evidence_writable") is False
            and target_a[0] != 0
            and target_b[0] != 0
            and forbidden_capabilities_clear(target_a[1])
            and forbidden_capabilities_clear(target_b[1])
        )

        sibling_state_a = subject_probe(SANDBOXES[0], "readable", str(state_path(meta_b)))
        sibling_state_b = subject_probe(SANDBOXES[1], "readable", str(state_path(meta_a)))
        sibling_signal_a = subject_probe(SANDBOXES[0], "signal", str(meta_b["target_process"]["pid"]))
        sibling_signal_b = subject_probe(SANDBOXES[1], "signal", str(meta_a["target_process"]["pid"]))
        boundary_ok = (
            sibling_state_a.get("readable") is False
            and sibling_state_b.get("readable") is False
            and sibling_signal_a.get("signal_permitted") is False
            and sibling_signal_b.get("signal_permitted") is False
        )
        reporter.check(
            "subject-boundary",
            identity_ok and boundary_ok,
            "subjects were unprivileged and could not access sibling state or processes",
        )

        before_fault = inventory()
        fault_env = dict(os.environ)
        fault_env["RANGE_INTERVIEW_FAULT"] = "create-after-owned-resource"
        fault = command([str(SANDBOX), "create", FAULT_SANDBOX], timeout=12, environment=fault_env)
        fault_status = status(FAULT_SANDBOX)
        partial_ok = (
            fault.returncode != 0
            and fault_status.get("state") == "absent"
            and diagnostic_available(fault_status)
            and inventory() == before_fault
        )

        invalid = command([str(SANDBOX), "collect", SANDBOXES[0], "invalid-run", "invalid-attempt"], timeout=7)
        invalid_status = status(SANDBOXES[0])
        invalid_ok = (
            invalid.returncode != 0
            and invalid_status.get("state") == "ready"
            and diagnostic_available(invalid_status)
        )
        reporter.check(
            "lifecycle-failures",
            partial_ok and invalid_ok,
            "partial create and invalid transition retained diagnostics and behaved safely",
        )

        own_a = subject_probe(
            SANDBOXES[0], "http", meta_a["target_endpoint"]["address"], meta_a["target_endpoint"]["service_port"]
        )
        own_b = subject_probe(
            SANDBOXES[1], "http", meta_b["target_endpoint"]["address"], meta_b["target_endpoint"]["service_port"]
        )
        allowed_ok = own_a.get("reachable") is True and own_b.get("reachable") is True
        reporter.check("allowed-path", allowed_ok, "each subject reached its own target")

        probes = {
            "a-to-b": subject_probe(
                SANDBOXES[0], "http", meta_b["target_endpoint"]["address"], meta_b["target_endpoint"]["service_port"]
            ),
            "b-to-a": subject_probe(
                SANDBOXES[1], "http", meta_a["target_endpoint"]["address"], meta_a["target_endpoint"]["service_port"]
            ),
            "management": subject_probe(
                SANDBOXES[0], "http", meta_a["fixture"]["address"], meta_a["fixture"]["management_port"]
            ),
            "forbidden-egress": subject_probe(
                SANDBOXES[1], "http", meta_b["fixture"]["address"], meta_b["fixture"]["forbidden_egress_port"]
            ),
            "dns-udp": subject_probe(
                SANDBOXES[0], "dns-udp", meta_a["fixture"]["address"], meta_a["fixture"]["dns_udp_port"]
            ),
            "dns-tcp": subject_probe(
                SANDBOXES[1], "dns-tcp", meta_b["fixture"]["address"], meta_b["fixture"]["dns_tcp_port"]
            ),
        }
        reached = sorted(name for name, value in probes.items() if value.get("reachable") is True)
        reporter.check(
            "declared-denials",
            not reached,
            "all declared forbidden paths denied" if not reached else f"reachable forbidden paths: {', '.join(reached)}",
        )

        runs = parallel_sandbox(
            "run",
            [(SANDBOXES[0], RUNS[0], ATTEMPTS[0]), (SANDBOXES[1], RUNS[1], ATTEMPTS[1])],
        )
        meta_a, meta_b = status(SANDBOXES[0]), status(SANDBOXES[1])
        execution_ok = (
            all(value.returncode == 0 for value in runs)
            and verify_state(meta_a, RUNS[0], ATTEMPTS[0])
            and verify_state(meta_b, RUNS[1], ATTEMPTS[1])
        )
        reporter.check("concurrent-execution", execution_ok, "both target transitions were observed independently")

        observed_state_a = state_sha256(meta_a)
        observed_state_b = state_sha256(meta_b)
        collected_a = sandbox("collect", SANDBOXES[0], RUNS[0], ATTEMPTS[0])
        collected_b = sandbox("collect", SANDBOXES[1], RUNS[1], ATTEMPTS[1])
        artifact_a = record_artifact(collected_a)
        artifact_b = record_artifact(collected_b)
        record_a = artifact_a[1] if artifact_a is not None else {}
        record_b = artifact_b[1] if artifact_b is not None else {}
        repeated_a = sandbox("collect", SANDBOXES[0], RUNS[0], ATTEMPTS[0])
        repeated_b = sandbox("collect", SANDBOXES[1], RUNS[1], ATTEMPTS[1])
        repeated_artifact_a = record_artifact(repeated_a)
        repeated_artifact_b = record_artifact(repeated_b)
        collection_repeatable = (
            artifact_a is not None
            and artifact_b is not None
            and repeated_artifact_a == artifact_a
            and repeated_artifact_b == artifact_b
        )
        reporter.check(
            "collection-repeatability",
            collection_repeatable,
            "repeated collection preserved both completed records",
        )
        evidence_ok = (
            record_is_independent(record_a, meta_a, RUNS[0], ATTEMPTS[0], observed_state_a)
            and record_is_independent(record_b, meta_b, RUNS[1], ATTEMPTS[1], observed_state_b)
            and subject_cannot_write_artifact(SANDBOXES[0], artifact_a)
            and subject_cannot_write_artifact(SANDBOXES[1], artifact_b)
        )
        reporter.check(
            "evidence-boundary",
            evidence_ok,
            "records were bound to the exact operator-observed protected state and identity",
        )

        hold = start_hold_open(meta_a)
        prior_processes = target_scope_processes(meta_a)
        original_anchor_a = process_identity(int(meta_a["subject_scope"]["anchor_pid"]))
        original_anchor_b = process_identity(int(meta_b["subject_scope"]["anchor_pid"]))
        prior_reset_generation = int(meta_a["reset_generation"])
        sandbox("reset", SANDBOXES[0])
        prior_processes_gone = bool(prior_processes) and all(
            not process_identity_alive(identity) for identity in prior_processes
        )
        invalidated, hold_detail = finish_hold_open(hold)
        hold = None
        reset_meta = status(SANDBOXES[0])
        sibling_meta = status(SANDBOXES[1])
        first_reset_ok = (
            int(reset_meta["reset_generation"]) == prior_reset_generation + 1
            and verify_manifest(reset_meta)
            and subject_scope_valid(reset_meta)
            and artifact_unchanged(artifact_a)
            and artifact_unchanged(artifact_b)
        )
        second_prior_processes = target_scope_processes(reset_meta)
        sandbox("reset", SANDBOXES[0])
        second_prior_processes_gone = bool(second_prior_processes) and all(
            not process_identity_alive(identity) for identity in second_prior_processes
        )
        reset_meta = status(SANDBOXES[0])
        reset_ok = (
            invalidated
            and first_reset_ok
            and int(reset_meta["reset_generation"]) == prior_reset_generation + 2
            and verify_manifest(reset_meta)
            and subject_scope_valid(reset_meta)
            and prior_processes_gone
            and second_prior_processes_gone
            and artifact_unchanged(artifact_a)
            and artifact_unchanged(artifact_b)
            and sibling_meta.get("state") == "completed"
            and verify_state(sibling_meta, RUNS[1], ATTEMPTS[1])
        )
        second = command([str(SANDBOX), "run", SANDBOXES[0], RUNS[2], ATTEMPTS[2]], timeout=12)
        reset_ok = reset_ok and second.returncode == 0
        reset_detail = (
            "repeat reset preserved evidence, removed prior processes, restored baseline, and allowed re-run"
            if reset_ok
            else hold_detail
        )
        reporter.check("reset-invariant", reset_ok, reset_detail)

        deleted = parallel_sandbox("delete", [(SANDBOXES[1],), (SANDBOXES[0],)])
        repeat_a = command([str(SANDBOX), "delete", SANDBOXES[0]], timeout=12)
        repeat_b = command([str(SANDBOX), "delete", SANDBOXES[1]], timeout=12)
        cleanup_ok = (
            all(value.returncode == 0 for value in deleted)
            and repeat_a.returncode == repeat_b.returncode == 0
            and status(SANDBOXES[0]).get("state") == status(SANDBOXES[1]).get("state") == "absent"
            and original_anchor_a is not None
            and not process_identity_alive(original_anchor_a)
            and original_anchor_b is not None
            and not process_identity_alive(original_anchor_b)
            and inventory() == initial_inventory
        )
        reporter.check("scoped-cleanup", cleanup_ok, "delete was scoped, complete, and repeatable")

        safety_ok = sentinel_intact(sentinel_path, sentinel_content, sentinel_process)
        reporter.check("safety-sentinel", safety_ok, "unrelated file, process, and nft table survived")
    except BaseException as error:
        reporter.check("verifier-completion", False, f"verification aborted: {type(error).__name__}: {error}")
    finally:
        if hold is not None and hold.poll() is None:
            hold.kill()
            hold.wait()
        for sandbox_id in (FAULT_SANDBOX, *reversed(SANDBOXES)):
            command([str(SANDBOX), "delete", sandbox_id], timeout=12)
        if not reporter.has("scoped-cleanup"):
            reporter.check(
                "scoped-cleanup",
                inventory() == initial_inventory,
                "reserved verifier resources were removed after an interrupted run",
            )
        if not reporter.has("safety-sentinel"):
            safety_ok = (
                sentinel_path is not None
                and sentinel_process is not None
                and sentinel_intact(sentinel_path, sentinel_content, sentinel_process)
            )
            reporter.check(
                "safety-sentinel",
                safety_ok,
                "unrelated verifier resources survived the interrupted run",
            )
        cleanup_sentinel(sentinel_path, sentinel_process)
    return reporter.finish()


if __name__ == "__main__":
    raise SystemExit(main())
