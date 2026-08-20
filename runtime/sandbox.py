#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Iterator


REPO_ROOT = Path(__file__).resolve().parents[1]
RUN_ROOT = Path("/run/range-interview")
SANDBOXES_ROOT = RUN_ROOT / "sandboxes"
LOCK_ROOT = RUN_ROOT / "locks"
DIAGNOSTIC_ROOT = RUN_ROOT / "diagnostics"
STATE_ROOT = Path("/var/lib/range-interview/state")
CGROUP_ROOT = Path("/sys/fs/cgroup/range-interview")
BASELINE_ROOT = REPO_ROOT / "fixtures/baseline/state"
BASELINE_MANIFEST = REPO_ROOT / "fixtures/baseline/manifest.sha256"
NFT_TABLE = "range_interview"

SUBJECT_UID_BASE = 22000
TARGET_UID_BASE = 23000
FIXTURE_UID = 2003
FIXTURE_GID = 2003

FIXTURE_NS = "ri-fixture"
FIXTURE_HOST_IF = "ri-hfixture"
FIXTURE_PEER_IF = "ri-pfixture"
FIXTURE_HOST_CIDR = "10.250.0.1/30"
FIXTURE_ADDRESS = "10.250.0.2"
FIXTURE_CIDR = f"{FIXTURE_ADDRESS}/30"
MANAGEMENT_PORT = 9000
EGRESS_PORT = 8081
DNS_PORT = 5353
TARGET_PORT = 8080
HOLD_OPEN_PORT = 8088

SANDBOX_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
IDENTITY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class LifecycleError(RuntimeError):
    pass


class InvalidTransition(LifecycleError):
    pass


class DeadlineExpired(LifecycleError):
    pass


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def emit(**value: object) -> None:
    print(json.dumps(value, sort_keys=True), flush=True)


def run(
    command: list[str],
    *,
    check: bool = True,
    capture: bool = False,
    quiet: bool = False,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    stdout: int | None = subprocess.PIPE if capture else subprocess.DEVNULL if quiet else None
    stderr: int | None = subprocess.PIPE if capture else subprocess.DEVNULL if quiet else None
    return subprocess.run(
        command,
        check=check,
        text=True,
        input=input_text,
        stdout=stdout,
        stderr=stderr,
    )


def atomic_json(path: Path, value: dict[str, object], mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}-")
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def atomic_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}-")
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write(value)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_json(path: Path) -> dict[str, object]:
    with path.open() as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise LifecycleError(f"expected an object in {path}")
    return value


def token_for(sandbox_id: str) -> str:
    return hashlib.sha256(sandbox_id.encode()).hexdigest()[:10]


def sandbox_dir(token: str) -> Path:
    return SANDBOXES_ROOT / token


def meta_path(token: str) -> Path:
    return sandbox_dir(token) / "meta.json"


def state_dir(token: str) -> Path:
    return STATE_ROOT / token


def cgroup_dir(token: str) -> Path:
    return CGROUP_ROOT / "sandboxes" / token


def subject_cgroup_dir(token: str) -> Path:
    return cgroup_dir(token) / "subject"


def target_cgroup_dir(token: str) -> Path:
    return cgroup_dir(token) / "target"


def run_cgroup_dir(token: str) -> Path:
    return cgroup_dir(token) / "run"


def diagnostic_path(token: str) -> Path:
    return DIAGNOSTIC_ROOT / f"{token}.log"


@contextlib.contextmanager
def locked(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        yield


@contextlib.contextmanager
def deadline_critical() -> Iterator[None]:
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def namespace_exists(name: str) -> bool:
    return (Path("/var/run/netns") / name).exists()


def link_exists(name: str) -> bool:
    return run(["ip", "link", "show", "dev", name], check=False, quiet=True).returncode == 0


def delete_namespace(name: str) -> None:
    if namespace_exists(name):
        run(["ip", "netns", "delete", name], check=False, quiet=True)


def delete_link(name: str) -> None:
    if link_exists(name):
        run(["ip", "link", "delete", name], check=False, quiet=True)


def create_link(
    namespace: str,
    host_interface: str,
    peer_interface: str,
    host_cidr: str,
    guest_cidr: str,
    gateway: str,
) -> None:
    run(["ip", "netns", "add", namespace])
    run(["ip", "link", "add", host_interface, "type", "veth", "peer", "name", peer_interface])
    run(["ip", "link", "set", peer_interface, "netns", namespace])
    run(["ip", "address", "add", host_cidr, "dev", host_interface])
    run(["ip", "link", "set", host_interface, "up"])
    run(["ip", "-n", namespace, "link", "set", "lo", "up"])
    run(["ip", "-n", namespace, "address", "add", guest_cidr, "dev", peer_interface])
    run(["ip", "-n", namespace, "link", "set", peer_interface, "up"])
    run(["ip", "-n", namespace, "route", "add", "default", "via", gateway])


def ensure_cgroup(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if not (path / "cgroup.procs").exists():
        raise LifecycleError(f"cgroup unavailable: {path}")


def process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def process_in_cgroup(pid: int, path: Path) -> bool:
    try:
        memberships = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
    except FileNotFoundError:
        return False
    expected = "/" + str(path.relative_to(Path("/sys/fs/cgroup")))
    return f"0::{expected}" in memberships


def process_start_time(pid: int) -> int:
    value = Path(f"/proc/{pid}/stat").read_text()
    close = value.rfind(")")
    if close < 0:
        raise LifecycleError(f"cannot parse process identity for PID {pid}")
    fields = value[close + 2 :].split()
    if len(fields) <= 19:
        raise LifecycleError(f"process identity is incomplete for PID {pid}")
    return int(fields[19])


def process_netns_inode(pid: int) -> int:
    return Path(f"/proc/{pid}/ns/net").stat().st_ino


def process_identity(pid: int) -> tuple[int, int, str]:
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
    if uid is None or gid is None or capabilities is None:
        raise LifecycleError(f"process credentials are incomplete for PID {pid}")
    return uid, gid, capabilities


def place_process(pid: int, path: Path) -> None:
    (path / "cgroup.procs").write_text(f"{pid}\n")


def unprivileged_command(uid: int, gid: int, namespace: str, command: list[str]) -> list[str]:
    return [
        "ip",
        "netns",
        "exec",
        namespace,
        "setpriv",
        f"--reuid={uid}",
        f"--regid={gid}",
        "--clear-groups",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--bounding-set=-all",
        "--no-new-privs",
        "--",
        *command,
    ]


def spawn(
    namespace: str,
    uid: int,
    gid: int,
    command: list[str],
    log_path: Path,
    cgroup: Path,
) -> subprocess.Popen[bytes]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.touch(mode=0o600, exist_ok=True)
    os.chmod(log_path, 0o600)
    process: subprocess.Popen[bytes] | None = None
    try:
        with log_path.open("ab", buffering=0) as stream:
            process = subprocess.Popen(
                unprivileged_command(uid, gid, namespace, command),
                stdout=stream,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        place_process(process.pid, cgroup)
    except BaseException:
        if process is not None and process_alive(process.pid):
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        raise
    return process


def terminate_recorded(meta: dict[str, object], field: str, group: Path) -> None:
    value = meta.get(field)
    if not isinstance(value, int) or not process_alive(value):
        return
    if not process_in_cgroup(value, group):
        raise LifecycleError(f"refusing to signal PID {value} outside {group}")
    os.kill(value, signal.SIGTERM)
    deadline = time.monotonic() + 0.25
    while process_alive(value) and time.monotonic() < deadline:
        time.sleep(0.05)
    if process_alive(value):
        os.kill(value, signal.SIGKILL)


def cgroup_processes(group: Path) -> set[int]:
    processes: set[int] = set()
    for path in (group / "cgroup.procs", *group.rglob("cgroup.procs")):
        try:
            processes.update(int(value) for value in path.read_text().splitlines())
        except (FileNotFoundError, PermissionError, ValueError):
            continue
    return processes


def terminate_scope(group: Path) -> None:
    if not group.exists():
        return
    processes = cgroup_processes(group)
    if not processes:
        return
    kill = group / "cgroup.kill"
    if not kill.exists():
        raise LifecycleError(f"cgroup.kill is unavailable for owned scope {group}")
    kill.write_text("1\n")
    wait_deadline = time.monotonic() + 1
    while time.monotonic() < wait_deadline:
        if not cgroup_processes(group):
            return
        time.sleep(0.02)
    raise LifecycleError(f"owned process scope did not empty: {group}")


def recursive_chown(path: Path, uid: int, gid: int) -> None:
    os.chown(path, uid, gid)
    for child in path.rglob("*"):
        os.chown(child, uid, gid)


def prepare_state(meta: dict[str, object]) -> None:
    token = str(meta["token"])
    destination = state_dir(token)
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(BASELINE_ROOT, destination)
    recursive_chown(destination, int(meta["target_uid"]), int(meta["target_gid"]))
    os.chmod(destination, 0o700)


def ensure_policy() -> None:
    if run(["nft", "list", "table", "inet", NFT_TABLE], check=False, quiet=True).returncode != 0:
        run(["nft", "add", "table", "inet", NFT_TABLE])
    if run(
        ["nft", "list", "chain", "inet", NFT_TABLE, "forward"], check=False, quiet=True
    ).returncode != 0:
        run(
            ["nft", "-f", "-"],
            input_text=(
                f"add chain inet {NFT_TABLE} forward "
                "{ type filter hook forward priority 0; policy accept; }\n"
            ),
        )


def fixture_meta_path() -> Path:
    return RUN_ROOT / "fixture.json"


def cleanup_fixture() -> None:
    path = fixture_meta_path()
    if path.exists():
        try:
            meta = read_json(path)
            pid = meta.get("pid")
            if isinstance(pid, int) and process_alive(pid):
                os.kill(pid, signal.SIGTERM)
        except (OSError, ValueError, json.JSONDecodeError):
            pass
    delete_namespace(FIXTURE_NS)
    delete_link(FIXTURE_HOST_IF)
    path.unlink(missing_ok=True)
    shutil.rmtree(CGROUP_ROOT / "fixture", ignore_errors=True)


def ensure_fixture() -> None:
    path = fixture_meta_path()
    if path.exists() and namespace_exists(FIXTURE_NS):
        meta = read_json(path)
        pid = meta.get("pid")
        if isinstance(pid, int) and process_alive(pid):
            return
    cleanup_fixture()
    fixture_cgroup = CGROUP_ROOT / "fixture"
    ensure_cgroup(fixture_cgroup)
    try:
        create_link(
            FIXTURE_NS,
            FIXTURE_HOST_IF,
            FIXTURE_PEER_IF,
            FIXTURE_HOST_CIDR,
            FIXTURE_CIDR,
            "10.250.0.1",
        )
        with deadline_critical():
            process = spawn(
                FIXTURE_NS,
                FIXTURE_UID,
                FIXTURE_GID,
                ["python3", str(REPO_ROOT / "runtime/sink.py")],
                RUN_ROOT / "fixture.log",
                fixture_cgroup,
            )
            atomic_json(path, {"pid": process.pid, "namespace": FIXTURE_NS}, mode=0o600)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            result = run(
                [
                    "curl",
                    "--silent",
                    "--show-error",
                    "--fail",
                    "--max-time",
                    "0.5",
                    f"http://{FIXTURE_ADDRESS}:{MANAGEMENT_PORT}/health",
                ],
                check=False,
                quiet=True,
            )
            if result.returncode == 0:
                return
            time.sleep(0.05)
        raise LifecycleError("fixture service did not become ready")
    except BaseException:
        cleanup_fixture()
        raise


def allocate_index() -> int:
    used: set[int] = set()
    for path in SANDBOXES_ROOT.glob("*/meta.json"):
        try:
            value = read_json(path).get("index")
            if isinstance(value, int):
                used.add(value)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
    for index in range(10, 240):
        if index not in used:
            return index
    raise LifecycleError("no sandbox network indexes available")


def allocate_generation() -> int:
    path = STATE_ROOT / "next-generation"
    try:
        current = int(path.read_text().strip())
    except (FileNotFoundError, ValueError):
        current = 0
    generation = current + 1
    atomic_text(path, f"{generation}\n")
    return generation


def network_values(index: int, token: str) -> dict[str, str]:
    return {
        "subject_namespace": f"ri-s-{token}",
        "target_namespace": f"ri-t-{token}",
        "subject_host_interface": f"ri-hs{token[:8]}",
        "subject_peer_interface": f"ri-ps{token[:8]}",
        "target_host_interface": f"ri-ht{token[:8]}",
        "target_peer_interface": f"ri-pt{token[:8]}",
        "subject_host_cidr": f"10.210.{index}.1/30",
        "subject_cidr": f"10.210.{index}.2/30",
        "subject_address": f"10.210.{index}.2",
        "target_host_cidr": f"10.211.{index}.1/30",
        "target_cidr": f"10.211.{index}.2/30",
        "target_address": f"10.211.{index}.2",
    }


def initialize_runtime(meta: dict[str, object]) -> None:
    token = str(meta["token"])
    runtime = sandbox_dir(token)
    runtime.mkdir(parents=True, mode=0o711, exist_ok=False)
    os.chmod(runtime, 0o711)
    (runtime / "logs").mkdir(mode=0o700)
    subject = runtime / "subject"
    subject.mkdir(mode=0o700)
    recursive_chown(subject, int(meta["subject_uid"]), int(meta["subject_gid"]))
    ensure_cgroup(cgroup_dir(token))
    ensure_cgroup(subject_cgroup_dir(token))
    ensure_cgroup(target_cgroup_dir(token))
    ensure_cgroup(run_cgroup_dir(token))
    prepare_state(meta)


def start_subject_anchor(meta: dict[str, object]) -> int:
    token = str(meta["token"])
    with deadline_critical():
        process = spawn(
            str(meta["subject_namespace"]),
            int(meta["subject_uid"]),
            int(meta["subject_gid"]),
            ["python3", str(REPO_ROOT / "runtime/anchor.py")],
            sandbox_dir(token) / "logs/subject-anchor.log",
            subject_cgroup_dir(token),
        )
        try:
            expected_netns = (Path("/var/run/netns") / str(meta["subject_namespace"])).stat().st_ino
            identity_deadline = time.monotonic() + 1
            while time.monotonic() < identity_deadline:
                if process_alive(process.pid) and process_netns_inode(process.pid) == expected_netns:
                    break
                time.sleep(0.01)
            else:
                raise LifecycleError("subject scope anchor did not enter its declared network namespace")
        except BaseException:
            if process_alive(process.pid):
                os.killpg(process.pid, signal.SIGKILL)
            raise
        meta["subject_anchor_pid"] = process.pid
        meta["subject_anchor_start_time"] = process_start_time(process.pid)
        meta["subject_netns_inode"] = expected_netns
        save_meta(meta)
    return process.pid


def subject_anchor_valid(meta: dict[str, object]) -> bool:
    pid = meta.get("subject_anchor_pid")
    if not isinstance(pid, int) or not process_alive(pid):
        return False
    try:
        uid, gid, capabilities = process_identity(pid)
        return (
            process_start_time(pid) == meta.get("subject_anchor_start_time")
            and process_netns_inode(pid) == meta.get("subject_netns_inode")
            and process_in_cgroup(pid, subject_cgroup_dir(str(meta["token"])))
            and uid == meta.get("subject_uid")
            and gid == meta.get("subject_gid")
            and int(capabilities, 16) == 0
        )
    except (FileNotFoundError, ProcessLookupError, ValueError, LifecycleError):
        return False


def start_target(meta: dict[str, object]) -> int:
    token = str(meta["token"])
    with deadline_critical():
        process = spawn(
            str(meta["target_namespace"]),
            int(meta["target_uid"]),
            int(meta["target_gid"]),
            [
                "python3",
                str(REPO_ROOT / "runtime/target.py"),
                "--sandbox-id",
                str(meta["sandbox_id"]),
                "--state-root",
                str(state_dir(token)),
            ],
            sandbox_dir(token) / "logs/target.log",
            target_cgroup_dir(token),
        )
        meta["target_pid"] = process.pid
        save_meta(meta)
    return process.pid


def readiness(meta: dict[str, object]) -> dict[str, object]:
    result = run(
        unprivileged_command(
            int(meta["subject_uid"]),
            int(meta["subject_gid"]),
            str(meta["subject_namespace"]),
            [
                "curl",
                "--silent",
                "--show-error",
                "--fail",
                "--max-time",
                "2",
                f"http://{meta['target_address']}:8080/health",
            ],
        ),
        capture=True,
    )
    value = json.loads(result.stdout)
    if value.get("sandbox_id") != meta["sandbox_id"] or not isinstance(value.get("state"), dict):
        raise LifecycleError("target health response has the wrong identity or state")
    return value


def wait_ready(meta: dict[str, object]) -> dict[str, object]:
    deadline = time.monotonic() + 3
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            return readiness(meta)
        except (subprocess.CalledProcessError, json.JSONDecodeError, LifecycleError) as error:
            last_error = error
            time.sleep(0.05)
    raise LifecycleError(f"target did not become ready: {last_error}")


def cleanup_sandbox(meta: dict[str, object]) -> None:
    token = str(meta["token"])
    failures: list[str] = []
    for group in (
        run_cgroup_dir(token),
        target_cgroup_dir(token),
        subject_cgroup_dir(token),
    ):
        try:
            terminate_scope(group)
        except LifecycleError as error:
            failures.append(str(error))
    if failures:
        raise LifecycleError("; ".join(failures))
    for field in ("subject_namespace", "target_namespace"):
        value = meta.get(field)
        if isinstance(value, str):
            delete_namespace(value)
            if namespace_exists(value):
                failures.append(f"network namespace remains: {value}")
    for field in ("subject_host_interface", "target_host_interface"):
        value = meta.get(field)
        if isinstance(value, str):
            delete_link(value)
            if link_exists(value):
                failures.append(f"network interface remains: {value}")
    if failures:
        raise LifecycleError("; ".join(failures))
    shutil.rmtree(state_dir(token), ignore_errors=True)
    if state_dir(token).exists():
        failures.append("sandbox state directory remains")
    for group in (
        run_cgroup_dir(token),
        target_cgroup_dir(token),
        subject_cgroup_dir(token),
        cgroup_dir(token),
    ):
        try:
            group.rmdir()
        except FileNotFoundError:
            continue
        except OSError as error:
            failures.append(f"cannot remove cgroup {group}: {error}")
    if failures:
        raise LifecycleError("; ".join(failures))
    shutil.rmtree(sandbox_dir(token), ignore_errors=True)
    if sandbox_dir(token).exists():
        raise LifecycleError("sandbox runtime directory remains")


def save_meta(meta: dict[str, object]) -> None:
    atomic_json(meta_path(str(meta["token"])), meta, mode=0o600)


def load_meta(sandbox_id: str) -> dict[str, object] | None:
    token = token_for(sandbox_id)
    path = meta_path(token)
    if not path.exists():
        return None
    meta = read_json(path)
    if meta.get("sandbox_id") != sandbox_id:
        raise LifecycleError("sandbox identifier hash collision")
    return meta


def write_diagnostic(sandbox_id: str, error: BaseException) -> None:
    token = token_for(sandbox_id)
    path = diagnostic_path(token)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as stream:
        stream.write(f"{now()} {type(error).__name__}: {error}\n")


def do_create(sandbox_id: str) -> None:
    if load_meta(sandbox_id) is not None:
        raise InvalidTransition("create requires state absent")
    ensure_policy()
    ensure_fixture()
    token = token_for(sandbox_id)
    index = allocate_index()
    meta: dict[str, object] = {
        "sandbox_id": sandbox_id,
        "token": token,
        "index": index,
        "state": "failed",
        "sandbox_generation": allocate_generation(),
        "reset_generation": 0,
        "subject_uid": SUBJECT_UID_BASE + index,
        "subject_gid": SUBJECT_UID_BASE + index,
        "target_uid": TARGET_UID_BASE + index,
        "target_gid": TARGET_UID_BASE + index,
        **network_values(index, token),
    }
    try:
        initialize_runtime(meta)
        create_link(
            str(meta["subject_namespace"]),
            str(meta["subject_host_interface"]),
            str(meta["subject_peer_interface"]),
            str(meta["subject_host_cidr"]),
            str(meta["subject_cidr"]),
            str(meta["subject_host_cidr"]).split("/")[0],
        )
        if os.environ.get("RANGE_INTERVIEW_FAULT") == "create-after-owned-resource":
            raise LifecycleError("injected create failure after owned resource allocation")
        create_link(
            str(meta["target_namespace"]),
            str(meta["target_host_interface"]),
            str(meta["target_peer_interface"]),
            str(meta["target_host_cidr"]),
            str(meta["target_cidr"]),
            str(meta["target_host_cidr"]).split("/")[0],
        )
        start_subject_anchor(meta)
        start_target(meta)
        wait_ready(meta)
        meta["state"] = "ready"
        save_meta(meta)
    except BaseException:
        cleanup_sandbox(meta)
        raise
    emit(operation="create", sandbox_id=sandbox_id, state="ready")


def require_state(meta: dict[str, object], operation: str, allowed: set[str]) -> None:
    state = str(meta.get("state"))
    if state not in allowed:
        raise InvalidTransition(f"{operation} is invalid from state {state}")


def do_wait_ready(meta: dict[str, object]) -> None:
    require_state(meta, "wait-ready", {"ready", "completed"})
    try:
        if not subject_anchor_valid(meta):
            raise LifecycleError("subject scope anchor is unavailable")
        health = readiness(meta)
    except BaseException:
        meta["state"] = "failed"
        meta["last_failure"] = "readiness_failed"
        save_meta(meta)
        raise
    emit(operation="wait-ready", sandbox_id=meta["sandbox_id"], state=meta["state"], health=health)


def trace_path(meta: dict[str, object], run_id: str, attempt_id: str) -> Path:
    identity = hashlib.sha256(f"{run_id}\0{attempt_id}".encode()).hexdigest()[:16]
    return sandbox_dir(str(meta["token"])) / "subject" / f"trace-{identity}.json"


def do_run(meta: dict[str, object], run_id: str, attempt_id: str) -> None:
    require_state(meta, "run", {"ready"})
    trace = trace_path(meta, run_id, attempt_id)
    started_at = now()
    with deadline_critical():
        process = spawn(
            str(meta["subject_namespace"]),
            int(meta["subject_uid"]),
            int(meta["subject_gid"]),
            [
                "python3",
                str(REPO_ROOT / "runtime/subject.py"),
                "--target",
                str(meta["target_address"]),
                "--run-id",
                run_id,
                "--attempt-id",
                attempt_id,
                "--trace",
                str(trace),
            ],
            sandbox_dir(str(meta["token"])) / "logs/subject.log",
            run_cgroup_dir(str(meta["token"])),
        )
        meta["subject_pid"] = process.pid
        save_meta(meta)
    try:
        exit_status = process.wait(timeout=7)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        exit_status = 124
    except BaseException:
        if process_alive(process.pid):
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        meta["state"] = "failed"
        meta["last_failure"] = "run_interrupted"
        save_meta(meta)
        raise
    meta.update(
        {
            "last_run_id": run_id,
            "last_attempt_id": attempt_id,
            "last_started_at": started_at,
            "last_ended_at": now(),
            "last_exit_status": exit_status,
            "last_trace": str(trace),
        }
    )
    if exit_status != 0 or not trace.exists():
        meta["state"] = "failed"
        save_meta(meta)
        raise LifecycleError(f"subject run failed with status {exit_status}")
    meta["state"] = "completed"
    save_meta(meta)
    emit(
        operation="run",
        sandbox_id=meta["sandbox_id"],
        state="completed",
        run_id=run_id,
        attempt_id=attempt_id,
    )


def baseline_digest() -> str:
    return hashlib.sha256(BASELINE_MANIFEST.read_bytes()).hexdigest()


def do_collect(meta: dict[str, object], run_id: str, attempt_id: str) -> None:
    require_state(meta, "collect", {"completed"})
    if meta.get("last_run_id") != run_id or meta.get("last_attempt_id") != attempt_id:
        raise InvalidTransition("collect identity does not match the completed run")
    trace = read_json(Path(str(meta["last_trace"])))
    passed = trace.get("verdict") == "pass"
    record = {
        "schema_version": 1,
        "run_id": run_id,
        "attempt_id": attempt_id,
        "sandbox_id": meta["sandbox_id"],
        "sandbox_generation": meta["sandbox_generation"],
        "reset_generation": meta["reset_generation"],
        "baseline_sha256": baseline_digest(),
        "started_at": meta["last_started_at"],
        "ended_at": meta["last_ended_at"],
        "outcome": "succeeded" if passed else "failed",
        "exit_status": meta["last_exit_status"],
        "collector": {"id": "sandbox-adapter", "vantage": "guest-operator"},
        "observations": [
            {
                "kind": "connectivity",
                "vantage": "subject-trace",
                "result": "pass" if passed else "fail",
                "details": {"trace": str(meta["last_trace"])},
            }
        ],
        "verdict": "pass" if passed else "fail",
        "verdict_reason": "subject run reported success" if passed else "subject run reported failure",
        "subject_trace": trace,
    }
    identity = hashlib.sha256(
        (
            f"{meta['sandbox_id']}\0{meta['sandbox_generation']}\0{meta['reset_generation']}\0"
            f"{run_id}\0{attempt_id}"
        ).encode()
    ).hexdigest()[:20]
    path = sandbox_dir(str(meta["token"])) / "records" / f"{identity}.json"
    path.parent.mkdir(mode=0o700, exist_ok=True)
    os.chmod(path.parent, 0o700)
    atomic_json(path, record, mode=0o600)
    emit(operation="collect", sandbox_id=meta["sandbox_id"], record=str(path), run_record=record)


def do_reset(meta: dict[str, object]) -> None:
    require_state(meta, "reset", {"ready", "completed", "failed"})
    try:
        terminate_scope(run_cgroup_dir(str(meta["token"])))
        terminate_recorded(meta, "target_pid", target_cgroup_dir(str(meta["token"])))
        if not subject_anchor_valid(meta):
            anchor_pid = meta.get("subject_anchor_pid")
            if isinstance(anchor_pid, int) and process_alive(anchor_pid):
                raise LifecycleError("subject scope anchor moved outside its declared identity")
            terminate_scope(subject_cgroup_dir(str(meta["token"])))
            start_subject_anchor(meta)
        prepare_state(meta)
        start_target(meta)
        wait_ready(meta)
    except BaseException:
        meta["state"] = "failed"
        save_meta(meta)
        raise
    meta["reset_generation"] = int(meta["reset_generation"]) + 1
    meta["state"] = "ready"
    for field in (
        "last_run_id",
        "last_attempt_id",
        "last_started_at",
        "last_ended_at",
        "last_exit_status",
        "last_trace",
        "subject_pid",
    ):
        meta.pop(field, None)
    save_meta(meta)
    emit(
        operation="reset",
        sandbox_id=meta["sandbox_id"],
        state="ready",
        reset_generation=meta["reset_generation"],
    )


def do_status(sandbox_id: str, meta: dict[str, object] | None) -> None:
    token = token_for(sandbox_id)
    if meta is None:
        emit(
            operation="status",
            sandbox_id=sandbox_id,
            state="absent",
            diagnostics=str(diagnostic_path(token)),
        )
        return
    target_pid = meta.get("target_pid")
    subject_scope_is_valid = subject_anchor_valid(meta)
    if meta.get("state") in {"ready", "completed"} and (
        not isinstance(target_pid, int)
        or not process_alive(target_pid)
        or not process_in_cgroup(target_pid, target_cgroup_dir(str(meta["token"])))
        or not subject_scope_is_valid
    ):
        meta["state"] = "failed"
        meta["last_failure"] = "runtime_scope_invalid"
        save_meta(meta)
    visible = dict(meta)
    visible.update(
        {
            "operation": "status",
            "diagnostics": str(diagnostic_path(token)),
            "fixture": {
                "address": FIXTURE_ADDRESS,
                "management_port": MANAGEMENT_PORT,
                "forbidden_egress_port": EGRESS_PORT,
                "dns_udp_port": DNS_PORT,
                "dns_tcp_port": DNS_PORT,
            },
            "subject_attachment": {
                "command": ["bin/subject", sandbox_id, "--"],
                "uid": meta["subject_uid"],
                "gid": meta["subject_gid"],
            },
            "subject_scope": {
                "anchor_pid": meta["subject_anchor_pid"],
                "pid_start_time": meta["subject_anchor_start_time"],
                "netns_inode": meta["subject_netns_inode"],
                "cgroup_path": str(subject_cgroup_dir(str(meta["token"]))),
                "uid": meta["subject_uid"],
                "gid": meta["subject_gid"],
                "ipv4_address": meta["subject_address"],
            },
            "target_endpoint": {
                "address": meta["target_address"],
                "service_port": TARGET_PORT,
                "hold_open_port": HOLD_OPEN_PORT,
            },
            "target_process": {"pid": meta["target_pid"]},
            "operator_state_root": str(state_dir(token)),
            "logs": str(sandbox_dir(token) / "logs"),
        }
    )
    emit(**visible)


def do_delete(meta: dict[str, object]) -> None:
    cleanup_sandbox(meta)
    emit(operation="delete", sandbox_id=meta["sandbox_id"], state="absent")


def validate_identifiers(operation: str, values: list[str]) -> tuple[str, str | None, str | None]:
    expected = 3 if operation in {"run", "collect"} else 1
    if len(values) != expected:
        raise LifecycleError(f"{operation} expects {expected} argument(s)")
    sandbox_id = values[0]
    if not SANDBOX_PATTERN.fullmatch(sandbox_id):
        raise LifecycleError("invalid sandbox-id")
    if expected == 1:
        return sandbox_id, None, None
    run_id, attempt_id = values[1:]
    if not IDENTITY_PATTERN.fullmatch(run_id) or not IDENTITY_PATTERN.fullmatch(attempt_id):
        raise LifecycleError("invalid run-id or attempt-id")
    return sandbox_id, run_id, attempt_id


def main() -> int:
    if os.geteuid() != 0:
        print("sandbox runtime requires root inside the disposable environment", file=sys.stderr)
        return 1
    if len(sys.argv) < 2:
        print("missing operation", file=sys.stderr)
        return 2
    operation = sys.argv[1]
    if operation not in {"create", "wait-ready", "run", "reset", "collect", "status", "delete"}:
        print(f"unknown operation: {operation}", file=sys.stderr)
        return 2
    sandbox_id = sys.argv[2] if len(sys.argv) >= 3 else "invalid"
    try:
        sandbox_id, run_id, attempt_id = validate_identifiers(operation, sys.argv[2:])
        internal_deadline = float(os.environ.get("RANGE_INTERVIEW_DEADLINE_SECONDS", "0"))
        if internal_deadline > 0:
            def expire(signum: int, frame: object) -> None:
                raise DeadlineExpired(f"{operation} reached its internal recovery deadline")

            signal.signal(signal.SIGALRM, expire)
            signal.setitimer(signal.ITIMER_REAL, internal_deadline)
        RUN_ROOT.mkdir(parents=True, exist_ok=True)
        os.chmod(RUN_ROOT, 0o711)
        SANDBOXES_ROOT.mkdir(parents=True, exist_ok=True)
        os.chmod(SANDBOXES_ROOT, 0o711)
        LOCK_ROOT.mkdir(parents=True, exist_ok=True)
        os.chmod(LOCK_ROOT, 0o700)
        DIAGNOSTIC_ROOT.mkdir(parents=True, exist_ok=True)
        os.chmod(DIAGNOSTIC_ROOT, 0o700)
        STATE_ROOT.mkdir(parents=True, exist_ok=True)
        os.chmod(STATE_ROOT, 0o711)
        if operation == "create":
            with locked(LOCK_ROOT / "registry.lock"), locked(LOCK_ROOT / f"{token_for(sandbox_id)}.lock"):
                do_create(sandbox_id)
            return 0

        meta = load_meta(sandbox_id)
        if operation == "status" and meta is None:
            do_status(sandbox_id, None)
            return 0
        if operation == "delete" and meta is None:
            emit(operation="delete", sandbox_id=sandbox_id, state="absent", result="no-op")
            return 0
        if meta is None:
            raise InvalidTransition(f"{operation} is invalid from state absent")

        lock_path = LOCK_ROOT / f"{token_for(sandbox_id)}.lock"
        with locked(lock_path):
            meta = load_meta(sandbox_id)
            if meta is None:
                raise InvalidTransition(f"{operation} is invalid from state absent")
            if operation == "wait-ready":
                do_wait_ready(meta)
            elif operation == "run":
                assert run_id is not None and attempt_id is not None
                do_run(meta, run_id, attempt_id)
            elif operation == "collect":
                assert run_id is not None and attempt_id is not None
                do_collect(meta, run_id, attempt_id)
            elif operation == "reset":
                do_reset(meta)
            elif operation == "status":
                do_status(sandbox_id, meta)
            elif operation == "delete":
                do_delete(meta)
        return 0
    except BaseException as error:
        if isinstance(error, KeyboardInterrupt):
            raise
        write_diagnostic(sandbox_id, error)
        print(
            json.dumps(
                {
                    "operation": operation,
                    "sandbox_id": sandbox_id,
                    "error": type(error).__name__,
                    "message": str(error),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
