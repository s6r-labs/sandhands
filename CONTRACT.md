# Public runtime contract

## Roles and trust boundaries

- **Operator:** invokes lifecycle operations in the disposable environment.
- **Subject:** untrusted episode workload. Its output is a trace input, never ground truth.
- **Target:** sandbox-owned service with canonical mutable state.
- **Collector:** evaluator-controlled observer outside the subject boundary.
- **Evaluator:** runs public and parameterized checks from named vantages and determines the verdict.

The subject must not receive a privileged helper, host-management credential, container-engine socket, evaluator write path, or authority to define its own verdict.

The trust claim under test is that the runtime subject cannot forge verdict-critical observations. Candidate-authored operator code is the implementation being evaluated, not a hostile hypervisor; the external evaluator independently corroborates its claims and makes the formal decision. `collect` must therefore derive observations from operator-visible state or probes rather than accepting a subject assertion as ground truth.

## Sandbox topology

The public lab uses at least two independently named sandboxes. Each sandbox owns its subject, target, network resources, runtime state, process/resource subtree, and evidence identity.

| Source | Destination | Required result |
| --- | --- | --- |
| subject A | target A service | allowed |
| subject B | target B service | allowed |
| subject A | target B service | denied |
| subject B | target A service | denied |
| either subject | management endpoint | denied |
| either subject | supplied forbidden-egress HTTP sink | denied |
| either subject | supplied UDP and TCP DNS sink | denied |
| evaluator collector | protected state readback | allowed out of band |

Every connectivity result must name its probe vantage. Root on the disposable host remains an administrative trust root and is not treated as an unprivileged network actor.

## Lifecycle adapter

The repository supplies one operator-facing adapter with these operations:

```text
sandbox create <sandbox-id>
sandbox wait-ready <sandbox-id>
sandbox run <sandbox-id> <run-id> <attempt-id>
sandbox reset <sandbox-id>
sandbox collect <sandbox-id> <run-id> <attempt-id>
sandbox status <sandbox-id>
sandbox delete <sandbox-id>
```

The candidate may replace all internal implementation. The operation names and observable meanings remain stable so the evaluator can drive any implementation consistently.

Each operation must:

- return within its published timeout;
- exit nonzero on failure;
- act only on resources owned by the supplied sandbox ID;
- distinguish requested termination from an unexpected crash where observable;
- reject or safely handle an invalid lifecycle transition; and
- leave diagnostics available when it fails.

Published deadlines are:

| Operation | Deadline |
| --- | ---: |
| `create` | 10 seconds |
| `wait-ready` | 5 seconds |
| `run` | 10 seconds |
| `reset` | 10 seconds |
| `collect` | 5 seconds |
| `status` | 2 seconds |
| `delete` | 10 seconds |

Crossing a deadline is a failed operation: return nonzero, preserve diagnostics, and leave the sandbox either in its last verified state or `failed`. Do not report success merely because cleanup or initialization continues asynchronously.

`reset` and `delete` must be safe to repeat. A documented no-op is acceptable. Cleanup must never use host-wide process matching, firewall flushing, recursive deletion outside an allocated prefix, or mutation of unrelated resources.

## Lifecycle states and identity

The externally observable states are `absent`, `ready`, `completed`, and `failed`. `completed` means the run has finished while the sandbox and target remain active and protocol-ready for collection until reset or delete. Operations are synchronous at the adapter boundary:

| Current state | Operation | Result on success |
| --- | --- | --- |
| `absent` | `create` | `ready` |
| any state | `status` | unchanged; report the current state |
| `ready` or `completed` | `wait-ready` | unchanged if protocol readiness succeeds |
| `ready` | `run` | `completed` |
| `completed` | `collect` or `status` | unchanged |
| `ready`, `completed`, or `failed` | `reset` | `ready` |
| any state | `delete` | `absent` |
| `absent` | `delete` | `absent` successful no-op |

Every transition not listed above returns nonzero without changing the last verified state. In particular, `create` on an existing sandbox, `run` outside `ready`, `wait-ready` from `absent` or `failed`, and `collect` without the matching completed run are invalid. `collect` is read-only and repeatable for the same identity. The normal sequence is `create`, `wait-ready`, `run`, `collect`, `reset`, and either another `run` or `delete`.

The evaluator supplies `run-id` and `attempt-id`; they are opaque and must not be inferred from sandbox names or reused for another run. Each successful `create` has a sandbox generation; recreating a previously deleted sandbox ID must allocate a new generation. Each successful verified `reset` increments a reset generation, while a failed reset does not advance it. Evidence is keyed by the full run, attempt, sandbox, sandbox-generation, and reset-generation identity.

Identifiers are command-line-safe ASCII. `sandbox-id` matches `[a-z][a-z0-9-]{0,31}`. `run-id` and `attempt-id` each match `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`. Their contents remain opaque even when they resemble an ordinal, timestamp, or sandbox name.

## Evaluator-owned environment interfaces

The following names and paths are supplied interoperability boundaries, not required candidate implementation mechanisms. Candidates may choose their own language, supervisor, network enforcement, or state-management design behind the lifecycle adapter.

The privileged lab container supplies passwordless `sudo` to the candidate for assessment work. This is administrative convenience inside the disposable container, not a VM boundary or permission for broad mutation. Preflight publishes the kernel features and delegates these owned prefixes:

- network namespaces and links beginning `ri-`;
- the `inet range_interview` packet-filter table;
- `/sys/fs/cgroup/range-interview/`;
- `/run/range-interview/`; and
- `/var/lib/range-interview/`.

The candidate may replace the mechanism inside those prefixes. Host-wide firewall tables, unrelated namespaces, system services, global cgroup configuration, and paths outside the prefixes are out of scope. Subject and target workloads run without root, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, access to `sudo`, or access to the container-engine socket.

The repository also supplies a convenience attachment command:

```text
bin/subject <sandbox-id> -- <command> [args...]
```

It runs a probe with the same unprivileged identity and network boundary as that sandbox's subject. It is available only while the sandbox is `ready` or `completed`; it does not grant administrative authority, and its output remains subject-vantage data rather than ground truth. Public smoke tests use this command, but the formal evaluator does not trust the command itself as proof of attachment.

`sandbox status` emits one JSON object. It always includes `sandbox_id` and `state`. For an existing sandbox it also preserves these discovery fields even if the implementation is replaced: `sandbox_generation`, `reset_generation`, `subject_attachment`, `target_endpoint`, `target_process`, `operator_state_root`, and `fixture`. In `ready` and `completed`, it additionally includes `subject_scope`. `target_process.pid` identifies the current target service process for external lifecycle observation. Its cgroup v2 membership defines the target workload's sandbox-owned process scope and remains beneath the delegated `/sys/fs/cgroup/range-interview/` subtree. These are evaluator interoperability descriptors, not prescriptions for a supervisor, firewall, or internal layout.

In `ready` and `completed`, `subject_scope` describes a live, unprivileged sandbox-infrastructure anchor with `anchor_pid`, `pid_start_time`, `netns_inode`, `cgroup_path`, `uid`, `gid`, and `ipv4_address`. The cgroup path is absolute and beneath the delegated cgroup subtree. The PID plus start time identifies one process instance; the remaining values equal that process's evaluator-observed credentials, network namespace, cgroup membership, and observed IPv4 address. The anchor has neither root nor `CAP_NET_ADMIN`/`CAP_SYS_ADMIN`. The evaluator may enter the anchor's network namespace itself and run a read-only probe after dropping to the declared UID/GID and clearing privileges. Reset may preserve or replace this infrastructure anchor but must revalidate it before reporting `ready`; delete invalidates it. No descriptor is required while `absent` or `failed`.

Successful `collect` emits `record`, an absolute evaluator-readable regular-file path beneath `/run/range-interview/` or `/var/lib/range-interview/`, and `run_record`, the schema-valid object stored at that path. The path and its components must not use a symlink to escape or alias that boundary, and neither the subject nor its containing directory may replace the record. Repeating `collect` for the same completed identity returns the same object and path without changing the record. The record remains byte-identical through reset and may be removed by delete.

## Readiness

Readiness requires a completed protocol-level health exchange against initialized canonical state. A process existing or a TCP listener accepting a connection is insufficient.

## Declared run transition

The supplied target begins with `fixtures/baseline/state/account.json`. A successful run request must originate through the unprivileged subject path and cause that target to decrement `balance` by exactly one while recording the evaluator-supplied `run-id` and `attempt-id` as `last_run` and `last_attempt`. It also records the connection peer as `last_source`; this must equal the current `subject_scope.ipv4_address`. Direct operator-side mutation, a substitute endpoint, or a locally fabricated success response does not satisfy the allowed path.

## Reset invariant

After reset:

- canonical mutable state matches `fixtures/baseline/manifest.sha256`;
- no target or run process or listener from the prior run remains; the declared subject-scope anchor is persistent sandbox infrastructure, not a run process;
- the connection created by the supplied `fixtures/hold-open` probe no longer exchanges data;
- the sandbox retains its own identity and cannot observe sibling state;
- a second run can start without manual repair; and
- prior evidence remains outside reset scope.

The baseline manifest uses SHA-256 lines in the same format as `sha256sum`, with paths relative to `fixtures/baseline/state/` and sorted bytewise by path. It covers only files beneath that directory. Runtime initialization copies that tree into the sandbox-owned state path. Logs, timestamps, process IDs, sockets, evidence, and run identifiers are outside the manifest and reset comparison.

## Concurrency invariant

Two supplied sandboxes must create, become ready, run, reset, collect, and delete without sharing mutable state or causing cleanup effects in the other sandbox. Implementations must not depend on fixed global ports, paths, PID files, locks, addresses, or evidence names.

## Evidence contract

The formal evaluator runs its collector from outside the candidate-controlled container. It observes the subject and target through operator-owned inspection interfaces, performs protected-state readback, and stores authoritative records on the evaluator host. After collection it may project a read-only copy beneath `/var/lib/range-interview/evidence/` in the container; that container path is never the authoritative source. The public schema is `schemas/run-record.schema.json`; public checks use the same schema and readback semantics as formal evaluation.

Candidates may change the lifecycle implementation and may add subject trace fields, but they may not make verdict-critical fields depend solely on a subject-writable file. A run record contains at least:

- run ID;
- attempt ID;
- sandbox ID;
- reset generation;
- baseline or configuration digest;
- start and end time;
- lifecycle outcome and exit status;
- independently observed protected state or connectivity result;
- collector identity or vantage; and
- explicit verdict reason.

A passing record for the declared run transition includes a `protected_state` observation bound to an operator-observed state value. Its `details` object contains the exact `run_id`, `attempt_id`, `sandbox_id`, `sandbox_generation`, `reset_generation`, and `state_sha256`. `state_sha256` is the SHA-256 digest of the observed `account.json` bytes after the declared run transition. A subject-provided digest or copied subject verdict is not an operator observation.

Evidence may contain subject output when labeled as subject-controlled. Subject output alone cannot prove isolation, reset, protected-state outcome, or success.

The baseline digest is computed from the published manifest described above. The formal evaluator uses its own collector binary, schema copy, and evidence store from outside the candidate container and working tree; modifying the public checker or a candidate-side record cannot establish a pass.

## Safety sentinels

The evaluator maintains unrelated processes, files, listeners, and network state inside the disposable environment. Candidate cleanup must leave them unchanged. A solution that reaches a green state through broad killing, deletion, or firewall mutation violates the contract.

## Evaluation compatibility

The evaluator may substitute contract-conforming sandbox identifiers, dynamically allocated subject or target addresses and endpoints, and baseline fixture values. Implementations must not depend on the example identifiers or values supplied by the public lab.

Evaluation will not require a particular language, container engine, firewall implementation, CNI, eBPF program, cloud account, model endpoint, or undocumented topology.
