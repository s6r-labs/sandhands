# Range runtime systems interview

This repository contains the candidate-visible materials for a two-hour systems exercise. The exercise evaluates the Linux runtime beneath reinforcement-learning rollouts and evaluations: network isolation, process ownership, deterministic reset, concurrent lifecycle behavior, and independently trustworthy evidence.

The repository is intentionally separate from the production range monorepo. It contains no real targets, credentials, candidate submissions, hidden evaluator checks, reference fixes, or private calibration results.

The public assessment is defined by:

- [`TASK.md`](TASK.md): candidate instructions and time boundary;
- [`CONTRACT.md`](CONTRACT.md): observable lifecycle, isolation, reset, and evidence requirements.

The scoring rubric, evaluator cases, reference solutions, and calibration material are private and have no shared Git ancestry with this repository. Candidates receive only the requirements needed to understand and operate the exercise.

The runnable lab will be added as a later independently reviewable milestone. Until a release is explicitly tagged, the assessment is under construction and must not be issued to candidates.

Local environment development uses the pinned disposable Linux image:

```sh
bin/lab build
bin/lab preflight
bin/lab shell
```

The supplied lab is the Linux container started by `bin/lab`. It is not a VM or a security boundary. The wrapper uses Docker `--privileged`, giving the container broad capabilities and device access so it can create namespaces, cgroups, interfaces, and packet-filter rules. The sandbox lifecycle itself remains ordinary Linux processes and kernel primitives rather than Docker APIs.

Use the wrapper only with a rootful Docker-compatible engine and cgroup v2. On macOS, the engine already runs inside its own Linux VM. On Linux, the Docker host itself must be a dedicated throwaway VM acknowledged with `RANGE_INTERVIEW_ACK_DISPOSABLE_VM=1`; that variable describes the outer host, not the lab container, and is not VM attestation. Never run a candidate submission directly on a general-purpose Linux host. Formal evaluation runs the privileged lab container on a fresh disposable worker and stores verdict evidence outside the candidate-controlled container.

Dependency resolution uses the Debian snapshot declared in `environment/Dockerfile`. A cohort release additionally records the published assessment-image digest; a mutable local `:dev` tag is not a release identifier.
