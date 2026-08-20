# Disposable Linux environment

`Dockerfile` defines the userspace and toolchain for local lab development. Its Debian base and package-index snapshot are immutable inputs. `bin/lab build` creates the local image, while `bin/lab preflight` proves the kernel and administrative features the exercise needs.

The supplied lab is a container, not a VM or an assessment security boundary. `bin/lab` starts it with Docker `--privileged`, which grants broad capabilities and device access needed to create namespaces, cgroups, interfaces, and packet-filter rules. Use it only on macOS with a VM-backed engine or on a Docker host that is itself a dedicated throwaway Linux VM. Do not run untrusted submissions on a workstation or shared Docker host.

The formal evaluator starts a fresh candidate container on an independently disposable worker, mounts the candidate submission read-only, drives it externally, and retains authoritative evidence outside that container. Before a cohort is issued, release metadata must bind the public Git tag to a published image digest and the private evaluator version.

Supported container features:

- Linux with cgroup v2;
- rootful Docker-compatible engine for the local wrapper;
- network namespaces, veth, nftables, and conntrack;
- writable delegated prefixes from `CONTRACT.md`; and
- distinct unprivileged `range-subject`, `range-target`, and `range-fixture` identities; and
- no production credentials, host engine socket, or unrelated workloads in the container.
