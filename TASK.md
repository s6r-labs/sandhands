# Sandbox runtime repair

## Objective

Repair a deliberately incomplete local rollout worker so two reusable sandboxes can run concurrently, communicate only through their declared paths, reset to the same baseline, clean up their owned resources, and produce evidence that the subject cannot forge.

The production frame is a node-local rollout data plane scheduled and managed by a Kubernetes control plane. This exercise isolates the Linux runtime primitive: no cluster, Kubernetes API, manifests, CRDs, Helm, or specific CNI are required. Your design notes should make clear which responsibilities remain node-local and which belong above this adapter.

This is a two-hour exercise. The published core is sufficient for full credit. There is no bonus category and no credit for extra services, UI, cloud deployment, a Kubernetes deployment, live-model integration, custom CI, or production packaging. Stop after two hours and report incomplete work precisely.

## Evaluation focus

Evaluation considers whether the submitted runtime is safe, functional, repeatable, observable, and well reasoned. In particular:

- Linux network and packet-path reasoning;
- process ownership, termination, and resource cleanup;
- deterministic sandbox reset;
- concurrent sandbox isolation;
- independent evidence and attribution;
- diagnosis, scope control, and explicit nonclaims; and
- first-order rollout-capacity judgment.

No particular implementation earns preferred treatment. Memorized firewall syntax, a preferred language or runtime, domain realism, model behavior, cloud familiarity, commit cadence, and unrequested scope are not evaluation targets. Detailed scoring and evaluator cases are intentionally not part of the candidate repository.

## Environment

Use the supplied privileged Linux container. It is a disposable lab environment, not a VM or containment boundary. The timer starts only after the provided preflight check passes. Environment-support time is not scored.

You may use local documentation, an IDE, assistive tools, and AI assistants. You remain responsible for the result and must be able to explain it during the follow-up.

Do not use real targets, public offensive activity, production credentials, customer data, or external model services. Do not modify resources outside the disposable exercise boundary.

## Task

Preserve the lifecycle adapter in [`CONTRACT.md`](CONTRACT.md), but change or replace its implementation as needed.

The supplied starter provides the lifecycle adapter, topology, deterministic services, fixtures, collector boundary, and public-check plumbing. The repair surface is limited to three bounded defects. You are not expected to build the lab or evaluator from scratch, and the task does not identify the defects' implementation-level causes.

Your implementation must establish all of the following:

1. Each subject can complete the declared request to its own target.
2. A subject cannot reach the sibling target, management endpoint, supplied forbidden-egress HTTP sink, or supplied UDP/TCP DNS sink.
3. Two sandboxes can run at the same time without shared state, identity, port, path, or cleanup collisions.
4. Reset terminates sandbox-owned descendants and listeners, restores canonical mutable state, and leaves the sandbox ready for a second run.
5. Delete is bounded, scoped, and safe to repeat.
6. Verdict-critical evidence is collected from outside the subject-controlled boundary and is tied to the exact run, attempt, sandbox, reset generation, and baseline.
7. Failed and invalid lifecycle operations retain useful diagnostics, return nonzero, and do not claim unsupported success. The public verifier includes one declared partial-start failure and invalid-transition check.

The public verifier will test both allowed and denied behavior. Configuration inspection and candidate-authored `PASS` files are not runtime proof.

## Submission

Submit the working tree at the two-hour boundary together with the provided submission note. The note must contain:

- the root cause you diagnosed for each repaired behavior;
- one allowed and one forbidden packet path;
- the reset invariant;
- the evidence trust boundary;
- exact verification commands and results;
- unresolved gaps and nonclaims; and
- the capacity answer below.

Keep the note below 500 words. A small, correct implementation with precise limitations scores better than speculative scope.

## Capacity question

Assume a target of 100,000 rollouts per hour. Each rollout occupies its sandbox for 30 seconds of execution, 2 seconds of reset, 3 seconds of evidence collection, and 1 second of release. Target 70% sandbox utilization.

Estimate baseline active-sandbox capacity. State your assumptions, explain how p95/p99 occupancy or reset latency changes the estimate, identify the first two likely bottlenecks you would measure, and describe the overload or backpressure behavior you would want before attempting this scale. Briefly state which work belongs in the rollout data plane rather than the scheduling/control plane. In one or two sentences, say what this node-local adapter owns and what the external scheduler must handle when a node terminates; no Kubernetes API detail or implementation is expected.
