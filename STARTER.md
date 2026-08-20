# Starter runtime

The starter is a small local rollout worker, not a production architecture. It already supplies the lifecycle adapter, unprivileged workload identities, deterministic services, dynamic sandbox allocation, fixture endpoints, scoped resource names, logs, and a run-record path. A bounded set of behaviors does not yet satisfy `CONTRACT.md`.

Run it only inside the disposable environment:

```sh
bin/lab shell
bin/preflight
bin/sandbox create alpha
bin/sandbox wait-ready alpha
bin/sandbox run alpha run-1 attempt-1
bin/sandbox collect alpha run-1 attempt-1
bin/sandbox reset alpha
bin/sandbox delete alpha
```

Every operation emits JSON on success. `status` reports the evaluator attachment, endpoints, generations, and diagnostic paths needed to inspect packet and process state. `bin/subject` runs a supplied probe from the unprivileged subject vantage. Runtime files live only under the prefixes published in `CONTRACT.md`.

The declared partial-start fixture is:

```sh
RANGE_INTERVIEW_FAULT=create-after-owned-resource bin/sandbox create partial
bin/sandbox status partial
```

That create must return nonzero without leaving sandbox resources. The variable is for verification only; solutions must not depend on it during normal operation.

You may make a focused repair or replace the internals. Keep `bin/sandbox` operations and their observable meanings stable. Do not edit fixtures to redefine the expected result.
