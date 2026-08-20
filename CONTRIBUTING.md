# Contributing

## Public and private boundary

This repository is permanently public to assessment candidates through its full Git history. The scoring rubric, score bands, hard-gate implementation, hidden evaluator checks, parameterized cases, reference implementations, failure-corpus patches, reviewer notes, calibration outcomes, and candidate submissions belong in a separate private repository with no shared Git ancestry.

Do not commit sensitive material here and later remove it. Deletion does not remove an object from Git history.

## History policy

Curate changes as complete, reviewable milestones. A useful public history should explain why the assessment contract exists and how its observable interfaces evolved without showing candidates the intended repair.

Expected milestone sequence:

1. Repository boundaries and contribution rules.
2. Minimal candidate task and observable runtime contract.
3. Reproducible disposable-Linux environment.
4. Deliberately incomplete sandbox runtime.
5. Invariant-based public verification and candidate handoff.

Each commit should:

- have one clear purpose and an imperative subject;
- include the relevant public tests or documentation;
- avoid WIP and fixup commits;
- preserve harness-neutral behavior;
- pass all checks available at that milestone; and
- contain no reference repair, hidden assertion, or reviewer preference.

Public verification must assert only the observable contract. Test names, comments, fixtures, and commit messages must not identify a seeded root cause, prescribe a repair mechanism, expose an implementation-specific failing path, or reveal scoring weights and evaluator prioritization.

History may be rewritten while the assessment is explicitly unreleased. Once a candidate version is tagged, do not rewrite it; fixes become a new version and apply only to a future cohort.

## Change discipline

Keep changes narrow. Record exact verification commands and distinguish structural checks from live runtime proof. Do not reward extra files, services, polish, or framework choices that are unrelated to the published scorecard.
