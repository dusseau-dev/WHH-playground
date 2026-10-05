# A09 AI-Assisted Detection Validation — Tasks

Each implementation task uses one red → green → refactor cycle before its dependents begin.

## T1 — Scope and settings normalization

**Depends on:** none

Add failing CLI and worker tests for the available opt-in scope, defaults, staging-only validation, safe canary path,
HTTPS Splunk origin, identifier validation, threshold/wait bounds, and configuration-required/forbidden behavior. Add
the smallest shared-shape implementations in the existing duplicated registries.

## T2 — Secret and YAML contract

**Depends on:** T1

Add failing tests for camelCase and snake_case parsing, nested-token extraction, profile secret references/presence,
clear-secret behavior, run snapshots, worker materialization, resume requirements, and redaction. Extend the existing
target-secret path with `splunkToken`; do not create a second secret store.

## T3 — Fixed corpus and marker generation

**Depends on:** T1

Add failing tests for corpus version, five matched scenario pairs, fictional/inert fixtures, deterministic fixture hashes,
and stable safe markers. Add one versioned data file and pure loader/marker functions.

## T4 — Splunk search and scoring runner

**Depends on:** T2, T3

Add failing tests for the v2 export request, bearer token, generated bounded SPL, streamed JSON parsing, calibration,
sequential target emission, no redirects, polling, de-duplication, latency, cohort thresholding, error statuses, and
evidence redaction. Implement with native `fetch`, `crypto`, and existing atomic file helpers.

## T5 — Temporal execution and resume

**Depends on:** T4

Add failing workflow/activity tests for dedicated phase ordering, agentless execution, cancellation, completed-artifact
loading, retry marker stability, progress state, and threshold failure that does not fail the workflow. Thread normalized
settings and the protected token through existing pipeline credentials.

## T6 — Canonical report and coverage

**Depends on:** T4, T5

Add failing report tests for optional result data, Markdown summary/scenario table, pass/fail completed coverage,
partial/unavailable incomplete coverage, cohort gap/median latency, and absence of raw records or secrets. Extend the
existing deterministic renderer and report validator.

## T7 — Local API, form, and Run Detail UI

**Depends on:** T2, T6

Add failing API/component/browser tests for conditional configuration, forced staging, secret presence/clear semantics,
validation messages, optional Run Detail summary, and one-scope execution. Extend existing screens rather than adding
a new dashboard.

## T8 — Documentation and verification

**Depends on:** T1, T2, T3, T4, T5, T6, T7

Update example configuration and operator documentation, then run targeted tests, full unit/integration checks, type
checking, Biome, build, and browser QA. Resolve review findings before the branch-finishing gate.
