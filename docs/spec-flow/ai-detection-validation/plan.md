# A09 AI-Assisted Detection Validation — Implementation Plan

## Architecture

Treat `alerting-effectiveness` as an opt-in granular scope with a dedicated executor, following the existing
`http-load-capacity` pattern rather than adding another agent lane or a generic vendor framework. The executor runs
after reconnaissance/assessment modules and before vulnerability lanes, and may run when no vulnerability class is
selected.

The implementation has four concrete pieces:

1. Shared CLI/worker configuration normalization and safety validation.
2. A worker-side deterministic runner containing the fixed corpus and direct Splunk REST integration.
3. Temporal orchestration plus canonical JSON/Markdown report integration.
4. Existing assessment-form and Run Detail UI extensions, including secret-reference handling.

No database or dependency changes are required.

## Public and persisted contracts

- Make `alerting-effectiveness` available with executor `detection-validation` and `bulkSelectable: false`.
- Add optional camelCase `detectionValidation` to CLI/API contracts and snake_case `detection_validation` to worker
  YAML/config types.
- Normalized settings contain `canaryPath`, `minimumDetectionRate`, `maxWaitSeconds`, and Splunk management origin,
  telemetry/alert indexes, and optional sourcetypes.
- Add `splunkToken` to target secret fields/references. Imported YAML may include a nested token, but parsing extracts
  it before persisted config is created. Profiles and run snapshots contain only secret references/presence.
- Add `DetectionValidationResult` with status `passed | failed | partial | unavailable` and an optional
  `detection_validation` property to canonical report data and Run Detail.
- Keep existing profile-file and report schema versions because every new field is optional.

## Data flow

1. The UI/config parser selects the scope, validates staging plus authorization, resolves the Splunk token, and
   includes settings in the protected worker configuration.
2. The workflow normalizes settings and passes them to a dedicated activity. Stable markers derive from workflow ID,
   corpus version, cohort, and scenario ID.
3. The runner sends a calibration request to the target canary using `redirect: 'manual'`; only HTTP 204 is accepted.
4. The runner polls the configured telemetry index through `POST /services/search/v2/jobs/export`. Failure to connect,
   authenticate, query, or observe calibration returns `unavailable` without emitting scenarios.
5. Ten frozen JSON fixtures run sequentially at one request per second. Responses are recorded, but only network
   failure makes emission incomplete; WAF blocking responses still count as emitted.
6. The runner polls the alert index, scans returned `_raw` strings for stable markers, captures the earliest `_time`,
   and de-duplicates by scenario ID.
7. It computes per-cohort counts/rates, percentage-point gap, and median first-seen latency. Any incomplete emission is
   `partial`; otherwise each cohort is compared independently with the configured threshold.
8. An atomic `detection-validation.json` evidence file is the source for resume, canonical report rendering, and the
   local Run Detail response. It excludes tokens, fixture bodies, and raw Splunk records.

## Safety and errors

- Require staging, an HTTPS Splunk origin without path/query/fragment, safe index/sourcetype identifiers, a relative
  target path without query/fragment, and a 0–1 threshold plus 30–600 second wait.
- Build SPL only from validated identifiers and Shannon markers; expose no arbitrary query input.
- Use native `fetch`/`crypto`, strict TLS, bounded response reads, abort timeouts, bounded search windows/results, and
  exact-value redaction.
- The activity returns evidence-backed failure states instead of throwing for expected detector outcomes. Invalid
  configuration remains a non-retryable workflow error; cancellation propagates normally.
- Stable markers and atomic evidence make activity retry/resume de-duplicated. A completed artifact is loaded rather
  than re-emitting scenarios.

## Testing and files

- Add pure normalization tests before contract code, then runner tests before the runner implementation.
- Exercise the runner using mocked target/Splunk fetch responses, including streaming JSON, auth failure, calibration
  timeout, one cohort miss, retry markers, redaction, and result hashes.
- Extend workflow/report tests for executor ordering, resume loading, completed-scope semantics, canonical rendering,
  and overall workflow completion on a failed threshold.
- Extend CLI/API/profile/form tests for secret extraction/reference behavior, conditional fields, and safety errors.
- Keep implementation concentrated in the existing scope/contracts/orchestration/report/UI subsystems plus one new
  worker runner and one versioned corpus data file.
