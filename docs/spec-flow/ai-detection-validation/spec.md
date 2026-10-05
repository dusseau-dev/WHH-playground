# A09 AI-Assisted Detection Validation

## User value

Detection and purple teams need a repeatable way to confirm that their staging WAF and SIEM alert on a small,
reviewed set of synthetic web behaviors, and to compare detection outcomes for fixed AI-authored and human-authored
variants without generating offensive content at runtime.

## Goals

- Make the existing A09 `alerting-effectiveness` scope an opt-in, staging-only assessment.
- Send one calibration request and ten inert, versioned simulations to a dedicated same-origin no-op endpoint.
- Correlate telemetry and alerts through Splunk using stable per-run and per-scenario markers.
- Score five AI-authored and five matched human-authored fixtures independently, with a configurable threshold that
  defaults to 100% for each cohort.
- Preserve deterministic machine-readable evidence and show a concise summary in the canonical report and Run Detail
  UI.
- Finish the Shannon workflow even when the detection threshold fails.

## Non-goals

- Runtime LLM generation, adaptive payload mutation, or optimization for bypassing defenses.
- Malware, implants, browser-store access, real credential handling, phishing delivery, real-brand imitation, endpoint
  or mobile execution, or compromised-account administration.
- Vendor abstraction, vendors other than Splunk, user-authored SPL, custom corpora, or CI workflow failure in v1.
- Treating the cohort delta as causal uplift or an evasion score.

## Users and stories

- As a detection engineer, I can select `alerting-effectiveness`, configure a staging canary and Splunk indexes, and
  confirm that the telemetry path works before simulations begin.
- As a purple-team operator, I can see which fixed scenarios generated alerts, how long detection took, and whether
  each cohort met the configured threshold.
- As a Shannon operator, I can store the Splunk token through the existing secret-reference mechanism without writing
  it to profiles, workflow history, logs, or deliverables.
- As a report consumer, I can distinguish a valid threshold failure from an incomplete or unavailable assessment.

## Functional requirements

1. `alerting-effectiveness` is available, excluded from bulk selection, and may run alone or with other scopes.
2. Selecting it requires staging, authorization confirmation, detection-validation settings, and a Splunk token.
3. The canary path is relative, same-origin, query/fragment-free, never redirects, and must return HTTP 204 to the
   calibration request.
4. Splunk configuration accepts an HTTPS management origin, telemetry index, alert index, optional sourcetypes, a
   30–600 second wait, and a 0–1 cohort threshold.
5. Shannon builds bounded searches itself and calls `POST /services/search/v2/jobs/export` with bearer authentication.
6. A telemetry calibration marker must be observable before the ten scenarios are emitted sequentially at no more
   than one request per second.
7. Scenario markers remain stable across retries and results are de-duplicated by marker.
8. Evidence contains corpus and fixture hashes, timestamps, response outcomes, detection outcomes, first-seen latency,
   cohort aggregates, and status, but no tokens, request bodies, or raw Splunk events.
9. Status is `passed`, `failed`, `partial`, or `unavailable`; both `passed` and threshold-based `failed` count as
   completed A09 coverage.
10. Canonical JSON/Markdown and Run Detail expose cohort scores, percentage-point gap, median latency, and scenario
    outcomes. The workflow itself still completes on a threshold failure.

## Success criteria

- A mocked end-to-end run can calibrate telemetry, emit all ten fixtures, correlate alerts, and render evidence.
- Five of five detections in each cohort passes at the default threshold; one miss in either cohort fails the check.
- Production targets, unsafe paths, invalid Splunk origins/indexes, missing settings, and missing tokens fail closed.
- Splunk/API failures and missing calibration are reported without leaking secrets or losing the rest of the report.
- Existing assessment modes, profiles, reports, and resume behavior remain compatible when the scope is not selected.
