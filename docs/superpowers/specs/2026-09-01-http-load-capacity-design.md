# HTTP Load and Capacity Assessment Design

## Purpose

Add an explicitly authorized, single-host HTTP load and capacity assessment to Shannon. Operators can select the check from the existing OWASP scope UI, configure the traffic envelope, and receive deterministic metrics in artifacts and reports. The test must not be enabled by defaults, parent bulk selection, profiles created from legacy configurations, or ordinary vulnerability-agent execution.

This feature is for systems the operator owns or has written permission to test. It does not support distributed traffic, proxy rotation, source-address spoofing, or traffic amplification.

## Scope Contract

`http-load-capacity` becomes an available assessment scope under `A06:2025 Insecure Design`. It is a dedicated activity-backed scope rather than an LLM agent-owned check.

The scope remains excluded from:

- Default assessment selections.
- "Select all standard checks" and OWASP parent bulk selection.
- Legacy vulnerability-class expansion.
- Vulnerability-agent derivation.

It can only be enabled by selecting its individual checkbox or providing its canonical scope ID explicitly. An assessment containing only this scope is valid even though it derives no vulnerability-agent lanes; recon, the load activity, and reporting still run.

## Configuration

The canonical configuration is:

```ts
interface HttpLoadConfig {
  concurrency: number;
  requestsPerSecond: number;
  durationSeconds: number;
}
```

Public CLI/API/profile/workflow inputs use `httpLoad`. Worker YAML and distributed configuration use `http_load` with `concurrency`, `requests_per_second`, and `duration_seconds`.

Defaults are:

- Concurrency: `5`.
- Request rate: `10` requests per second.
- Duration: `15` seconds.

The elevated-load thresholds are `20` concurrent connections, `50` requests per second, or `60` seconds. Exceeding any threshold requires an additional explicit elevated-load confirmation in the UI or CLI.

The worker enforces emergency ceilings independently of browser validation:

- Concurrency: `1,000`.
- Request rate: `10,000` requests per second.
- Duration: `3,600` seconds.

All values must be finite positive integers. `http_load` is rejected unless `http-load-capacity` is selected. Selecting the scope without explicit parameters applies the safe defaults during normalization.

## Authorization

The new-assessment UI continues to require the existing target-authorization checkbox. When elevated thresholds are exceeded, it also requires a second confirmation that the operator understands the test can disrupt the target.

CLI/config starts selecting `http-load-capacity` require `--i-own-this-target`. Elevated values additionally require `--allow-elevated-load`. These confirmations are run-time acknowledgements and are not stored in reusable profiles or report artifacts.

The normalized pipeline input carries authorization booleans so the worker can reject direct API or Temporal callers that bypass CLI validation. The activity passes the existing Python tool's required `--i-own-this-target` flag only after worker-side validation succeeds.

## User Interface

The A06 child appears as `HTTP load and capacity` with an enabled checkbox and an `Explicit opt-in` label. Selecting it reveals a compact load configuration panel with numeric inputs for concurrency, requests per second, and duration.

The panel displays the estimated maximum scheduled request count (`requestsPerSecond * durationSeconds`) and a neutral warning that load testing can degrade availability. Crossing an elevated threshold reveals the second confirmation. Clearing the scope removes run-time confirmations but retains the entered numeric values for convenient adjustment.

Profiles may persist the numeric load configuration and selected scope, but never either authorization confirmation. Loading such a profile therefore requires fresh confirmation before starting a run.

## Worker Execution

A dedicated Temporal activity runs the test after vulnerability and safe-demonstration phases and before report assembly. It does not run through the agent executor and does not add a durable agent ID.

The activity invokes `apps/worker/scripts/http_flood_test.py` with the exact target URL, normalized parameters, and the safety flag. The worker image already contains Python 3 and copies the worker application directory, so the script ships with the runtime without a new dependency.

The Python script gains a machine-readable JSON output option while retaining its current terminal output and standalone safety gate. It continues to:

- Use direct operating-system networking from one worker host.
- Issue HTTP GET requests only.
- Avoid redirects to additional hosts.
- Bound queued work and response bytes.
- Avoid proxy rotation and source-address manipulation.
- Handle `SIGINT` and `SIGTERM` gracefully.

The activity heartbeats progress, forwards cancellation to the child process, and has no automatic retry. A retry or resume skips execution when a valid completed result artifact already exists. Failed or interrupted runs preserve a sanitized diagnostic without treating partial output as completed coverage.

## Artifacts And Reporting

The completed activity atomically writes `.shannon/http-load-capacity.json` beneath the run working directory. The artifact contains:

- Target origin and path without embedded credentials, with sensitive query values redacted.
- Start and completion timestamps.
- Configured concurrency, request rate, and duration.
- Sent, completed, successful, failed, and errored request counts.
- Bytes read and HTTP status counts.
- Average, minimum, and maximum response latency.
- Whether the run ended normally or was interrupted.

Secrets and configured request headers are not persisted. Activity logs and failure details pass through the existing centralized redaction service.

Report assembly adds a deterministic `## HTTP Load and Capacity` section when selected. A completed artifact renders the parameters and observed metrics with neutral capacity language. A missing or interrupted artifact is reported as incomplete. OWASP coverage marks this scope completed only when the completed artifact validates; completion does not claim that the service is resilient or vulnerability-free.

## Resume And Compatibility

Normalized load parameters participate in the existing configuration hash and resume comparison. Changing the selected scope or any load parameter on resume is rejected. Existing sessions and profiles remain valid because all new fields are additive and the scope is absent by default.

The activity artifact provides idempotency across workflow resume. Authorization confirmations are not included in reusable profiles; the original workflow input retains them for Temporal replay, while a newly initiated resume path must reconfirm when execution has not completed.

## Error Handling

Validation errors identify the invalid field without echoing sensitive configuration. Runtime failures distinguish startup failure, timeout, cancellation, invalid result output, and request-level errors. Individual request failures remain metrics rather than producing per-request logs.

The load activity failing does not silently pass. The workflow records the scope as incomplete and proceeds to report generation when a valid partial diagnostic can be recorded; setup or contract failures before traffic begins fail preflight.

## Testing

Tests cover:

- Registry availability, explicit-opt-in defaults, parent selection, and zero-agent scope normalization.
- API, CLI, YAML, profile, snapshot, and workflow input transformations.
- Authorization and elevated-load confirmation requirements.
- Numeric defaults, thresholds, emergency ceilings, duplicates, and invalid values.
- Python safety-gate and JSON-result behavior using a local HTTP server.
- Activity argument construction, cancellation, no-retry behavior, artifact validation, and resume idempotency.
- Workflow ordering and execution exactly once.
- Structured and Markdown report output for completed, interrupted, and unselected runs.
- Desktop and mobile UI behavior, profile restoration, submitted payloads, and accessibility.

Final verification includes CLI and worker type checks, unit and integration suites, full Playwright E2E coverage, production builds, and desktop/mobile screenshot inspection.
