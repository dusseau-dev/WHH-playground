# Architecture and Local Control Plane

## Source Modes

`SourceMode` is either `source-assisted` or `url-only`. Existing callers that provide `repoPath` and omit `sourceMode` remain source-assisted. URL-only callers provide a writable `workingDirectory` but no repository.

Both modes run target preflight, configured authentication validation, live reconnaissance, selected security test categories, optional safe demonstrations, evidence triage, and reporting. Source-assisted mode additionally validates the repository, synchronizes source deny rules, and runs source pre-recon. URL-only mode rejects `code_path` rules and uses a dedicated prompt tree that cannot depend on source artifacts.

## Run Controller

The CLI and Hono API call the same `ScanController`. It creates a versioned `.shannon/run.json` in the workspace before launching Docker. The record contains:

- Lifecycle status and timestamps
- Immutable target, source mode, repository, and normalized configuration
- Required target-secret field names, never secret values
- Attempt-specific task queues, container names, workflow IDs, and Docker labels
- Output and pipeline-testing choices

The controller reconciles records against Temporal progress, legacy `session.json`, and managed container state. Failed or cancelled runs resume from the immutable snapshot. A resume cannot alter target, mode, repository, or configuration.

For URL-only runs, `/app/target` is backed by the workspace runtime directory. Source-assisted repositories remain read-only and use workspace-backed writable overlays for deliverables, scratch data, and browser state.

## Profiles and Secrets

Profiles are versioned YAML under `~/.shannon/profiles`. Files contain non-secret configuration and secret references. On macOS, the optional `@napi-rs/keyring` adapter stores target credentials in Keychain. If Keychain is unavailable, and on other platforms, credentials are session-only and must be re-entered after the UI restarts.

Provider credentials are not edited by the UI. They continue to use environment variables, `.env` in clone mode, or `~/.shannon/config.toml` created by `shannon setup` in package mode.

Resolved target credentials are written only to a mode-`0600` runtime worker configuration. Runtime configurations are deleted when runs reach a terminal state and stale files are collected at controller startup.

## Local API

`shannon ui` serves the packaged React application and `/api/v1` from a Hono server bound to `127.0.0.1`. The server enforces:

- Random HttpOnly, `SameSite=Strict` session cookie
- Same-origin Host and Origin checks with no CORS
- Per-process CSRF token for mutations
- Content Security Policy and restrictive browser headers
- Strict Zod request schemas and bounded YAML imports
- Realpath containment for static and workspace files
- Downloads limited to the final report and evidence referenced by triage
- Centralized activity, error, and report redaction/sanitization

SSE run streams emit snapshots, redacted activity increments, reconnect cursors, and heartbeats. Closing the UI does not stop workers; reopening reconstructs state from workspaces, Temporal, and container metadata.

## Packaging

The CLI bundle is built first with `tsdown` for Node 20, then Vite writes the client to `apps/cli/dist/ui` without cleaning the CLI output. Assets resolve relative to `import.meta.url`, so the published package works from any current directory. The worker image remains on Node 22.
