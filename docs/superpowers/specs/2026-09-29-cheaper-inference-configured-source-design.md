# Cheaper Inference configured model source

## Summary

Shannon's operator UI distinguishes the runner's environment-backed model from manual per-run provider overrides. The existing behavior is technically capable of using an environment-backed gateway, but its source picker makes direct providers look equivalent to the configured source. Selecting one of those direct-provider entries unexpectedly requires a model ID and API key.

Add first-class recognition for Cheaper Inference as an environment-backed OpenAI-compatible gateway. When the runner is configured for Cheaper Inference, the UI displays `Cheaper Inference (configured)`, keeps its credential on the server, uses the model from `SHANNON_AI_MODEL` by default, and offers models returned by the gateway's `/models` endpoint. Direct-provider entries remain available in a clearly labeled `Per-run override` group and continue to require explicit credentials.

## Goals

- Recognize `https://api.cheaperinference.com/v1` and equivalent normalized Cheaper Inference API URLs as Cheaper Inference.
- Make the configured environment source the obvious default in the assessment form.
- Use the environment's default model without requiring browser input.
- Populate optional model overrides from the configured gateway's `/models` endpoint.
- Keep environment credentials server-side and out of bootstrap responses, browser state, run snapshots, profiles, logs, and report artifacts.
- Preserve manual per-run provider overrides for operators who deliberately need a different provider or credential.
- Document the supported Cheaper Inference environment configuration without embedding a real credential.

## Non-goals

- Supporting multiple simultaneous environment-backed providers.
- Automatically editing an operator's `.env` or TOML configuration.
- Accepting or persisting the credential that was exposed during product discussion.
- Changing the worker's provider protocol or adding a Cheaper Inference-specific wire format.
- Benchmarking model quality, price, or assessment effectiveness.
- Making a live paid inference request in automated tests.

## Configuration contract

Cheaper Inference uses Shannon's existing generic gateway variables:

```env
SHANNON_AI_MODEL=openai:claude-sonnet-4.6
SHANNON_AI_BASE_URL=https://api.cheaperinference.com/v1
SHANNON_AI_OPENAI_FORMAT=chat-completions
SHANNON_AI_API_KEY=<rotated-secret-from-a-local-secret-store>
```

`SHANNON_AI_MODEL` remains required at process configuration time because it supplies the default model for unattended runs. The assessment form does not require a model ID when it uses the configured source. `SHANNON_AI_API_KEY` remains the credential name so the existing CLI-to-worker allowlist, validation, redaction, and Docker forwarding behavior is unchanged.

## User experience

The model-source select keeps the environment-backed source first and selected by default:

```text
Cheaper Inference (configured)
──────── Per-run override ────────
OpenRouter
Anthropic
OpenAI
xAI
Custom gateway
```

The separator is implemented with a native `optgroup` labelled `Per-run override`, preserving keyboard and screen-reader behavior.

When the configured source is selected:

- No API-key field is rendered.
- The model field uses the configured model as its placeholder and effective default.
- If the provider catalog loads, the field offers catalog models while still permitting the configured model.
- Choosing no model sends no `providerConfig`; the server and worker use the complete environment configuration.
- Choosing another catalog model sends only the safe model/provider metadata already returned by bootstrap. It sends no credential.
- A status notice names Cheaper Inference and reports whether its server-side credential is configured.

When a per-run override is selected:

- Model ID and provider API key remain required.
- Custom gateways continue to require provider ID, base URL, and API format.
- Existing secret-field masking and non-persistence behavior remains unchanged.

## Architecture and data flow

### Provider recognition

The CLI model-catalog layer identifies known catalog gateways from the normalized configured base URL. OpenRouter behavior remains unchanged. A Cheaper Inference hostname matcher recognizes `api.cheaperinference.com` without treating unrelated subdomains or lookalike suffixes as trusted providers.

`describeConfiguredModel` returns safe metadata:

- `providerId: "cheaper-inference"`
- `providerLabel: "Cheaper Inference"`
- the configured model ID
- whether a server-side credential exists
- whether a catalog is available
- a credential-free `providerConfig` containing the existing OpenAI provider type, base URL, and API format

No API-key value crosses this boundary.

### Model catalog

`listConfiguredModels` supports known catalog providers rather than only OpenRouter. For Cheaper Inference it requests the normalized configured base URL plus `/models`, authenticates with the already selected server-side credential, and parses the existing OpenAI-style `{ data: [...] }` catalog envelope.

Catalog results are de-duplicated and sorted using the current behavior. A missing display name falls back to the model ID. Optional context length is retained when supplied.

### Assessment request

The current request construction remains the security boundary:

1. Empty configured-source model input omits `providerConfig` entirely.
2. A configured-source model override copies only bootstrap's safe provider metadata and replaces the model.
3. `ScanController` accepts a keyless override only when provider type, configured provider identity, normalized base URL, and API format match the active environment configuration.
4. The worker receives the environment credential through the existing provider-scoped forwarding path.

Manual override requests continue to carry an ephemeral credential to the controller's secret-staging path. Those credentials are redacted and excluded from durable run state.

## Failure behavior

- If no configured credential exists, the UI names the configured source and shows a warning. Starting a run continues to fail through the existing credential preflight.
- If `/models` is unreachable, times out, rejects authentication, or returns an invalid payload, the UI reports that the catalog is unavailable but still allows the configured default model.
- A keyless model override whose provider metadata does not exactly match the configured environment is rejected before launch.
- A manual per-run override without its model ID or credential remains a form validation error.
- Provider errors must not include credential values or unredacted response bodies.

## Testing strategy

Implementation follows red-green-refactor.

### CLI model-catalog tests

- Cheaper Inference is identified from its official base URL.
- Bootstrap metadata uses the expected label and never exposes the API key.
- The Cheaper Inference `/models` endpoint is called with server-side bearer authentication.
- Catalog parsing, sorting, de-duplication, missing names, and context lengths behave like the existing OpenRouter catalog.
- Lookalike hostnames are not recognized as Cheaper Inference.
- Catalog failures keep their existing sanitized error messages.

### Form and request tests

- The configured environment source validates without a browser-supplied model ID or API key.
- Manual provider overrides still require both fields.
- The configured default sends no `providerConfig`.
- A configured model override sends safe provider metadata without a credential.
- The rendered source picker groups manual choices under `Per-run override` and labels the configured Cheaper Inference source correctly.

### Regression checks

- Existing OpenRouter catalog tests continue to pass.
- CLI and worker unit suites pass.
- Type checking, linting, and the CLI production build pass.
- A local UI smoke check confirms the configured-source state renders without credential fields.

## Documentation

Update the provider/gateway documentation with a Cheaper Inference example using placeholder credentials. State that only Claude models are officially supported by Shannon even when the gateway exposes other model families. Link to Cheaper Inference's official API documentation for current endpoint and model details.

## Acceptance criteria

- A runner configured with the Cheaper Inference base URL renders `Cheaper Inference (configured)` as the selected source.
- The configured source never asks for an API key and does not require model input in the form.
- The environment model is used when the model field is left blank.
- Available Cheaper Inference models can be selected from the server-loaded catalog.
- A catalog outage does not prevent use of the environment model.
- Manual overrides are visibly separated and preserve their current validation.
- No credential is returned by the API or written to durable product state.
- Relevant unit, type, lint, build, and UI smoke checks pass.
