# Cheaper Inference Configured Source Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Cheaper Inference a recognized environment-backed model source whose server-side credential and default model require no browser input, while retaining clearly separated manual per-run overrides.

**Architecture:** Extend the CLI's existing base-URL-based catalog identification so Cheaper Inference uses the same safe bootstrap and catalog path as OpenRouter. Keep request and credential forwarding contracts unchanged: the browser receives only safe provider metadata, while `SHANNON_AI_API_KEY` remains server-side. Update the React source picker with a native `optgroup`, then document the environment configuration.

**Tech Stack:** TypeScript, Vitest, React 19, React Hook Form, Testing Library, Hono, Zod, Vite.

## Global Constraints

- Use `SHANNON_AI_MODEL`, `SHANNON_AI_BASE_URL`, `SHANNON_AI_OPENAI_FORMAT`, and `SHANNON_AI_API_KEY`; do not introduce a second credential-forwarding path.
- Never include a real API key in source, tests, documentation, browser responses, run snapshots, profiles, logs, or artifacts.
- The configured model remains the unattended default; a blank configured-source model field must omit `providerConfig`.
- Only known catalog hosts may enable server-side `/models` requests.
- OpenRouter behavior and manual provider overrides must remain backward compatible.
- Only Claude models remain officially supported by Shannon, even when a gateway lists other model families.
- Do not edit the workspace `.env`; the exposed credential must be revoked and replaced locally by the operator.

## File structure

- `apps/cli/src/model-catalog.ts` — identify known catalog gateways, produce safe provider metadata, and load their model catalogs.
- `apps/cli/tests/model-catalog.test.ts` — cover Cheaper Inference recognition, credential isolation, model loading, sorting, and lookalike rejection.
- `apps/cli/web/src/components/AssessmentConfigFields.tsx` — visually and semantically separate the configured source from per-run overrides.
- `apps/cli/tests/assessment-config-fields.test.tsx` — render the model section and assert configured-source and override behavior.
- `README.md` — document the Cheaper Inference environment contract and official endpoint.

---

### Task 1: Recognize and load the Cheaper Inference catalog

**Files:**
- Modify: `apps/cli/tests/model-catalog.test.ts`
- Modify: `apps/cli/src/model-catalog.ts`

**Interfaces:**
- Consumes: `resolveCliModelSelection(env?: NodeJS.ProcessEnv): CliModelSelection` from `apps/cli/src/model-spec.ts`.
- Produces: unchanged public functions `describeConfiguredModel(env?: NodeJS.ProcessEnv): ConfiguredModelDescription` and `listConfiguredModels(options?: ListConfiguredModelsOptions): Promise<ModelCatalogItem[]>`.
- Preserves: `ConfiguredModelDescription.providerConfig` contains no `apiKey` or `authToken`.

- [ ] **Step 1: Write failing Cheaper Inference catalog tests**

Add this environment fixture and tests to `apps/cli/tests/model-catalog.test.ts`:

```ts
const cheaperInferenceEnvironment = {
  SHANNON_AI_MODEL: 'openai:claude-sonnet-4.6',
  SHANNON_AI_BASE_URL: 'https://api.cheaperinference.com/v1',
  SHANNON_AI_OPENAI_FORMAT: 'chat-completions',
  SHANNON_AI_API_KEY: 'server-side-cheaper-inference-secret',
};

it('describes Cheaper Inference without exposing its credential', () => {
  const configuration = describeConfiguredModel(cheaperInferenceEnvironment);

  expect(configuration).toEqual({
    providerId: 'cheaper-inference',
    providerLabel: 'Cheaper Inference',
    modelId: 'claude-sonnet-4.6',
    credentialConfigured: true,
    catalogAvailable: true,
    providerConfig: {
      providerType: 'openai',
      baseUrl: 'https://api.cheaperinference.com/v1',
      openAIFormat: 'chat-completions',
    },
  });
  expect(JSON.stringify(configuration)).not.toContain('server-side-cheaper-inference-secret');
});

it('does not trust a Cheaper Inference lookalike hostname', () => {
  expect(
    describeConfiguredModel({
      ...cheaperInferenceEnvironment,
      SHANNON_AI_BASE_URL: 'https://api.cheaperinference.com.attacker.test/v1',
    }),
  ).toMatchObject({ providerId: 'openai', providerLabel: 'OpenAI', catalogAvailable: false });
});

it('loads Cheaper Inference models with the credential kept server-side', async () => {
  const fetcher = vi.fn(
    async () =>
      new Response(
        JSON.stringify({
          data: [
            { id: 'gpt-5.6-sol', name: 'GPT 5.6 Sol', context_length: 400_000 },
            { id: 'claude-sonnet-4.6', name: 'Claude Sonnet 4.6', context_length: 1_000_000 },
            { id: 'claude-sonnet-4.6', name: 'Duplicate' },
            { id: 'claude-opus-4.6' },
          ],
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
  );

  await expect(listConfiguredModels({ env: cheaperInferenceEnvironment, fetcher })).resolves.toEqual([
    { id: 'claude-sonnet-4.6', name: 'Claude Sonnet 4.6', contextLength: 1_000_000 },
    { id: 'claude-opus-4.6', name: 'claude-opus-4.6' },
    { id: 'gpt-5.6-sol', name: 'GPT 5.6 Sol', contextLength: 400_000 },
  ]);
  expect(fetcher).toHaveBeenCalledWith('https://api.cheaperinference.com/v1/models', {
    headers: { Authorization: 'Bearer server-side-cheaper-inference-secret', Accept: 'application/json' },
    signal: expect.any(AbortSignal),
  });
});
```

- [ ] **Step 2: Run the focused test and verify RED**

Run:

```bash
npx --yes pnpm@10.33.0 --filter @keygraph/shannon exec vitest run tests/model-catalog.test.ts
```

Expected: FAIL because Cheaper Inference is labelled `OpenAI`, `catalogAvailable` is `false`, and `listConfiguredModels` rejects the provider.

- [ ] **Step 3: Implement a known-catalog provider classifier**

Replace the OpenRouter-only catalog check in `apps/cli/src/model-catalog.ts` with a small classifier:

```ts
interface CatalogProvider {
  readonly id: 'openrouter' | 'cheaper-inference';
  readonly label: 'OpenRouter' | 'Cheaper Inference';
}

function catalogProvider(baseUrl: string | undefined): CatalogProvider | undefined {
  if (!baseUrl) return undefined;
  try {
    const hostname = new URL(baseUrl).hostname.toLowerCase();
    if (hostname === 'openrouter.ai' || hostname.endsWith('.openrouter.ai')) {
      return { id: 'openrouter', label: 'OpenRouter' };
    }
    if (hostname === 'api.cheaperinference.com') {
      return { id: 'cheaper-inference', label: 'Cheaper Inference' };
    }
  } catch {
    return undefined;
  }
  return undefined;
}
```

Use it in `describeConfiguredModel`:

```ts
const catalog = catalogProvider(selection.baseUrl);
return {
  providerId: catalog?.id ?? selection.providerId,
  providerLabel: catalog?.label ?? providerLabel(selection.providerId),
  modelId: selection.modelId,
  credentialConfigured: selection.credentialConfigured,
  catalogAvailable: catalog !== undefined,
  providerConfig: safeProviderConfig(env),
};
```

Use it in `listConfiguredModels`:

```ts
if (!catalogProvider(selection.baseUrl)) {
  throw new Error('A model catalog is not available for the configured provider');
}
```

Do not alter credential selection, catalog parsing, URL normalization, timeout, or sanitized error behavior.

- [ ] **Step 4: Run model-catalog and controller security tests and verify GREEN**

Run:

```bash
npx --yes pnpm@10.33.0 --filter @keygraph/shannon exec vitest run tests/model-catalog.test.ts tests/scan-controller.test.ts
```

Expected: PASS, including the existing keyless model-override and credential-persistence tests.

- [ ] **Step 5: Commit the catalog support**

```bash
git add apps/cli/src/model-catalog.ts apps/cli/tests/model-catalog.test.ts
git commit -m "feat(cli): recognize Cheaper Inference catalog"
```

---

### Task 2: Separate the configured source from manual overrides

**Files:**
- Create: `apps/cli/tests/assessment-config-fields.test.tsx`
- Modify: `apps/cli/web/src/components/AssessmentConfigFields.tsx`

**Interfaces:**
- Consumes: `ConfiguredModelDescription` and `UseFormReturn<AssessmentFormValues>`.
- Produces: unchanged `AssessmentConfigFields` props and form value contract.
- Preserves: `modelSource === "environment"` renders no API-key field; all other sources use the existing validation and request construction.

- [ ] **Step 1: Write a failing rendered-form test**

Create `apps/cli/tests/assessment-config-fields.test.tsx`:

```tsx
// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { render, screen, within } from '@testing-library/react';
import { useForm } from 'react-hook-form';
import { describe, expect, it } from 'vitest';
import {
  AssessmentConfigFields,
  type AssessmentFormValues,
  assessmentDefaults,
} from '../web/src/components/AssessmentConfigFields.js';
import type { ConfiguredModelDescription } from '../web/src/types/api.js';

const configuredModel: ConfiguredModelDescription = {
  providerId: 'cheaper-inference',
  providerLabel: 'Cheaper Inference',
  modelId: 'claude-sonnet-4.6',
  credentialConfigured: true,
  catalogAvailable: true,
  providerConfig: {
    providerType: 'openai',
    baseUrl: 'https://api.cheaperinference.com/v1',
    openAIFormat: 'chat-completions',
  },
};

function ModelForm() {
  const form = useForm<AssessmentFormValues>({ defaultValues: assessmentDefaults });
  return (
    <AssessmentConfigFields
      form={form}
      showModelConfig
      modelConfiguration={configuredModel}
      modelOptions={[{ id: 'claude-opus-4.6', name: 'Claude Opus 4.6' }]}
    />
  );
}

describe('assessment model configuration', () => {
  it('uses the configured source without exposing credential fields and groups manual overrides', () => {
    render(<ModelForm />);

    const sourceSelect = screen.getByLabelText('Model source');
    expect(sourceSelect).toHaveValue('environment');
    expect(screen.getByRole('option', { name: 'Cheaper Inference (configured)' })).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Model' })).toHaveAttribute('placeholder', 'claude-sonnet-4.6');
    expect(screen.queryByLabelText('Provider API key')).not.toBeInTheDocument();
    expect(screen.getByText('Cheaper Inference credential is configured on this runner.')).toBeInTheDocument();

    const overrideGroup = sourceSelect.querySelector('optgroup[label="Per-run override"]') as HTMLOptGroupElement;
    expect(overrideGroup).not.toBeNull();
    expect(within(overrideGroup).getAllByRole('option').map((option) => option.textContent)).toEqual([
      'OpenRouter',
      'Anthropic',
      'OpenAI',
      'xAI',
      'Custom gateway',
    ]);
  });
});
```

- [ ] **Step 2: Run the component test and verify RED**

Run:

```bash
npx --yes pnpm@10.33.0 --filter @keygraph/shannon exec vitest run tests/assessment-config-fields.test.tsx
```

Expected: FAIL because the manual options are direct children of the select and no `Per-run override` group exists.

- [ ] **Step 3: Group the manual options with native select semantics**

Change only the model-source select in `AssessmentConfigFields.tsx`:

```tsx
<select {...register("modelSource")}>
  <option value="environment">
    {modelConfiguration ? `${modelConfiguration.providerLabel} (configured)` : "Environment default"}
  </option>
  <optgroup label="Per-run override">
    <option value="openrouter">OpenRouter</option>
    <option value="anthropic">Anthropic</option>
    <option value="openai">OpenAI</option>
    <option value="xai">xAI</option>
    <option value="custom">Custom gateway</option>
  </optgroup>
</select>
```

Do not change `assessmentFormSchema`, `assessmentDefaults`, or `providerConfig` request construction: they already implement the approved configured-source behavior and manual override validation.

- [ ] **Step 4: Run form and component tests and verify GREEN**

Run:

```bash
npx --yes pnpm@10.33.0 --filter @keygraph/shannon exec vitest run tests/assessment-config-fields.test.tsx tests/assessment-form.test.ts
```

Expected: PASS.

- [ ] **Step 5: Run the CLI type checker**

Run:

```bash
npx --yes pnpm@10.33.0 --filter @keygraph/shannon check
```

Expected: PASS with no TypeScript errors in the Node or web projects.

- [ ] **Step 6: Commit the source-picker change**

```bash
git add apps/cli/web/src/components/AssessmentConfigFields.tsx apps/cli/tests/assessment-config-fields.test.tsx
git commit -m "feat(ui): separate configured model source"
```

---

### Task 3: Document Cheaper Inference configuration

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: the existing `SHANNON_AI_*` gateway contract.
- Produces: an operator-facing configuration example with placeholder credentials and an official documentation link.

- [ ] **Step 1: Add a Cheaper Inference subsection under Custom Base URL**

Add this content after the generic gateway environment example in `README.md`:

````markdown
#### Cheaper Inference

[Cheaper Inference](https://api.cheaperinference.com/docs) exposes an OpenAI-compatible API and model catalog. Configure it as the runner's environment-backed source:

```bash
export SHANNON_AI_MODEL=openai:claude-sonnet-4.6
export SHANNON_AI_BASE_URL=https://api.cheaperinference.com/v1
export SHANNON_AI_OPENAI_FORMAT=chat-completions
# Inject SHANNON_AI_API_KEY through your shell or secret manager.
```

The local operator UI labels this source **Cheaper Inference (configured)**, uses the environment model by default, and loads optional model choices without sending the credential to the browser. Use an exact model ID returned by the provider's `/v1/models` endpoint.
````

Keep the existing warning that only Claude models are officially supported.

- [ ] **Step 2: Validate documentation safety and formatting**

Run:

```bash
git diff --check
if rg -n 'ci_live_[A-Za-z0-9]+' README.md docs/superpowers/specs docs/superpowers/plans; then exit 1; fi
```

Expected: PASS with no whitespace errors and no live-looking Cheaper Inference credential.

- [ ] **Step 3: Commit the documentation**

```bash
git add README.md
git commit -m "docs: explain Cheaper Inference setup"
```

---

### Task 4: Full verification and local UI smoke test

**Files:**
- Verify only; no source changes expected.

**Interfaces:**
- Verifies the production CLI build and localhost UI using process-local placeholder configuration.

- [ ] **Step 1: Run all unit tests**

Run:

```bash
npx --yes pnpm@10.33.0 test
```

Expected: PASS for both `@keygraph/shannon` and `@shannon/worker`.

- [ ] **Step 2: Run type checking and linting**

Run:

```bash
npx --yes pnpm@10.33.0 check
npx --yes pnpm@10.33.0 biome
```

Expected: PASS without errors.

- [ ] **Step 3: Build the production CLI and UI**

Run:

```bash
npx --yes pnpm@10.33.0 --filter @keygraph/shannon build
```

Expected: `dist/index.mjs` and `dist/ui/` build successfully. Vite's existing chunk-size advisory is non-blocking.

- [ ] **Step 4: Start a disposable configured-source smoke server**

Run in a persistent terminal session:

```bash
SHANNON_AI_MODEL=openai:claude-sonnet-4.6 \
SHANNON_AI_BASE_URL=https://api.cheaperinference.com/v1 \
SHANNON_AI_OPENAI_FORMAT=chat-completions \
SHANNON_AI_API_KEY=smoke-test-placeholder \
./shannon ui --port 8790 --no-open
```

Expected: `Shannon UI: http://127.0.0.1:8790`.

- [ ] **Step 5: Verify health and safe bootstrap metadata**

Run:

```bash
curl -sS http://127.0.0.1:8790/api/v1/health
curl -sS -c .context/cheaper-inference-smoke.cookies http://127.0.0.1:8790/ >/dev/null
curl -sS -b .context/cheaper-inference-smoke.cookies http://127.0.0.1:8790/api/v1/bootstrap
```

Expected: health returns `"status":"ok"`; bootstrap returns `providerId: "cheaper-inference"`, `providerLabel: "Cheaper Inference"`, `modelId: "claude-sonnet-4.6"`, and `catalogAvailable: true`; output does not contain `smoke-test-placeholder`.

- [ ] **Step 6: Stop the disposable server and inspect scope**

Send `SIGINT` to the persistent smoke-server session, then run:

```bash
git status --short
git log --oneline -4
```

Expected: only the pre-existing untracked `docs/competitive/` directory remains outside committed work; the design, plan, catalog, UI, tests, and documentation commits are present.
