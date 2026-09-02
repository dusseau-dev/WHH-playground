# HTTP Load and Capacity Assessment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `http-load-capacity` an explicitly authorized, manually configured, single-host assessment that executes through a dedicated worker activity and appears deterministically in Shannon reports.

**Architecture:** Keep the five vulnerability agents unchanged. A dedicated Python load generator runs from a non-retrying Temporal activity after vulnerability testing; typed normalization shared within each package enforces defaults, elevated thresholds, and emergency ceilings before traffic begins. The CLI and UI carry ephemeral authorization acknowledgements to the workflow while profiles and snapshots persist only non-secret load parameters.

**Tech Stack:** TypeScript 5.9, Zod, Temporal TypeScript SDK, React 19, React Hook Form, Python 3 asyncio, Vitest, Playwright.

## Global Constraints

- The scope is selectable but excluded from defaults, legacy category expansion, OWASP parent bulk selection, and `Select all standard checks`.
- Defaults are concurrency `5`, request rate `10` requests/second, and duration `15` seconds.
- Elevated thresholds are concurrency `20`, request rate `50`, and duration `60`; exceeding any threshold requires a second acknowledgement.
- Emergency ceilings are concurrency `1,000`, request rate `10,000`, and duration `3,600`.
- CLI/config starts selecting the scope require `--i-own-this-target`; elevated values also require `--allow-elevated-load`.
- Traffic originates from one worker host with normal OS source addressing; no proxies, spoofing, distribution, amplification, or redirect following.
- The existing five durable vulnerability agent IDs and artifact contracts remain unchanged.
- Authorization acknowledgements are never stored in profiles, report artifacts, or reusable run snapshots.
- Existing unrelated working-tree changes must not be reverted or accidentally included in feature-only commits.

---

## File Map

**Create**

- `apps/worker/src/types/http-load.ts`: canonical worker settings, result schema, constants, normalization, and authorization validation.
- `apps/worker/src/services/http-load-runner.ts`: child-process execution, cancellation, result validation, and artifact idempotency.
- `apps/worker/scripts/http_flood_test.py`: worker-packaged single-host asyncio load generator with JSON output.
- `apps/worker/tests/http-load.test.ts`: worker normalization, runner, local-server, cancellation, and artifact tests.
- `apps/cli/src/http-load.ts`: CLI-safe duplicate of public constants and normalization rules.
- `apps/cli/tests/http-load.test.ts`: CLI contract, confirmation, profile, and launch tests.

**Modify**

- `apps/worker/src/types/scopes.ts`, `apps/cli/src/security-scopes.ts`: activity-backed execution metadata and explicit-opt-in bulk behavior.
- `apps/worker/src/types/config.ts`, `apps/worker/src/config-parser.ts`, `apps/worker/configs/config-schema.json`: YAML and distributed configuration.
- `apps/worker/src/temporal/shared.ts`, `apps/worker/src/temporal/activities.ts`, `apps/worker/src/temporal/workflows.ts`: pipeline contract, activity, ordering, progress, and resume invariants.
- `apps/worker/src/services/structured-report.ts`, `apps/worker/src/services/report-renderer.ts`: deterministic result and coverage rendering.
- `apps/cli/src/contracts.ts`, `apps/cli/src/assessment-config.ts`, `apps/cli/src/scan-controller.ts`, `apps/cli/src/commands/start.ts`, `apps/cli/src/index.ts`, `apps/cli/src/ui/server.ts`: public contracts and ephemeral authorization flow.
- `apps/cli/web/src/components/AssessmentConfigFields.tsx`, `apps/cli/web/src/components/AssessmentScopeSelector.tsx`, `apps/cli/web/src/pages/NewAssessmentPage.tsx`, `apps/cli/web/src/pages/RunDetailPage.tsx`, `apps/cli/web/src/types/api.ts`, `apps/cli/web/src/lib/api.ts`, `apps/cli/web/src/styles.css`: configuration controls and resume confirmation.
- Existing focused tests in `apps/worker/tests/assessment-scopes.test.ts`, `apps/worker/tests/config-preflight.test.ts`, `apps/worker/tests/resume-scope.test.ts`, `apps/worker/tests/workflow-resume-finalization.test.ts`, `apps/worker/tests/report-model.test.ts`, `apps/cli/tests/security-scopes.test.ts`, `apps/cli/tests/assessment-profiles.test.ts`, `apps/cli/tests/scan-controller.test.ts`, and `apps/cli/tests/e2e/operator-ui.spec.ts`.

---

### Task 1: Worker Scope And Configuration Contract

**Files:**
- Create: `apps/worker/src/types/http-load.ts`
- Modify: `apps/worker/src/types/scopes.ts`
- Modify: `apps/worker/src/types/config.ts`
- Modify: `apps/worker/src/config-parser.ts`
- Modify: `apps/worker/configs/config-schema.json`
- Modify: `apps/worker/src/temporal/shared.ts`
- Test: `apps/worker/tests/http-load.test.ts`
- Test: `apps/worker/tests/assessment-scopes.test.ts`
- Test: `apps/worker/tests/config-preflight.test.ts`

**Interfaces:**
- Produces `HttpLoadSettings`, `HttpLoadResult`, `normalizeHttpLoadSettings()`, `isElevatedHttpLoad()`, and `assertHttpLoadAuthorization()`.
- Produces scope metadata `executor: 'http-load'` and `bulkSelectable: false` for `http-load-capacity`.
- Produces `PipelineInput.httpLoad`, `PipelineInput.httpLoadAuthorizationConfirmed`, and `PipelineInput.elevatedLoadConfirmed`; `ActivityInput` carries the same normalized fields.

- [ ] **Step 1: Write failing worker contract tests**

```ts
it('keeps HTTP load explicitly selectable but outside standard defaults', () => {
  const definition = ASSESSMENT_SCOPE_REGISTRY.find(({ id }) => id === 'http-load-capacity');
  expect(definition).toMatchObject({
    availability: 'available',
    executor: 'http-load',
    bulkSelectable: false,
  });
  expect(DEFAULT_ASSESSMENT_SCOPES).not.toContain('http-load-capacity');
  expect(normalizeAssessmentScope({ testScopes: ['http-load-capacity'] }).vulnClasses).toEqual([]);
});

it('normalizes safe defaults and enforces elevated and emergency limits', () => {
  expect(normalizeHttpLoadSettings(['http-load-capacity'])).toEqual({
    concurrency: 5,
    requestsPerSecond: 10,
    durationSeconds: 15,
  });
  expect(isElevatedHttpLoad({ concurrency: 21, requestsPerSecond: 10, durationSeconds: 15 })).toBe(true);
  expect(() =>
    normalizeHttpLoadSettings(['http-load-capacity'], {
      concurrency: 1001,
      requestsPerSecond: 10,
      durationSeconds: 15,
    }),
  ).toThrow(/concurrency.*1,000/i);
});
```

- [ ] **Step 2: Run the worker tests and confirm the missing-contract failures**

Run: `pnpm --filter @shannon/worker exec vitest run tests/http-load.test.ts tests/assessment-scopes.test.ts tests/config-preflight.test.ts`

Expected: FAIL because `http-load-capacity` is still coming soon and the HTTP load interfaces do not exist.

- [ ] **Step 3: Add the canonical worker types and normalization**

```ts
export const HTTP_LOAD_SCOPE = 'http-load-capacity' as const;
export const HTTP_LOAD_DEFAULTS = { concurrency: 5, requestsPerSecond: 10, durationSeconds: 15 } as const;
export const HTTP_LOAD_ELEVATED_THRESHOLDS = {
  concurrency: 20,
  requestsPerSecond: 50,
  durationSeconds: 60,
} as const;
export const HTTP_LOAD_EMERGENCY_LIMITS = {
  concurrency: 1_000,
  requestsPerSecond: 10_000,
  durationSeconds: 3_600,
} as const;

export interface HttpLoadSettings {
  readonly concurrency: number;
  readonly requestsPerSecond: number;
  readonly durationSeconds: number;
}

export function normalizeHttpLoadSettings(
  scopes: readonly AssessmentScope[],
  value?: Partial<HttpLoadSettings>,
): HttpLoadSettings | undefined;

export function assertHttpLoadAuthorization(
  settings: HttpLoadSettings | undefined,
  authorizationConfirmed: boolean,
  elevatedLoadConfirmed: boolean,
): void;
```

Validation must reject non-integers, non-finite values, zero/negative values, orphaned settings, missing ownership acknowledgement, and missing elevated acknowledgement.

- [ ] **Step 4: Thread the settings through worker configuration**

Add camel-case `httpLoad?: HttpLoadSettings`, `httpLoadAuthorizationConfirmed?: boolean`, and `elevatedLoadConfirmed?: boolean` to `PipelineInput` and `ActivityInput`. Add YAML/distributed form:

```ts
http_load?: {
  concurrency?: number;
  requests_per_second?: number;
  duration_seconds?: number;
};
```

`distributeConfig()` must emit a fully normalized `http_load` only when the scope is selected. `normalizeCliPipelineInput()` must normalize settings and remove neither authorization acknowledgement.

Permit an empty derived `vuln_classes` array only when explicit `test_scopes` derive no agent lane, which is currently the load-only case. Continue rejecting a caller-supplied empty legacy class array without such scopes. Apply the same semantic rule in TypeScript and JSON Schema validation.

- [ ] **Step 5: Run focused worker tests**

Run: `pnpm --filter @shannon/worker exec vitest run tests/http-load.test.ts tests/assessment-scopes.test.ts tests/config-preflight.test.ts`

Expected: all focused tests PASS.

- [ ] **Step 6: Commit the worker contract slice**

```bash
git add apps/worker/src/types/http-load.ts apps/worker/src/types/scopes.ts apps/worker/src/types/config.ts apps/worker/src/config-parser.ts apps/worker/configs/config-schema.json apps/worker/src/temporal/shared.ts apps/worker/tests/http-load.test.ts apps/worker/tests/assessment-scopes.test.ts apps/worker/tests/config-preflight.test.ts
git commit -m "feat(worker): add HTTP load assessment contract"
```

### Task 2: CLI Contracts, Profiles, And Authorization

**Files:**
- Create: `apps/cli/src/http-load.ts`
- Create: `apps/cli/tests/http-load.test.ts`
- Modify: `apps/cli/src/security-scopes.ts`
- Modify: `apps/cli/src/contracts.ts`
- Modify: `apps/cli/src/assessment-config.ts`
- Modify: `apps/cli/src/scan-controller.ts`
- Modify: `apps/cli/src/commands/start.ts`
- Modify: `apps/cli/src/index.ts`
- Modify: `apps/cli/src/ui/server.ts`
- Test: `apps/cli/tests/security-scopes.test.ts`
- Test: `apps/cli/tests/assessment-profiles.test.ts`
- Test: `apps/cli/tests/scan-controller.test.ts`
- Test: `apps/cli/tests/api.test.ts`

**Interfaces:**
- Consumes the exact constants and validation behavior from Task 1, duplicated locally because the published CLI does not depend on the private worker package.
- Produces `AssessmentConfig.httpLoad`, ephemeral `authorizationConfirmed`, and `elevatedLoadConfirmed` launch fields.
- Produces CLI flags `--i-own-this-target` and `--allow-elevated-load`.

- [ ] **Step 1: Write failing CLI contract tests**

```ts
it('requires explicit authorization for a selected load test', () => {
  const config = AssessmentConfigSchema.parse({ testScopes: ['http-load-capacity'] });
  expect(config.httpLoad).toEqual(HTTP_LOAD_DEFAULTS);
  expect(() =>
    RunLaunchSpecSchema.parse({
      targetUrl: 'https://authorized.test',
      sourceMode: 'url-only',
      config,
    }),
  ).toThrow(/i-own-this-target|authorization/i);
});

it('does not persist authorization acknowledgements in snapshots or profiles', async () => {
  const workspacesDir = await temporaryDirectory();
  const { controller } = testController(workspacesDir);
  const run = await controller.startRun({
    targetUrl: 'https://authorized.test',
    sourceMode: 'url-only',
    config: {
      testCategories: [],
      testScopes: ['http-load-capacity'],
      testSurfaces: ['browser', 'api-graphql'],
      httpLoad: HTTP_LOAD_DEFAULTS,
    },
    authorizationConfirmed: true,
    elevatedLoadConfirmed: true,
  });
  expect(run.snapshot).not.toHaveProperty('authorizationConfirmed');
  expect(run.snapshot).not.toHaveProperty('elevatedLoadConfirmed');
});
```

- [ ] **Step 2: Run focused CLI tests and verify they fail**

Run: `pnpm --filter @keygraph/shannon exec vitest run tests/http-load.test.ts tests/security-scopes.test.ts tests/assessment-profiles.test.ts tests/scan-controller.test.ts tests/api.test.ts`

Expected: FAIL because the CLI catalog and launch schemas do not support active HTTP load settings.

- [ ] **Step 3: Add CLI normalization and schema refinements**

Expose the same settings interface and constants as Task 1. `AssessmentConfigSchema` must insert defaults when selected, reject orphaned configuration, preserve normalized values in profile version 1, and permit an empty derived `testCategories` only for explicit scopes that require no agent lane.

Extend launch-only input with:

```ts
authorizationConfirmed?: true;
elevatedLoadConfirmed?: true;
```

Extend `RunSnapshotSchema` by omitting both fields. Validate that the regular acknowledgement exists for every load run and the elevated acknowledgement exists only when `isElevatedHttpLoad(config.httpLoad)` is true.

- [ ] **Step 4: Add CLI flags and controller propagation**

```text
--i-own-this-target    Confirm ownership or written authorization for HTTP load testing
--allow-elevated-load  Confirm elevated HTTP load parameters may disrupt the target
```

`start()` passes these booleans to `ScanController.startRun()`. The UI API maps its existing `authorizationConfirmed: true` plus the new elevated acknowledgement into the same launch contract. Resume requests selecting HTTP load must provide fresh acknowledgement before a replacement workflow starts.

`ScanController` maps launch-level `authorizationConfirmed` to worker-only `httpLoadAuthorizationConfirmed`; it forwards `elevatedLoadConfirmed` unchanged. Neither field enters `RunSnapshot`, profile YAML, distributed assessment configuration, or report data.

- [ ] **Step 5: Verify snapshot and profile persistence**

Run: `pnpm --filter @keygraph/shannon exec vitest run tests/http-load.test.ts tests/assessment-profiles.test.ts tests/scan-controller.test.ts tests/api.test.ts`

Expected: PASS; profile/snapshot JSON contains `httpLoad` settings and contains no acknowledgement fields.

- [ ] **Step 6: Commit the CLI contract slice**

```bash
git add apps/cli/src/http-load.ts apps/cli/src/security-scopes.ts apps/cli/src/contracts.ts apps/cli/src/assessment-config.ts apps/cli/src/scan-controller.ts apps/cli/src/commands/start.ts apps/cli/src/index.ts apps/cli/src/ui/server.ts apps/cli/tests/http-load.test.ts apps/cli/tests/security-scopes.test.ts apps/cli/tests/assessment-profiles.test.ts apps/cli/tests/scan-controller.test.ts apps/cli/tests/api.test.ts
git commit -m "feat(cli): add authorized HTTP load configuration"
```

### Task 3: Explicit-Opt-In UI Controls

**Files:**
- Modify: `apps/cli/web/src/components/AssessmentConfigFields.tsx`
- Modify: `apps/cli/web/src/components/AssessmentScopeSelector.tsx`
- Modify: `apps/cli/web/src/pages/NewAssessmentPage.tsx`
- Modify: `apps/cli/web/src/pages/RunDetailPage.tsx`
- Modify: `apps/cli/web/src/types/api.ts`
- Modify: `apps/cli/web/src/lib/api.ts`
- Modify: `apps/cli/web/src/styles.css`
- Test: `apps/cli/tests/assessment-form.test.ts`
- Test: `apps/cli/tests/e2e/operator-ui.spec.ts`

**Interfaces:**
- Consumes `HTTP_LOAD_DEFAULTS`, thresholds, limits, `isElevatedHttpLoad()`, and normalized profile settings from Task 2.
- Produces `CreateRunRequest.elevatedLoadConfirmed` only after explicit confirmation.

- [ ] **Step 1: Write failing form and Playwright tests**

```ts
it('requires an elevated acknowledgement above the soft thresholds', () => {
  const result = assessmentFormSchema.safeParse(values({
    testScopes: { ...assessmentDefaults.testScopes, 'http-load-capacity': true },
    httpLoadConcurrency: 21,
    elevatedLoadConfirmed: false,
  }));
  expect(result.error?.issues).toContainEqual(
    expect.objectContaining({ path: ['elevatedLoadConfirmed'] }),
  );
});
```

Playwright must expand A06, select `HTTP load and capacity`, enter `25`, `75`, and `90`, verify the estimated `6,750 requests`, require the second confirmation, and assert the submitted request contains normalized settings and both acknowledgements.

- [ ] **Step 2: Run the form and desktop Playwright tests to verify failure**

Run: `pnpm --filter @keygraph/shannon exec vitest run tests/assessment-form.test.ts`

Run: `pnpm --filter @keygraph/shannon exec playwright test tests/e2e/operator-ui.spec.ts --grep "HTTP load" --project=desktop`

Expected: FAIL because the checkbox is disabled and the controls do not exist.

- [ ] **Step 3: Make the scope explicitly selectable**

Keep `availableTestScopes` as all selectable scopes, add `standardTestScopes` for defaults/bulk controls, and change the toolbar copy to `Select all standard checks`. OWASP parent selection must use only `bulkSelectable !== false` children. Render `Explicit opt-in` beside the load checkbox.

- [ ] **Step 4: Add the load configuration panel**

Add three number inputs using React Hook Form with `valueAsNumber`, stable dimensions, and the emergency ceilings as `max` attributes. Render the panel only when selected. Render the estimated count with integer-safe multiplication and a warning notice. Render the elevated confirmation only when thresholds are crossed.

Form fields:

```ts
httpLoadConcurrency: z.number().int().min(1).max(1_000),
httpLoadRequestsPerSecond: z.number().int().min(1).max(10_000),
httpLoadDurationSeconds: z.number().int().min(1).max(3_600),
elevatedLoadConfirmed: z.boolean(),
```

- [ ] **Step 5: Preserve settings but clear acknowledgements across profiles**

`toRequest()` includes `config.httpLoad` only when selected. Profile save/load keeps the three values, while every profile load and scope clear resets `elevatedLoadConfirmed` to false. Resume UI displays equivalent confirmations before calling the API.

- [ ] **Step 6: Run unit and desktop/mobile E2E tests**

Run: `pnpm --filter @keygraph/shannon exec vitest run tests/assessment-form.test.ts tests/http-load.test.ts`

Run: `pnpm --filter @keygraph/shannon exec playwright test tests/e2e/operator-ui.spec.ts --grep "HTTP load"`

Expected: all tests PASS at desktop and mobile widths with no accessibility violations.

- [ ] **Step 7: Commit the UI slice**

```bash
git add apps/cli/web/src/components/AssessmentConfigFields.tsx apps/cli/web/src/components/AssessmentScopeSelector.tsx apps/cli/web/src/pages/NewAssessmentPage.tsx apps/cli/web/src/pages/RunDetailPage.tsx apps/cli/web/src/types/api.ts apps/cli/web/src/lib/api.ts apps/cli/web/src/styles.css apps/cli/tests/assessment-form.test.ts apps/cli/tests/e2e/operator-ui.spec.ts
git commit -m "feat(ui): configure explicit HTTP load assessments"
```

### Task 4: Python Load Generator JSON Contract

**Files:**
- Create: `apps/worker/scripts/http_flood_test.py`
- Test: `apps/worker/tests/http-load.test.ts`

**Interfaces:**
- Consumes CLI flags `target`, `--concurrency`, `--rate`, `--duration`, `--json-output`, and `--i-own-this-target`.
- Produces a versioned JSON object consumed by `parseHttpLoadResult()` from Task 1.

- [ ] **Step 1: Add failing subprocess tests around a local HTTP server**

```ts
it('refuses traffic without the ownership flag', async () => {
  const result = await runPython([target, '--concurrency', '1', '--rate', '1', '--duration', '1']);
  expect(result.exitCode).toBe(2);
  expect(requestCount).toBe(0);
});

it('writes a bounded machine-readable summary', async () => {
  const result = await runPython([
    target,
    '--concurrency', '2',
    '--rate', '4',
    '--duration', '1',
    '--json-output', outputPath,
    '--i-own-this-target',
  ]);
  expect(result.exitCode).toBe(0);
  expect(await readJson(outputPath)).toMatchObject({ version: 1, status: 'completed', sent: 4 });
});
```

- [ ] **Step 2: Run the focused script tests and verify failure**

Run: `pnpm --filter @shannon/worker exec vitest run tests/http-load.test.ts -t "ownership flag|machine-readable"`

Expected: FAIL because the worker-packaged script and JSON option do not exist.

- [ ] **Step 3: Package the existing asyncio implementation and add JSON output**

The JSON object must use this stable shape:

```json
{
  "version": 1,
  "status": "completed",
  "started_at": "2026-09-01T12:00:00+00:00",
  "completed_at": "2026-09-01T12:00:01+00:00",
  "target": "https://authorized.test/path",
  "concurrency": 2,
  "requests_per_second": 4,
  "duration_seconds": 1,
  "elapsed_seconds": 1.01,
  "sent": 4,
  "completed": 4,
  "success": 4,
  "failure": 0,
  "errors": 0,
  "bytes_read": 512,
  "average_latency_ms": 8.5,
  "minimum_latency_ms": 6.2,
  "maximum_latency_ms": 11.1,
  "status_counts": { "200": 4 }
}
```

Write JSON atomically, redact sensitive query values, preserve the legal disclaimer, and retain graceful `SIGINT`/`SIGTERM` handling.

- [ ] **Step 4: Run script tests**

Run: `pnpm --filter @shannon/worker exec vitest run tests/http-load.test.ts -t "ownership flag|machine-readable"`

Expected: PASS with request count bounded by configured scheduling.

- [ ] **Step 5: Commit the script slice**

```bash
git add apps/worker/scripts/http_flood_test.py apps/worker/tests/http-load.test.ts
git commit -m "feat(worker): add bounded HTTP load generator"
```

### Task 5: Activity Runner, Cancellation, And Artifact Idempotency

**Files:**
- Create: `apps/worker/src/services/http-load-runner.ts`
- Modify: `apps/worker/src/temporal/activities.ts`
- Test: `apps/worker/tests/http-load.test.ts`
- Test: `apps/worker/tests/activity-source-mode.test.ts`

**Interfaces:**
- Produces `runHttpLoadCapacity(options): Promise<HttpLoadResult>` and `readCompletedHttpLoadResult(workingDirectory)`.
- Produces activity `runHttpLoadCapacityActivity(input): Promise<HttpLoadResult>`.

- [ ] **Step 1: Write failing runner tests**

```ts
it('returns an existing valid completed artifact without starting a child', async () => {
  await atomicWrite(resultPath, completedResult);
  const spawn = vi.fn();
  await expect(runHttpLoadCapacity({ ...options, spawn })).resolves.toEqual(completedResult);
  expect(spawn).not.toHaveBeenCalled();
});

it('forwards cancellation to the child process', async () => {
  const controller = new AbortController();
  const running = runHttpLoadCapacity({ ...options, signal: controller.signal });
  controller.abort();
  await expect(running).rejects.toMatchObject({ name: 'AbortError' });
  expect(child.kill).toHaveBeenCalledWith('SIGTERM');
});
```

- [ ] **Step 2: Run runner tests and verify failure**

Run: `pnpm --filter @shannon/worker exec vitest run tests/http-load.test.ts -t "existing valid|forwards cancellation|activity"`

Expected: FAIL because the runner and activity do not exist.

- [ ] **Step 3: Implement child execution and artifact validation**

Use `spawn('python3', args, { stdio: ['ignore', 'pipe', 'pipe'] })`; never invoke a shell. Arguments come only from normalized numbers and the validated URL. Stream sanitized progress to the activity logger, heartbeat every two seconds, cap captured stderr, terminate with `SIGTERM` on abort, and escalate to `SIGKILL` after five seconds.

The canonical artifact path is:

```ts
path.join(workingDirectory, '.shannon', 'http-load-capacity.json');
```

Only a schema-valid `status: 'completed'` artifact is idempotent. Invalid or interrupted files are replaced atomically after the next explicitly authorized execution.

- [ ] **Step 4: Expose the non-retrying activity**

The activity validates authorization before spawn, uses `Context.current().cancellationSignal`, and rethrows Temporal cancellation. Contract errors become non-retryable `ApplicationFailure`s with redacted details.

- [ ] **Step 5: Run activity and runner tests**

Run: `pnpm --filter @shannon/worker exec vitest run tests/http-load.test.ts tests/activity-source-mode.test.ts`

Expected: PASS.

- [ ] **Step 6: Commit the activity slice**

```bash
git add apps/worker/src/services/http-load-runner.ts apps/worker/src/temporal/activities.ts apps/worker/tests/http-load.test.ts apps/worker/tests/activity-source-mode.test.ts
git commit -m "feat(worker): execute HTTP load activity"
```

### Task 6: Workflow Ordering And Resume Invariants

**Files:**
- Modify: `apps/worker/src/temporal/workflows.ts`
- Modify: `apps/worker/src/temporal/activities.ts`
- Modify: `apps/worker/src/audit/metrics-tracker.ts`
- Test: `apps/worker/tests/workflow-resume-finalization.test.ts`
- Test: `apps/worker/tests/resume-scope.test.ts`
- Test: `apps/worker/tests/source-mode.test.ts`

**Interfaces:**
- Consumes `runHttpLoadCapacityActivity()` from Task 5.
- Persists normalized `httpLoad` inside `session.session.scope` and its configuration hash projection.

- [ ] **Step 1: Write failing workflow tests**

```ts
it('runs HTTP load once after vulnerability work and before reporting', async () => {
  const state = await runWorkflow(loadOnlyInput);
  expect(activityOrder).toEqual([
    'prepareWorkingDirectory',
    'recon',
    'http-load-capacity',
    'report',
    'report-output',
  ]);
  expect(state.completedAgents).not.toContain('http-load-capacity');
});

it('rejects changed load parameters on resume', async () => {
  await persistOrValidateRunScope(originalInput, [], true);
  await expect(
    persistOrValidateRunScope({ ...originalInput, httpLoad: { ...originalInput.httpLoad, durationSeconds: 30 } }, [], true),
  ).rejects.toThrow(/resume scope mismatch/i);
});
```

- [ ] **Step 2: Run workflow/resume tests and verify failure**

Run: `pnpm --filter @shannon/worker exec vitest run tests/workflow-resume-finalization.test.ts tests/resume-scope.test.ts tests/source-mode.test.ts`

Expected: FAIL because no load phase or persisted load settings exist.

- [ ] **Step 3: Add the dedicated activity proxy and phase**

Create a proxy with `maximumAttempts: 1`, `heartbeatTimeout: '10 seconds'`, and `startToCloseTimeout: '65 minutes'`. Execute it after vulnerability/safe-demonstration pipelines and before triage/reporting. Set `currentPhase` to `http-load-capacity`, keep `currentAgent` null, and emit normal phase-transition logs.

When no vulnerability lanes are selected, skip triage and run recon, HTTP load, and report only. Do not add a new agent ID or `AgentMetrics` entry.

Catch a returned runtime `incomplete` result, log it with redaction, and continue to reporting. Contract, authorization, and setup validation fail before traffic begins; workflow cancellation remains cancellation rather than an incomplete report path.

- [ ] **Step 4: Persist resume scope and normalized hash**

Add `httpLoad?: HttpLoadSettings` to session scope. Compare every normalized field during resume and include the settings in current and legacy-aware hash projections. Backfill only sessions that do not select `http-load-capacity`; sessions selecting it without settings are invalid.

- [ ] **Step 5: Run workflow/resume tests**

Run: `pnpm --filter @shannon/worker exec vitest run tests/workflow-resume-finalization.test.ts tests/resume-scope.test.ts tests/source-mode.test.ts`

Expected: PASS.

- [ ] **Step 6: Commit the workflow slice**

```bash
git add apps/worker/src/temporal/workflows.ts apps/worker/src/temporal/activities.ts apps/worker/src/audit/metrics-tracker.ts apps/worker/tests/workflow-resume-finalization.test.ts apps/worker/tests/resume-scope.test.ts apps/worker/tests/source-mode.test.ts
git commit -m "feat(worker): schedule HTTP load phase"
```

### Task 7: Deterministic Coverage And Report Results

**Files:**
- Modify: `apps/worker/src/types/scopes.ts`
- Modify: `apps/worker/src/services/structured-report.ts`
- Modify: `apps/worker/src/services/report-renderer.ts`
- Modify: `apps/worker/src/temporal/activities.ts`
- Test: `apps/worker/tests/report-model.test.ts`
- Test: `apps/worker/tests/prompts-reporting-redaction.test.ts`
- Test: `apps/worker/tests/assessment-scopes.test.ts`

**Interfaces:**
- Extends `buildScopeCoverage(selectedScopes, notAssessed, completedActivityScopes?)`.
- Adds optional `ReportData.http_load_capacity` using `HttpLoadResult`.

- [ ] **Step 1: Write failing report and coverage tests**

```ts
it('marks activity-backed load coverage complete only with a completed result', () => {
  expect(
    buildScopeCoverage(['http-load-capacity'], [], ['http-load-capacity']).find(
      ({ owasp_id }) => owasp_id === 'A06:2025',
    ),
  ).toMatchObject({
    status: 'completed',
    selected_scopes: ['http-load-capacity'],
    completed_scopes: ['http-load-capacity'],
  });
  expect(
    buildScopeCoverage(['http-load-capacity'], []).find(({ owasp_id }) => owasp_id === 'A06:2025')?.status,
  ).toBe('incomplete');
});

it('renders neutral HTTP capacity metrics', () => {
  expect(renderReport(reportWithCompletedLoad)).toContain('## HTTP Load and Capacity');
  expect(renderReport(reportWithCompletedLoad)).toContain('| Requests sent | 150 |');
  expect(renderReport(reportWithCompletedLoad)).not.toMatch(/resilient|safe from denial|passed capacity/i);
});
```

- [ ] **Step 2: Run report tests and verify failure**

Run: `pnpm --filter @shannon/worker exec vitest run tests/report-model.test.ts tests/prompts-reporting-redaction.test.ts tests/assessment-scopes.test.ts`

Expected: FAIL because activity-backed completion and HTTP metrics are not represented.

- [ ] **Step 3: Load the artifact into structured report finalization**

`runReportAgent()` reads the validated artifact from the working directory and passes it into `createStructuredReportSession()`. The report data stores only the already-redacted result. Missing or interrupted output leaves the selected scope incomplete.

- [ ] **Step 4: Render the deterministic report section**

Place `## HTTP Load and Capacity` after OWASP coverage. Include configured envelope, actual elapsed time, sent/completed/success/failure/error counts, status counts, and average/minimum/maximum latency. State that results describe only the observed run and are not a guarantee of availability.

- [ ] **Step 5: Run report tests**

Run: `pnpm --filter @shannon/worker exec vitest run tests/report-model.test.ts tests/prompts-reporting-redaction.test.ts tests/assessment-scopes.test.ts`

Expected: PASS with no secret-bearing target query values in snapshots or reports.

- [ ] **Step 6: Commit the report slice**

```bash
git add apps/worker/src/types/scopes.ts apps/worker/src/services/structured-report.ts apps/worker/src/services/report-renderer.ts apps/worker/src/temporal/activities.ts apps/worker/tests/report-model.test.ts apps/worker/tests/prompts-reporting-redaction.test.ts apps/worker/tests/assessment-scopes.test.ts
git commit -m "feat(worker): report HTTP load capacity results"
```

### Task 8: Full Verification And Browser QA

**Files:**
- Modify only files required to correct failures introduced by Tasks 1-7.
- Test: all CLI and worker suites.

**Interfaces:**
- Verifies the complete public behavior; introduces no new contract.

- [ ] **Step 1: Run formatting and type checks**

Run: `pnpm biome check apps/cli apps/worker`

Run: `pnpm --filter @keygraph/shannon check`

Run: `pnpm --filter @shannon/worker check`

Expected: exit `0` from all commands.

- [ ] **Step 2: Run all unit and integration tests**

Run: `pnpm --filter @keygraph/shannon test`

Run: `pnpm --filter @shannon/worker test`

Run: `pnpm --filter @keygraph/shannon test:integration`

Run: `pnpm --filter @shannon/worker test:integration`

Expected: all tests PASS with zero failures.

- [ ] **Step 3: Run production builds and full browser coverage**

Run: `pnpm --filter @keygraph/shannon build`

Run: `pnpm --filter @shannon/worker build`

Run: `pnpm --filter @keygraph/shannon test:e2e`

Expected: builds exit `0`; desktop and mobile Playwright projects pass.

- [ ] **Step 4: Perform local authorized smoke testing**

Start a loopback-only HTTP fixture, run the worker-packaged Python script at `2` connections, `4` requests/second, and `2` seconds, and confirm the JSON artifact reports approximately eight scheduled requests. Do not send traffic to an external target during automated verification.

- [ ] **Step 5: Inspect desktop and mobile screenshots**

Start `./shannon ui --port 8788 --no-open`, select the load scope, exercise standard and elevated values, and capture screenshots at `1440x900` and `390x844`. Verify no overlap, clipped labels, unexpected layout shift, or enabled start action before all required confirmations.

- [ ] **Step 6: Review the final diff**

Run: `git diff --check`

Run: `git diff origin/main... --stat`

If verification required a code correction, rerun the failing gate and commit that correction with the exact files from its owning task before declaring completion. Leave unrelated pre-existing changes unstaged.
