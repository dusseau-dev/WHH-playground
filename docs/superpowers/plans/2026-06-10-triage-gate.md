# Triage Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `triage` LLM agent between exploitation and reporting that emits a validated `triage_verdicts.json` (PASS/DOWNGRADE/KILL/CHAIN_REQUIRED); the report deterministically renders a Confirmed-findings table + a Considered-&-ruled-out appendix, or a loud UNVALIDATED banner if triage didn't run (fail-open).

**Architecture:** A new agent in the `AGENTS` registry (so `AgentExecutionService` runs it for free), inserted into `workflows.ts` as a fail-open phase before reporting. Validation (`triage-validation.ts`) and deterministic rendering (`triage-report.ts`) are pure modules; `assembleFinalReport` prepends the rendered sections to the concatenated evidence.

**Tech Stack:** TypeScript (ESM, `tsc`), Temporal, `zx` fs/path, hand-rolled validation mirroring `queue-validation.ts` + `Result<T,E>`. **No test runner** (repo has none — decision C). Gates per task: `pnpm --filter @shannon/worker check` (tsc) + `pnpm biome`. Behavioral verification: a standalone smoke script (Task 8). Spec: `docs/superpowers/specs/2026-06-10-triage-gate-design.md`.

---

## File Structure

**Create**
- `apps/worker/src/services/triage-validation.ts` — verdict types + `validateTriageVerdicts`.
- `apps/worker/src/services/triage-report.ts` — `loadVerdicts` + pure `renderVerdictSections`.
- `apps/worker/prompts/triage-verdict.txt` — triage agent prompt.
- `apps/worker/prompts/pipeline-testing/triage-verdict.txt` — minimal prompt for `--pipeline-testing`.
- `apps/worker/src/scripts/verify-triage.ts` — standalone rendering smoke (decision-C verification).

**Modify**
- `apps/worker/src/types/deliverables.ts` — add `TRIAGE_VERDICT`.
- `apps/worker/src/types/agents.ts` — add `'triage'` to `ALL_AGENTS`.
- `apps/worker/src/session-manager.ts` — `AGENTS` entry + `AGENT_PHASE_MAP` + `PLAYWRIGHT_SESSION_MAPPING` + `AGENT_VALIDATORS`.
- `apps/worker/src/temporal/shared.ts` — `PipelineState.triageRan`.
- `apps/worker/src/temporal/activities.ts` — `runTriageAgent` export.
- `apps/worker/src/temporal/workflows.ts` — fail-open triage phase.
- `apps/worker/src/services/reporting.ts` — prepend verdict sections in `assembleFinalReport`.
- `apps/worker/prompts/report-executive.txt` — consume verdicts / preserve sections.
- `COVERAGE.md` — note the triage phase.

> **Note on paths:** the existing validators/report read deliverables via `path.join(sourceDir, '.shannon', 'deliverables', <file>)` (e.g. `reporting.ts:31`, `session-manager.ts:147`). Mirror that exact join for `triage_verdicts.json` so it resolves wherever the evidence files do — do not invent a new path scheme.

> **Prerequisites are metadata:** the workflow sequences phases explicitly (`workflows.ts`), so `triage.prerequisites` is descriptive. Do NOT add `triage` to `report.prerequisites` — that must stay independent so report still runs when triage fails open.

---

## Task 1: Verdict types + validator

**Files:**
- Create: `apps/worker/src/services/triage-validation.ts`
- Modify: `apps/worker/src/types/deliverables.ts`

- [ ] **Step 1: Add the deliverable type.** In `apps/worker/src/types/deliverables.ts`, add to the `DeliverableType` enum (after `SSRF_EVIDENCE`, line 32):

```ts
  SSRF_EVIDENCE = 'SSRF_EVIDENCE',

  // Triage gate
  TRIAGE_VERDICT = 'TRIAGE_VERDICT',
```

and add to `DELIVERABLE_FILENAMES` (after the `SSRF_EVIDENCE` entry, line 50):

```ts
  [DeliverableType.SSRF_EVIDENCE]: 'ssrf_exploitation_evidence.md',
  [DeliverableType.TRIAGE_VERDICT]: 'triage_verdicts.json',
```

- [ ] **Step 2: Create the validator.** Write `apps/worker/src/services/triage-validation.ts`:

```ts
// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Triage verdict schema + validator (mirrors queue-validation.ts: hand-rolled
 * shape checks returning Result<T, PentestError>, no extra deps).
 */

import { ErrorCode } from '../types/errors.js';
import { err, isErr, ok, type Result } from '../types/result.js';
import { PentestError } from './error-handling.js';

export type Verdict = 'PASS' | 'DOWNGRADE' | 'KILL' | 'CHAIN_REQUIRED';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export const VERDICTS: readonly Verdict[] = ['PASS', 'DOWNGRADE', 'KILL', 'CHAIN_REQUIRED'];
export const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export interface TriageVerdict {
  id: string;
  vulnType: string;
  title: string;
  verdict: Verdict;
  severity: Severity;
  claimedSeverity?: Severity;
  reason: string;
  evidenceFile: string;
}

export interface TriageVerdicts {
  version: 1;
  verdicts: TriageVerdict[];
}

function isVerdict(v: unknown): v is Verdict {
  return typeof v === 'string' && (VERDICTS as readonly string[]).includes(v);
}

function isSeverity(s: unknown): s is Severity {
  return typeof s === 'string' && (SEVERITIES as readonly string[]).includes(s);
}

function invalid(message: string, context: Record<string, unknown>): Result<never, PentestError> {
  return err(new PentestError(message, 'validation', true, context, ErrorCode.OUTPUT_VALIDATION_FAILED));
}

function validateEntry(entry: unknown, index: number): Result<TriageVerdict, PentestError> {
  if (typeof entry !== 'object' || entry === null) {
    return invalid(`Triage verdict ${index} is not an object`, { index });
  }
  const e = entry as Record<string, unknown>;

  for (const key of ['id', 'vulnType', 'title', 'reason', 'evidenceFile'] as const) {
    if (typeof e[key] !== 'string' || (e[key] as string).length === 0) {
      return invalid(`Triage verdict ${index} missing/empty '${key}'`, { index, key });
    }
  }
  if (!isVerdict(e.verdict)) {
    return invalid(`Triage verdict ${index} has invalid 'verdict': ${String(e.verdict)}`, { index });
  }
  if (!isSeverity(e.severity)) {
    return invalid(`Triage verdict ${index} has invalid 'severity': ${String(e.severity)}`, { index });
  }
  if (e.claimedSeverity !== undefined && !isSeverity(e.claimedSeverity)) {
    return invalid(`Triage verdict ${index} has invalid 'claimedSeverity'`, { index });
  }

  return ok({
    id: e.id as string,
    vulnType: e.vulnType as string,
    title: e.title as string,
    verdict: e.verdict,
    severity: e.severity,
    reason: e.reason as string,
    evidenceFile: e.evidenceFile as string,
    ...(e.claimedSeverity !== undefined && { claimedSeverity: e.claimedSeverity as Severity }),
  });
}

/** Validate a parsed triage_verdicts.json object. */
export function validateTriageVerdicts(raw: unknown): Result<TriageVerdicts, PentestError> {
  if (typeof raw !== 'object' || raw === null) {
    return invalid('Triage verdicts must be a JSON object', {});
  }
  const obj = raw as Record<string, unknown>;
  if (obj.version !== 1) {
    return invalid(`Triage verdicts 'version' must be 1`, { version: obj.version });
  }
  if (!Array.isArray(obj.verdicts)) {
    return invalid(`Triage verdicts 'verdicts' must be an array`, {});
  }

  const verdicts: TriageVerdict[] = [];
  for (let i = 0; i < obj.verdicts.length; i++) {
    const result = validateEntry(obj.verdicts[i], i);
    if (isErr(result)) return result;
    verdicts.push(result.value);
  }
  return ok({ version: 1, verdicts });
}
```

> **Self-check while writing:** `exactOptionalPropertyTypes` is on — use the spread form for `claimedSeverity` (shown), never `claimedSeverity: undefined`.

- [ ] **Step 3: Type-check + lint.**

Run: `pnpm --filter @shannon/worker check && pnpm biome`
Expected: PASS (no errors).

- [ ] **Step 4: Commit.**

```bash
git add apps/worker/src/services/triage-validation.ts apps/worker/src/types/deliverables.ts
git commit -m "feat(triage): add verdict schema + validator and TRIAGE_VERDICT deliverable type"
```

---

## Task 2: Deterministic verdict rendering

**Files:**
- Create: `apps/worker/src/services/triage-report.ts`

- [ ] **Step 1: Write the renderer.** Create `apps/worker/src/services/triage-report.ts`:

```ts
// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Deterministic rendering of triage verdicts into the report's authoritative
 * "Confirmed Findings" and "Considered & Ruled Out" sections (or the UNVALIDATED
 * banner when verdicts are missing/invalid — fail-open).
 */

import { fs, path } from 'zx';
import type { ActivityLogger } from '../types/activity-logger.js';
import { isErr } from '../types/result.js';
import { type Severity, type TriageVerdicts, validateTriageVerdicts } from './triage-validation.js';

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const UNVALIDATED_BANNER = [
  '> ## ⚠️ Triage did not run — findings are UNVALIDATED',
  '>',
  '> The triage gate did not produce verdicts for this run, so the findings below were',
  '> NOT validated for exploitability. Treat them as raw, unconfirmed candidates.',
].join('\n');

/** Escape a markdown table cell. */
function cell(s: string): string {
  return s.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

/**
 * Load + validate triage_verdicts.json. Returns null (fail-open) if missing/invalid.
 * Mirrors the deliverable path-join used by assembleFinalReport / the agent validators.
 */
export async function loadVerdicts(sourceDir: string, logger: ActivityLogger): Promise<TriageVerdicts | null> {
  const file = path.join(sourceDir, '.shannon', 'deliverables', 'triage_verdicts.json');
  if (!(await fs.pathExists(file))) {
    logger.warn('triage_verdicts.json not found — report will be UNVALIDATED');
    return null;
  }
  try {
    const raw = JSON.parse(await fs.readFile(file, 'utf8')) as unknown;
    const result = validateTriageVerdicts(raw);
    if (isErr(result)) {
      logger.warn(`triage_verdicts.json invalid (${result.error.message}) — report will be UNVALIDATED`);
      return null;
    }
    return result.value;
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    logger.warn(`triage_verdicts.json unreadable (${msg}) — report will be UNVALIDATED`);
    return null;
  }
}

/** Pure: render the verdict sections markdown (or the banner when verdicts === null). */
export function renderVerdictSections(verdicts: TriageVerdicts | null): string {
  if (verdicts === null) return UNVALIDATED_BANNER;

  const confirmed = verdicts.verdicts
    .filter((v) => v.verdict === 'PASS' || v.verdict === 'DOWNGRADE')
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  const ruledOut = verdicts.verdicts.filter((v) => v.verdict === 'KILL' || v.verdict === 'CHAIN_REQUIRED');

  const lines: string[] = ['## Confirmed Findings', ''];
  if (confirmed.length === 0) {
    lines.push('_No findings passed triage validation._');
  } else {
    lines.push('| Severity | Type | Finding | Verdict |', '| --- | --- | --- | --- |');
    for (const v of confirmed) {
      const downgrade = v.verdict === 'DOWNGRADE' && v.claimedSeverity ? ` (was ${v.claimedSeverity})` : '';
      lines.push(`| ${v.severity.toUpperCase()}${downgrade} | ${v.vulnType} | ${cell(v.title)} | ${v.verdict} |`);
    }
  }

  lines.push('', '## Considered & Ruled Out', '');
  if (ruledOut.length === 0) {
    lines.push('_Nothing was ruled out._');
  } else {
    lines.push('| Type | Finding | Outcome | Reason |', '| --- | --- | --- | --- |');
    for (const v of ruledOut) {
      const outcome =
        v.verdict === 'CHAIN_REQUIRED' ? 'potential chain component — not standalone-exploitable' : 'ruled out';
      lines.push(`| ${v.vulnType} | ${cell(v.title)} | ${outcome} | ${cell(v.reason)} |`);
    }
  }
  return lines.join('\n');
}
```

- [ ] **Step 2: Type-check + lint.** Run: `pnpm --filter @shannon/worker check && pnpm biome` — Expected: PASS.

- [ ] **Step 3: Commit.**

```bash
git add apps/worker/src/services/triage-report.ts
git commit -m "feat(triage): deterministic verdict-section + UNVALIDATED-banner rendering"
```

---

## Task 3: Register the triage agent

**Files:**
- Modify: `apps/worker/src/types/agents.ts:15-29`, `apps/worker/src/session-manager.ts`

- [ ] **Step 1: Add to `ALL_AGENTS`.** In `apps/worker/src/types/agents.ts`, insert `'triage'` before `'report'` (line 28):

```ts
    'authz-exploit',
    'triage',
    'report',
  ] as const;
```

- [ ] **Step 2: Add imports to `session-manager.ts`** (after line 10):

```ts
import { isErr } from './types/result.js';
import { validateTriageVerdicts } from './services/triage-validation.js';
```

- [ ] **Step 3: Add the `AGENTS` entry** in `session-manager.ts`, immediately before the `report:` entry (line 100):

```ts
  triage: {
    name: 'triage',
    displayName: 'Triage gate',
    prerequisites: ['injection-exploit', 'xss-exploit', 'auth-exploit', 'ssrf-exploit', 'authz-exploit'],
    promptTemplate: 'triage-verdict',
    deliverableFilename: 'triage_verdicts.json',
    modelTier: 'large',
  },
  report: {
```

- [ ] **Step 4: Add to `AGENT_PHASE_MAP`** before `report: 'reporting'` (line 127). (v1: bucket triage under `reporting` to avoid touching `PhaseName` and `metrics-tracker.ts:321`'s `Record<PhaseName,...>` literal — note this as a deliberate smallest-surface choice.)

```ts
  triage: 'reporting',
  report: 'reporting',
```

- [ ] **Step 5: Add to `PLAYWRIGHT_SESSION_MAPPING`** after `'report-executive': 'agent3'` (line 177):

```ts
  'report-executive': 'agent3',
  'triage-verdict': 'agent3',
```

- [ ] **Step 6: Add the `AGENT_VALIDATORS` entry** before the `report:` validator (line 209):

```ts
  triage: async (sourceDir: string, logger: ActivityLogger): Promise<boolean> => {
    const verdictsFile = path.join(sourceDir, '.shannon', 'deliverables', 'triage_verdicts.json');
    if (!(await fs.pathExists(verdictsFile))) {
      logger.warn('Missing required deliverable: triage_verdicts.json');
      return false;
    }
    try {
      const raw = JSON.parse(await fs.readFile(verdictsFile, 'utf8')) as unknown;
      const result = validateTriageVerdicts(raw);
      if (isErr(result)) {
        logger.warn(`Invalid triage_verdicts.json: ${result.error.message}`);
        return false;
      }
      return true;
    } catch (error) {
      logger.warn(`Could not read triage_verdicts.json: ${error instanceof Error ? error.message : String(error)}`);
      return false;
    }
  },
```

- [ ] **Step 7: Type-check + lint.** Run: `pnpm --filter @shannon/worker check && pnpm biome`
Expected: PASS. (tsc enforces that `AGENTS`, `AGENT_PHASE_MAP`, and `AGENT_VALIDATORS` — all `Record<AgentName, …>` — now include `triage`. If you missed one, this fails here.)

- [ ] **Step 8: Confirm prerequisites are metadata.** Run: `grep -rn "\.prerequisites" apps/worker/src | grep -v node_modules` — verify no runtime gate would block `report` on `triage`. (Workflow ordering is explicit; expect only display/resume usage.)

- [ ] **Step 9: Commit.**

```bash
git add apps/worker/src/types/agents.ts apps/worker/src/session-manager.ts
git commit -m "feat(triage): register triage agent in AGENTS, phase map, session map, validators"
```

---

## Task 4: Triage activity wrapper

**Files:**
- Modify: `apps/worker/src/temporal/activities.ts:257-259`

- [ ] **Step 1: Add `runTriageAgent`** immediately after `runReportAgent` (line 259):

```ts
export async function runReportAgent(input: ActivityInput): Promise<AgentMetrics> {
  return runAgentActivity('report', input);
}

export async function runTriageAgent(input: ActivityInput): Promise<AgentMetrics> {
  return runAgentActivity('triage', input);
}
```

- [ ] **Step 2: Type-check + lint.** Run: `pnpm --filter @shannon/worker check && pnpm biome` — Expected: PASS.

- [ ] **Step 3: Commit.**

```bash
git add apps/worker/src/temporal/activities.ts
git commit -m "feat(triage): add runTriageAgent activity"
```

---

## Task 5: Workflow wiring (fail-open)

**Files:**
- Modify: `apps/worker/src/temporal/shared.ts:44-55`, `apps/worker/src/temporal/workflows.ts:144-155, 457-459`

- [ ] **Step 1: Add `triageRan` to `PipelineState`.** In `shared.ts`, add to the `PipelineState` interface (after `deliverables`, line 54):

```ts
  deliverables: DeliverableEntry[];
  /** False when the triage gate failed open — the report renders an UNVALIDATED banner. */
  triageRan: boolean;
```

- [ ] **Step 2: Initialize it** in `workflows.ts`, in the `state` literal (after `deliverables: [],`, line 154):

```ts
    deliverables: [],
    triageRan: false,
```

- [ ] **Step 3: Insert the fail-open triage phase** in `workflows.ts` between the exploitation-complete log (line 457) and the `// === Phase 5: Reporting ===` comment (line 459):

```ts
    await a.logPhaseTransition(activityInput, 'vulnerability-exploitation', 'complete');

    // === Phase 4.5: Triage Gate (fail-open) ===
    // Validates each finding before reporting. A triage failure must never lose a
    // completed exploitation run, so this is wrapped fail-open: on error the report
    // renders all findings under an UNVALIDATED banner (see services/reporting.ts).
    if (!shouldSkip('triage')) {
      state.currentPhase = 'triage';
      state.currentAgent = 'triage';
      await a.logPhaseTransition(activityInput, 'triage', 'start');
      try {
        state.agentMetrics.triage = await a.runTriageAgent(activityInput);
        state.completedAgents.push('triage');
        state.triageRan = true;
        await a.logPhaseTransition(activityInput, 'triage', 'complete');
      } catch (error) {
        state.triageRan = false;
        const msg = error instanceof Error ? error.message : String(error);
        log.warn(`Triage gate failed — continuing fail-open (report will be UNVALIDATED): ${msg}`);
      }
    } else {
      log.info('Skipping triage (already complete)');
      state.completedAgents.push('triage');
      state.triageRan = true;
    }

    // === Phase 5: Reporting ===
```

- [ ] **Step 4: Type-check + lint.** Run: `pnpm --filter @shannon/worker check && pnpm biome` — Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add apps/worker/src/temporal/shared.ts apps/worker/src/temporal/workflows.ts
git commit -m "feat(triage): insert fail-open triage phase before reporting"
```

---

## Task 6: Report integration

**Files:**
- Modify: `apps/worker/src/services/reporting.ts:7-10, 57`, `apps/worker/prompts/report-executive.txt:36-41`

- [ ] **Step 1: Import the renderer** in `reporting.ts` — add ONE import after the existing `import { PentestError } from './error-handling.js';` (line 10; do not re-import PentestError):

```ts
import { loadVerdicts, renderVerdictSections } from './triage-report.js';
```

- [ ] **Step 2: Prepend verdict sections.** In `reporting.ts`, replace `assembleFinalReport`'s line 57:

```ts
  const finalContent = sections.join('\n\n');
```

with:

```ts
  // Prepend the deterministic triage sections (Confirmed / Ruled-out tables, or the
  // UNVALIDATED banner if verdicts are missing/invalid — fail-open).
  const verdicts = await loadVerdicts(sourceDir, logger);
  const verdictMarkdown = renderVerdictSections(verdicts);
  const finalContent = [verdictMarkdown, ...sections].join('\n\n');
```

- [ ] **Step 3: Update the report prompt.** In `apps/worker/prompts/report-executive.txt`, add to `<input_files>` (after line 40):

```
- `.shannon/deliverables/triage_verdicts.json` - Triage verdicts (authoritative validation results)
```

and append this block at the end of `<instructions>` (before the closing `</instructions>`, line 129):

```
5. RESPECT THE TRIAGE GATE:
   - The report already begins with deterministic "## Confirmed Findings" and
     "## Considered & Ruled Out" sections built from triage_verdicts.json. PRESERVE
     them verbatim — do not delete, reorder, or move findings between them.
   - If a "⚠️ Triage did not run — findings are UNVALIDATED" banner is present, KEEP it
     at the very top and state in the Executive Summary that findings are unvalidated.
   - Align the Executive Summary with the Confirmed Findings table. Do NOT describe a
     KILL/ruled-out finding as confirmed, and do NOT promote a ruled-out item.
```

- [ ] **Step 4: Type-check + lint.** Run: `pnpm --filter @shannon/worker check && pnpm biome` — Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add apps/worker/src/services/reporting.ts apps/worker/prompts/report-executive.txt
git commit -m "feat(triage): render verdict sections in the assembled report; teach report agent to respect them"
```

---

## Task 7: Triage prompts

**Files:**
- Create: `apps/worker/prompts/triage-verdict.txt`, `apps/worker/prompts/pipeline-testing/triage-verdict.txt`

- [ ] **Step 1: Write `apps/worker/prompts/triage-verdict.txt`:**

```
<role>
You are a senior penetration-test triage analyst. You receive candidate findings produced by
the exploitation agents and decide, for each one, whether it is a real, exploitable finding —
applying a strict gate so only validated findings reach the company-facing report.
</role>

<target>
URL: {{WEB_URL}}
{{DESCRIPTION}}

Workspace:
- .shannon/deliverables/ (read-write)
- .shannon/scratchpad/ (read-write)
</target>

<input_files>
Read the exploitation evidence and queue files that exist for this run:
- `.shannon/deliverables/injection_exploitation_evidence.md` + `injection_exploitation_queue.json`
- `.shannon/deliverables/xss_exploitation_evidence.md` + `xss_exploitation_queue.json`
- `.shannon/deliverables/auth_exploitation_evidence.md` + `auth_exploitation_queue.json`
- `.shannon/deliverables/ssrf_exploitation_evidence.md` + `ssrf_exploitation_queue.json`
- `.shannon/deliverables/authz_exploitation_evidence.md` + `authz_exploitation_queue.json`
Some files may be absent — only triage the findings that exist.
</input_files>

<rubric>
For EACH candidate finding, answer these 7 questions:
1. Exploitable now: can an attacker trigger it with a real request against the target as
   configured — not "theoretically"?
2. Proven impact: is there concrete evidence (response data, state change, working PoC) —
   not just a suspicious pattern?
3. Realistic preconditions: does it work without privileges/conditions an attacker can't obtain?
4. Not by-design: is it not intended/documented behavior?
5. Not a duplicate of another finding in this run?
6. In scope: is it against the authorized target/host?
7. Material severity: is it above purely informational/cosmetic?

Assign a verdict:
- PASS — all yes.
- DOWNGRADE — real but lower impact than claimed; set `severity` to the corrected level and
  put the original in `claimedSeverity`.
- KILL — any disqualifying "no" on questions 1, 2, 3, or 6.
- CHAIN_REQUIRED — only valuable when combined with another finding (not standalone-exploitable).
One disqualifying "no" = KILL.
</rubric>

<output>
Produce STRICT JSON (no prose, no markdown fences) with a verdict for every candidate finding:

{
  "version": 1,
  "verdicts": [
    {
      "id": "<stable unique id, e.g. injection-1>",
      "vulnType": "injection|xss|auth|ssrf|authz",
      "title": "<short finding title>",
      "verdict": "PASS|DOWNGRADE|KILL|CHAIN_REQUIRED",
      "severity": "critical|high|medium|low|info",
      "claimedSeverity": "critical|high|medium|low|info  (optional; only for DOWNGRADE)",
      "reason": "<one-paragraph justification grounded in the evidence>",
      "evidenceFile": "<the *_exploitation_evidence.md this came from>"
    }
  ]
}

To save it:
1. Use the Write tool to create `.shannon/deliverables/triage_verdicts.json` containing the JSON.
2. Run: save-deliverable --type TRIAGE_VERDICT --file-path ".shannon/deliverables/triage_verdicts.json"
   (returns {"status":"success","filepath":"..."} or {"status":"error","message":"...","retryable":true})

If there are zero candidate findings, still emit {"version":1,"verdicts":[]}.
Every field except claimedSeverity is REQUIRED and non-empty, or validation rejects it and you retry.
</output>
```

- [ ] **Step 2: Write the pipeline-testing variant** `apps/worker/prompts/pipeline-testing/triage-verdict.txt` (minimal, for fast `--pipeline-testing` runs):

```
<role>You are a triage analyst (pipeline-testing mode — be fast).</role>
<target>URL: {{WEB_URL}}</target>
<task>
Read any `.shannon/deliverables/*_exploitation_evidence.md` files that exist. For each finding,
emit a verdict (PASS/DOWNGRADE/KILL/CHAIN_REQUIRED). Use the Write tool to create
`.shannon/deliverables/triage_verdicts.json` with STRICT JSON:
{"version":1,"verdicts":[{"id":"injection-1","vulnType":"injection","title":"...","verdict":"PASS","severity":"low","reason":"...","evidenceFile":"injection_exploitation_evidence.md"}]}
If none exist, emit {"version":1,"verdicts":[]}. Then run:
  save-deliverable --type TRIAGE_VERDICT --file-path ".shannon/deliverables/triage_verdicts.json"
</task>
```

- [ ] **Step 3: Sanity-check the prompts load.** Run: `ls apps/worker/prompts/triage-verdict.txt apps/worker/prompts/pipeline-testing/triage-verdict.txt` — Expected: both exist. (Prompts are `.txt`, not type-checked; verify the filenames match `promptTemplate: 'triage-verdict'`.)

- [ ] **Step 4: Commit.**

```bash
git add apps/worker/prompts/triage-verdict.txt apps/worker/prompts/pipeline-testing/triage-verdict.txt
git commit -m "feat(triage): triage-verdict prompt (full + pipeline-testing)"
```

---

## Task 8: Rendering smoke (decision-C verification)

**Files:**
- Create: `apps/worker/src/scripts/verify-triage.ts`

- [ ] **Step 1: Write the smoke script** `apps/worker/src/scripts/verify-triage.ts`:

```ts
#!/usr/bin/env node

// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Standalone smoke for the triage → report rendering path (the repo has no test
 * runner). Seeds a temp deliverables dir, runs assembleFinalReport, and asserts the
 * Confirmed/ruled-out tables and the fail-open UNVALIDATED banner. Run after build:
 *   pnpm --filter @shannon/worker build && node apps/worker/dist/scripts/verify-triage.js
 */

import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { assembleFinalReport } from '../services/reporting.js';

const logger = { info: () => {}, warn: () => {}, error: () => {} };
const failures: string[] = [];
function assert(cond: boolean, msg: string): void {
  if (!cond) failures.push(msg);
}

function seed(): string {
  const root = mkdtempSync(join(tmpdir(), 'triage-smoke-'));
  const dir = join(root, '.shannon', 'deliverables');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'injection_exploitation_evidence.md'), '# Injection Exploitation Evidence\n');
  return root;
}

async function main(): Promise<void> {
  // Case 1: valid verdicts → Confirmed table + ruled-out appendix, no banner.
  const root1 = seed();
  writeFileSync(
    join(root1, '.shannon', 'deliverables', 'triage_verdicts.json'),
    JSON.stringify({
      version: 1,
      verdicts: [
        { id: 'injection-1', vulnType: 'injection', title: 'SQLi in /login', verdict: 'PASS', severity: 'high', reason: 'Dumped users table.', evidenceFile: 'injection_exploitation_evidence.md' },
        { id: 'xss-1', vulnType: 'xss', title: 'Reflected XSS', verdict: 'KILL', severity: 'info', reason: 'Output encoded; not exploitable.', evidenceFile: 'xss_exploitation_evidence.md' },
      ],
    }),
  );
  const report1 = await assembleFinalReport(root1, logger);
  assert(report1.includes('## Confirmed Findings'), 'case1: missing Confirmed section');
  assert(report1.includes('SQLi in /login'), 'case1: missing PASS finding');
  assert(report1.includes('## Considered & Ruled Out'), 'case1: missing ruled-out section');
  assert(report1.includes('Reflected XSS'), 'case1: missing KILL finding in appendix');
  assert(!report1.includes('UNVALIDATED'), 'case1: banner shown despite valid verdicts');

  // Case 2: no verdicts file → fail-open UNVALIDATED banner.
  const root2 = seed();
  const report2 = await assembleFinalReport(root2, logger);
  assert(report2.includes('UNVALIDATED'), 'case2: missing UNVALIDATED banner');

  // Case 3: invalid verdicts (bad enum) → fail-open banner.
  const root3 = seed();
  writeFileSync(
    join(root3, '.shannon', 'deliverables', 'triage_verdicts.json'),
    JSON.stringify({ version: 1, verdicts: [{ id: 'x', vulnType: 'xss', title: 't', verdict: 'NOPE', severity: 'high', reason: 'r', evidenceFile: 'f.md' }] }),
  );
  const report3 = await assembleFinalReport(root3, logger);
  assert(report3.includes('UNVALIDATED'), 'case3: invalid verdicts did not fail open to banner');

  if (failures.length > 0) {
    console.error('TRIAGE SMOKE FAILED:\n' + failures.map((f) => `  - ${f}`).join('\n'));
    process.exit(1);
  }
  console.log('TRIAGE SMOKE PASSED (3 cases)');
}

main().catch((e) => {
  console.error('TRIAGE SMOKE ERROR:', e);
  process.exit(1);
});
```

- [ ] **Step 2: Build + run the smoke.**

Run: `pnpm --filter @shannon/worker build && node apps/worker/dist/scripts/verify-triage.js`
Expected: `TRIAGE SMOKE PASSED (3 cases)` and exit 0.

- [ ] **Step 3: Lint.** Run: `pnpm biome` — Expected: PASS.

- [ ] **Step 4: Commit.**

```bash
git add apps/worker/src/scripts/verify-triage.ts
git commit -m "test(triage): standalone rendering smoke (confirmed/ruled-out/fail-open banner)"
```

---

## Task 9: Docs

**Files:**
- Modify: `COVERAGE.md`

- [ ] **Step 1: Note the triage phase.** Read `COVERAGE.md` first, then add this subsection (adapt the heading level to match the file):

```md
### Triage gate

Between exploitation and reporting, a `triage` agent validates every candidate finding against a
7-point exploitability rubric and emits `triage_verdicts.json` with one verdict each:

- **PASS** — confirmed; appears under "Confirmed Findings".
- **DOWNGRADE** — real but lower severity than claimed (severity corrected).
- **KILL** — not exploitable; moved to the "Considered & Ruled Out" appendix with a reason.
- **CHAIN_REQUIRED** — only exploitable combined with another finding (appendix, labelled).

Phase order: pre-recon → recon → vuln+exploit → **triage** → report. The gate is **fail-open**: if
triage errors, the report still renders all findings under a "⚠️ Triage did not run — findings are
UNVALIDATED" banner.
```

- [ ] **Step 2: Commit.**

```bash
git add COVERAGE.md
git commit -m "docs(triage): document the triage gate phase and verdicts"
```

---

## Final verification (Phase 5 gate)

- [ ] `pnpm --filter @shannon/worker check` — typecheck clean.
- [ ] `pnpm biome` — lint/format clean.
- [ ] `pnpm --filter @shannon/worker build && node apps/worker/dist/scripts/verify-triage.js` — smoke PASSED.
- [ ] (Manual, optional, needs creds) a real `--pipeline-testing` run against a target to confirm the triage agent emits valid `triage_verdicts.json` and the report renders the sections end-to-end.

## Out of scope (per spec)
CVSS vectors (P5), attack-chain computation (P4 — `CHAIN_REQUIRED` is label-only), cross-run dedup (P5), UI changes, and a unit-test framework (decision C — gates are typecheck + biome + the smoke).
