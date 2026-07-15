# Triage Gate (P1) — Design Spec

**Date:** 2026-06-10
**Status:** Approved (design) — pending implementation plan
**Origin:** full-flow brainstorming; top recommendation from the Claude-BugHunter analysis

## Context / Why

Shannon runs `vuln-analysis → exploitation → report`, but every finding the exploitation
agents produce flows **straight into the report with no validation pass**. False positives,
theoretical-only issues, and low-value noise reach the company-facing report — the single
biggest thing that erodes trust in automated security tooling (a noisy scanner dump is
indistinguishable from a rigorous assessment).

The Claude-BugHunter project's most-praised feature is its **validation gate** ("the phase that
saves you from yourself"). This spec adapts that idea to Shannon's defensive/company context as a
**triage gate**: an independent, adversarial validation pass between exploitation and reporting
that forces every candidate finding through an exploitability rubric before it can appear as a
confirmed finding.

**Goal: biggest trust win, smallest surface.** One new agent, following Shannon's existing
"everything is an agent" pattern, producing a structured verdict artifact that the report honors —
and which P4 (attack chaining) and P5 (CVSS/dedup/ticketing) can reuse.

## Decisions (locked during brainstorming)

- **Output shape (Q1 = C):** the report shows a clean **Confirmed findings** list AND an auditable
  **Considered & ruled out** appendix (with reasons). Not a silent filter.
- **CHAIN_REQUIRED (Q2 = A):** kept as a real verdict but **label-only** in v1 — routed to the
  appendix as "potential chain component — not standalone-exploitable." No chaining logic (that is P4).
- **Failure mode (Q3 = A):** **fail-open + loud banner.** If triage errors after retries or emits
  invalid output, the workflow continues and the report renders all findings under a prominent
  "⚠️ Triage did not run — findings are UNVALIDATED" banner. A triage glitch never fails a
  completed exploitation run.

## Architecture

A new **`triage` LLM agent** between the exploitation and reporting phases. Chosen over:
(2) a deterministic rules service — the rubric is inherently qualitative ("proven impact, not
theoretical") and it would force a finding-schema migration onto the exploit agents; and
(3) folding triage into the report agent — dilutes the gate and loses the independent verdict
artifact that makes the gate trustworthy and reusable.

### Phase placement

```
preflight → pre-recon → recon → vuln+exploit (pipelined) → [TRIAGE] → report
```

Inserted in `apps/worker/src/temporal/workflows.ts` (~lines 457–461), after the
exploitation phase completes and before reporting.

### Components

1. **`triage` AgentDefinition** — `apps/worker/src/session-manager.ts` (`AGENTS`) +
   `apps/worker/src/types/agents.ts` (`ALL_AGENTS`, `AgentName`):
   - `promptTemplate: 'triage-verdict'`, `deliverableFilename: 'triage_verdicts.json'`,
     `modelTier: 'large'` (judgment-heavy).
   - **Gating:** triage sits immediately before `report` and **mirrors the report agent's
     prerequisite/gating behavior** — whatever makes `report` run under `--only` subsets (a subset
     of exploit agents) makes triage run too. It must NOT hard-require all five `*-exploit` agents
     to have run, or it would dead-lock on a subset run; it triages whatever exploitation evidence
     exists. `report`'s prerequisites gain `triage`.
   - Mode-agnostic: reads exploitation evidence, not source → no separate `blackboxPromptTemplate`.

2. **Prompt** — `apps/worker/prompts/triage-verdict.txt`:
   - Inputs: the `{vulnType}_exploitation_evidence.md` + `{vulnType}_exploitation_queue.json`
     deliverables that exist for this run.
   - Rubric (7 questions, company/defensive context):
     1. Exploitable *now* with a real request against the target as configured — not theoretical?
     2. Proven impact (response data, state change, working PoC) — not just a suspicious pattern?
     3. Realistic preconditions — works without privileges/conditions an attacker can't obtain?
     4. Not by-design / intended behavior?
     5. Not a duplicate of another finding in this run?
     6. In authorized scope (target/host per run config)?
     7. Material severity — above purely informational/cosmetic?
   - Verdicts: **PASS** (all yes) · **DOWNGRADE** (real but lower than claimed → adjust severity) ·
     **KILL** (any disqualifying "no" on Q1–Q3 or Q6) · **CHAIN_REQUIRED** (only valuable combined
     with another finding). One disqualifying "no" = KILL.
   - Output: STRICT JSON to `triage_verdicts.json` via `save-deliverable` (`--type TRIAGE_VERDICT`).
     Each verdict carries a stable `id`, a coarse `severity`, the `claimedSeverity` if the evidence
     asserted one, a one-paragraph `reason`, and the `evidenceFile` it came from.

3. **Verdict schema + validator** — `apps/worker/src/services/triage-validation.ts`, mirroring
   `apps/worker/src/services/queue-validation.ts` (hand-rolled shape validation + `Result<T,E>`;
   no new dependencies):
   ```ts
   type Verdict = 'PASS' | 'DOWNGRADE' | 'KILL' | 'CHAIN_REQUIRED';
   type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
   interface TriageVerdict {
     id: string; vulnType: string; title: string;
     verdict: Verdict; severity: Severity; claimedSeverity?: Severity;
     reason: string; evidenceFile: string;
   }
   interface TriageVerdicts { version: 1; verdicts: TriageVerdict[]; }
   function validateTriageVerdicts(raw: unknown): Result<TriageVerdicts, PentestError>;
   ```
   Checks: `version === 1`, `verdicts` is an array, each entry has all required fields,
   `verdict`/`severity` ∈ their enums. Invalid → `Err`.

4. **Thin activity** — `runTriageAgent(input): Promise<AgentMetrics>` in
   `apps/worker/src/temporal/activities.ts`: same shape as the other agent activities (heartbeat,
   error classification), delegating to `AgentExecutionService` (which runs any registered agent
   automatically). After the agent runs, read + `validateTriageVerdicts`; on `Err`/missing, log a
   warning and signal fail-open.

5. **Pipeline state** — add `triageRan?: boolean` to `PipelineState`
   (`apps/worker/src/temporal/shared.ts`): set `true` on valid verdicts, `false` on fail-open.

6. **Workflow registration** — `apps/worker/src/temporal/workflows.ts`: insert the triage phase
   between exploitation-complete and reporting, wrapped in a fail-open guard:
   ```
   try   { run triage agent; validate output; state.triageRan = true }
   catch / invalid { state.triageRan = false; log warning; continue to report }
   ```
   Runs sequentially after the exploit agents (no parallelism).

7. **Report consumes verdicts** — `apps/worker/prompts/report-executive.txt` +
   `apps/worker/src/services/reporting.ts`:
   - Add `triage_verdicts.json` to the report's input deliverables.
   - **Confirmed Findings** = PASS + DOWNGRADE (rendered at adjusted `severity`), sorted
     critical → info.
   - **Considered & Ruled Out (appendix)** = KILL (with `reason`) + CHAIN_REQUIRED (labeled
     "potential chain component — not standalone-exploitable").
   - **Banner is deterministic:** `reporting.ts` prepends the "⚠️ Triage did not run — findings are
     UNVALIDATED" banner whenever `triageRan === false` (not left to the LLM). The Confirmed/appendix
     *sectioning* is done by the report LLM guided by `triage_verdicts.json` (see Known limitation).

8. **save-deliverable** — `apps/worker/src/scripts/save-deliverable.ts`: add
   `TRIAGE_VERDICT → triage_verdicts.json` to `DELIVERABLE_FILENAMES`; add to the `reporting.ts`
   input list.

### Data flow

```
exploit evidence + queues → triage agent (LLM applies rubric)
  → triage_verdicts.json (validated)
  → report agent (Confirmed list + ruled-out appendix)  | or UNVALIDATED banner + all findings
```

## Error handling

- Triage agent uses Shannon's standard 3× per-agent retry.
- Persistent failure or invalid output → fail-open: `triageRan = false`, workflow proceeds, report
  shows the UNVALIDATED banner with all findings. The run is never failed by triage.

## Testing

- **Unit — `triage-validation`:** valid payload, wrong `version`, non-array `verdicts`, missing
  required field, out-of-enum `verdict`/`severity` (mirrors the queue-validation tests).
- **Unit — report bucketing** as a pure function over `TriageVerdict[]` → `{ confirmed[], appendix[],
  banner? }`: the four verdict buckets, severity sort, and the fail-open branch.
- **Integration (`--pipeline-testing`):** a fixture run with seeded evidence + a hand-authored
  `triage_verdicts.json` to verify Confirmed/appendix/banner rendering without a live LLM. (The
  LLM's judgment itself is not deterministically unit-testable; we test plumbing + validation +
  rendering.)
- Update `COVERAGE.md` / docs to note the triage phase.

## Scope / non-goals (v1)

- No CVSS vectors — coarse `severity` enum only (full CVSS = P5).
- No attack-chaining computation — `CHAIN_REQUIRED` is label-only (P4).
- No cross-run dedup engine — "not a duplicate" is an in-run LLM judgment, not a dedup system (P5).
- No UI changes.

## Known limitation (v1)

Confirmed/appendix *sectioning* is performed by the report LLM guided by `triage_verdicts.json`, so
in principle the LLM could misplace a finding. The verdicts JSON is the source of truth and is
itself a deliverable, so any misplacement is auditable. Fully deterministic rendering (assembling
sections directly from verdict records) is deferred to P5, which introduces structured findings
keyed by `id`. The UNVALIDATED banner is already deterministic.

## Defaults

- Severity enum: `critical | high | medium | low | info`.
- JSON verdict value `CHAIN_REQUIRED` (underscore); rendered label "potential chain component —
  not standalone-exploitable."
- `triage` `modelTier: large`.

## Review note

The rubric and fail-open behavior will be sanity-checked by **security-agent** during Phase 6
(code review).
