#!/usr/bin/env node

// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Standalone smoke for the triage → report rendering path (the repo has no test
 * runner). Seeds a temp deliverables dir, runs assembleFinalReport, and asserts the
 * Confirmed/ruled-out tables and the fail-open UNVALIDATED banner. Also exercises the
 * pure renderVerdictSections/validateTriageVerdicts helpers where a temp dir isn't
 * needed. Run after build:
 *   pnpm --filter @shannon/worker build && node apps/worker/dist/scripts/verify-triage.js
 */

import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { assembleFinalReport } from '../services/reporting.js';
import { renderVerdictSections } from '../services/triage-report.js';
import { type TriageVerdicts, validateTriageVerdicts } from '../services/triage-validation.js';

const logger = { info: () => {}, warn: () => {}, error: () => {} };
const failures: string[] = [];
function assert(cond: boolean, msg: string): void {
  if (!cond) failures.push(msg);
}

/** Validate a raw object and return the parsed verdicts, or record a failure and return null. */
function parse(raw: unknown, label: string): TriageVerdicts | null {
  const result = validateTriageVerdicts(raw);
  if (result.ok) return result.value;
  failures.push(`${label}: verdicts failed validation (${result.error.message})`);
  return null;
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
        {
          id: 'injection-1',
          vulnType: 'injection',
          title: 'SQLi in /login',
          verdict: 'PASS',
          severity: 'high',
          reason: 'Dumped users table.',
          evidenceFile: 'injection_exploitation_evidence.md',
        },
        {
          id: 'xss-1',
          vulnType: 'xss',
          title: 'Reflected XSS',
          verdict: 'KILL',
          severity: 'info',
          reason: 'Output encoded; not exploitable.',
          evidenceFile: 'xss_exploitation_evidence.md',
        },
      ],
    }),
  );
  const report1 = await assembleFinalReport(root1, undefined, logger, true);
  assert(report1.includes('## Confirmed Findings'), 'case1: missing Confirmed section');
  assert(report1.includes('SQLi in /login'), 'case1: missing PASS finding');
  assert(report1.includes('## Considered & Ruled Out'), 'case1: missing ruled-out section');
  assert(report1.includes('Reflected XSS'), 'case1: missing KILL finding in appendix');
  assert(!report1.includes('UNVALIDATED'), 'case1: banner shown despite valid verdicts');

  // Case 2: no verdicts file → fail-open UNVALIDATED banner.
  const root2 = seed();
  const report2 = await assembleFinalReport(root2, undefined, logger, true);
  assert(report2.includes('UNVALIDATED'), 'case2: missing UNVALIDATED banner');

  // Case 3: invalid verdicts (bad enum) → fail-open banner.
  const root3 = seed();
  writeFileSync(
    join(root3, '.shannon', 'deliverables', 'triage_verdicts.json'),
    JSON.stringify({
      version: 1,
      verdicts: [
        { id: 'x', vulnType: 'xss', title: 't', verdict: 'NOPE', severity: 'high', reason: 'r', evidenceFile: 'f.md' },
      ],
    }),
  );
  const report3 = await assembleFinalReport(root3, undefined, logger, true);
  assert(report3.includes('UNVALIDATED'), 'case3: invalid verdicts did not fail open to banner');

  // Case 4: DOWNGRADE label — renders "(was <sev>)" in the Confirmed table. Pure function.
  const downgrade = parse(
    {
      version: 1,
      verdicts: [
        {
          id: 'authz-1',
          vulnType: 'authz',
          title: 'IDOR on /orders',
          verdict: 'DOWNGRADE',
          severity: 'medium',
          claimedSeverity: 'high',
          reason: 'Real but limited blast radius.',
          evidenceFile: 'authz_exploitation_evidence.md',
        },
      ],
    },
    'case4',
  );
  if (downgrade) {
    const rendered4 = renderVerdictSections(downgrade, true);
    assert(rendered4.includes('IDOR on /orders'), 'case4: missing DOWNGRADE finding in Confirmed table');
    assert(rendered4.includes('(was high)'), 'case4: missing "(was high)" downgrade label');
  }

  // Case 5: CHAIN_REQUIRED label — renders in the appendix as a "potential chain component". Pure function.
  const chain = parse(
    {
      version: 1,
      verdicts: [
        {
          id: 'ssrf-1',
          vulnType: 'ssrf',
          title: 'Blind SSRF to metadata',
          verdict: 'CHAIN_REQUIRED',
          severity: 'low',
          reason: 'Only useful chained with credential exfil.',
          evidenceFile: 'ssrf_exploitation_evidence.md',
        },
      ],
    },
    'case5',
  );
  if (chain) {
    const rendered5 = renderVerdictSections(chain, true);
    assert(rendered5.includes('Blind SSRF to metadata'), 'case5: missing CHAIN_REQUIRED finding in appendix');
    assert(rendered5.includes('potential chain component'), 'case5: missing "potential chain component" label');
  }

  // Case 6: empty verdicts with triageRan=true → both section headers, NO banner. Pure function.
  const empty = parse({ version: 1, verdicts: [] }, 'case6');
  if (empty) {
    const rendered6 = renderVerdictSections(empty, true);
    assert(rendered6.includes('## Confirmed Findings'), 'case6: missing Confirmed header for empty verdicts');
    assert(rendered6.includes('## Considered & Ruled Out'), 'case6: missing ruled-out header for empty verdicts');
    assert(!rendered6.includes('UNVALIDATED'), 'case6: banner shown for empty-but-valid verdicts');
  }

  // Case 7 (F1 stale-file): a VALID verdicts file is on disk, but the gate did NOT run this
  // execution (triageRan=false). The banner must honor the run's gate outcome, not just disk state.
  const root7 = seed();
  writeFileSync(
    join(root7, '.shannon', 'deliverables', 'triage_verdicts.json'),
    JSON.stringify({
      version: 1,
      verdicts: [
        {
          id: 'injection-1',
          vulnType: 'injection',
          title: 'SQLi in /login',
          verdict: 'PASS',
          severity: 'high',
          reason: 'Dumped users table.',
          evidenceFile: 'injection_exploitation_evidence.md',
        },
      ],
    }),
  );
  const report7 = await assembleFinalReport(root7, undefined, logger, false);
  assert(report7.includes('UNVALIDATED'), 'case7: stale valid verdicts on disk but triageRan=false must show banner');

  if (failures.length > 0) {
    console.error(`TRIAGE SMOKE FAILED:\n${failures.map((f) => `  - ${f}`).join('\n')}`);
    process.exit(1);
  }
  console.log('TRIAGE SMOKE PASSED (7 cases)');
}

main().catch((e) => {
  console.error('TRIAGE SMOKE ERROR:', e);
  process.exit(1);
});
