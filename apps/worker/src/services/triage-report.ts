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
import { deliverablesDir } from '../paths.js';
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
  return s
    .replace(/[`<>]/g, (c) => (c === '`' ? '\\`' : c === '<' ? '&lt;' : '&gt;'))
    .replace(/\|/g, '\\|')
    .replace(/\r?\n/g, ' ');
}

/**
 * Load + validate triage_verdicts.json. Returns null (fail-open) if missing/invalid.
 * Resolves the deliverables directory the same way assembleFinalReport does, so the
 * verdicts file is read from wherever the evidence files live.
 */
export async function loadVerdicts(
  sourceDir: string,
  deliverablesSubdir: string | undefined,
  logger: ActivityLogger,
): Promise<TriageVerdicts | null> {
  const file = path.join(deliverablesDir(sourceDir, deliverablesSubdir), 'triage_verdicts.json');
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
export function renderVerdictSections(verdicts: TriageVerdicts | null, triageRan: boolean): string {
  // Banner if the gate did not run this execution (authoritative) OR verdicts are missing/invalid (fail-open guard).
  if (!triageRan || verdicts === null) return UNVALIDATED_BANNER;

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
