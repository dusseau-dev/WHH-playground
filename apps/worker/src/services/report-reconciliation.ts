// Copyright (C) 2025 Keygraph, Inc.

import type { AddFindingInput, FindingSeverity } from '../collectors/finding-collector.js';
import { isErr } from '../types/result.js';
import { type TriageVerdict, type TriageVerdicts, validateTriageVerdicts } from './triage-validation.js';

export type TriageStatus = 'validated' | 'unvalidated';

export interface RuledOutFinding {
  readonly finding_id: string;
  readonly title: string;
  readonly category: string;
  readonly severity: FindingSeverity;
  readonly verdict: 'KILL' | 'CHAIN_REQUIRED';
  readonly reason: string;
  readonly original_severity?: FindingSeverity;
}

export interface ReconciledReportFindings {
  readonly findings: AddFindingInput[];
  readonly ruled_out: RuledOutFinding[];
  readonly triage_status: TriageStatus;
  readonly validation_issues: string[];
}

export interface ReconciliationOptions {
  /** Whether the triage activity ran in this execution. A stale file is not authoritative. */
  readonly triageRan: boolean;
  /** Exact IDs emitted by the candidate queues, when available. */
  readonly knownFindingIds?: readonly string[];
}

function countIds(values: readonly string[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const value of values) counts.set(value, (counts.get(value) ?? 0) + 1);
  return counts;
}

function duplicateIds(values: readonly string[]): string[] {
  return [...countIds(values).entries()]
    .filter(([, count]) => count > 1)
    .map(([id]) => id)
    .sort();
}

function unvalidatedFinding(finding: AddFindingInput, reason: string): AddFindingInput {
  return {
    ...finding,
    triage: { validation_state: 'unvalidated', reason },
  };
}

function allUnvalidated(findings: readonly AddFindingInput[], issue: string): ReconciledReportFindings {
  return {
    findings: findings.map((finding) => unvalidatedFinding(finding, issue)),
    ruled_out: [],
    triage_status: 'unvalidated',
    validation_issues: [issue],
  };
}

function ruledOutFromVerdict(verdict: TriageVerdict, finding?: AddFindingInput): RuledOutFinding {
  return {
    finding_id: verdict.id,
    title: finding?.title ?? verdict.title,
    category: finding?.category ?? verdict.vulnType,
    severity: verdict.severity,
    verdict: verdict.verdict as 'KILL' | 'CHAIN_REQUIRED',
    reason: verdict.reason,
    ...((verdict.claimedSeverity ?? finding?.severity) !== undefined && {
      original_severity: (verdict.claimedSeverity ?? finding?.severity) as FindingSeverity,
    }),
  };
}

/**
 * Reconcile report-agent prose with the triage gate without ever hiding a human-visible candidate
 * when the join is missing or ambiguous. IDs are exact and are never normalized.
 */
export function reconcileReportFindings(
  findings: readonly AddFindingInput[],
  triage: TriageVerdicts | unknown | null,
  options: ReconciliationOptions,
): ReconciledReportFindings {
  if (findings.length === 0 && (options.knownFindingIds?.length ?? 0) === 0) {
    return { findings: [], ruled_out: [], triage_status: 'validated', validation_issues: [] };
  }
  if (!options.triageRan) {
    return allUnvalidated(findings, 'Triage gate did not run; report findings are unvalidated.');
  }
  if (triage === null || triage === undefined) {
    return allUnvalidated(findings, 'Triage output is missing; report findings are unvalidated.');
  }

  const validated = validateTriageVerdicts(triage);
  if (isErr(validated)) {
    return allUnvalidated(findings, `Triage output is invalid: ${validated.error.message}`);
  }

  const verdicts = validated.value.verdicts;
  const duplicateFindingIds = new Set(duplicateIds(findings.map((finding) => finding.finding_id)));
  const duplicateVerdictIds = new Set(duplicateIds(verdicts.map((verdict) => verdict.id)));
  const knownIds = options.knownFindingIds ? new Set(options.knownFindingIds) : undefined;
  const findingIds = new Set(findings.map((finding) => finding.finding_id));
  const uniqueVerdicts = new Map<string, TriageVerdict>();
  for (const verdict of verdicts) {
    if (!duplicateVerdictIds.has(verdict.id)) uniqueVerdicts.set(verdict.id, verdict);
  }

  const issues: string[] = [];
  if (duplicateFindingIds.size > 0) {
    issues.push(`Duplicate report finding IDs: ${[...duplicateFindingIds].join(', ')}`);
  }
  if (duplicateVerdictIds.size > 0) {
    issues.push(`Duplicate triage verdict IDs: ${[...duplicateVerdictIds].join(', ')}`);
  }

  const unknownIds = knownIds ? [...findingIds].filter((id) => !knownIds.has(id)).sort() : [];
  if (unknownIds.length > 0) issues.push(`Unknown report finding IDs: ${unknownIds.join(', ')}`);

  const missingIds = [...findingIds]
    .filter((id) => !duplicateFindingIds.has(id) && !duplicateVerdictIds.has(id) && !uniqueVerdicts.has(id))
    .sort();
  if (missingIds.length > 0) issues.push(`Missing triage verdicts for report finding IDs: ${missingIds.join(', ')}`);

  const confirmed: AddFindingInput[] = [];
  const ruledOut: RuledOutFinding[] = [];
  for (const finding of findings) {
    const id = finding.finding_id;
    const affected: string[] = [];
    if (duplicateFindingIds.has(id)) affected.push('duplicate report finding ID');
    if (duplicateVerdictIds.has(id)) affected.push('duplicate triage verdict ID');
    if (knownIds && !knownIds.has(id)) affected.push('unknown report finding ID');
    const verdict = uniqueVerdicts.get(id);
    if (!verdict) affected.push('missing unambiguous triage verdict');

    if (affected.length > 0) {
      confirmed.push(unvalidatedFinding(finding, affected.join('; ')));
      continue;
    }

    if (!verdict) continue;

    if (verdict.verdict === 'KILL' || verdict.verdict === 'CHAIN_REQUIRED') {
      ruledOut.push(ruledOutFromVerdict(verdict, finding));
      continue;
    }

    const originalSeverity = verdict.claimedSeverity ?? finding.severity;
    confirmed.push({
      ...finding,
      severity: verdict.severity,
      ...(verdict.verdict === 'DOWNGRADE' && { original_severity: originalSeverity }),
      triage: {
        validation_state: 'validated',
        verdict: verdict.verdict,
        reason: verdict.reason,
      },
    });
  }

  // A filtered PASS/DOWNGRADE is intentionally absent. Extra negative verdicts remain useful in
  // the appendix, provided their IDs are unambiguous.
  for (const verdict of verdicts) {
    if (
      !findingIds.has(verdict.id) &&
      !duplicateVerdictIds.has(verdict.id) &&
      (verdict.verdict === 'KILL' || verdict.verdict === 'CHAIN_REQUIRED')
    ) {
      ruledOut.push(ruledOutFromVerdict(verdict));
    }
  }

  ruledOut.sort((a, b) => a.finding_id.localeCompare(b.finding_id) || a.verdict.localeCompare(b.verdict));
  return {
    findings: confirmed,
    ruled_out: ruledOut,
    triage_status: issues.length === 0 ? 'validated' : 'unvalidated',
    validation_issues: issues,
  };
}
