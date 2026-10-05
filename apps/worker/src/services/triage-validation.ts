// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Triage verdict schema + validator (mirrors queue-validation.ts: hand-rolled
 * shape checks returning Result<T, PentestError>, no extra deps).
 */

import { type FindingSeverity, SEVERITY_VALUES } from '../collectors/finding-collector.js';
import { ErrorCode } from '../types/errors.js';
import { err, isErr, ok, type Result } from '../types/result.js';
import { PentestError } from './error-handling.js';

export type Verdict = 'PASS' | 'DOWNGRADE' | 'KILL' | 'CHAIN_REQUIRED';
export type Severity = FindingSeverity;

export const VERDICTS: readonly Verdict[] = ['PASS', 'DOWNGRADE', 'KILL', 'CHAIN_REQUIRED'];
export const SEVERITIES: readonly Severity[] = SEVERITY_VALUES;

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
