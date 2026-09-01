// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Deterministic queue-JSON to findings-MD renderer.
 *
 * Used when safe demonstrations are disabled: the demonstration agents did not
 * run, so there is no
 * `*_exploitation_evidence.md` to concatenate into the report. This module
 * reads each `*_exploitation_queue.json` (already SDK-validated against the
 * schemas in ../ai/queue-schemas.ts) and writes a `*_findings.md` per class
 * in the canonical body shape that report-executive.txt's cleanup expects.
 *
 * No LLM in the loop — every field maps directly from a JSON key.
 */

import { fs, path } from 'zx';
import type { AuthFinding, AuthzFinding, InjectionFinding, SsrfFinding, XssFinding } from '../ai/queue-schemas.js';
import { deliverablesDir } from '../paths.js';
import type { ActivityLogger } from '../types/activity-logger.js';
import type { SourceMode, VulnClass } from '../types/config.js';

const SOURCE_ASSISTED_DISCLAIMER = [
  '> Safe-demonstration agents were not run for this assessment. Each entry',
  '> documents a candidate supported by the evidence collected during analysis;',
  '> live proof of impact is not included.',
].join('\n');

const URL_ONLY_DISCLAIMER = [
  '> Safe-demonstration agents were not run for this assessment. Each entry',
  '> documents a candidate identified through URL-only dynamic testing; code-level',
  '> coverage, source-location attribution, and live proof of impact are not included.',
].join('\n');

interface ClassConfig<T> {
  readonly heading: string;
  readonly noneFoundLabel: string;
  readonly queueFile: string;
  readonly findingsFile: string;
  readonly renderEntry: (entry: T, sourceMode: SourceMode) => string;
}

interface QueueDocument<T> {
  vulnerabilities?: T[];
}

// === Common Render Helpers ===

function summaryRow(label: string, value: string | undefined | null | boolean): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value === 'string' && value.trim() === '') return null;
  return `- **${label}:** ${value}`;
}

function formatSourceAssistedLocation(endpoint: string | undefined, codeLocation: string | undefined): string {
  if (endpoint && codeLocation) return `${endpoint} (${codeLocation})`;
  return endpoint ?? codeLocation ?? '';
}

function formatUrlOnlyLocation(endpoint: string | undefined): string {
  return endpoint ?? '';
}

function buildEntry(
  id: string,
  title: string,
  summaryRows: ReadonlyArray<string | null>,
  notes: string | undefined,
): string {
  const lines: string[] = [];
  lines.push(`### ${id}: ${title}`);
  lines.push('');
  lines.push('**Summary:**');
  for (const row of summaryRows) {
    if (row !== null) lines.push(row);
  }
  lines.push('');
  if (notes && notes.trim() !== '') {
    lines.push(`**Notes:** ${notes.trim()}`);
  }
  return lines.join('\n').trimEnd();
}

// === Per-Class Renderers ===

function renderAuthEntry(e: AuthFinding, sourceMode: SourceMode): string {
  const location =
    sourceMode === 'url-only'
      ? formatUrlOnlyLocation(e.source_endpoint)
      : formatSourceAssistedLocation(e.source_endpoint, e.vulnerable_code_location);
  return buildEntry(
    e.ID,
    e.vulnerability_type,
    [
      summaryRow('Vulnerable location', location),
      summaryRow('Overview', e.missing_defense),
      summaryRow('Impact', e.exploitation_hypothesis),
    ],
    e.notes,
  );
}

function renderSsrfEntry(e: SsrfFinding, sourceMode: SourceMode): string {
  const location =
    sourceMode === 'url-only'
      ? formatUrlOnlyLocation(e.source_endpoint)
      : formatSourceAssistedLocation(e.source_endpoint, e.vulnerable_code_location);
  return buildEntry(
    e.ID,
    e.vulnerability_type,
    [
      summaryRow('Vulnerable location', location),
      summaryRow('Overview', e.missing_defense),
      summaryRow('Impact', e.exploitation_hypothesis),
    ],
    e.notes,
  );
}

function renderAuthzEntry(e: AuthzFinding, sourceMode: SourceMode): string {
  const location =
    sourceMode === 'url-only'
      ? formatUrlOnlyLocation(e.endpoint)
      : formatSourceAssistedLocation(e.endpoint, e.vulnerable_code_location);
  return buildEntry(
    e.ID,
    e.vulnerability_type,
    [
      summaryRow('Vulnerable location', location),
      summaryRow('Overview', e.guard_evidence),
      summaryRow('Impact', e.side_effect),
    ],
    e.notes,
  );
}

function renderInjectionEntry(e: InjectionFinding, sourceMode: SourceMode): string {
  const location =
    sourceMode === 'url-only'
      ? e.path
      : e.path && e.sink_call
        ? `${e.sink_call} (path: ${e.path})`
        : (e.sink_call ?? e.path);
  return buildEntry(
    e.ID,
    e.vulnerability_type,
    [summaryRow('Vulnerable location', location), summaryRow('Overview', e.mismatch_reason)],
    e.notes,
  );
}

function renderXssEntry(e: XssFinding, sourceMode: SourceMode): string {
  const location =
    sourceMode === 'url-only'
      ? e.path
      : e.path && e.sink_function
        ? `${e.sink_function} (path: ${e.path})`
        : (e.sink_function ?? e.path);
  return buildEntry(
    e.ID,
    e.vulnerability_type,
    [summaryRow('Vulnerable location', location), summaryRow('Overview', e.mismatch_reason)],
    e.notes,
  );
}

// === Class Registry ===

const CLASSES: Record<VulnClass, ClassConfig<unknown>> = {
  auth: {
    heading: 'Authentication',
    noneFoundLabel: 'authentication',
    queueFile: 'auth_exploitation_queue.json',
    findingsFile: 'auth_findings.md',
    renderEntry: (e, sourceMode) => renderAuthEntry(e as AuthFinding, sourceMode),
  },
  authz: {
    heading: 'Authorization',
    noneFoundLabel: 'authorization',
    queueFile: 'authz_exploitation_queue.json',
    findingsFile: 'authz_findings.md',
    renderEntry: (e, sourceMode) => renderAuthzEntry(e as AuthzFinding, sourceMode),
  },
  injection: {
    heading: 'Injection',
    noneFoundLabel: 'injection',
    queueFile: 'injection_exploitation_queue.json',
    findingsFile: 'injection_findings.md',
    renderEntry: (e, sourceMode) => renderInjectionEntry(e as InjectionFinding, sourceMode),
  },
  xss: {
    heading: 'XSS',
    noneFoundLabel: 'XSS',
    queueFile: 'xss_exploitation_queue.json',
    findingsFile: 'xss_findings.md',
    renderEntry: (e, sourceMode) => renderXssEntry(e as XssFinding, sourceMode),
  },
  ssrf: {
    heading: 'SSRF',
    noneFoundLabel: 'SSRF',
    queueFile: 'ssrf_exploitation_queue.json',
    findingsFile: 'ssrf_findings.md',
    renderEntry: (e, sourceMode) => renderSsrfEntry(e as SsrfFinding, sourceMode),
  },
};

// === Class File Assembly ===

function renderClassFile(config: ClassConfig<unknown>, entries: readonly unknown[], sourceMode: SourceMode): string {
  const sections: string[] = [];
  sections.push(`# ${config.heading} Findings`);
  sections.push('');
  sections.push(sourceMode === 'url-only' ? URL_ONLY_DISCLAIMER : SOURCE_ASSISTED_DISCLAIMER);
  sections.push('');
  sections.push('## Identified Vulnerabilities');
  sections.push('');
  if (entries.length === 0) {
    sections.push(`No ${config.noneFoundLabel} vulnerabilities were identified.`);
    sections.push('');
  } else {
    for (const entry of entries) {
      sections.push(config.renderEntry(entry, sourceMode));
      sections.push('');
    }
  }
  return `${sections.join('\n').trimEnd()}\n`;
}

// === Public Entry Point ===

/**
 * Render `*_findings.md` per class from each `*_exploitation_queue.json`.
 *
 * Idempotent: skips classes whose findings file already exists, or whose queue
 * is missing (class out of scope this run). Per-class failures are logged and
 * other classes still proceed.
 */
export async function renderFindingsFromQueues(
  sourceDir: string,
  deliverablesSubdir: string | undefined,
  logger: ActivityLogger,
  sourceMode: SourceMode = 'source-assisted',
): Promise<void> {
  const dir = deliverablesDir(sourceDir, deliverablesSubdir);

  for (const config of Object.values(CLASSES)) {
    const queuePath = path.join(dir, config.queueFile);
    const findingsPath = path.join(dir, config.findingsFile);

    if (await fs.pathExists(findingsPath)) {
      logger.info(`${config.heading}: ${config.findingsFile} already exists, skipping`);
      continue;
    }
    if (!(await fs.pathExists(queuePath))) {
      logger.info(`${config.heading}: no queue file (class out of scope), skipping`);
      continue;
    }

    try {
      const doc = (await fs.readJson(queuePath)) as QueueDocument<unknown>;
      const entries = doc.vulnerabilities ?? [];
      const markdown = renderClassFile(config, entries, sourceMode);
      await fs.writeFile(findingsPath, markdown);
      logger.info(`${config.heading}: rendered ${entries.length} finding(s) to ${config.findingsFile}`);
    } catch (error) {
      const err = error as Error;
      logger.warn(`${config.heading}: failed to render findings from ${config.queueFile}: ${err.message}`);
    }
  }
}
