// Copyright (C) 2025 Keygraph, Inc.

import type {
  AddFindingInput,
  AdditionalSection,
  FindingSeverity,
  StepItem,
  StructuredStep,
} from '../collectors/finding-collector.js';
import { ALL_VULN_CLASSES, type SourceMode, type VulnClass } from '../types/config.js';
import type { RuledOutFinding, TriageStatus } from './report-reconciliation.js';

export interface ReportMeta {
  readonly target: string;
  readonly assessment_date: string;
  readonly scope: string;
  readonly executive_summary: string;
  readonly safe_demonstration: boolean;
  readonly model?: string;
  readonly source_mode: SourceMode;
  readonly validation_state: TriageStatus;
}

export interface ReportData {
  readonly report_meta: ReportMeta;
  readonly findings: readonly AddFindingInput[];
  readonly ruled_out: readonly RuledOutFinding[];
  readonly not_assessed: readonly VulnClass[];
  readonly triage_status: TriageStatus;
  readonly validation_issues?: readonly string[];
}

const SEVERITY_ORDER: Record<FindingSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const NOT_ASSESSED_LABELS: Record<VulnClass, string> = {
  injection: 'SQL/Command Injection',
  xss: 'Cross-Site Scripting (XSS)',
  auth: 'Authentication',
  authz: 'Authorization',
  ssrf: 'Server-Side Request Forgery (SSRF)',
};

const MODE_COVERAGE: Record<SourceMode, string> = {
  'source-assisted':
    'Source code and the live target were available. Code locations are shown only when joined from an exact vulnerability-queue finding ID.',
  'url-only':
    'Assessment was limited to the live target. Source code, repository paths, and code-location attribution were not assessed.',
};

const ANALYSIS_ONLY_DISCLAIMER = [
  '> Exploitation was not run for this assessment. Findings were identified through analysis;',
  '> impact is assessed rather than demonstrated, and no live exploitation steps or proof of',
  '> impact are presented.',
].join('\n');

function titleCase(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

/** Escape agent-authored inline text so it cannot change the Markdown structure. */
export function escapeMarkdown(value: string): string {
  return value
    .replace(/\r?\n/g, ' ')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/([\\`*_[\]{}()#+\-.!|])/g, '\\$1');
}

function renderCodeBlock(language: string, content: string): string {
  const longest = Math.max(0, ...[...content.matchAll(/`+/g)].map((match) => match[0].length));
  const fence = '`'.repeat(Math.max(3, longest + 1));
  return `${fence}${language.replace(/[^a-zA-Z0-9_+-]/g, '')}\n${content}\n${fence}`;
}

function renderStepItem(item: StepItem): string {
  return item.kind === 'prose' ? escapeMarkdown(item.text) : renderCodeBlock(item.block.language, item.block.content);
}

function renderStepItems(items: readonly StepItem[]): string {
  return items.map(renderStepItem).join('\n\n');
}

function renderStructuredStep(step: StructuredStep, index: number): string {
  const title = step.title ? `: ${escapeMarkdown(step.title)}` : '';
  return `**Step ${index + 1}${title}**\n\n${renderStepItems(step.items)}`;
}

function renderAdditionalSection(section: AdditionalSection): string {
  return `#### ${escapeMarkdown(section.heading)}\n\n${renderStepItems(section.items)}`;
}

function compareFindings(a: AddFindingInput, b: AddFindingInput): number {
  return (
    SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
    a.finding_id.localeCompare(b.finding_id) ||
    a.title.localeCompare(b.title)
  );
}

function renderFinding(finding: AddFindingInput, meta: ReportMeta): string {
  const lines: string[] = [`### ${escapeMarkdown(finding.finding_id)}: ${escapeMarkdown(finding.title)}`, ''];
  lines.push('**Summary:**');
  const original =
    finding.original_severity && finding.original_severity !== finding.severity
      ? ` (downgraded from ${titleCase(finding.original_severity)})`
      : '';
  lines.push(`- **Severity:** ${titleCase(finding.severity)}${original}`);
  if (finding.confidence) lines.push(`- **Confidence:** ${titleCase(finding.confidence)}`);
  lines.push(`- **OWASP:** ${escapeMarkdown(finding.owasp_category)}`);
  lines.push(`- **Vulnerable location:** ${escapeMarkdown(finding.vulnerable_location)}`);
  if (finding.http_location) {
    const parameter = finding.http_location.parameter
      ? ` (parameter: ${escapeMarkdown(finding.http_location.parameter)})`
      : '';
    lines.push(
      `- **HTTP location:** ${escapeMarkdown(finding.http_location.method.toUpperCase())} ${escapeMarkdown(finding.http_location.url)}${parameter}`,
    );
  }
  if (meta.source_mode === 'source-assisted' && finding.code_locations?.length) {
    const locations = [...finding.code_locations].sort(
      (a, b) =>
        a.file.localeCompare(b.file) || (a.start_line ?? 0) - (b.start_line ?? 0) || a.role.localeCompare(b.role),
    );
    for (const location of locations) {
      const range = location.start_line
        ? `:${location.start_line}${location.end_line && location.end_line !== location.start_line ? `-${location.end_line}` : ''}`
        : '';
      const symbol = location.symbol ? ` (${escapeMarkdown(location.symbol)})` : '';
      lines.push(`- **Code location (${location.role}):** ${escapeMarkdown(location.file)}${range}${symbol}`);
    }
  }
  if (finding.triage) {
    const verdict = finding.triage.verdict ? ` — ${finding.triage.verdict}` : '';
    lines.push(
      `- **Triage:** ${finding.triage.validation_state === 'validated' ? 'Validated' : 'UNVALIDATED'}${verdict}`,
    );
    if (finding.triage.reason) lines.push(`- **Triage reason:** ${escapeMarkdown(finding.triage.reason)}`);
  }
  if (finding.auth_state) lines.push(`- **Auth state:** ${escapeMarkdown(finding.auth_state)}`);
  if (meta.safe_demonstration && finding.status) lines.push(`- **Status:** ${titleCase(finding.status)}`);
  if (finding.prerequisites) lines.push(`- **Prerequisites:** ${escapeMarkdown(finding.prerequisites)}`);

  lines.push(
    '',
    '**Overview:**',
    escapeMarkdown(finding.overview),
    '',
    '**Impact:**',
    escapeMarkdown(finding.impact),
    '',
  );
  if (meta.safe_demonstration && finding.exploitation_steps?.length) {
    lines.push('**Exploitation Steps:**', '');
    finding.exploitation_steps.forEach((step, index) => {
      lines.push(renderStructuredStep(step, index), '');
    });
  }
  if (meta.safe_demonstration && finding.proof_of_impact?.length) {
    lines.push('**Proof of Impact:**', '', renderStepItems(finding.proof_of_impact), '');
  }
  lines.push('**Remediation:**', escapeMarkdown(finding.remediation), '');
  if (finding.notes?.length) lines.push('**Notes:**', '', renderStepItems(finding.notes), '');
  for (const section of finding.additional_sections ?? []) lines.push(renderAdditionalSection(section), '');
  return lines.join('\n').trimEnd();
}

function renderValidation(data: ReportData): string {
  if (data.triage_status === 'validated' && data.report_meta.validation_state === 'validated') {
    return '> **VALIDATED:** Confirmed findings were reconciled with an unambiguous triage verdict.';
  }
  const lines = [
    '> ## ⚠️ UNVALIDATED REPORT FINDINGS',
    '>',
    '> One or more findings could not be reconciled unambiguously. They remain visible as candidates and require human review.',
  ];
  if (data.validation_issues?.length) {
    lines.push('', '**Validation issues:**', '');
    for (const issue of [...data.validation_issues].sort()) lines.push(`- ${escapeMarkdown(issue)}`);
  }
  return lines.join('\n');
}

function renderNotAssessed(classes: readonly VulnClass[]): string {
  const unique = ALL_VULN_CLASSES.filter((item) => classes.includes(item));
  return [
    '## Not Assessed',
    '',
    'The following vulnerability classes did not complete. Absence of findings in these classes is not a clean result:',
    '',
    ...unique.map((item) => `- ${NOT_ASSESSED_LABELS[item]} — not assessed.`),
  ].join('\n');
}

function renderRuledOut(entries: readonly RuledOutFinding[]): string {
  const lines = ['## Considered & Ruled Out', ''];
  if (entries.length === 0) return [...lines, '_Nothing was ruled out._'].join('\n');
  lines.push('| ID | Type | Finding | Outcome | Reason |', '| --- | --- | --- | --- | --- |');
  for (const entry of [...entries].sort((a, b) => a.finding_id.localeCompare(b.finding_id))) {
    const outcome = entry.verdict === 'CHAIN_REQUIRED' ? 'Chain required; not standalone-exploitable' : 'Ruled out';
    lines.push(
      `| ${escapeMarkdown(entry.finding_id)} | ${escapeMarkdown(entry.category)} | ${escapeMarkdown(entry.title)} | ${outcome} | ${escapeMarkdown(entry.reason)} |`,
    );
  }
  return lines.join('\n');
}

/** Deterministically render the canonical report model. */
export function renderReport(data: ReportData): string {
  const meta = data.report_meta;
  const sections: string[] = [
    '# Security Assessment Report',
    '',
    '## Executive Summary',
    `- Target: ${escapeMarkdown(meta.target)}`,
    `- Assessment Date: ${escapeMarkdown(meta.assessment_date)}`,
    `- Scope: ${escapeMarkdown(meta.scope)}`,
    `- Safe Demonstration: ${meta.safe_demonstration ? 'enabled' : 'disabled'}`,
    ...(meta.model ? [`- Model: ${escapeMarkdown(meta.model)}`] : []),
    `- Validation: ${data.triage_status === 'validated' ? 'Validated' : 'UNVALIDATED'}`,
    '',
    escapeMarkdown(meta.executive_summary),
    '',
    '## Mode',
    '',
    meta.source_mode === 'url-only' ? 'URL-Only' : 'Source-Assisted',
    '',
    '## Coverage',
    '',
    MODE_COVERAGE[meta.source_mode],
    '',
    renderValidation(data),
  ];

  if (!meta.safe_demonstration) sections.push('', ANALYSIS_ONLY_DISCLAIMER);
  if (data.not_assessed.length > 0) sections.push('', renderNotAssessed(data.not_assessed));

  sections.push('', '## Confirmed Findings', '');
  const sortedFindings = [...data.findings].sort(compareFindings);
  if (sortedFindings.length === 0) {
    sections.push('_No findings passed triage validation._');
  } else {
    for (const finding of sortedFindings) sections.push(renderFinding(finding, meta), '');
  }
  sections.push(renderRuledOut(data.ruled_out));
  return `${sections.join('\n').trimEnd()}\n`;
}
