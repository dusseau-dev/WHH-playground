// Copyright (C) 2025 Keygraph, Inc.

/** Deterministic canonical report.json to SARIF 2.1.0 rendering. */

import { createHash } from 'node:crypto';
import path from 'node:path';
import type { AddFindingInput, CodeLocation } from '../collectors/finding-collector.js';
import type { ReportData } from './report-renderer.js';

export interface SarifOptions {
  readonly workspaceName: string;
}

interface SarifRule {
  readonly id: string;
  readonly name: string;
  readonly shortDescription: { readonly text: string };
  readonly fullDescription: { readonly text: string };
  readonly help: { readonly text: string };
  readonly properties: { readonly tags: readonly string[] };
}

type FindingCategory = AddFindingInput['category'];

const TOOL_NAME = 'Shannon';
const TOOL_URI = 'https://github.com/KeygraphHQ/shannon';
const OWASP_TAXONOMY_NAME = 'OWASP Top Ten 2025';

const RULES: Readonly<Record<FindingCategory, SarifRule>> = {
  Injection: rule('shannon/injection', 'Injection', 'Separate untrusted data from interpreter syntax at every sink.'),
  XSS: rule('shannon/xss', 'Cross-Site Scripting', 'Encode untrusted output for its browser context.'),
  Authentication: rule('shannon/auth', 'Authentication', 'Harden credential verification and session lifecycle.'),
  Authorization: rule(
    'shannon/authz',
    'Authorization',
    'Enforce server-side ownership and role checks for every resource.',
  ),
  SSRF: rule('shannon/ssrf', 'Server-Side Request Forgery', 'Allowlist destinations and block private network ranges.'),
};

const CATEGORY_ORDER: readonly FindingCategory[] = ['Injection', 'XSS', 'Authentication', 'Authorization', 'SSRF'];

function rule(id: string, name: string, help: string): SarifRule {
  return {
    id,
    name,
    shortDescription: { text: name },
    fullDescription: { text: `${name} vulnerability identified by Shannon.` },
    help: { text: help },
    properties: { tags: ['security', 'shannon'] },
  };
}

function severityToLevel(severity: string): 'error' | 'warning' | 'note' {
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium') return 'warning';
  return 'note';
}

/** Only repository-relative paths are allowed into source locations. */
export function normalizeSarifSourcePath(file: string): string | null {
  if (!file || file.includes('\0') || /^[a-zA-Z]:[\\/]/.test(file) || file.startsWith('/') || file.startsWith('\\')) {
    return null;
  }
  const slashPath = file.replaceAll('\\', '/');
  if (slashPath.split('/').includes('..')) return null;
  const normalized = path.posix.normalize(slashPath).replace(/^\.\//, '');
  if (!normalized || normalized === '.' || normalized === '..' || normalized.startsWith('../')) return null;
  return normalized;
}

function safeCodeLocation(location: CodeLocation): (CodeLocation & { readonly file: string }) | null {
  const file = normalizeSarifSourcePath(location.file);
  if (!file) return null;
  if (location.start_line !== undefined && location.start_line !== null && location.start_line < 1) return null;
  if (location.end_line !== undefined && location.end_line !== null && location.end_line < 1) return null;
  return { ...location, file };
}

function toSarifLocation(location: CodeLocation & { readonly file: string }) {
  const region: Record<string, number> = {};
  if (location.start_line) region.startLine = location.start_line;
  if (location.end_line) region.endLine = location.end_line;
  return {
    physicalLocation: {
      artifactLocation: { uri: location.file },
      ...(Object.keys(region).length > 0 && { region }),
    },
    ...(location.symbol && { logicalLocations: [{ name: location.symbol, kind: 'function' }] }),
    message: { text: location.role },
  };
}

function safeHttpUrl(finding: AddFindingInput): URL | null {
  if (!finding.http_location) return null;
  try {
    const url = new URL(finding.http_location.url);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    url.username = '';
    url.password = '';
    // Evidence identifies the endpoint and parameter separately; query values may contain secrets.
    url.search = '';
    url.hash = '';
    return url;
  } catch {
    return null;
  }
}

function httpFallback(finding: AddFindingInput, url: URL | null) {
  if (!finding.http_location || !url) return null;
  return {
    physicalLocation: { artifactLocation: { uri: url.href } },
    message: { text: `${finding.http_location.method.toUpperCase()} ${url.href}` },
  };
}

function splitOwaspCategory(label: string): { readonly id: string; readonly name: string } {
  const [id, , ...nameParts] = label.split(' ');
  return { id: id ?? label, name: nameParts.join(' ') };
}

function fingerprint(ruleId: string, findingId: string): string {
  return createHash('sha256').update(`${ruleId}\0${findingId}`).digest('hex');
}

function renderFinding(finding: AddFindingInput, ruleId: string): Record<string, unknown> | null {
  const safeLocations = (finding.code_locations ?? []).flatMap((location) => {
    const safe = safeCodeLocation(location);
    return safe ? [safe] : [];
  });
  const primary = safeLocations.find((location) => location.role === 'sink') ?? safeLocations[0];
  const httpUrl = safeHttpUrl(finding);
  const fallback = primary ? null : httpFallback(finding, httpUrl);
  if (!primary && !fallback) return null;

  const related = primary ? safeLocations.filter((location) => location !== primary) : safeLocations;
  const owasp = splitOwaspCategory(finding.owasp_category);
  return {
    ruleId,
    level: severityToLevel(finding.severity),
    message: {
      text: `${finding.title}. ${finding.overview}`,
      markdown: [
        `**${finding.title}**`,
        '',
        finding.overview,
        '',
        '**Impact**',
        '',
        finding.impact,
        '',
        '**Remediation**',
        '',
        finding.remediation,
        '',
        'Full evidence: `Security-Assessment-Report.md`',
      ].join('\n'),
    },
    locations: [primary ? toSarifLocation(primary) : fallback],
    ...(related.length > 0 && {
      relatedLocations: related.map((location, index) => ({ id: index + 1, ...toSarifLocation(location) })),
    }),
    ...(finding.http_location &&
      httpUrl && {
        webRequest: { method: finding.http_location.method.toUpperCase(), target: httpUrl.href },
      }),
    taxa: [{ id: owasp.id, toolComponent: { name: OWASP_TAXONOMY_NAME } }],
    partialFingerprints: { 'shannon/finding-id/v1': fingerprint(ruleId, finding.finding_id) },
    properties: {
      findingId: finding.finding_id,
      ...(finding.original_severity && { originalSeverity: finding.original_severity }),
      ...(finding.triage?.verdict && { triageVerdict: finding.triage.verdict }),
      ...(finding.http_location?.parameter && { parameter: finding.http_location.parameter }),
    },
  };
}

/** Render SARIF. Callers own eligibility gating; locationless findings are intentionally omitted. */
export function renderSarif(data: ReportData, options: SarifOptions): string {
  const sorted = [...data.findings].sort(
    (a, b) =>
      CATEGORY_ORDER.indexOf(a.category) - CATEGORY_ORDER.indexOf(b.category) ||
      a.finding_id.localeCompare(b.finding_id),
  );
  const rendered = sorted.flatMap((finding) => {
    const ruleDefinition = RULES[finding.category];
    const result = renderFinding(finding, ruleDefinition.id);
    return result ? [{ category: finding.category, owasp: splitOwaspCategory(finding.owasp_category), result }] : [];
  });
  const usedCategories = CATEGORY_ORDER.filter((category) => rendered.some((entry) => entry.category === category));
  const rules = usedCategories.map((category) => RULES[category]);
  const results = usedCategories.flatMap((category, ruleIndex) =>
    rendered.filter((entry) => entry.category === category).map((entry) => ({ ...entry.result, ruleIndex })),
  );
  const taxa = [...new Map(rendered.map((entry) => [entry.owasp.id, entry.owasp])).values()].sort((a, b) =>
    a.id.localeCompare(b.id),
  );
  const workspaceName = options.workspaceName.replace(/[^a-zA-Z0-9._-]/g, '_');

  const log = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: TOOL_NAME, informationUri: TOOL_URI, rules } },
        automationDetails: { id: `shannon/safe-demonstration/${workspaceName}` },
        invocations: [{ executionSuccessful: data.not_assessed.length === 0 }],
        ...(taxa.length > 0 && {
          taxonomies: [
            {
              name: OWASP_TAXONOMY_NAME,
              organization: 'OWASP',
              informationUri: 'https://owasp.org/Top10/',
              shortDescription: { text: 'OWASP Top Ten 2025 categories.' },
              taxa,
            },
          ],
        }),
        results,
        properties: {
          target: data.report_meta.target,
          assessmentDate: data.report_meta.assessment_date,
          sourceMode: data.report_meta.source_mode,
          notAssessed: [...data.not_assessed],
        },
      },
    ],
  };
  return `${JSON.stringify(log, null, 2)}\n`;
}
