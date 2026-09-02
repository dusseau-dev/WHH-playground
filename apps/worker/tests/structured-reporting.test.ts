import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { ToolDefinition } from '@earendil-works/pi-coding-agent';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AddFindingInput } from '../src/collectors/finding-collector.js';
import { createReportMetaCollector } from '../src/collectors/report-meta-collector.js';
import { injectAssessmentModeSections, injectModelIntoReport } from '../src/services/reporting.js';
import {
  createStructuredReportSession,
  isReportData,
  PUBLIC_REPORT_MARKDOWN_FILENAME,
  REPORT_MARKDOWN_FILENAME,
  synchronizeHttpLoadReportFiles,
  validateStructuredReportFiles,
} from '../src/services/structured-report.js';
import type { HttpLoadResult } from '../src/types/http-load.js';

const roots: string[] = [];
const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };

const completedHttpLoadResult: HttpLoadResult = {
  version: 1,
  status: 'completed',
  started_at: '2026-08-24T12:00:00.000Z',
  completed_at: '2026-08-24T12:00:15.000Z',
  target: 'https://target.test/',
  concurrency: 5,
  requests_per_second: 10,
  duration_seconds: 15,
  elapsed_seconds: 15,
  sent: 150,
  completed: 150,
  success: 150,
  failure: 0,
  errors: 0,
  bytes_read: 15_000,
  average_latency_ms: 25,
  minimum_latency_ms: 10,
  maximum_latency_ms: 50,
  status_counts: { '200': 150 },
};

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => fs.rm(root, { recursive: true, force: true })));
  vi.clearAllMocks();
});

async function makeDeliverables(): Promise<string> {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'shannon-structured-report-'));
  roots.push(root);
  const deliverables = path.join(root, '.shannon', 'deliverables');
  await fs.mkdir(deliverables, { recursive: true });
  return deliverables;
}

function finding(id: string): AddFindingInput {
  return {
    finding_id: id,
    title: 'SQL injection in search',
    category: 'Injection',
    owasp_category: 'A05:2025 — Injection',
    severity: 'high',
    confidence: 'high',
    vulnerable_location: '/search?q=',
    http_location: { method: 'GET', url: 'https://target.test/search', parameter: 'q' },
    overview: 'The query parameter reaches a database query.',
    impact: 'An attacker may read data outside their account.',
    remediation: 'Use a parameterized query.',
  };
}

function requiredTool(tools: readonly ToolDefinition[], index: number): ToolDefinition {
  const tool = tools[index];
  if (!tool) throw new Error(`Expected report tool at index ${index}`);
  return tool;
}

async function callTool(tool: ToolDefinition, input: unknown) {
  return tool.execute('call', input as never, undefined, undefined, {} as never);
}

describe('report metadata collector', () => {
  it('captures set_report_meta exactly once', async () => {
    const collector = createReportMetaCollector();
    expect(collector.tools[0]?.name).toBe('set_report_meta');

    await callTool(requiredTool(collector.tools, 0), {
      target: 'https://target.test',
      assessment_date: '2026-08-24',
      scope: 'injection, xss',
      executive_summary: 'One confirmed issue.',
      ignored: 'not retained',
    });
    const duplicate = await callTool(requiredTool(collector.tools, 0), {
      target: 'https://target.test',
      assessment_date: '2026-08-24',
      scope: 'other',
      executive_summary: 'Other.',
    });

    expect(collector.get()).toEqual({
      target: 'https://target.test',
      assessment_date: '2026-08-24',
      scope: 'injection, xss',
      executive_summary: 'One confirmed issue.',
    });
    expect(JSON.stringify(duplicate)).toContain('DuplicateError');
  });
});

describe('structured report pipeline finalizer', () => {
  it('rejects malformed optional HTTP load report data', () => {
    expect(
      isReportData({
        report_meta: {
          target: 'https://target.test',
          assessment_date: '2026-08-24',
          scope: 'load',
          executive_summary: 'Summary.',
          safe_demonstration: false,
          source_mode: 'url-only',
          validation_state: 'validated',
        },
        findings: [],
        ruled_out: [],
        not_assessed: [],
        triage_status: 'validated',
        http_load_capacity: { status: 'completed' },
      }),
    ).toBe(false);
  });

  it('persists completed HTTP load evidence and completes its OWASP check', async () => {
    const deliverablesPath = await makeDeliverables();
    const session = await createStructuredReportSession({
      deliverablesPath,
      webUrl: 'https://target.test',
      sourceMode: 'url-only',
      safeDemonstration: false,
      triageRan: false,
      selectedVulnClasses: [],
      selectedTestScopes: ['http-load-capacity'],
      httpLoadResult: completedHttpLoadResult,
    });
    await callTool(requiredTool(session.tools, 0), {
      target: 'https://target.test',
      assessment_date: '2026-08-24',
      scope: 'HTTP load and capacity',
      executive_summary: 'A bounded load observation was collected.',
    });

    const report = await session.finalize(logger);
    const a06 = report.scope_coverage?.find(({ owasp_id }) => owasp_id === 'A06:2025');
    expect(report.http_load_capacity).toEqual(completedHttpLoadResult);
    expect(a06).toMatchObject({ status: 'completed', completed_scopes: ['http-load-capacity'] });
    expect(await fs.readFile(path.join(deliverablesPath, REPORT_MARKDOWN_FILENAME), 'utf8')).toContain(
      '## HTTP Load and Capacity',
    );
  });

  it('repairs an existing structured report after a resumed load activity completes', async () => {
    const deliverablesPath = await makeDeliverables();
    const session = await createStructuredReportSession({
      deliverablesPath,
      webUrl: 'https://target.test',
      sourceMode: 'url-only',
      safeDemonstration: false,
      triageRan: false,
      selectedVulnClasses: [],
      selectedTestScopes: ['http-load-capacity'],
    });
    await callTool(requiredTool(session.tools, 0), {
      target: 'https://target.test',
      assessment_date: '2026-08-24',
      scope: 'HTTP load and capacity',
      executive_summary: 'A load observation was selected.',
    });
    const initial = await session.finalize(logger);
    expect(initial.http_load_capacity).toBeUndefined();
    expect(initial.scope_coverage?.find(({ owasp_id }) => owasp_id === 'A06:2025')?.status).toBe('incomplete');

    expect(
      await synchronizeHttpLoadReportFiles(deliverablesPath, ['http-load-capacity'], completedHttpLoadResult),
    ).toBe(true);

    const repaired = JSON.parse(await fs.readFile(path.join(deliverablesPath, 'report.json'), 'utf8'));
    expect(repaired.http_load_capacity).toEqual(completedHttpLoadResult);
    expect(repaired.scope_coverage.find(({ owasp_id }: { owasp_id: string }) => owasp_id === 'A06:2025')).toMatchObject(
      {
        status: 'completed',
        completed_scopes: ['http-load-capacity'],
      },
    );
    expect(await validateStructuredReportFiles(deliverablesPath, logger)).toBe(true);
  });

  it('writes validated canonical JSON and Markdown with exact IDs, locations, filters, and extra verdicts', async () => {
    const deliverablesPath = await makeDeliverables();
    await fs.writeFile(
      path.join(deliverablesPath, 'injection_exploitation_queue.json'),
      JSON.stringify({
        vulnerabilities: [
          {
            ID: 'INJ-VULN-01',
            code_locations: [{ file: 'src/search.ts', start_line: 42, role: 'sink' }],
          },
          { ID: 'FILTERED-VULN-02' },
        ],
      }),
    );
    await fs.writeFile(
      path.join(deliverablesPath, 'triage_verdicts.json'),
      JSON.stringify({
        version: 1,
        verdicts: [
          {
            id: 'INJ-VULN-01',
            vulnType: 'Injection',
            title: 'SQL injection in search',
            verdict: 'PASS',
            severity: 'high',
            reason: 'Confirmed by evidence.',
            evidenceFile: 'injection_exploitation_evidence.md',
          },
          {
            id: 'FILTERED-VULN-02',
            vulnType: 'Injection',
            title: 'Filtered low impact candidate',
            verdict: 'KILL',
            severity: 'low',
            reason: 'Not reproducible.',
            evidenceFile: 'injection_exploitation_evidence.md',
          },
        ],
      }),
    );
    await fs.mkdir(path.join(deliverablesPath, 'modules'), { recursive: true });
    await fs.writeFile(
      path.join(deliverablesPath, 'modules', 'manifest.json'),
      JSON.stringify({
        schema_version: 1,
        selected_modules: ['passive-exposure', 'automated-dast'],
        results: [
          { id: 'passive-exposure', status: 'completed', evidencePath: 'modules/passive-exposure.json' },
          { id: 'automated-dast', status: 'partial', evidencePath: 'modules/automated-dast.json' },
        ],
      }),
    );
    await Promise.all([
      fs.writeFile(
        path.join(deliverablesPath, 'modules', 'passive-exposure.json'),
        JSON.stringify({ schema_version: 1, module: 'passive-exposure', status: 'completed' }),
      ),
      fs.writeFile(
        path.join(deliverablesPath, 'modules', 'automated-dast.json'),
        JSON.stringify({ schema_version: 1, module: 'automated-dast', status: 'partial' }),
      ),
    ]);

    const session = await createStructuredReportSession({
      deliverablesPath,
      webUrl: 'https://target.test',
      sourceMode: 'source-assisted',
      safeDemonstration: false,
      triageRan: true,
      selectedVulnClasses: ['injection', 'xss'],
      selectedAssessmentModules: ['passive-exposure', 'automated-dast'],
    });
    expect(session.tools.map((tool) => tool.name)).toEqual(['set_report_meta', 'add_finding']);
    await callTool(requiredTool(session.tools, 0), {
      target: 'https://target.test',
      assessment_date: '2026-08-24',
      scope: 'injection and xss',
      executive_summary: 'One confirmed issue; low-impact candidates were omitted by report policy.',
    });
    await callTool(requiredTool(session.tools, 1), finding('INJ-VULN-01'));

    const report = await session.finalize(logger);
    const jsonPath = path.join(deliverablesPath, 'report.json');
    const markdownPath = path.join(deliverablesPath, REPORT_MARKDOWN_FILENAME);
    const publicMarkdownPath = path.join(deliverablesPath, PUBLIC_REPORT_MARKDOWN_FILENAME);
    const raw = JSON.parse(await fs.readFile(jsonPath, 'utf8'));
    const markdown = await fs.readFile(markdownPath, 'utf8');
    const publicMarkdown = await fs.readFile(publicMarkdownPath, 'utf8');

    expect(report).toEqual(raw);
    expect(raw.report_meta).toMatchObject({
      target: 'https://target.test',
      safe_demonstration: false,
      source_mode: 'source-assisted',
      validation_state: 'validated',
    });
    expect(raw.findings).toHaveLength(1);
    expect(raw.findings[0]).toMatchObject({
      finding_id: 'INJ-VULN-01',
      code_locations: [{ file: 'src/search.ts', start_line: 42, role: 'sink' }],
      triage: { validation_state: 'validated', verdict: 'PASS' },
    });
    expect(raw.ruled_out.map((entry: { finding_id: string }) => entry.finding_id)).toEqual(['FILTERED-VULN-02']);
    expect(raw.not_assessed).toEqual(['xss']);
    expect(raw.module_coverage).toEqual([
      expect.objectContaining({ id: 'passive-exposure', status: 'completed' }),
      expect.objectContaining({ id: 'automated-dast', status: 'partial' }),
    ]);
    expect(markdown).toContain('## Mode\n\nSource-Assisted');
    expect(markdown).toContain('## Assessment Methods');
    expect(markdown).toContain('| Automated vulnerability scan | Partial | modules/automated\\-dast\\.json |');
    expect(markdown).toContain('src/search\\.ts:42');
    expect(publicMarkdown).toBe(markdown);
    expect(await validateStructuredReportFiles(deliverablesPath, logger)).toBe(true);
    await expect(fs.access(`${jsonPath}.tmp`)).rejects.toThrow();
    await expect(fs.access(`${markdownPath}.tmp`)).rejects.toThrow();
    await expect(fs.access(`${publicMarkdownPath}.tmp`)).rejects.toThrow();
  });

  it.each([
    ['missing triage', undefined],
    ['invalid triage', '{not-json'],
  ])('keeps collected findings visible and unvalidated with %s', async (_case, triageBody) => {
    const deliverablesPath = await makeDeliverables();
    await fs.writeFile(
      path.join(deliverablesPath, 'injection_exploitation_queue.json'),
      JSON.stringify({ vulnerabilities: [{ ID: 'INJ-VULN-01' }] }),
    );
    if (triageBody !== undefined) {
      await fs.writeFile(path.join(deliverablesPath, 'triage_verdicts.json'), triageBody);
    }
    const session = await createStructuredReportSession({
      deliverablesPath,
      webUrl: 'https://target.test',
      sourceMode: 'url-only',
      safeDemonstration: false,
      triageRan: true,
      selectedVulnClasses: ['injection'],
    });
    await callTool(requiredTool(session.tools, 0), {
      target: 'https://target.test',
      assessment_date: '2026-08-24',
      scope: 'injection',
      executive_summary: 'Candidate finding requires human review.',
    });
    await callTool(requiredTool(session.tools, 1), finding('INJ-VULN-01'));

    const report = await session.finalize(logger);
    expect(report.triage_status).toBe('unvalidated');
    expect(report.findings[0]?.finding_id).toBe('INJ-VULN-01');
    expect(report.findings[0]?.triage?.validation_state).toBe('unvalidated');
    expect(report.findings[0]?.code_locations).toBeUndefined();
    expect(report.validation_issues?.join(' ')).toMatch(/triage output is (missing|invalid)/i);
  });

  it('rejects report finding IDs that are not exact queue IDs', async () => {
    const deliverablesPath = await makeDeliverables();
    await fs.writeFile(
      path.join(deliverablesPath, 'injection_exploitation_queue.json'),
      JSON.stringify({ vulnerabilities: [{ ID: 'INJ-VULN-01' }] }),
    );
    const session = await createStructuredReportSession({
      deliverablesPath,
      webUrl: 'https://target.test',
      sourceMode: 'source-assisted',
      safeDemonstration: false,
      triageRan: false,
      selectedVulnClasses: ['injection'],
    });
    await callTool(requiredTool(session.tools, 0), {
      target: 'https://target.test',
      assessment_date: '2026-08-24',
      scope: 'injection',
      executive_summary: 'Summary.',
    });
    const response = await callTool(requiredTool(session.tools, 1), finding('inj-vuln-01'));

    expect(JSON.stringify(response)).toContain('UnknownFindingId');
    expect(session.getFindings()).toEqual([]);
  });

  it('updates report.json model metadata and rerenders without duplicating Mode/Coverage', async () => {
    const deliverablesPath = await makeDeliverables();
    const workingDirectory = path.dirname(path.dirname(deliverablesPath));
    const outputPath = await fs.mkdtemp(path.join(os.tmpdir(), 'shannon-report-model-'));
    roots.push(outputPath);
    await fs.writeFile(
      path.join(deliverablesPath, 'injection_exploitation_queue.json'),
      JSON.stringify({ vulnerabilities: [] }),
    );
    const session = await createStructuredReportSession({
      deliverablesPath,
      webUrl: 'https://target.test',
      sourceMode: 'url-only',
      safeDemonstration: false,
      triageRan: false,
      selectedVulnClasses: ['injection'],
    });
    await callTool(requiredTool(session.tools, 0), {
      target: 'https://target.test',
      assessment_date: '2026-08-24',
      scope: 'injection',
      executive_summary: 'No confirmed findings.',
    });
    await session.finalize(logger);
    await fs.writeFile(
      path.join(outputPath, 'session.json'),
      JSON.stringify({ metrics: { agents: { report: { model: 'pi/test-model' } } } }),
    );

    await injectModelIntoReport(workingDirectory, '.shannon/deliverables', outputPath, logger);
    await injectAssessmentModeSections(workingDirectory, '.shannon/deliverables', 'url-only', logger);

    const raw = JSON.parse(await fs.readFile(path.join(deliverablesPath, 'report.json'), 'utf8'));
    const markdown = await fs.readFile(path.join(deliverablesPath, REPORT_MARKDOWN_FILENAME), 'utf8');
    const publicMarkdown = await fs.readFile(path.join(deliverablesPath, PUBLIC_REPORT_MARKDOWN_FILENAME), 'utf8');
    expect(raw.report_meta.model).toBe('pi/test-model');
    expect(markdown).toContain('- Model: pi/test\\-model');
    expect(publicMarkdown).toBe(markdown);
    expect(markdown.match(/^## Mode$/gm)).toHaveLength(1);
    expect(markdown.match(/^## Coverage$/gm)).toHaveLength(1);
    expect(await validateStructuredReportFiles(deliverablesPath, logger)).toBe(true);
  });
});
