import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { distributeConfig, parseConfigYAML } from '../src/config-parser.js';
import { renderReportPdf } from '../src/services/pdf-renderer.js';
import {
  DefaultReportOutputProvider,
  isSarifEligible,
  REPORT_PDF_FILENAME,
  REPORT_SARIF_FILENAME,
} from '../src/services/report-output.js';
import type { ReportData } from '../src/services/report-renderer.js';
import { normalizeSarifSourcePath, renderSarif } from '../src/services/sarif-renderer.js';
import type { ActivityInput } from '../src/temporal/activities.js';
import type { ActivityLogger } from '../src/types/activity-logger.js';

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

function finding(
  id: string,
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info',
  overrides: Partial<ReportData['findings'][number]> = {},
): ReportData['findings'][number] {
  return {
    finding_id: id,
    title: `${id} title`,
    category: 'Injection',
    owasp_category: 'A05:2025 — Injection',
    severity,
    vulnerable_location: '/api/search',
    http_location: { method: 'get', url: `https://example.test/${id}`, parameter: 'q' },
    overview: `${id} overview`,
    impact: `${id} impact`,
    remediation: `${id} remediation`,
    triage: { validation_state: 'validated', verdict: 'PASS', reason: 'Confirmed.' },
    ...overrides,
  };
}

function report(overrides: Partial<ReportData> = {}): ReportData {
  return {
    report_meta: {
      target: 'https://example.test',
      assessment_date: '2026-08-24',
      scope: 'Application',
      executive_summary: 'Two findings were confirmed.',
      safe_demonstration: true,
      source_mode: 'source-assisted',
      validation_state: 'validated',
    },
    findings: [finding('F-2', 'info'), finding('F-1', 'high')],
    ruled_out: [],
    not_assessed: [],
    triage_status: 'validated',
    ...overrides,
  };
}

const logger = (): ActivityLogger => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn() });

interface ParsedSarif {
  runs: Array<{
    automationDetails: { id: string };
    invocations: Array<{ executionSuccessful: boolean }>;
    results: Array<{
      level: string;
      locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }>;
      relatedLocations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }>;
      partialFingerprints: Record<string, string>;
    }>;
  }>;
}

describe('SARIF rendering and eligibility', () => {
  it('renders deterministic stable results with safe sink-primary locations and severity mappings', () => {
    const data = report({
      findings: [
        finding('F-2', 'info', {
          code_locations: [],
          http_location: { method: 'get', url: 'https://user:secret@example.test/F-2?token=secret', parameter: 'q' },
        }),
        finding('F-1', 'high', {
          original_severity: 'critical',
          triage: { validation_state: 'validated', verdict: 'DOWNGRADE', reason: 'Limited scope.' },
          code_locations: [
            { file: 'src/source.ts', start_line: 2, role: 'source' },
            { file: '../../etc/passwd', start_line: 1, role: 'sink' },
            { file: '/tmp/absolute.ts', start_line: 1, role: 'guard' },
            { file: 'src/sink.ts', start_line: 20, end_line: 21, role: 'sink', symbol: 'query' },
          ],
        }),
        finding('F-3', 'medium', { code_locations: [] }),
        finding('F-4', 'critical', { code_locations: [] }),
        finding('F-5', 'low', { code_locations: [] }),
        finding('F-6', 'medium', { http_location: null, code_locations: [] }),
      ],
      not_assessed: ['ssrf'],
    });

    const first = renderSarif(data, { workspaceName: 'my workspace' });
    const second = renderSarif({ ...data, findings: [...data.findings].reverse() }, { workspaceName: 'my workspace' });
    expect(second).toBe(first);

    const parsed = JSON.parse(first) as ParsedSarif;
    const run = parsed.runs[0];
    if (!run) throw new Error('Expected one SARIF run');
    expect(run.automationDetails.id).toBe('shannon/safe-demonstration/my_workspace');
    expect(run.invocations[0].executionSuccessful).toBe(false);
    expect(run.results).toHaveLength(5);
    expect(run.results.map((result) => result.level)).toEqual(['error', 'note', 'warning', 'error', 'note']);
    expect(run.results[0].locations[0].physicalLocation.artifactLocation.uri).toBe('src/sink.ts');
    expect(run.results[0].relatedLocations[0].physicalLocation.artifactLocation.uri).toBe('src/source.ts');
    expect(run.results[0].partialFingerprints['shannon/finding-id/v1']).toMatch(/^[a-f0-9]{64}$/);
    expect(run.results[1].locations[0].physicalLocation.artifactLocation.uri).toBe('https://example.test/F-2');
  });

  it('rejects absolute and traversal paths on POSIX and Windows', () => {
    expect(normalizeSarifSourcePath('src/app.ts')).toBe('src/app.ts');
    expect(normalizeSarifSourcePath('./src/app.ts')).toBe('src/app.ts');
    expect(normalizeSarifSourcePath('../secret')).toBeNull();
    expect(normalizeSarifSourcePath('src/../secret')).toBeNull();
    expect(normalizeSarifSourcePath('src/../../secret')).toBeNull();
    expect(normalizeSarifSourcePath('/etc/passwd')).toBeNull();
    expect(normalizeSarifSourcePath('C:\\Windows\\system.ini')).toBeNull();
  });

  it('fails closed unless requested safe-demonstration data is fully triage validated', () => {
    expect(isSarifEligible(report(), true)).toBe(true);
    expect(isSarifEligible(report(), false)).toBe(false);
    expect(isSarifEligible(report({ report_meta: { ...report().report_meta, safe_demonstration: false } }), true)).toBe(
      false,
    );
    expect(isSarifEligible(report({ triage_status: 'unvalidated' }), true)).toBe(false);
    expect(isSarifEligible(report({ findings: [finding('F-1', 'high', { triage: undefined })] }), true)).toBe(false);
  });

  it('normalizes natural and legacy string report.sarif values', () => {
    expect(distributeConfig(parseConfigYAML('report:\n  sarif: true')).report.sarif).toBe(true);
    expect(distributeConfig(parseConfigYAML('report:\n  sarif: "false"')).report.sarif).toBe(false);
  });
});

describe('Typst PDF rendering', () => {
  it('uses direct exec-file arguments, copies a complete PDF, and cleans the temp directory', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'shannon-pdf-test-'));
    roots.push(root);
    const template = path.join(root, 'report.typ');
    const output = path.join(root, 'out', REPORT_PDF_FILENAME);
    await writeFile(template, '#let ignored = 1', 'utf8');
    let workDir = '';
    const commandRunner = vi.fn(async (executable: string, args: readonly string[]) => {
      expect(executable).toBe('typst');
      expect(args[0]).toBe('compile');
      expect(args).not.toContain('--shell');
      workDir = args[args.indexOf('--root') + 1] ?? '';
      const dataArg = args[args.indexOf('--input') + 1];
      expect(dataArg).toBe('data=/report.json');
      const outputArg = args.at(-1);
      if (!outputArg) throw new Error('Expected Typst output path');
      await writeFile(outputArg, '%PDF-1.7 test', 'utf8');
    });

    await renderReportPdf({ reportData: report(), templatePath: template, outputPath: output, commandRunner });

    expect(await readFile(output, 'utf8')).toBe('%PDF-1.7 test');
    expect(commandRunner).toHaveBeenCalledOnce();
    expect(existsSync(workDir)).toBe(false);
  });

  it('cleans its isolated directory and publishes no partial PDF on compiler failure', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'shannon-pdf-fail-'));
    roots.push(root);
    const template = path.join(root, 'report.typ');
    const output = path.join(root, REPORT_PDF_FILENAME);
    await writeFile(template, '#let ignored = 1', 'utf8');
    let workDir = '';

    await expect(
      renderReportPdf({
        reportData: report(),
        templatePath: template,
        outputPath: output,
        commandRunner: async (_executable, args) => {
          workDir = args[args.indexOf('--root') + 1] ?? '';
          throw new Error('typst failed');
        },
      }),
    ).rejects.toThrow('typst failed');
    expect(existsSync(workDir)).toBe(false);
    expect(existsSync(output)).toBe(false);
  });
});

describe('default report output orchestration', () => {
  async function setup(data: ReportData, sarif: boolean): Promise<{ root: string; input: ActivityInput }> {
    const root = await mkdtemp(path.join(os.tmpdir(), 'shannon-artifacts-'));
    roots.push(root);
    const deliverables = path.join(root, '.shannon', 'deliverables');
    await import('node:fs/promises').then(({ mkdir }) => mkdir(deliverables, { recursive: true }));
    await writeFile(path.join(deliverables, 'report.json'), JSON.stringify(data), 'utf8');
    return {
      root,
      input: {
        webUrl: 'https://example.test',
        workingDirectory: root,
        sourceMode: 'source-assisted',
        workflowId: 'workflow-1',
        sessionId: 'workspace-1',
        configData: {
          avoid: [],
          focus: [],
          authentication: null,
          description: '',
          vuln_classes: ['injection'],
          safeDemonstration: true,
          report: { sarif },
          rules_of_engagement: '',
        },
      },
    };
  }

  it('keeps SARIF when PDF fails and logs a nonfatal warning', async () => {
    const { root, input } = await setup(report(), true);
    const log = logger();
    const provider = new DefaultReportOutputProvider({
      pdfRenderer: async () => Promise.reject(new Error('no typst')),
    });

    const result = await provider.generate(input, log);

    expect(result.artifacts?.map((artifact) => artifact.kind)).toEqual(['sarif']);
    expect(existsSync(path.join(root, '.shannon', 'deliverables', REPORT_PDF_FILENAME))).toBe(false);
    expect(existsSync(path.join(root, '.shannon', 'deliverables', REPORT_SARIF_FILENAME))).toBe(true);
    expect(log.warn).toHaveBeenCalledWith(expect.stringContaining('PDF report generation failed'));
  });

  it('removes stale SARIF when the current report is ineligible', async () => {
    const baseline = report();
    const data = report({
      triage_status: 'unvalidated',
      report_meta: { ...baseline.report_meta, validation_state: 'unvalidated' },
    });
    const { root, input } = await setup(data, true);
    const sarifPath = path.join(root, '.shannon', 'deliverables', REPORT_SARIF_FILENAME);
    await writeFile(sarifPath, 'stale', 'utf8');
    const provider = new DefaultReportOutputProvider({
      pdfRenderer: async ({ outputPath }) => writeFile(outputPath, '%PDF', 'utf8'),
    });

    const result = await provider.generate(input, logger());

    expect(result.artifacts?.map((artifact) => artifact.kind)).toEqual(['pdf']);
    expect(existsSync(sarifPath)).toBe(false);
  });

  it('keeps a successful PDF when SARIF rendering fails', async () => {
    const { root, input } = await setup(report(), true);
    const log = logger();
    const provider = new DefaultReportOutputProvider({
      pdfRenderer: async ({ outputPath }) => writeFile(outputPath, '%PDF', 'utf8'),
      sarifRenderer: () => {
        throw new Error('sarif failed');
      },
    });

    const result = await provider.generate(input, log);

    expect(result.artifacts?.map((artifact) => artifact.kind)).toEqual(['pdf']);
    expect(existsSync(path.join(root, '.shannon', 'deliverables', REPORT_PDF_FILENAME))).toBe(true);
    expect(existsSync(path.join(root, '.shannon', 'deliverables', REPORT_SARIF_FILENAME))).toBe(false);
    expect(log.warn).toHaveBeenCalledWith(expect.stringContaining('SARIF report generation failed'));
  });

  it('resolves report.sarif from configPath for CLI-style runs', async () => {
    const { root, input } = await setup(report(), false);
    const configPath = path.join(root, 'config.yaml');
    await writeFile(configPath, 'report:\n  sarif: true\n', 'utf8');
    const provider = new DefaultReportOutputProvider({
      pdfRenderer: async ({ outputPath }) => writeFile(outputPath, '%PDF', 'utf8'),
    });

    const result = await provider.generate({ ...input, configData: undefined, configPath }, logger());

    expect(result.artifacts?.map((artifact) => artifact.kind)).toEqual(['pdf', 'sarif']);
  });
});
