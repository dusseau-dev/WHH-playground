import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { type AddFindingInput, createFindingCollector } from '../src/collectors/finding-collector.js';
import { attachQueueCodeLocations } from '../src/services/code-location-join.js';
import type { DetectionValidationResult } from '../src/services/detection-validation-runner.js';
import { reconcileReportFindings } from '../src/services/report-reconciliation.js';
import { type ReportData, renderReport } from '../src/services/report-renderer.js';
import type { HttpLoadResult } from '../src/types/http-load.js';
import { buildScopeCoverage } from '../src/types/scopes.js';

const completedHttpLoadResult: HttpLoadResult = {
  version: 1,
  status: 'completed',
  started_at: '2026-08-24T12:00:00.000Z',
  completed_at: '2026-08-24T12:00:15.000Z',
  target: 'https://target.test/load?token=%5BREDACTED%5D',
  concurrency: 5,
  requests_per_second: 10,
  duration_seconds: 15,
  elapsed_seconds: 15.125,
  sent: 150,
  completed: 149,
  success: 145,
  failure: 4,
  errors: 1,
  bytes_read: 12_345,
  average_latency_ms: 42.125,
  minimum_latency_ms: 12.5,
  maximum_latency_ms: 240.75,
  status_counts: { '200': 145, '503': 4 },
};

const failedDetectionValidationResult: DetectionValidationResult = {
  schema_version: 1,
  corpus_version: '1',
  corpus_sha256: 'c'.repeat(64),
  status: 'failed',
  target: 'https://target.test',
  started_at: '2026-09-29T12:00:00.000Z',
  completed_at: '2026-09-29T12:00:30.000Z',
  run_marker: 'shn-run-0123456789abcdef01234567',
  minimum_detection_rate: 1,
  calibration: {
    sent_at: '2026-09-29T12:00:00.000Z',
    http_status: 204,
    telemetry_observed: true,
    first_seen_at: '2026-09-29T12:00:01.000Z',
    latency_ms: 1000,
  },
  cohorts: {
    ai: { total: 5, detected: 4, detection_rate: 0.8, threshold: 1, passed: false, median_latency_ms: 2100 },
    human: { total: 5, detected: 5, detection_rate: 1, threshold: 1, passed: true, median_latency_ms: 1800 },
  },
  detection_gap_percentage_points: 20,
  scenarios: [
    {
      id: 'credential-submission-ai',
      pair_id: 'credential-submission',
      cohort: 'ai',
      technique: 'Fake credential submission',
      fixture_sha256: 'a'.repeat(64),
      marker: 'shn-sim-0123456789abcdef01234567',
      emission_status: 'sent',
      sent_at: '2026-09-29T12:00:02.000Z',
      http_status: 204,
      detected: false,
    },
    {
      id: 'credential-submission-human',
      pair_id: 'credential-submission',
      cohort: 'human',
      technique: 'Fake credential submission',
      fixture_sha256: 'b'.repeat(64),
      marker: 'shn-sim-abcdef0123456789abcdef01',
      emission_status: 'sent',
      sent_at: '2026-09-29T12:00:03.000Z',
      http_status: 204,
      detected: true,
      first_seen_at: '2026-09-29T12:00:05.000Z',
      latency_ms: 2000,
    },
  ],
};

function finding(id: string, severity: AddFindingInput['severity'] = 'high'): AddFindingInput {
  return {
    finding_id: id,
    title: `Finding ${id}`,
    category: 'Injection',
    owasp_category: 'A05:2025 — Injection',
    severity,
    confidence: 'high',
    vulnerable_location: '/search?q=',
    http_location: { method: 'GET', url: 'https://target.test/search', parameter: 'q' },
    overview: `Overview for ${id}`,
    impact: `Impact for ${id}`,
    remediation: `Fix ${id}`,
  };
}

function verdict(
  id: string,
  outcome: 'PASS' | 'DOWNGRADE' | 'KILL' | 'CHAIN_REQUIRED',
  severity: AddFindingInput['severity'] = 'high',
) {
  return {
    id,
    vulnType: 'Injection',
    title: `Finding ${id}`,
    verdict: outcome,
    severity,
    reason: `${outcome} reason`,
    evidenceFile: 'injection.md',
  };
}

describe('finding collector', () => {
  it('uses add_finding, accepts info severity, and rejects duplicate stable IDs', async () => {
    const collector = createFindingCollector(false);
    const tool = collector.tools[0];
    if (!tool) throw new Error('Expected add_finding tool');
    expect(tool.name).toBe('add_finding');

    const input = finding('INJ-VULN-01', 'info');
    const first = await tool.execute('one', input, undefined, undefined, {} as never);
    const duplicate = await tool.execute('two', input, undefined, undefined, {} as never);

    expect(first.content[0]).toMatchObject({ type: 'text' });
    expect(JSON.stringify(duplicate)).toContain('DuplicateError');
    expect(collector.getAll()).toEqual([input]);
    expect(JSON.stringify(tool.parameters)).not.toContain('code_locations');
  });
});

describe('triage reconciliation', () => {
  it('does not require triage when no vulnerability lanes produced candidates', () => {
    expect(reconcileReportFindings([], null, { triageRan: false, knownFindingIds: [] })).toEqual({
      findings: [],
      ruled_out: [],
      triage_status: 'validated',
      validation_issues: [],
    });
  });

  it('applies PASS and DOWNGRADE, and moves KILL/CHAIN_REQUIRED to ruled out', () => {
    const candidates = [
      finding('PASS-1', 'medium'),
      finding('DOWN-1', 'critical'),
      finding('KILL-1'),
      finding('CHAIN-1'),
    ];
    const result = reconcileReportFindings(
      candidates,
      {
        version: 1,
        verdicts: [
          verdict('PASS-1', 'PASS', 'low'),
          { ...verdict('DOWN-1', 'DOWNGRADE', 'medium'), claimedSeverity: 'critical' },
          verdict('KILL-1', 'KILL'),
          verdict('CHAIN-1', 'CHAIN_REQUIRED'),
        ],
      },
      { triageRan: true },
    );

    expect(result.triage_status).toBe('validated');
    expect(result.findings.map((entry) => [entry.finding_id, entry.severity])).toEqual([
      ['PASS-1', 'low'],
      ['DOWN-1', 'medium'],
    ]);
    expect(result.findings[1]).toMatchObject({
      original_severity: 'critical',
      triage: { validation_state: 'validated', verdict: 'DOWNGRADE', reason: 'DOWNGRADE reason' },
    });
    expect(result.ruled_out.map((entry) => [entry.finding_id, entry.verdict])).toEqual([
      ['CHAIN-1', 'CHAIN_REQUIRED'],
      ['KILL-1', 'KILL'],
    ]);
  });

  it.each([
    ['gate did not run', null, { triageRan: false }],
    ['missing output', null, { triageRan: true }],
    ['invalid output', { version: 1, verdicts: [{ nope: true }] }, { triageRan: true }],
  ])('keeps every candidate human-visible and unvalidated when %s', (_name, triage, options) => {
    const result = reconcileReportFindings([finding('A'), finding('B')], triage, options);
    expect(result.triage_status).toBe('unvalidated');
    expect(result.findings.map((entry) => entry.finding_id)).toEqual(['A', 'B']);
    expect(result.findings.every((entry) => entry.triage?.validation_state === 'unvalidated')).toBe(true);
  });

  it('keeps only affected findings unvalidated for partial, duplicate, and unknown IDs', () => {
    const result = reconcileReportFindings(
      [finding('OK'), finding('MISSING'), finding('DUP'), finding('DUP'), finding('UNKNOWN')],
      {
        version: 1,
        verdicts: [verdict('OK', 'PASS'), verdict('DUP', 'KILL'), verdict('DUP', 'PASS')],
      },
      { triageRan: true, knownFindingIds: ['OK', 'MISSING', 'DUP'] },
    );

    expect(result.triage_status).toBe('unvalidated');
    expect(result.findings.map((entry) => entry.finding_id)).toEqual(['OK', 'MISSING', 'DUP', 'DUP', 'UNKNOWN']);
    expect(result.findings.find((entry) => entry.finding_id === 'OK')?.triage?.validation_state).toBe('validated');
    expect(result.validation_issues.join(' ')).toMatch(/missing.*MISSING/i);
    expect(result.validation_issues.join(' ')).toMatch(/duplicate.*DUP/i);
    expect(result.validation_issues.join(' ')).toMatch(/unknown.*UNKNOWN/i);
  });

  it('allows extra verdicts and may retain extra KILL/CHAIN_REQUIRED entries in ruled out', () => {
    const result = reconcileReportFindings(
      [finding('PASS-1')],
      {
        version: 1,
        verdicts: [verdict('PASS-1', 'PASS'), verdict('FILTERED-PASS', 'PASS'), verdict('EXTRA-KILL', 'KILL')],
      },
      { triageRan: true, knownFindingIds: ['PASS-1', 'FILTERED-PASS', 'EXTRA-KILL'] },
    );

    expect(result.triage_status).toBe('validated');
    expect(result.validation_issues).toEqual([]);
    expect(result.findings.map((entry) => entry.finding_id)).toEqual(['PASS-1']);
    expect(result.ruled_out.map((entry) => entry.finding_id)).toEqual(['EXTRA-KILL']);
  });
});

describe('exact queue code-location join', () => {
  it('joins exact IDs only and never adds queue code locations in URL-only mode', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'shannon-locations-'));
    const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
    await fs.writeFile(
      path.join(dir, 'injection_exploitation_queue.json'),
      JSON.stringify({
        vulnerabilities: [
          { ID: 'EXACT', code_locations: [{ file: 'src/query.ts', start_line: 12, role: 'sink' }] },
          { ID: 'exact', code_locations: [{ file: 'wrong.ts', role: 'sink' }] },
        ],
      }),
    );
    try {
      const sourceJoined = await attachQueueCodeLocations(
        [finding('EXACT'), finding('EXACT ')],
        dir,
        logger,
        'source-assisted',
      );
      expect(sourceJoined[0]?.code_locations).toEqual([{ file: 'src/query.ts', start_line: 12, role: 'sink' }]);
      expect(sourceJoined[1]?.code_locations).toBeUndefined();

      const urlOnly = await attachQueueCodeLocations([finding('EXACT')], dir, logger, 'url-only');
      expect(urlOnly[0]?.http_location?.url).toBe('https://target.test/search');
      expect(urlOnly[0]?.code_locations).toBeUndefined();
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });
});

describe('deterministic markdown report', () => {
  it('renders mode, coverage, validation, caveats, info, and escaped deterministic ordering', () => {
    const high = { ...finding('HIGH-2'), title: 'High | <unsafe>' };
    const info = finding('INFO-1', 'info');
    const data: ReportData = {
      report_meta: {
        target: 'https://target.test/<prod>',
        assessment_date: '2026-08-24',
        scope: 'auth | injection',
        executive_summary: 'Summary *not emphasis*.',
        safe_demonstration: false,
        model: 'test-model',
        source_mode: 'url-only',
        validation_state: 'unvalidated',
      },
      findings: [info, high],
      ruled_out: [
        {
          finding_id: 'KILL-1',
          title: 'Ruled | out',
          category: 'Injection',
          severity: 'low',
          verdict: 'KILL',
          reason: 'No <evidence>',
        },
      ],
      not_assessed: ['ssrf'],
      scope_coverage: buildScopeCoverage(['csrf', 'ssrf', 'xxe'], ['ssrf']),
      triage_status: 'unvalidated',
      validation_issues: ['Missing verdict for INFO-1'],
    };

    const rendered = renderReport(data);
    expect(rendered).toContain('## Mode');
    expect(rendered).toContain('URL-Only');
    expect(rendered).toContain('## Coverage');
    expect(rendered).toContain('## OWASP Coverage');
    expect(rendered).toContain(
      '| A01:2025 Broken Access Control | Available | Cross-site request forgery, Server-side request forgery | Incomplete |',
    );
    expect(rendered).toContain('| A03:2025 Software Supply Chain Failures | Coming soon | — | Coming soon |');
    expect(rendered).toMatch(/UNVALIDATED/);
    expect(rendered).toContain('Exploitation was not run');
    expect(rendered).toContain('## Not Assessed');
    expect(rendered).toContain('## Considered & Ruled Out');
    expect(rendered).toContain('Info');
    expect(rendered).toContain('High \\| &lt;unsafe&gt;');
    expect(rendered).toContain('Summary \\*not emphasis\\*\\.');
    expect(rendered.indexOf('### HIGH\\-2')).toBeLessThan(rendered.indexOf('### INFO\\-1'));
    expect(renderReport(data)).toBe(rendered);
    expect(rendered.endsWith('\n')).toBe(true);
  });

  it('renders deterministic HTTP load observations without claiming proven capacity', () => {
    const data: ReportData = {
      report_meta: {
        target: 'https://target.test',
        assessment_date: '2026-08-24',
        scope: 'HTTP load and capacity',
        executive_summary: 'A bounded load observation was collected.',
        safe_demonstration: false,
        source_mode: 'url-only',
        validation_state: 'validated',
      },
      findings: [],
      ruled_out: [],
      not_assessed: [],
      scope_coverage: buildScopeCoverage(['http-load-capacity'], [], ['http-load-capacity']),
      http_load_capacity: completedHttpLoadResult,
      triage_status: 'validated',
    };

    const rendered = renderReport(data);
    expect(rendered).toContain('## HTTP Load and Capacity');
    expect(rendered).toContain('| Status | Completed |');
    expect(rendered).toContain('| Configured request rate | 10 requests/second |');
    expect(rendered).toContain('| HTTP status counts | 200: 145, 503: 4 |');
    expect(rendered).toContain('observations from this bounded run');
    expect(rendered).not.toContain('token');
    expect(rendered).not.toMatch(/proved capacity|proven capacity|resilien(?:t|ce)/i);
  });

  it('renders detection validation scores, gap, latency, and scenario outcomes without causal claims', () => {
    const data: ReportData = {
      report_meta: {
        target: 'https://target.test',
        assessment_date: '2026-09-29',
        scope: 'Alerting effectiveness',
        executive_summary: 'A fixed paired detection simulation was assessed.',
        safe_demonstration: false,
        source_mode: 'url-only',
        validation_state: 'validated',
      },
      findings: [],
      ruled_out: [],
      not_assessed: [],
      scope_coverage: buildScopeCoverage(['alerting-effectiveness'], [], ['alerting-effectiveness']),
      detection_validation: failedDetectionValidationResult,
      triage_status: 'validated',
    };

    const rendered = renderReport(data);
    expect(rendered).toContain('## Detection Validation');
    expect(rendered).toContain('| AI-authored | 4/5 | 80% | 100% | Failed | 2,100 ms |');
    expect(rendered).toContain('| Detection gap | 20 percentage points |');
    expect(rendered).toContain('| credential\\-submission\\-human | Human-authored | Detected | 2,000 ms |');
    expect(rendered).not.toMatch(/causal|uplift|evasion score/i);
  });
});
