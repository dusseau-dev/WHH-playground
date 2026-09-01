import AxeBuilder from '@axe-core/playwright';
import { expect, type Page, type Route, test } from '@playwright/test';

type RunStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';

interface MockRun {
  kind: 'managed';
  runId: string;
  workspacePath: string;
  status: RunStatus;
  snapshot: {
    targetUrl: string;
    sourceMode: 'url-only' | 'source-assisted';
    repoPath?: string;
    config: {
      testCategories: string[];
      safeDemonstration: boolean;
      pipeline: { maxConcurrentPipelines: number };
    };
    requiredSecretFields: string[];
  };
  attempts: Array<{ attemptNumber: number; startedAt: string }>;
  createdAt: string;
  updatedAt: string;
  completedAt?: string;
  lastError?: string;
}

interface MockDetail {
  run: MockRun;
  progress: {
    status: 'running' | 'completed' | 'failed' | 'cancelled';
    currentPhase: string | null;
    currentAgent: string | null;
    activeAgents: string[];
    activeTestCategories: string[];
    expectedAgents: string[];
    completedAgents: string[];
    failedAgent: string | null;
    error: string | null;
    elapsedMs: number;
    triageRan: boolean;
    summary: { totalCostUsd: number; totalDurationMs: number };
  } | null;
  metrics: { total_duration_ms: number; total_cost_usd: number } | null;
  triage: { version: 1; verdicts: unknown[] } | null;
  unvalidatedFindings: Array<{ id: string; vulnType: string; title: string; reason: string }>;
  reportAvailable: boolean;
  reportArtifacts: Array<{
    kind: 'markdown' | 'pdf' | 'sarif';
    filename: string;
    contentType: string;
  }>;
  evidenceFiles: string[];
}

const timestamp = '2026-07-18T16:00:00.000Z';

function run(
  id: string,
  status: RunStatus = 'completed',
  sourceMode: MockRun['snapshot']['sourceMode'] = 'url-only',
): MockRun {
  return {
    kind: 'managed',
    runId: id,
    workspacePath: `/tmp/workspaces/${id}`,
    status,
    snapshot: {
      targetUrl: `https://${id}.example.test`,
      sourceMode,
      ...(sourceMode === 'source-assisted' && { repoPath: '/Users/operator/project' }),
      config: {
        testCategories: ['injection', 'xss', 'auth', 'authz', 'ssrf'],
        safeDemonstration: true,
        pipeline: { maxConcurrentPipelines: 3 },
      },
      requiredSecretFields: [],
    },
    attempts: [{ attemptNumber: 1, startedAt: timestamp }],
    createdAt: timestamp,
    updatedAt: timestamp,
    ...(status === 'completed' && { completedAt: timestamp }),
    ...(status === 'failed' && { lastError: 'Worker stopped before report generation' }),
  };
}

function detail(record: MockRun): MockDetail {
  const agents = [
    ...(record.snapshot.sourceMode === 'source-assisted' ? ['pre-recon'] : []),
    'recon',
    'injection-vuln',
    'injection-exploit',
    'triage',
    'report',
  ];
  const terminal = record.status === 'completed';
  return {
    run: record,
    progress: {
      status: terminal
        ? 'completed'
        : record.status === 'failed'
          ? 'failed'
          : record.status === 'cancelled'
            ? 'cancelled'
            : 'running',
      currentPhase: terminal ? null : 'vulnerability-analysis',
      currentAgent: terminal ? null : 'injection-vuln',
      activeAgents: terminal ? [] : ['injection-vuln'],
      activeTestCategories: terminal ? [] : ['injection'],
      expectedAgents: agents,
      completedAgents: terminal ? agents : ['recon'],
      failedAgent: record.status === 'failed' ? 'injection-vuln' : null,
      error: record.status === 'failed' ? (record.lastError ?? null) : null,
      elapsedMs: 83_000,
      triageRan: terminal,
      summary: { totalCostUsd: 0.42, totalDurationMs: 83_000 },
    },
    metrics: { total_duration_ms: 83_000, total_cost_usd: 0.42 },
    triage: terminal
      ? {
          version: 1,
          verdicts: [
            {
              id: 'xss-1',
              vulnType: 'xss',
              title: 'Reflected marker executes in search',
              verdict: 'PASS',
              severity: 'medium',
              reason: 'A harmless marker executed in a controlled browser context.',
              evidenceFile: 'xss_evidence.txt',
            },
            {
              id: 'auth-2',
              vulnType: 'auth',
              title: 'Logout invalidation control',
              verdict: 'KILL',
              severity: 'info',
              reason: 'The prior session was rejected after logout.',
              evidenceFile: 'auth_evidence.txt',
            },
          ],
        }
      : null,
    unvalidatedFindings: [],
    reportAvailable: terminal,
    reportArtifacts: terminal
      ? [
          {
            kind: 'markdown',
            filename: 'comprehensive_security_assessment_report.md',
            contentType: 'text/markdown; charset=utf-8',
          },
        ]
      : [],
    evidenceFiles: terminal ? ['xss_evidence.txt', 'auth_evidence.txt'] : [],
  };
}

class MockApi {
  readonly runs = new Map<string, MockDetail>();
  readonly profiles = new Map<string, Record<string, unknown>>();
  lastStartBody: Record<string, unknown> | null = null;
  resumeRequiresSecrets = false;

  constructor(private readonly page: Page) {}

  async install(): Promise<void> {
    await this.page.route('**/api/v1/**', (route) => this.handle(route));
  }

  seed(record: MockRun): MockDetail {
    const value = detail(record);
    this.runs.set(record.runId, value);
    return value;
  }

  private json(route: Route, value: unknown, status = 200) {
    return route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(value) });
  }

  private async handle(route: Route): Promise<void> {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname.replace('/api/v1', '');
    const method = request.method();

    if (path === '/bootstrap') {
      await this.json(route, {
        data: {
          csrfToken: 'browser-csrf',
          version: 'test',
          platform: 'darwin',
          secretStore: { persistence: 'memory', available: false },
        },
      });
      return;
    }
    if (path === '/runs' && method === 'GET') {
      await this.json(route, { data: [...this.runs.values()].map((value) => value.run) });
      return;
    }
    if (path === '/runs' && method === 'POST') {
      this.lastStartBody = request.postDataJSON() as Record<string, unknown>;
      const record = run(
        'new-assessment',
        'running',
        this.lastStartBody.sourceMode as MockRun['snapshot']['sourceMode'],
      );
      record.snapshot.targetUrl = String(this.lastStartBody.targetUrl);
      const value = detail(record);
      this.runs.set(record.runId, value);
      await this.json(route, { data: record }, 202);
      return;
    }
    if (path === '/profiles' && method === 'GET') {
      await this.json(route, { data: [...this.profiles.values()] });
      return;
    }
    if (path === '/profiles' && method === 'POST') {
      const body = request.postDataJSON() as Record<string, unknown>;
      const profile = {
        version: 1,
        id: 'profile-browser',
        name: body.name,
        targetUrl: body.targetUrl,
        sourceMode: body.sourceMode,
        config: body.config ?? {},
        hasSecret: {},
        createdAt: timestamp,
        updatedAt: timestamp,
      };
      this.profiles.set('profile-browser', profile);
      await this.json(route, { data: profile }, 201);
      return;
    }
    const profileMatch = path.match(/^\/profiles\/([^/]+)$/);
    if (profileMatch && method === 'GET') {
      await this.json(route, { data: this.profiles.get(profileMatch[1] ?? '') });
      return;
    }
    if (profileMatch && method === 'PUT') {
      const current = this.profiles.get(profileMatch[1] ?? '') ?? {};
      const body = request.postDataJSON() as Record<string, unknown>;
      const profile = { ...current, ...body, id: profileMatch[1], updatedAt: timestamp, hasSecret: {} };
      this.profiles.set(String(profileMatch[1]), profile);
      await this.json(route, { data: profile });
      return;
    }
    const eventMatch = path.match(/^\/runs\/([^/]+)\/events$/);
    if (eventMatch) {
      const value = this.runs.get(eventMatch[1] ?? '');
      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache' },
        body: `event: snapshot\ndata: ${JSON.stringify(value)}\n\nevent: activity\ndata: ${JSON.stringify({ offset: 22, text: '[2026-07-18T16:00:00Z] recon complete\\n' })}\n\n`,
      });
      return;
    }
    const cancelMatch = path.match(/^\/runs\/([^/]+)\/cancel$/);
    if (cancelMatch && method === 'POST') {
      const value = this.runs.get(cancelMatch[1] ?? '');
      if (value) {
        value.run.status = 'cancelled';
        if (value.progress) value.progress.status = 'cancelled';
      }
      await this.json(route, { data: value?.run });
      return;
    }
    const resumeMatch = path.match(/^\/runs\/([^/]+)\/resume$/);
    if (resumeMatch && method === 'POST') {
      const body = (request.postDataJSON() ?? {}) as { secrets?: Record<string, string> };
      if (this.resumeRequiresSecrets && !body.secrets?.password) {
        await this.json(
          route,
          { error: { code: 'missing_secrets', message: 'Target secrets must be supplied again: password' } },
          409,
        );
        return;
      }
      const value = this.runs.get(resumeMatch[1] ?? '');
      if (value) {
        value.run.status = 'running';
        value.run.attempts.push({ attemptNumber: 2, startedAt: timestamp });
        if (value.progress) value.progress.status = 'running';
      }
      await this.json(route, { data: value?.run }, 202);
      return;
    }
    const reportMatch = path.match(/^\/runs\/([^/]+)\/report$/);
    if (reportMatch) {
      await this.json(route, {
        data: {
          filename: 'comprehensive_security_assessment_report.md',
          markdown:
            '# Security Assessment Report\n\n## Mode\n\nURL-Only\n\n## Coverage\n\nThis assessment used browser and API observations against the authorized live target. Code-level coverage and source-location attribution were unavailable in URL-only mode.\n\n## Confirmed Findings\n\nOne controlled XSS marker was confirmed.',
          sourceMode: 'url-only',
          coverageNotice:
            'URL-only mode used browser and API observations; code-level coverage and source-location attribution were unavailable.',
        },
      });
      return;
    }
    if (/^\/runs\/[^/]+\/reports\/(?:markdown|pdf|sarif)$/.test(path)) {
      await route.fulfill({ status: 200, contentType: 'application/octet-stream', body: 'report artifact' });
      return;
    }
    if (/\/artifacts\//.test(path)) {
      await route.fulfill({ status: 200, contentType: 'text/plain', body: 'sanitized evidence' });
      return;
    }
    const runMatch = path.match(/^\/runs\/([^/]+)$/);
    if (runMatch && method === 'GET') {
      await this.json(route, { data: this.runs.get(runMatch[1] ?? '') });
      return;
    }
    await this.json(route, { error: { code: 'not_found', message: path } }, 404);
  }
}

async function expectNoAxeViolations(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations).toEqual([]);
}

test('creates profiles and configures both assessment modes', async ({ page }) => {
  const api = new MockApi(page);
  await api.install();
  await page.goto('/runs');
  await expect(page.getByText('No assessments have been run')).toBeVisible();

  if ((page.viewportSize()?.width ?? 0) < 760) {
    await page.getByRole('button', { name: 'Open navigation' }).click();
  }
  await page.getByRole('link', { name: 'Profiles' }).click();
  await page.getByRole('button', { name: 'New profile' }).click();
  await page.getByLabel('Profile name').fill('Staging target');
  await page.getByLabel('Target URL').fill('https://staging.example.test');
  await page.getByRole('button', { name: 'Save profile' }).click();
  await expect(page.getByText('Staging target').first()).toBeVisible();

  if ((page.viewportSize()?.width ?? 0) < 760) {
    await page.getByRole('button', { name: 'Open navigation' }).click();
  }
  await page.getByRole('link', { name: 'New assessment' }).click();
  await expect(page.getByText('URL-only mode uses browser and API observations; code-level coverage')).toBeVisible();
  await page.getByText('Source assisted', { exact: true }).click();
  await expect(page.getByLabel('Source assisted')).toBeChecked();
  await expect(page.getByLabel('Repository path')).toBeVisible();
  await page.getByLabel('Repository path').fill('/Users/operator/project');
  await page.getByText('URL only', { exact: true }).click();
  await expect(page.getByLabel('URL only')).toBeChecked();
  await expect(page.getByLabel('Repository path')).toHaveCount(0);
  await page.getByLabel('Model source').selectOption('openrouter');
  await page.getByLabel('Model ID').fill('~anthropic/claude-sonnet-latest');
  await page.getByLabel('Provider API key', { exact: true }).fill('sk-or-v1-runtime-only-provider-key');
  await page.getByText('Cross-site scripting', { exact: true }).click();
  await expect(page.getByLabel('Cross-site scripting')).not.toBeChecked();
  await page.getByRole('button', { name: 'Decrease concurrency' }).click();
  await page.getByText('Rules and reporting').click();
  await page.getByText('SARIF report', { exact: true }).click();
  await expect(page.getByRole('switch', { name: 'SARIF report' })).toBeChecked();
  await page.getByLabel('Target URL').fill('https://new.example.test');
  await page.getByText('I confirm I am authorized to test this target.').click();
  await page.getByRole('button', { name: 'Start assessment' }).click();
  await expect(page).toHaveURL(/\/runs\/new-assessment$/);
  expect(api.lastStartBody).toMatchObject({ sourceMode: 'url-only', targetUrl: 'https://new.example.test' });
  expect(api.lastStartBody).toMatchObject({
    providerConfig: {
      providerType: 'openai',
      model: '~anthropic/claude-sonnet-latest',
      baseUrl: 'https://openrouter.ai/api/v1',
      openAIFormat: 'chat-completions',
      apiKey: 'sk-or-v1-runtime-only-provider-key',
    },
  });
  expect(api.lastStartBody).toMatchObject({ config: { safeDemonstration: true } });
  expect(api.lastStartBody).toMatchObject({ config: { report: { sarif: true } } });
  expect((api.lastStartBody?.config as Record<string, unknown>).demonstrate).toBeUndefined();
  await expectNoAxeViolations(page);
});

test('shows validated findings, report, evidence, and URL-only coverage', async ({ page }) => {
  const api = new MockApi(page);
  await api.install();
  const validated = api.seed(run('validated-run'));
  validated.reportArtifacts.push(
    { kind: 'pdf', filename: 'Security-Assessment-Report.pdf', contentType: 'application/pdf' },
    { kind: 'sarif', filename: 'report.sarif', contentType: 'application/sarif+json; charset=utf-8' },
  );
  await page.goto('/runs/validated-run');
  await expect(page.getByText('URL-only mode used browser and API observations; code-level coverage')).toBeVisible();
  await expect(page.getByText('Reflected marker executes in search')).toBeVisible();
  await expect(page.getByRole('link', { name: /xss_evidence.txt/ })).toBeVisible();
  await page.getByRole('tab', { name: 'Report' }).click();
  await expect(page.getByRole('heading', { name: 'Mode' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Coverage' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Download Markdown' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Download PDF' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Download SARIF' })).toBeVisible();
  await expectNoAxeViolations(page);
});

test('hides unavailable secondary report downloads', async ({ page }) => {
  const api = new MockApi(page);
  await api.install();
  api.seed(run('markdown-only-run'));
  await page.goto('/runs/markdown-only-run');
  await page.getByRole('tab', { name: 'Report' }).click();
  await expect(page.getByRole('link', { name: 'Download Markdown' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Download PDF' })).toHaveCount(0);
  await expect(page.getByRole('link', { name: 'Download SARIF' })).toHaveCount(0);
});

test('labels pipeline status and marks missing historical progress unavailable', async ({ page }) => {
  const api = new MockApi(page);
  await api.install();
  const historical = api.seed(run('historical-run'));
  historical.progress = null;

  await page.goto('/runs/historical-run');

  await expect(page.getByRole('heading', { name: 'Pipeline execution status' })).toBeVisible();
  await expect(page.locator('.stage-icon[title="unavailable"]')).toHaveCount(13);
  await expect(page.locator('.stage-icon[title="skipped"]')).toHaveCount(0);
  await expect(page.getByText('Status unavailable')).toHaveCount(13);
  await expectNoAxeViolations(page);
});

test('labels fail-open findings and supports resume secret entry and cancellation', async ({ page }) => {
  const api = new MockApi(page);
  await api.install();
  const failed = run('failed-run', 'failed');
  failed.snapshot.requiredSecretFields = ['password'];
  const failedDetail = api.seed(failed);
  failedDetail.unvalidatedFindings = [
    { id: 'authz-1', vulnType: 'authz', title: 'Cross-role object candidate', reason: 'Triage did not complete.' },
  ];
  api.resumeRequiresSecrets = true;
  await page.goto('/runs/failed-run');
  await expect(page.getByText('Cross-role object candidate')).toBeVisible();
  await expect(page.getByText('unvalidated')).toBeVisible();
  await page.getByRole('button', { name: 'Resume' }).click();
  await expect(page.getByText('Re-enter session-only credentials')).toBeVisible();
  await page.getByLabel('Target password').fill('replacement-secret');
  await page.getByRole('button', { name: 'Resume attempt' }).click();
  await expect(page.getByText('running', { exact: true })).toBeVisible();

  await page.getByRole('button', { name: 'Cancel run' }).click();
  await page.getByRole('button', { name: 'Confirm cancel' }).click();
  await expect(page.getByText('cancelled', { exact: true })).toBeVisible();
  await page.getByRole('tab', { name: 'Activity' }).click();
  await page.keyboard.press('Tab');
  await expect(page.locator(':focus')).toBeVisible();
  await expectNoAxeViolations(page);
});
