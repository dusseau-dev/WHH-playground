import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { RunLaunchSpec } from '../src/contracts.js';
import { FakeRuntime, FakeTemporal, testController } from './helpers.js';

const temporaryDirectories: string[] = [];

async function temporaryDirectory(): Promise<string> {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'shannon-controller-'));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) => fs.rm(directory, { recursive: true, force: true })),
  );
});

const authentication = {
  loginType: 'form' as const,
  loginUrl: 'https://target.test/login',
  username: 'operator',
  successCondition: { type: 'url_contains' as const, value: '/home' },
};

describe('managed run launch', () => {
  it('persists an immutable non-secret snapshot before starting Temporal and Docker', async () => {
    const workspacesDir = await temporaryDirectory();
    const { controller, runtime, temporal } = testController(workspacesDir);
    const run = await controller.startRun({
      targetUrl: 'https://target.test',
      sourceMode: 'url-only',
      workspace: 'url-only-run',
      profileRef: { id: 'profile-1', version: 1, updatedAt: '2026-08-23T12:00:00.000Z' },
      config: {
        testCategories: ['injection', 'authz'],
        safeDemonstration: false,
        pipeline: { maxConcurrentPipelines: 2 },
        report: { sarif: true },
        authentication,
      },
      secrets: { password: 'runtime-only-password' },
      secretRefs: { password: 'keychain:profile-1:password' },
    });

    expect(run).toMatchObject({
      kind: 'managed',
      version: 1,
      runId: 'url-only-run',
      workspacePath: path.join(workspacesDir, 'url-only-run'),
      status: 'running',
    });
    expect(run.snapshot).toMatchObject({
      targetUrl: 'https://target.test',
      sourceMode: 'url-only',
      profileRef: { id: 'profile-1' },
      requiredSecretFields: ['password'],
      secretRefs: { password: 'keychain:profile-1:password' },
    });
    expect(run.snapshotHash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(run.attempts).toHaveLength(1);
    expect(run.attempts[0]).toMatchObject({
      attemptNumber: 1,
      status: 'running',
      workflowId: 'url-only-run-attempt-1-attempt1',
      temporalRunId: 'temporal-1',
    });

    expect(temporal.starts).toHaveLength(1);
    expect(temporal.starts[0]?.input).toMatchObject({
      webUrl: 'https://target.test',
      sourceMode: 'url-only',
      workingDirectory: '/app/target',
      sessionId: 'url-only-run',
      vulnClasses: ['injection', 'authz'],
      safeDemonstration: false,
      pipelineConfig: { max_concurrent_pipelines: 2 },
    });
    expect(runtime.launches[0]).toMatchObject({
      workflowId: 'url-only-run-attempt-1-attempt1',
      workingDirectory: '/app/target',
      sourceMode: 'url-only',
      labels: {
        'shannon.managed': 'true',
        'shannon.run': 'url-only-run',
        'shannon.attempt': '1',
      },
    });

    const runPath = path.join(workspacesDir, 'url-only-run', '.shannon', 'run.json');
    const snapshot = await fs.readFile(runPath, 'utf8');
    const runtimeConfig = await fs.readFile(
      path.join(workspacesDir, 'url-only-run', '.shannon', 'runtime', 'worker-config.yaml'),
      'utf8',
    );
    await expect(fs.access(path.join(workspacesDir, 'url-only-run', 'run.json'))).rejects.toThrow();
    expect(snapshot).not.toContain('runtime-only-password');
    expect(runtimeConfig).toContain('runtime-only-password');
    expect(runtimeConfig).toContain('sarif: true');
    expect(JSON.stringify(temporal.starts)).not.toContain('runtime-only-password');
    if (process.platform !== 'win32') {
      expect((await fs.stat(runPath)).mode & 0o777).toBe(0o600);
      expect((await fs.stat(path.dirname(runPath))).mode & 0o777).toBe(0o777);
    }
  });

  it('starts source-assisted mode with a read-only repository and rejects URL credentials', async () => {
    const root = await temporaryDirectory();
    const repo = path.join(root, 'repository');
    await fs.mkdir(repo);
    const { controller, runtime } = testController(path.join(root, 'workspaces'));
    await controller.startRun({
      targetUrl: 'https://target.test',
      sourceMode: 'source-assisted',
      repoPath: repo,
      workspace: 'source-run',
      config: {},
    });
    expect(runtime.launches[0]?.repo).toEqual({
      hostPath: await fs.realpath(repo),
      containerPath: `/repos/${path.basename(repo)}`,
    });
    await expect(
      controller.startRun({
        targetUrl: 'https://operator:secret@target.test',
        sourceMode: 'url-only',
        workspace: 'credential-url',
        config: {},
      }),
    ).rejects.toThrow(/credentials|userinfo/i);
  });

  it('resolves stored secret references without persisting their values', async () => {
    const workspacesDir = await temporaryDirectory();
    const { controller } = testController(workspacesDir, {
      secretValues: { 'keychain:profile-1:password': 'reference-only-password' },
    });
    await controller.startRun({
      targetUrl: 'https://target.test',
      sourceMode: 'url-only',
      workspace: 'reference-start',
      config: { authentication },
      secretRefs: { password: 'keychain:profile-1:password' },
    });

    const internal = path.join(workspacesDir, 'reference-start', '.shannon');
    expect(await fs.readFile(path.join(internal, 'runtime', 'worker-config.yaml'), 'utf8')).toContain(
      'reference-only-password',
    );
    expect(await fs.readFile(path.join(internal, 'run.json'), 'utf8')).not.toContain('reference-only-password');
  });

  it('rolls back the workflow and marks the run failed when Docker launch fails', async () => {
    const workspacesDir = await temporaryDirectory();
    const runtime = new FakeRuntime();
    runtime.failSpawn = true;
    const { controller, temporal } = testController(workspacesDir, { runtime });

    await expect(
      controller.startRun({
        targetUrl: 'https://target.test',
        sourceMode: 'url-only',
        workspace: 'failed-start',
        config: {},
      }),
    ).rejects.toThrow(/docker run exited/);

    expect(temporal.cancelled).toEqual(['failed-start-attempt-1-attempt1']);
    const stored = JSON.parse(
      await fs.readFile(path.join(workspacesDir, 'failed-start', '.shannon', 'run.json'), 'utf8'),
    );
    expect(stored.status).toBe('failed');
    await expect(
      fs.access(path.join(workspacesDir, 'failed-start', '.shannon', 'runtime', 'worker-config.yaml')),
    ).rejects.toThrow();
  });
});

describe('resume and cancellation', () => {
  it('resumes from the stored snapshot and resolves its stored secret references', async () => {
    const workspacesDir = await temporaryDirectory();
    const { controller, runtime, temporal } = testController(workspacesDir, {
      secretValues: { 'keychain:profile-1:password': 'resolved-on-resume' },
    });
    const original: RunLaunchSpec = {
      targetUrl: 'https://target.test',
      sourceMode: 'url-only',
      workspace: 'resume-run',
      profileRef: { id: 'profile-1', version: 1, updatedAt: '2026-08-23T12:00:00.000Z' },
      config: { testCategories: ['xss'], safeDemonstration: true, authentication },
      secrets: { password: 'first-password' },
      secretRefs: { password: 'keychain:profile-1:password' },
    };
    const started = await controller.startRun(original);
    await controller.cancelRun(started.runId);
    const resumed = await controller.resumeRun(started.runId);

    expect(resumed.snapshot).toEqual(started.snapshot);
    expect(resumed.snapshotHash).toBe(started.snapshotHash);
    expect(resumed.attempts).toHaveLength(2);
    expect(temporal.starts[1]?.input).toMatchObject({
      webUrl: original.targetUrl,
      sourceMode: original.sourceMode,
      resumeFromWorkspace: 'resume-run',
      vulnClasses: ['xss'],
      safeDemonstration: true,
    });
    expect(runtime.launches).toHaveLength(2);
    const runtimeConfig = await fs.readFile(
      path.join(workspacesDir, 'resume-run', '.shannon', 'runtime', 'worker-config.yaml'),
      'utf8',
    );
    expect(runtimeConfig).toContain('resolved-on-resume');
    expect(await fs.readFile(path.join(workspacesDir, 'resume-run', '.shannon', 'run.json'), 'utf8')).not.toContain(
      'resolved-on-resume',
    );
  });

  it('requires re-entry when a required secret reference cannot be resolved', async () => {
    const workspacesDir = await temporaryDirectory();
    const { controller } = testController(workspacesDir);
    const started = await controller.startRun({
      targetUrl: 'https://target.test',
      sourceMode: 'url-only',
      workspace: 'missing-secret',
      config: { authentication },
      secrets: { password: 'first-password' },
      secretRefs: { password: 'memory:profile-1:password' },
    });
    await controller.cancelRun(started.runId);
    await expect(controller.resumeRun(started.runId)).rejects.toThrow(/password/);
  });

  it('rejects a snapshot changed after its hash was persisted', async () => {
    const workspacesDir = await temporaryDirectory();
    const { controller } = testController(workspacesDir);
    const started = await controller.startRun({
      targetUrl: 'https://target.test',
      sourceMode: 'url-only',
      workspace: 'tampered-run',
      config: {},
    });
    await controller.cancelRun(started.runId);
    const runPath = path.join(workspacesDir, 'tampered-run', '.shannon', 'run.json');
    const stored = JSON.parse(await fs.readFile(runPath, 'utf8'));
    stored.snapshot.targetUrl = 'https://changed.test';
    await fs.writeFile(runPath, JSON.stringify(stored));
    await expect(controller.resumeRun(started.runId)).rejects.toThrow(/snapshot.*hash|integrity/i);
  });

  it('stops the exactly labeled worker when Temporal does not close before the deadline', async () => {
    const workspacesDir = await temporaryDirectory();
    const temporal = new FakeTemporal();
    temporal.cancelResult = null;
    const { controller, runtime } = testController(workspacesDir, { temporal });
    const started = await controller.startRun({
      targetUrl: 'https://target.test',
      sourceMode: 'url-only',
      workspace: 'cancel-timeout',
      config: {},
    });

    const cancelled = await controller.cancelRun(started.runId);
    expect(cancelled.status).toBe('cancelled');
    expect(runtime.stopped).toEqual([started.attempts[0]?.containerName]);
  });

  it('keeps a completion race instead of overwriting it as cancelled', async () => {
    const workspacesDir = await temporaryDirectory();
    const temporal = new FakeTemporal();
    temporal.cancelResult = 'completed';
    const { controller } = testController(workspacesDir, { temporal });
    const started = await controller.startRun({
      targetUrl: 'https://target.test',
      sourceMode: 'url-only',
      workspace: 'completion-race',
      config: {},
    });
    expect((await controller.cancelRun(started.runId)).status).toBe('completed');
  });
});

describe('progress and reconciliation', () => {
  it('returns Temporal activity progress and persists terminal status', async () => {
    const workspacesDir = await temporaryDirectory();
    const { controller, runtime, temporal } = testController(workspacesDir);
    const started = await controller.startRun({
      targetUrl: 'https://target.test',
      sourceMode: 'url-only',
      workspace: 'progress-run',
      config: { authentication },
      secrets: { password: 'ephemeral-progress-password' },
    });
    const runtimeConfig = path.join(workspacesDir, 'progress-run', '.shannon', 'runtime', 'worker-config.yaml');
    await expect(fs.access(runtimeConfig)).resolves.toBeUndefined();
    const workflowId = started.attempts[0]?.workflowId as string;
    expect((await controller.getRunProgress(started.runId))?.currentPhase).toBe('recon');
    temporal.setStatus(workflowId, 'completed');
    await controller.getRunProgress(started.runId);
    expect((await controller.listRuns()).find((run) => run.runId === started.runId)?.status).toBe('completed');
    await expect(fs.access(runtimeConfig)).rejects.toThrow();
    expect(runtime.stopped).toEqual([]);
  });

  it('fails and cancels a running workflow whose unique worker is gone', async () => {
    const workspacesDir = await temporaryDirectory();
    const runtime = new FakeRuntime();
    const temporal = new FakeTemporal();
    const { controller } = testController(workspacesDir, { runtime, temporal });
    const started = await controller.startRun({
      targetUrl: 'https://target.test',
      sourceMode: 'url-only',
      workspace: 'orphan-workflow',
      config: {},
    });
    runtime.removeContainer(started.attempts[0]?.containerName as string);

    const reconciled = await controller.reconcileRuns();
    expect(reconciled.find((run) => run.runId === started.runId)?.status).toBe('failed');
    expect(temporal.cancelled).toContain(started.attempts[0]?.workflowId);
  });

  it('stops labeled containers that have no matching managed attempt', async () => {
    const workspacesDir = await temporaryDirectory();
    const runtime = new FakeRuntime();
    runtime.addContainer({
      name: 'shannon-worker-orphan',
      running: true,
      status: 'running',
      exitCode: null,
      labels: {
        'shannon.managed': 'true',
        'shannon.run': 'missing-run',
        'shannon.attempt': '1',
      },
    });
    const { controller } = testController(workspacesDir, { runtime });
    await controller.reconcileRuns();
    expect(runtime.stopped).toEqual(['shannon-worker-orphan']);
  });

  it('stops a container whose run and attempt labels match but workflow label does not', async () => {
    const workspacesDir = await temporaryDirectory();
    const runtime = new FakeRuntime();
    const { controller } = testController(workspacesDir, { runtime });
    const started = await controller.startRun({
      targetUrl: 'https://target.test',
      sourceMode: 'url-only',
      workspace: 'label-mismatch',
      config: {},
    });
    const attempt = started.attempts[0];
    if (!attempt) throw new Error('Missing attempt');
    runtime.addContainer({
      name: attempt.containerName,
      running: true,
      status: 'running',
      exitCode: null,
      labels: { ...attempt.dockerLabels, 'shannon.workflow': 'other-workflow' },
    });

    await controller.reconcileRuns();
    expect(runtime.stopped).toContain(attempt.containerName);
  });

  it('preserves state and containers when Temporal is unavailable', async () => {
    const workspacesDir = await temporaryDirectory();
    const runtime = new FakeRuntime();
    const temporal = new FakeTemporal();
    const { controller } = testController(workspacesDir, { runtime, temporal });
    const started = await controller.startRun({
      targetUrl: 'https://target.test',
      sourceMode: 'url-only',
      workspace: 'outage-run',
      config: {},
    });
    temporal.unavailable = true;
    const reconciled = await controller.reconcileRuns();
    expect(reconciled.find((run) => run.runId === started.runId)?.status).toBe('running');
    expect(runtime.stopped).toEqual([]);
  });
});

describe('legacy workspaces and artifacts', () => {
  it('lists session-only workspaces as read-only without managing them', async () => {
    const workspacesDir = await temporaryDirectory();
    const workspacePath = path.join(workspacesDir, 'legacy-run');
    await fs.mkdir(path.join(workspacePath, 'deliverables'), { recursive: true });
    await fs.writeFile(
      path.join(workspacePath, 'session.json'),
      JSON.stringify({
        session: {
          id: 'legacy-workflow',
          webUrl: 'https://legacy.test',
          status: 'completed',
          createdAt: '2026-01-01T00:00:00.000Z',
          completedAt: '2026-01-01T01:00:00.000Z',
        },
        metrics: { total_cost_usd: 1 },
      }),
    );
    await fs.writeFile(
      path.join(workspacePath, 'deliverables', 'comprehensive_security_assessment_report.md'),
      '# Old',
    );
    const { controller, runtime, temporal } = testController(workspacesDir);

    const legacy = (await controller.listRuns()).find((run) => run.runId === 'legacy-run');
    expect(legacy).toMatchObject({ kind: 'legacy', readOnly: true, status: 'completed' });
    await expect(controller.cancelRun('legacy-run')).rejects.toThrow(/read-only|legacy/i);
    await expect(controller.resumeRun('legacy-run')).rejects.toThrow(/read-only|legacy/i);
    expect(temporal.cancelled).toEqual([]);
    expect(runtime.stopped).toEqual([]);
  });

  it('surfaces queue candidates and enforces report/evidence containment', async () => {
    const workspacesDir = await temporaryDirectory();
    const { controller } = testController(workspacesDir);
    await controller.startRun({
      targetUrl: 'https://target.test',
      sourceMode: 'url-only',
      workspace: 'artifact-run',
      config: {},
    });
    const deliverables = path.join(workspacesDir, 'artifact-run', '.shannon', 'deliverables');
    await fs.writeFile(
      path.join(deliverables, 'xss_exploitation_queue.json'),
      JSON.stringify({
        vulnerabilities: [
          { ID: 'xss-1', vulnerability_type: 'Reflected script context', notes: 'Repeatable inert marker break-out' },
        ],
      }),
    );
    await fs.writeFile(
      path.join(deliverables, 'comprehensive_security_assessment_report.md'),
      '# Report\n<script>alert(1)</script>\n[bad](javascript:alert(1))',
    );

    const detail = await controller.getRunDetail('artifact-run');
    expect(detail.triage).toBeNull();
    expect(detail.unvalidatedFindings[0]).toMatchObject({ id: 'xss-1', vulnType: 'xss' });
    const report = await controller.getReport('artifact-run');
    expect(report.markdown).toMatch(/^## Mode\n\nURL-Only/);
    expect(report.markdown).not.toContain('<script>');
    await expect(controller.getArtifactPath('artifact-run', '../run.json')).rejects.toThrow(/allowlisted/);
  });

  it('reports fixed Markdown, PDF, and SARIF availability while preserving legacy Markdown', async () => {
    const workspacesDir = await temporaryDirectory();
    const { controller } = testController(workspacesDir);
    await controller.startRun({
      targetUrl: 'https://target.test',
      sourceMode: 'url-only',
      workspace: 'multi-report-run',
      config: {},
    });
    const workspace = path.join(workspacesDir, 'multi-report-run');
    const deliverables = path.join(workspace, '.shannon', 'deliverables');
    await fs.writeFile(path.join(deliverables, 'comprehensive_security_assessment_report.md'), '# Report');
    await fs.writeFile(path.join(deliverables, 'Security-Assessment-Report.pdf'), '%PDF-1.7');
    await fs.writeFile(path.join(deliverables, 'report.sarif'), '{"version":"2.1.0"}');

    const detail = await controller.getRunDetail('multi-report-run');
    expect(detail.reportAvailable).toBe(true);
    expect(detail.reportArtifacts).toEqual([
      expect.objectContaining({ kind: 'markdown', contentType: 'text/markdown; charset=utf-8' }),
      expect.objectContaining({ kind: 'pdf', contentType: 'application/pdf' }),
      expect.objectContaining({ kind: 'sarif', contentType: 'application/sarif+json; charset=utf-8' }),
    ]);
    await expect(controller.getReportArtifactPath('multi-report-run', 'markdown')).resolves.toBe(
      await fs.realpath(path.join(deliverables, 'comprehensive_security_assessment_report.md')),
    );
    await expect(controller.getReportArtifactPath('multi-report-run', 'report.json' as never)).rejects.toThrow(
      /artifact kind/i,
    );

    const outside = path.join(workspacesDir, 'outside.pdf');
    await fs.writeFile(outside, '%PDF-outside');
    await fs.rm(path.join(deliverables, 'Security-Assessment-Report.pdf'));
    await fs.symlink(outside, path.join(deliverables, 'Security-Assessment-Report.pdf'));
    await expect(controller.getReportArtifactPath('multi-report-run', 'pdf')).rejects.toThrow(/not found/i);
    await fs.rm(path.join(deliverables, 'Security-Assessment-Report.pdf'));
    await fs.writeFile(path.join(deliverables, 'comprehensive_security_assessment_report.pdf'), '%PDF-legacy');
    await expect(controller.getReportArtifactPath('multi-report-run', 'pdf')).resolves.toBe(
      await fs.realpath(path.join(deliverables, 'comprehensive_security_assessment_report.pdf')),
    );
  });
});
