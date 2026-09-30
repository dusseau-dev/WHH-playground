import { beforeEach, describe, expect, it, vi } from 'vitest';

const harness = vi.hoisted(() => {
  const order: string[] = [];
  const activity = (name: string, value?: unknown) =>
    vi.fn(async () => {
      order.push(name);
      return value;
    });
  const completedAgents = ['recon', 'xss-vuln', 'triage', 'report'];
  const moduleResults = [
    { id: 'passive-exposure', status: 'completed', evidencePath: 'modules/passive-exposure.json' },
  ];
  const general = {
    persistOrValidateRunScope: activity('persist'),
    loadResumeState: activity('load', {
      workspaceName: 'workspace-a',
      originalUrl: 'https://example.test',
      completedAgents,
      checkpointHash: 'checkpoint-1',
      originalWorkflowId: 'workflow-original',
    }),
    restoreGitCheckpoint: activity('restore'),
    loadAssessmentModuleResultsActivity: activity('load-module-evidence', moduleResults),
    injectReportMetadataActivity: activity('metadata'),
    injectReportModeSectionsActivity: activity('mode'),
    generateReportOutputActivity: activity('outputs'),
    saveCheckpoint: activity('checkpoint'),
    logWorkflowComplete: activity('complete'),
    runReconAgent: activity('run-recon', {
      durationMs: 1,
      inputTokens: 0,
      outputTokens: 0,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
      costUsd: 0,
      numTurns: 0,
    }),
    syncPlaywrightStealthConfig: activity('playwright'),
    initDeliverableGit: activity('git'),
    logPhaseTransition: activity('phase'),
    runHttpLoadCapacityActivity: activity('http-load-capacity', { status: 'completed' }),
    assembleReportActivity: activity('assemble'),
    runReportAgent: activity('report', {
      durationMs: 1,
      inputTokens: 0,
      outputTokens: 0,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
      costUsd: 0,
      numTurns: 0,
    }),
    runTriageAgent: activity('triage'),
  };
  const modules = {
    runAssessmentModulesActivity: activity('modules', moduleResults),
  };
  const detection = {
    runDetectionValidationActivity: activity('detection-validation', { status: 'failed' }),
    loadDetectionValidationResultActivity: activity('load-detection-evidence', { status: 'failed' }),
  };
  const preflight = {
    prepareWorkingDirectory: activity('prepare'),
    runPreflightValidation: activity('preflight'),
    syncPlaywrightStealthConfig: activity('playwright'),
  };
  const auth = { runAuthenticationValidation: activity('auth') };
  return { order, general, modules, detection, preflight, auth };
});

vi.mock('@temporalio/workflow', () => ({
  ApplicationFailure: {
    nonRetryable: (message: string, type: string) => Object.assign(new Error(message), { type }),
  },
  defineQuery: (name: string) => name,
  isCancellation: () => false,
  log: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  proxyActivities: (options: { startToCloseTimeout: string; retry?: { maximumAttempts?: number } }) => {
    if (options.startToCloseTimeout === '2 minutes') return harness.preflight;
    if (options.startToCloseTimeout === '10 minutes') return harness.auth;
    if (options.startToCloseTimeout === '15 minutes') return harness.detection;
    if (options.startToCloseTimeout === '2 hours' && options.retry?.maximumAttempts === 1) return harness.modules;
    return harness.general;
  },
  setHandler: vi.fn(),
  workflowInfo: () => ({ workflowId: 'workflow-resume' }),
}));

import { pentestPipeline } from '../src/temporal/workflows.js';

beforeEach(() => {
  harness.order.length = 0;
  vi.clearAllMocks();
});

describe('all-complete resume finalization', () => {
  it('fails closed before activities when inline configuration could contain credentials', async () => {
    await expect(
      pentestPipeline({
        webUrl: 'https://example.test',
        sourceMode: 'url-only',
        workingDirectory: '/app/target',
        configYAML: 'authentication:\n  credentials:\n    password: must-not-enter-history\n',
      }),
    ).rejects.toThrow('use configPath or stage it behind secretRef');
    expect(harness.order).toEqual([]);
  });

  it('runs an activity-backed load-only scope after recon and before reporting without triage', async () => {
    harness.general.loadResumeState.mockClear();
    const state = await pentestPipeline({
      webUrl: 'https://example.test',
      sourceMode: 'url-only',
      workingDirectory: '/app/target',
      testScopes: ['http-load-capacity'],
      vulnClasses: [],
      httpLoadAuthorizationConfirmed: true,
      safeDemonstration: false,
    });

    const reconIndex = harness.order.indexOf('run-recon');
    const loadIndex = harness.order.indexOf('http-load-capacity');
    const reportIndex = harness.order.indexOf('report');
    expect(reconIndex).toBeGreaterThan(-1);
    expect(loadIndex).toBeGreaterThan(reconIndex);
    expect(reportIndex).toBeGreaterThan(loadIndex);
    expect(harness.general.runTriageAgent).not.toHaveBeenCalled();
    expect(state.completedAgents).toEqual(['recon', 'report']);
    expect(state.completedAgents).not.toContain('http-load-capacity');
    expect(state.httpLoadStatus).toBe('completed');
  });

  it('fails the workflow when the load activity cannot produce a result', async () => {
    harness.general.runHttpLoadCapacityActivity.mockRejectedValueOnce(new Error('load generator unavailable'));

    await expect(
      pentestPipeline({
        webUrl: 'https://example.test',
        sourceMode: 'url-only',
        workingDirectory: '/app/target',
        testScopes: ['http-load-capacity'],
        vulnClasses: [],
        httpLoadAuthorizationConfirmed: true,
        safeDemonstration: false,
      }),
    ).rejects.toThrow('load generator unavailable');

    expect(harness.general.runReportAgent).not.toHaveBeenCalled();
  });

  it('runs detection validation as a dedicated non-fatal executor', async () => {
    const state = await pentestPipeline({
      webUrl: 'https://example.test',
      sourceMode: 'url-only',
      workingDirectory: '/app/target',
      testScopes: ['alerting-effectiveness'],
      vulnClasses: [],
      moduleSafety: { targetEnvironment: 'staging' },
      detectionValidation: {
        canaryPath: '/__shannon__/detection-simulation',
        minimumDetectionRate: 1,
        maxWaitSeconds: 30,
        splunk: {
          managementUrl: 'https://splunk.example.test:8089',
          telemetryIndex: 'waf_events',
          alertIndex: 'security_alerts',
        },
      },
      detectionValidationAuthorizationConfirmed: true,
      safeDemonstration: false,
    });

    expect(harness.order.indexOf('detection-validation')).toBeGreaterThan(harness.order.indexOf('run-recon'));
    expect(harness.order.indexOf('report')).toBeGreaterThan(harness.order.indexOf('detection-validation'));
    expect(state).toMatchObject({ status: 'completed', detectionValidationStatus: 'failed' });
    expect(harness.general.runTriageAgent).not.toHaveBeenCalled();
  });

  it('rejects detection validation against a non-HTTPS target before activities', async () => {
    await expect(
      pentestPipeline({
        webUrl: 'http://example.test',
        sourceMode: 'url-only',
        workingDirectory: '/app/target',
        testScopes: ['alerting-effectiveness'],
        vulnClasses: [],
        moduleSafety: { targetEnvironment: 'staging' },
        detectionValidation: {
          canaryPath: '/__shannon__/detection-simulation',
          minimumDetectionRate: 1,
          maxWaitSeconds: 30,
          splunk: {
            managementUrl: 'https://splunk.example.test:8089',
            telemetryIndex: 'waf_events',
            alertIndex: 'security_alerts',
          },
        },
        detectionValidationAuthorizationConfirmed: true,
      }),
    ).rejects.toThrow(/HTTPS target/i);
  });

  it('loads prior detection evidence during all-complete resume finalization', async () => {
    const state = await pentestPipeline({
      webUrl: 'https://example.test',
      sourceMode: 'url-only',
      workingDirectory: '/app/target',
      sessionId: 'workspace-a',
      resumeFromWorkspace: 'workspace-a',
      vulnClasses: [],
      testScopes: ['alerting-effectiveness'],
      moduleSafety: { targetEnvironment: 'staging' },
      detectionValidation: {
        canaryPath: '/__shannon__/detection-simulation',
        minimumDetectionRate: 1,
        maxWaitSeconds: 30,
        splunk: {
          managementUrl: 'https://splunk.example.test:8089',
          telemetryIndex: 'waf_events',
          alertIndex: 'security_alerts',
        },
      },
      detectionValidationAuthorizationConfirmed: true,
      safeDemonstration: false,
    });

    expect(harness.detection.loadDetectionValidationResultActivity).toHaveBeenCalledOnce();
    expect(harness.detection.runDetectionValidationActivity).not.toHaveBeenCalled();
    expect(state.detectionValidationStatus).toBe('failed');
  });

  it('repairs report artifacts, checkpoints them, and records workflow completion', async () => {
    const state = await pentestPipeline({
      webUrl: 'https://example.test',
      sourceMode: 'url-only',
      workingDirectory: '/app/target',
      sessionId: 'workspace-a',
      resumeFromWorkspace: 'workspace-a',
      vulnClasses: ['xss'],
      safeDemonstration: false,
      checkpointsEnabled: true,
    });

    expect(harness.order).toEqual([
      'prepare',
      'persist',
      'load',
      'restore',
      'load-module-evidence',
      'metadata',
      'mode',
      'outputs',
      'checkpoint',
      'complete',
    ]);
    expect(state).toMatchObject({
      status: 'completed',
      triageRan: true,
      completedAgents: ['recon', 'xss-vuln', 'triage', 'report'],
      moduleResults: [{ id: 'passive-exposure', status: 'completed', evidencePath: 'modules/passive-exposure.json' }],
    });
    expect(harness.general.saveCheckpoint).toHaveBeenCalledWith(
      expect.objectContaining({ sessionId: 'workspace-a' }),
      'report-output',
      'reporting',
      expect.objectContaining({ status: 'completed' }),
    );
    expect(harness.general.runReconAgent).not.toHaveBeenCalled();
    expect(harness.modules.runAssessmentModulesActivity).not.toHaveBeenCalled();
    expect(harness.preflight.runPreflightValidation).not.toHaveBeenCalled();
  });
});
