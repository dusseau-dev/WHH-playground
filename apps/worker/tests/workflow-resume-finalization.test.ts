import { beforeEach, describe, expect, it, vi } from 'vitest';

const harness = vi.hoisted(() => {
  const order: string[] = [];
  const activity = (name: string, value?: unknown) =>
    vi.fn(async () => {
      order.push(name);
      return value;
    });
  const completedAgents = ['recon', 'xss-vuln', 'triage', 'report'];
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
    injectReportMetadataActivity: activity('metadata'),
    injectReportModeSectionsActivity: activity('mode'),
    generateReportOutputActivity: activity('outputs'),
    saveCheckpoint: activity('checkpoint'),
    logWorkflowComplete: activity('complete'),
    runReconAgent: activity('run-recon'),
  };
  const preflight = {
    prepareWorkingDirectory: activity('prepare'),
    runPreflightValidation: activity('preflight'),
  };
  const auth = { runAuthenticationValidation: activity('auth') };
  return { order, general, preflight, auth };
});

vi.mock('@temporalio/workflow', () => ({
  ApplicationFailure: {
    nonRetryable: (message: string, type: string) => Object.assign(new Error(message), { type }),
  },
  defineQuery: (name: string) => name,
  isCancellation: () => false,
  log: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  proxyActivities: (options: { startToCloseTimeout: string }) => {
    if (options.startToCloseTimeout === '2 minutes') return harness.preflight;
    if (options.startToCloseTimeout === '10 minutes') return harness.auth;
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
    });
    expect(harness.general.saveCheckpoint).toHaveBeenCalledWith(
      expect.objectContaining({ sessionId: 'workspace-a' }),
      'report-output',
      'reporting',
      expect.objectContaining({ status: 'completed' }),
    );
    expect(harness.general.runReconAgent).not.toHaveBeenCalled();
    expect(harness.preflight.runPreflightValidation).not.toHaveBeenCalled();
  });
});
