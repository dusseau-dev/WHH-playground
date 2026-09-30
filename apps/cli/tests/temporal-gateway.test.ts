import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { DynamicTemporalGateway, type TemporalWorkflowStart } from '../src/scan-controller.js';

function request(): TemporalWorkflowStart {
  return {
    workflowId: 'run-attempt-1',
    taskQueue: 'shannon-queue',
    input: {
      webUrl: 'https://target.test',
      sourceMode: 'url-only',
      workingDirectory: '/app/target',
      workflowId: 'run-attempt-1',
      sessionId: 'run',
    },
  };
}

function moduleFor(handle: Record<string, unknown>) {
  const start = vi.fn(async () => handle);
  const getHandle = vi.fn(() => handle);
  const close = vi.fn(async () => undefined);
  const withDeadline = vi.fn(async (_deadline: number | Date, operation: () => Promise<unknown>) => operation());
  const connect = vi.fn(async () => ({ close, withDeadline }));
  class Client {
    readonly workflow = { start, getHandle };
  }
  return { module: { Connection: { connect }, Client }, start, getHandle, connect, close, withDeadline };
}

describe('DynamicTemporalGateway', () => {
  it('submits the controller-provided workflow identity and input', async () => {
    const harness = moduleFor({ firstExecutionRunId: 'temporal-run-1' });
    const gateway = new DynamicTemporalGateway('temporal.test:7233', async () => harness.module);

    await expect(gateway.startWorkflow(request(), 250)).resolves.toEqual({
      workflowId: 'run-attempt-1',
      temporalRunId: 'temporal-run-1',
    });
    expect(harness.connect).toHaveBeenCalledWith({ address: 'temporal.test:7233', connectTimeout: 250 });
    expect(harness.start).toHaveBeenCalledWith('pentestPipelineWorkflow', {
      taskQueue: 'shannon-queue',
      workflowId: 'run-attempt-1',
      args: [request().input],
    });
    expect(harness.close).toHaveBeenCalledOnce();
  });

  it('replaces legacy inline provider credentials with a local opaque reference', async () => {
    const workspacePath = await fs.mkdtemp(path.join(os.tmpdir(), 'shannon-temporal-secrets-'));
    const harness = moduleFor({ firstExecutionRunId: 'temporal-run-1' });
    const gateway = new DynamicTemporalGateway(
      'temporal.test:7233',
      async () => harness.module,
      () => workspacePath,
    );
    const secretApiKey = 'sk-provider-secret';
    const secretToken = 'gateway-auth-secret';
    const targetPassword = 'target-auth-password';
    const legacy = request();
    legacy.input.apiKey = secretApiKey;
    legacy.input.configYAML = `authentication:\n  credentials:\n    username: operator\n    password: ${targetPassword}\n`;
    legacy.input.providerConfig = {
      providerType: 'generic',
      baseUrl: 'https://gateway.test/v1',
      authToken: secretToken,
    };

    try {
      await gateway.startWorkflow(legacy, 250);

      const submitted = harness.start.mock.calls[0]?.[1] as {
        args: Array<Record<string, unknown>>;
      };
      const submittedInput = submitted.args[0];
      expect(submittedInput).toMatchObject({
        secretRef: expect.stringMatching(/^ps_[a-f0-9]{32}$/),
        providerConfig: { providerType: 'generic', baseUrl: 'https://gateway.test/v1' },
      });
      expect(JSON.stringify(submittedInput)).not.toContain(secretApiKey);
      expect(JSON.stringify(submittedInput)).not.toContain(secretToken);
      expect(JSON.stringify(submittedInput)).not.toContain(targetPassword);
      expect(submittedInput).not.toHaveProperty('apiKey');
      expect(submittedInput).not.toHaveProperty('configYAML');

      const secretDirectory = path.join(workspacePath, '.shannon', 'runtime', 'workflow-secrets');
      const [secretFilename] = await fs.readdir(secretDirectory);
      if (!secretFilename) throw new Error('Expected staged workflow secret');
      const secretPath = path.join(secretDirectory, secretFilename);
      const stored = await fs.readFile(secretPath, 'utf8');
      expect(stored).toContain(secretApiKey);
      expect(stored).toContain(secretToken);
      expect(stored).toContain(targetPassword);
      if (process.platform !== 'win32') {
        expect((await fs.stat(secretPath)).mode & 0o777).toBe(0o600);
        expect((await fs.stat(secretDirectory)).mode & 0o777).toBe(0o700);
      }
    } finally {
      await fs.rm(workspacePath, { force: true, recursive: true });
    }
  });

  it('decodes a structured cancelled result from a completed Temporal execution', async () => {
    const harness = moduleFor({
      describe: async () => ({ status: { name: 'COMPLETED' } }),
      result: async () => ({
        status: 'cancelled',
        currentPhase: null,
        currentAgent: null,
        completedAgents: ['recon'],
        failedAgent: null,
        error: null,
      }),
    });
    const gateway = new DynamicTemporalGateway('temporal.test:7233', async () => harness.module);

    await expect(gateway.getWorkflow('run-attempt-1')).resolves.toMatchObject({
      status: 'cancelled',
      progress: { status: 'cancelled', workflowId: 'run-attempt-1' },
    });
  });

  it('maps Temporal not-found errors without masking other failures', async () => {
    const notFound = new Error('workflow not found');
    notFound.name = 'WorkflowNotFoundError';
    const harness = moduleFor({
      describe: async () => Promise.reject(notFound),
      cancel: async () => Promise.reject(notFound),
    });
    const gateway = new DynamicTemporalGateway('temporal.test:7233', async () => harness.module);

    await expect(gateway.getWorkflow('missing')).resolves.toBeNull();
    await expect(gateway.cancelWorkflow('missing')).resolves.toBe(false);
  });
});
