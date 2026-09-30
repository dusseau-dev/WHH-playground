import { beforeEach, describe, expect, it, vi } from 'vitest';

const {
  order,
  runPiPrompt,
  validateAgentOutput,
  commitGitSuccess,
  rollbackGitWorkspace,
  atomicWrite,
  ensureDirectory,
} = vi.hoisted(() => ({
  order: [] as string[],
  runPiPrompt: vi.fn(),
  validateAgentOutput: vi.fn(),
  commitGitSuccess: vi.fn(),
  rollbackGitWorkspace: vi.fn(async () => undefined),
  atomicWrite: vi.fn(async () => undefined),
  ensureDirectory: vi.fn(async () => undefined),
}));

vi.mock('../src/ai/pi/pi-executor.js', () => ({
  runPiPrompt,
  validateAgentOutput,
}));
vi.mock('../src/services/git-manager.js', () => ({
  createGitCheckpoint: vi.fn(async () => undefined),
  rollbackGitWorkspace,
  getGitCommitHash: vi.fn(async () => 'checkpoint'),
  commitGitSuccess,
}));
vi.mock('../src/services/prompt-manager.js', () => ({
  loadPrompt: vi.fn(async () => 'report prompt'),
}));
vi.mock('../src/utils/file-io.js', () => ({
  atomicWrite,
  ensureDirectory,
}));

import { AgentExecutionService } from '../src/services/agent-execution.js';

describe('AgentExecutionService post-execution finalizer', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    order.splice(0);
    runPiPrompt.mockResolvedValue({
      success: true,
      result: 'done',
      duration: 10,
      cost: 0.1,
      turns: 3,
      inputTokens: 101,
      outputTokens: 202,
      cacheReadTokens: 303,
      cacheWriteTokens: 404,
    });
    validateAgentOutput.mockImplementation(async () => {
      order.push('validate');
      return true;
    });
    commitGitSuccess.mockImplementation(async () => {
      order.push('commit');
    });
    atomicWrite.mockResolvedValue(undefined);
    ensureDirectory.mockResolvedValue(undefined);
  });

  it('passes caller tools and finalizes after agent success but before validation and commit', async () => {
    const service = new AgentExecutionService({
      loadOptional: vi.fn(async () => ({ ok: true, value: null })),
    } as never);
    const callerTools = [{ name: 'set_report_meta' }, { name: 'add_finding' }] as never;
    const auditSession = {
      sessionMetadata: { id: 'test-session', webUrl: 'https://target.test' },
      setRedactionSecrets: vi.fn(),
      redactText: (value: string) => value,
      redactValue: <T>(value: T) => value,
      startAgent: vi.fn(async () => undefined),
      endAgent: vi.fn(async () => undefined),
    };

    const result = await service.execute(
      'report',
      {
        webUrl: 'https://target.test',
        workingDirectory: '/tmp/work',
        sourceMode: 'url-only',
        deliverablesPath: '/tmp/work/.shannon/deliverables',
        attemptNumber: 1,
        callerTools,
        postExecutionFinalizer: async () => {
          order.push('finalize');
        },
      },
      auditSession as never,
      { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
    );

    if (!result.ok) throw result.error;
    expect(runPiPrompt.mock.calls[0]?.[0].callerTools).toBe(callerTools);
    expect(order).toEqual(['finalize', 'validate', 'commit']);
    expect(result.value).toMatchObject({
      cost_usd: 0.1,
      input_tokens: 101,
      output_tokens: 202,
      cache_read_tokens: 303,
      cache_write_tokens: 404,
      num_turns: 3,
    });
    expect(auditSession.endAgent).toHaveBeenCalledWith('report', expect.objectContaining(result.value));
  });

  it('rolls back to the preassembled report when finalization fails', async () => {
    const service = new AgentExecutionService({
      loadOptional: vi.fn(async () => ({ ok: true, value: null })),
    } as never);
    const auditSession = {
      sessionMetadata: { id: 'test-session', webUrl: 'https://target.test' },
      setRedactionSecrets: vi.fn(),
      redactText: (value: string) => value,
      redactValue: <T>(value: T) => value,
      startAgent: vi.fn(async () => undefined),
      endAgent: vi.fn(async () => undefined),
    };

    const result = await service.execute(
      'report',
      {
        webUrl: 'https://target.test',
        workingDirectory: '/tmp/work',
        sourceMode: 'url-only',
        deliverablesPath: '/tmp/work/.shannon/deliverables',
        attemptNumber: 1,
        postExecutionFinalizer: async () => {
          throw new Error('missing report metadata');
        },
      },
      auditSession as never,
      { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
    );

    expect(result).toMatchObject({ ok: false });
    expect(rollbackGitWorkspace).toHaveBeenCalledWith(
      '/tmp/work/.shannon/deliverables',
      'post-execution finalization failure',
      expect.anything(),
    );
    expect(validateAgentOutput).not.toHaveBeenCalled();
    expect(commitGitSuccess).not.toHaveBeenCalled();
    expect(rollbackGitWorkspace).toHaveBeenCalledTimes(1);
    expect(auditSession.endAgent).toHaveBeenCalledTimes(1);
    expect(auditSession.endAgent).toHaveBeenCalledWith(
      'report',
      expect.objectContaining({
        success: false,
        cost_usd: 0.1,
        input_tokens: 101,
        output_tokens: 202,
        cache_read_tokens: 303,
        cache_write_tokens: 404,
        num_turns: 3,
      }),
    );
  });

  it('atomically writes structured output and cleans up cancellation at the post-write boundary', async () => {
    const service = new AgentExecutionService({
      loadOptional: vi.fn(async () => ({ ok: true, value: null })),
    } as never);
    const controller = new AbortController();
    const cancellation = new Error('temporal activity cancelled after queue write');
    const auditSession = {
      sessionMetadata: { id: 'test-session', webUrl: 'https://target.test' },
      setRedactionSecrets: vi.fn(),
      redactText: (value: string) => value,
      redactValue: <T>(value: T) => value,
      startAgent: vi.fn(async () => undefined),
      endAgent: vi.fn(async () => undefined),
    };
    const structuredOutput = { vulnerabilities: [] };
    runPiPrompt.mockResolvedValue({
      success: true,
      result: 'done',
      structuredOutput,
      duration: 12,
      cost: 0.2,
      turns: 3,
      inputTokens: 101,
      outputTokens: 202,
      cacheReadTokens: 303,
      cacheWriteTokens: 404,
      model: 'test-model',
    });
    atomicWrite.mockImplementationOnce(async () => {
      controller.abort(cancellation);
    });
    const postExecutionFinalizer = vi.fn(async () => undefined);

    await expect(
      service.execute(
        'auth-vuln',
        {
          webUrl: 'https://target.test',
          workingDirectory: '/tmp/work',
          sourceMode: 'url-only',
          deliverablesPath: '/tmp/work/.shannon/deliverables',
          attemptNumber: 2,
          cancellationSignal: controller.signal,
          postExecutionFinalizer,
        },
        auditSession as never,
        { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
      ),
    ).rejects.toBe(cancellation);

    expect(atomicWrite).toHaveBeenCalledWith(
      '/tmp/work/.shannon/deliverables/auth_exploitation_queue.json',
      structuredOutput,
    );
    expect(postExecutionFinalizer).not.toHaveBeenCalled();
    expect(validateAgentOutput).not.toHaveBeenCalled();
    expect(commitGitSuccess).not.toHaveBeenCalled();
    expect(rollbackGitWorkspace).toHaveBeenCalledTimes(1);
    expect(rollbackGitWorkspace).toHaveBeenCalledWith(
      '/tmp/work/.shannon/deliverables',
      'agent execution cancellation',
      expect.anything(),
    );
    expect(auditSession.endAgent).toHaveBeenCalledTimes(1);
    expect(auditSession.endAgent).toHaveBeenCalledWith(
      'auth-vuln',
      expect.objectContaining({
        attemptNumber: 2,
        duration_ms: 12,
        cost_usd: 0.2,
        input_tokens: 101,
        output_tokens: 202,
        cache_read_tokens: 303,
        cache_write_tokens: 404,
        num_turns: 3,
        success: false,
        model: 'test-model',
        error: cancellation.message,
      }),
    );
  });

  it('cleans up cancellation after caller finalization and closes audit state once', async () => {
    const service = new AgentExecutionService({
      loadOptional: vi.fn(async () => ({ ok: true, value: null })),
    } as never);
    const controller = new AbortController();
    const cancellation = new Error('temporal activity cancelled after report finalization');
    const auditSession = {
      sessionMetadata: { id: 'test-session', webUrl: 'https://target.test' },
      setRedactionSecrets: vi.fn(),
      redactText: (value: string) => value,
      redactValue: <T>(value: T) => value,
      startAgent: vi.fn(async () => undefined),
      endAgent: vi.fn(async () => undefined),
    };
    const postExecutionFinalizer = vi.fn(async () => {
      controller.abort(cancellation);
    });

    await expect(
      service.execute(
        'report',
        {
          webUrl: 'https://target.test',
          workingDirectory: '/tmp/work',
          sourceMode: 'url-only',
          deliverablesPath: '/tmp/work/.shannon/deliverables',
          attemptNumber: 1,
          cancellationSignal: controller.signal,
          postExecutionFinalizer,
        },
        auditSession as never,
        { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
      ),
    ).rejects.toBe(cancellation);

    expect(postExecutionFinalizer).toHaveBeenCalledTimes(1);
    expect(validateAgentOutput).not.toHaveBeenCalled();
    expect(commitGitSuccess).not.toHaveBeenCalled();
    expect(rollbackGitWorkspace).toHaveBeenCalledTimes(1);
    expect(auditSession.startAgent).toHaveBeenCalledTimes(1);
    expect(auditSession.endAgent).toHaveBeenCalledTimes(1);
    expect(auditSession.endAgent).toHaveBeenCalledWith(
      'report',
      expect.objectContaining({ success: false, error: cancellation.message }),
    );
  });
});
