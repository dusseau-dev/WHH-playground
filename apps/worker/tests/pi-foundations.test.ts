import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it, vi } from 'vitest';

describe('Pi model runtime foundations', () => {
  it('uses per-run ProviderConfig before environment selection without serializing credentials', async () => {
    const { resolvePiModelRuntime } = await import('../src/ai/pi/model-runtime.js');
    const runtime = await resolvePiModelRuntime({
      modelTier: 'medium',
      providerConfig: {
        providerType: 'openai',
        apiKey: 'per-run-secret',
        baseUrl: 'https://gateway.test/v1',
        openAIFormat: 'responses',
        model: 'gpt-private',
      },
      env: {
        SHANNON_AI_MODEL: 'anthropic:claude-env',
        SHANNON_AI_API_KEY: 'environment-secret',
      },
    });

    expect(runtime.selection).toMatchObject({
      providerId: 'openai',
      modelId: 'gpt-private',
      source: 'provider-config',
      baseUrl: 'https://gateway.test/v1',
      openAIFormat: 'responses',
    });
    expect(runtime.model).toMatchObject({
      provider: 'openai',
      id: 'gpt-private',
      baseUrl: 'https://gateway.test/v1',
      api: 'openai-responses',
    });
    expect(runtime.credentials.get('openai')).toBe('per-run-secret');
    expect(JSON.stringify(runtime)).not.toContain('per-run-secret');
    expect(JSON.stringify(runtime)).not.toContain('environment-secret');
  });

  it('keeps a configured gateway credential in the environment when only the model changes', async () => {
    const { resolvePiModelRuntime } = await import('../src/ai/pi/model-runtime.js');
    const runtime = await resolvePiModelRuntime({
      providerConfig: {
        providerType: 'openai',
        model: 'anthropic/claude-opus-4.6',
        baseUrl: 'https://openrouter.ai/api/v1',
        openAIFormat: 'chat-completions',
      },
      env: {
        SHANNON_AI_MODEL: 'openai:anthropic/claude-sonnet-4.6',
        SHANNON_AI_BASE_URL: 'https://openrouter.ai/api/v1',
        SHANNON_AI_OPENAI_FORMAT: 'chat-completions',
        SHANNON_AI_API_KEY: 'environment-openrouter-secret',
      },
    });

    expect(runtime.model).toMatchObject({
      provider: 'openai',
      id: 'anthropic/claude-opus-4.6',
      baseUrl: 'https://openrouter.ai/api/v1',
      api: 'openai-completions',
    });
    expect(runtime.credentials.get('openai')).toBe('environment-openrouter-secret');
  });

  it('creates a usable synthetic model for an unknown generic gateway', async () => {
    const { resolvePiModelRuntime } = await import('../src/ai/pi/model-runtime.js');
    const runtime = await resolvePiModelRuntime({
      providerConfig: {
        providerType: 'generic',
        providerId: 'private-router',
        apiKey: 'router-secret',
        baseUrl: 'https://router.test/v1',
        openAIFormat: 'chat-completions',
        model: 'team/security-model',
      },
      env: {},
    });

    expect(runtime.model).toMatchObject({
      provider: 'private-router',
      id: 'team/security-model',
      baseUrl: 'https://router.test/v1',
      api: 'openai-completions',
    });
    expect(runtime.selection.openAIFormat).toBe('chat-completions');
    expect(runtime.credentials.get('private-router')).toBe('router-secret');
  });

  it.each([
    {
      source: 'bearer token',
      env: {
        AWS_BEARER_TOKEN_BEDROCK: 'bearer-token',
        AWS_REGION: 'us-east-1',
      },
      expectedCredential: {
        type: 'api_key',
        key: 'bearer-token',
        env: { AWS_REGION: 'us-east-1' },
      },
    },
    {
      source: 'access-key session',
      env: {
        AWS_ACCESS_KEY_ID: 'access-key',
        AWS_SECRET_ACCESS_KEY: 'secret-key',
        AWS_SESSION_TOKEN: 'session-token',
        AWS_DEFAULT_REGION: 'us-west-2',
      },
      expectedCredential: {
        type: 'api_key',
        env: {
          AWS_ACCESS_KEY_ID: 'access-key',
          AWS_SECRET_ACCESS_KEY: 'secret-key',
          AWS_SESSION_TOKEN: 'session-token',
          AWS_DEFAULT_REGION: 'us-west-2',
        },
      },
    },
    {
      source: 'profile',
      env: {
        AWS_PROFILE: 'audit-role',
        AWS_SHARED_CREDENTIALS_FILE: '/tmp/.aws/credentials',
        AWS_CONFIG_FILE: '/tmp/.aws/config',
      },
      expectedCredential: {
        type: 'api_key',
        env: {
          AWS_PROFILE: 'audit-role',
          AWS_SHARED_CREDENTIALS_FILE: '/tmp/.aws/credentials',
          AWS_CONFIG_FILE: '/tmp/.aws/config',
        },
      },
    },
    {
      source: 'web identity',
      env: {
        AWS_WEB_IDENTITY_TOKEN_FILE: '/tmp/shannon-aws-web-identity-token',
        AWS_ROLE_ARN: 'arn:aws:iam::123456789012:role/audit',
        AWS_ROLE_SESSION_NAME: 'shannon',
      },
      expectedCredential: {
        type: 'api_key',
        env: {
          AWS_WEB_IDENTITY_TOKEN_FILE: '/tmp/shannon-aws-web-identity-token',
          AWS_ROLE_ARN: 'arn:aws:iam::123456789012:role/audit',
          AWS_ROLE_SESSION_NAME: 'shannon',
        },
      },
    },
    {
      source: 'ECS task role',
      env: {
        AWS_CONTAINER_CREDENTIALS_FULL_URI: 'http://169.254.170.2/v2/credentials/id',
        AWS_CONTAINER_AUTHORIZATION_TOKEN: 'container-token',
      },
      expectedCredential: {
        type: 'api_key',
        env: {
          AWS_CONTAINER_CREDENTIALS_FULL_URI: 'http://169.254.170.2/v2/credentials/id',
          AWS_CONTAINER_AUTHORIZATION_TOKEN: 'container-token',
        },
      },
    },
  ])('preserves the selected Bedrock $source mechanism in memory', async ({ env, expectedCredential }) => {
    const { resolvePiModelRuntime } = await import('../src/ai/pi/model-runtime.js');
    const runtime = await resolvePiModelRuntime({
      env: {
        SHANNON_AI_MODEL: 'amazon-bedrock:us.anthropic.claude-sonnet-4-6',
        ...env,
      },
    });

    expect(runtime.selection.credential.configured).toBe(true);
    expect(await runtime.credentials.read('amazon-bedrock')).toEqual(expectedCredential);
    if (!('key' in expectedCredential)) expect(runtime.credentials.get('amazon-bedrock')).toBeUndefined();
  });

  it('preserves a temporary Bedrock access-key ProviderConfig as AWS environment', async () => {
    const { resolvePiModelRuntime } = await import('../src/ai/pi/model-runtime.js');
    const runtime = await resolvePiModelRuntime({
      providerConfig: {
        providerType: 'amazon-bedrock',
        model: 'us.anthropic.claude-sonnet-4-6',
        awsRegion: 'us-east-1',
        awsAccessKeyId: 'access-key',
        awsSecretAccessKey: 'secret-key',
        awsSessionToken: 'session-token',
      },
      env: {},
    });

    expect(await runtime.credentials.read('amazon-bedrock')).toEqual({
      type: 'api_key',
      env: {
        AWS_REGION: 'us-east-1',
        AWS_ACCESS_KEY_ID: 'access-key',
        AWS_SECRET_ACCESS_KEY: 'secret-key',
        AWS_SESSION_TOKEN: 'session-token',
      },
    });
    expect(runtime.credentials.get('amazon-bedrock')).toBeUndefined();
  });
});

describe('Pi execution safety foundations', () => {
  it('propagates cancellation instead of converting it to an ordinary failed result', async () => {
    const { runPiPrompt } = await import('../src/ai/pi/pi-executor.js');
    const cwd = await fs.mkdtemp(path.join(os.tmpdir(), 'shannon-pi-cancel-'));
    const controller = new AbortController();
    const reason = new Error('temporal activity cancelled');
    controller.abort(reason);

    try {
      await expect(
        runPiPrompt({
          prompt: 'Do work',
          workingDirectory: cwd,
          description: 'Cancellation proof',
          logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
          cancellationSignal: controller.signal,
          runtimeOptions: { modelTier: 'medium' },
        }),
      ).rejects.toBe(reason);
    } finally {
      await fs.rm(cwd, { recursive: true, force: true });
    }
  });

  it('requires bounded bash timeouts', async () => {
    const { evaluateBashTimeout } = await import('../src/ai/extensions/bash-timeout/index.js');

    expect(evaluateBashTimeout(undefined)).toMatchObject({ block: true });
    expect(evaluateBashTimeout(Number.POSITIVE_INFINITY)).toMatchObject({ block: true });
    expect(evaluateBashTimeout(601)).toMatchObject({ block: true });
    expect(evaluateBashTimeout(120)).toBeUndefined();
  });

  it('relays an already-aborted signal and removes live listeners', async () => {
    const { attachCancellation } = await import('../src/ai/pi/pi-executor.js');
    const alreadyAborted = new AbortController();
    alreadyAborted.abort();
    const abort = vi.fn();

    attachCancellation(alreadyAborted.signal, abort)();
    expect(abort).toHaveBeenCalledTimes(1);

    const live = new AbortController();
    const liveAbort = vi.fn();
    const cleanup = attachCancellation(live.signal, liveAbort);
    live.abort();
    cleanup();
    expect(liveAbort).toHaveBeenCalledTimes(1);
  });

  it('aggregates top-level and child usage including failed-run spend', async () => {
    const { aggregatePiUsage } = await import('../src/ai/pi/pi-executor.js');

    expect(
      aggregatePiUsage(
        { cost: 1.25, tokens: { input: 10, output: 20, cacheRead: 30, cacheWrite: 40 } },
        { cost: 2.5, inputTokens: 1, outputTokens: 2, cacheReadTokens: 3, cacheWriteTokens: 4 },
      ),
    ).toEqual({ cost: 3.75, inputTokens: 11, outputTokens: 22, cacheReadTokens: 33, cacheWriteTokens: 44 });
  });

  it('keeps cwd at workingDirectory and resolves optional deliverables paths beneath it', async () => {
    const { buildPiExecutionPaths } = await import('../src/ai/pi/pi-executor.js');

    expect(buildPiExecutionPaths('/tmp/assessment', 'artifacts/results')).toEqual({
      cwd: '/tmp/assessment',
      deliverablesDir: '/tmp/assessment/artifacts/results',
      playwrightOutputDir: '/tmp/assessment/artifacts/.playwright-cli',
    });
  });

  it('redacts audit, console, error-file, and returned failure surfaces', async () => {
    const { runPiPrompt } = await import('../src/ai/pi/pi-executor.js');
    const secret = 'pi-runtime-secret';
    const cwd = await fs.mkdtemp(path.join(os.tmpdir(), 'shannon-pi-redaction-'));
    const auditEvents: unknown[] = [];
    const consoleLog = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    const previousLoaderSetting = global.SHANNON_DISABLE_LOADER;
    global.SHANNON_DISABLE_LOADER = true;
    try {
      const auditSession = {
        redactText: (value: string) => value.replaceAll(secret, '[REDACTED]'),
        redactValue: <T>(value: T): T => JSON.parse(JSON.stringify(value).replaceAll(secret, '[REDACTED]')) as T,
        logEvent: async (_eventType: string, data: unknown) => {
          auditEvents.push(data);
        },
      };
      const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
      const result = await runPiPrompt({
        prompt: `Do not echo ${secret}`,
        workingDirectory: cwd,
        description: 'Pi redaction proof',
        auditSession: auditSession as never,
        logger,
        deliverablesSubdir: 'artifacts',
        runtimeOptions: {
          providerConfig: {
            providerType: 'generic',
            providerId: 'private-provider',
            apiKey: secret,
            model: secret,
          },
          env: {},
        },
      });

      const errorLog = await fs.readFile(path.join(cwd, 'artifacts', 'error.log'), 'utf8');
      expect(result.success).toBe(false);
      expect(JSON.stringify(result)).not.toContain(secret);
      expect(JSON.stringify(auditEvents)).not.toContain(secret);
      expect(JSON.stringify(consoleLog.mock.calls)).not.toContain(secret);
      expect(errorLog).not.toContain(secret);
    } finally {
      global.SHANNON_DISABLE_LOADER = previousLoaderSetting;
      consoleLog.mockRestore();
      await fs.rm(cwd, { recursive: true, force: true });
    }
  });
});

describe('Pi custom tools', () => {
  it('captures vulnerability queues with the named TypeBox tool and optional code locations', async () => {
    const { createQueueSubmitTool } = await import('../src/ai/queue-schemas.js');
    const submit = createQueueSubmitTool('injection-vuln', true);

    expect(submit?.tool.name).toBe('submit_exploitation_queue');
    const payload = {
      vulnerabilities: [
        {
          ID: 'INJECTION-VULN-01',
          vulnerability_type: 'SQL injection',
          externally_exploitable: true,
          confidence: 'high',
          code_locations: [{ file: 'src/query.ts', start_line: 12, role: 'sink' }],
        },
      ],
    };
    await submit?.tool.execute('queue-1', payload, undefined, undefined, {} as never);
    expect(submit?.getCaptured()).toEqual(payload);
    expect(submit?.directive).toMatch(/submit_exploitation_queue/);
  });

  it('captures authentication verdicts with the named TypeBox tool', async () => {
    const authModule = await import('../src/services/validate-authentication.js');
    const submit = authModule.createAuthSubmitTool();

    expect(submit.tool.name).toBe('submit_auth_result');
    await submit.tool.execute(
      'auth-1',
      { login_success: false, failure_point: 'username_or_password', failure_detail: 'Rejected.' },
      undefined,
      undefined,
      {} as never,
    );
    expect(submit.getCaptured()).toMatchObject({ login_success: false, failure_point: 'username_or_password' });
    expect(submit.directive).toMatch(/submit_auth_result/);
  });

  it('captures a TypeBox-backed structured submission and terminates the turn', async () => {
    const { createGenericSubmitTool } = await import('../src/ai/submit-tool.js');
    const submit = createGenericSubmitTool({
      type: 'object',
      properties: { verdict: { type: 'string' } },
      required: ['verdict'],
      additionalProperties: false,
    });

    const result = await submit.tool.execute('call-1', { verdict: 'confirmed' }, undefined, undefined, {} as never);
    expect(submit.getCaptured()).toEqual({ verdict: 'confirmed' });
    expect(result).toMatchObject({ terminate: true });
    expect(submit.directive).toMatch(/submit_result/);
  });

  it('replaces todo state and globs files from the working directory', async () => {
    const { createGlobTool, createTodoWriteTool } = await import('../src/ai/pi/session-tools.js');
    const note = vi.fn(async () => undefined);
    const todo = createTodoWriteTool({ logNote: note });
    await todo.execute(
      'todo-1',
      { todos: [{ content: 'Map routes', status: 'in_progress', activeForm: 'Mapping routes' }] },
      undefined,
      undefined,
      {} as never,
    );
    expect(note).toHaveBeenCalledWith('todo', '[~] Map routes');

    const cwd = await fs.mkdtemp(path.join(os.tmpdir(), 'shannon-pi-tools-'));
    try {
      await fs.mkdir(path.join(cwd, 'src'));
      await fs.writeFile(path.join(cwd, 'src', 'one.ts'), 'export {};');
      const glob = createGlobTool(cwd);
      const result = await glob.execute('glob-1', { pattern: '**/*.ts' }, undefined, undefined, {} as never);
      expect(result.content[0]).toMatchObject({ type: 'text', text: path.join(cwd, 'src', 'one.ts') });
    } finally {
      await fs.rm(cwd, { recursive: true, force: true });
    }
  });

  it('translates code_path avoids into cross-tool deny rules', async () => {
    const { buildPermissionConfig } = await import('../src/ai/pi/permission-system.js');

    expect(buildPermissionConfig(['secrets'])).toEqual({
      permission: {
        '*': 'allow',
        path: {
          '*': 'allow',
          secrets: 'deny',
          'secrets/*': 'deny',
          '*/secrets': 'deny',
          '*/secrets/*': 'deny',
        },
        external_directory: 'allow',
      },
    });
  });
});

describe('runtime secret collection', () => {
  it('includes every supported Pi provider key', async () => {
    const { collectRuntimeProviderSecrets } = await import('../src/services/redaction.js');
    const previous = {
      OPENAI_API_KEY: process.env.OPENAI_API_KEY,
      XAI_API_KEY: process.env.XAI_API_KEY,
      SHANNON_AI_API_KEY: process.env.SHANNON_AI_API_KEY,
      AWS_SESSION_TOKEN: process.env.AWS_SESSION_TOKEN,
      AWS_CONTAINER_AUTHORIZATION_TOKEN: process.env.AWS_CONTAINER_AUTHORIZATION_TOKEN,
    };
    process.env.OPENAI_API_KEY = 'openai-secret';
    process.env.XAI_API_KEY = 'xai-secret';
    process.env.SHANNON_AI_API_KEY = 'gateway-secret';
    process.env.AWS_SESSION_TOKEN = 'session-secret';
    process.env.AWS_CONTAINER_AUTHORIZATION_TOKEN = 'ecs-secret';

    try {
      expect(collectRuntimeProviderSecrets()).toEqual(
        expect.arrayContaining(['openai-secret', 'xai-secret', 'gateway-secret', 'session-secret', 'ecs-secret']),
      );
    } finally {
      for (const [name, value] of Object.entries(previous)) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
    }
  });
});
