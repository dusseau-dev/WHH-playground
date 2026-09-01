import { beforeEach, describe, expect, it, vi } from 'vitest';

const createAgentSessionMock = vi.hoisted(() => vi.fn());

vi.mock('@earendil-works/pi-coding-agent', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@earendil-works/pi-coding-agent')>()),
  createAgentSession: createAgentSessionMock,
}));

import { validatePiCredentials } from '../src/services/preflight.js';

describe('Pi preflight gateway diagnostic redaction', () => {
  beforeEach(() => {
    createAgentSessionMock.mockReset();
    createAgentSessionMock.mockResolvedValue({
      session: {
        abort: vi.fn(),
        dispose: vi.fn(),
        prompt: vi.fn().mockRejectedValue(new Error('401 unauthorized')),
        subscribe: vi.fn(),
      },
    });
  });

  it.each([
    {
      caseName: 'URL userinfo',
      baseUrl: 'https://gateway-user:gateway-password@gateway.example/v1',
      secrets: ['gateway-user', 'gateway-password'],
    },
    {
      caseName: 'query and fragment tokens',
      baseUrl: 'https://gateway.example/v1?access_token=query-secret#fragment-secret',
      secrets: ['access_token', 'query-secret', 'fragment-secret'],
    },
  ])('removes $caseName from logs and errors while preserving the request URL', async ({ baseUrl, secrets }) => {
    const info = vi.fn();
    const result = await validatePiCredentials('/tmp', { info, warn: vi.fn(), error: vi.fn() }, undefined, {
      providerType: 'generic',
      providerId: 'private-router',
      model: 'security-model',
      apiKey: 'provider-api-key',
      baseUrl,
      openAIFormat: 'chat-completions',
    });

    expect(result.ok).toBe(false);
    if (result.ok) throw new Error('Expected credential validation to fail');

    const logged = info.mock.calls.map(([message]) => message).join('\n');
    const diagnostic = `${logged}\n${result.error.message}\n${JSON.stringify(result.error.context)}`;
    expect(diagnostic).toContain('custom endpoint (https://gateway.example/v1)');
    for (const secret of secrets) expect(diagnostic).not.toContain(secret);

    expect(createAgentSessionMock).toHaveBeenCalledOnce();
    expect(createAgentSessionMock.mock.calls[0]?.[0].model.baseUrl).toBe(baseUrl);
  });
});
