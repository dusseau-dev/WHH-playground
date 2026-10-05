import { afterEach, describe, expect, it, vi } from 'vitest';
import { resolveModelSelection } from '../src/ai/model-resolver.js';
import { parseModelSpec } from '../src/ai/model-spec.js';

afterEach(() => {
  vi.restoreAllMocks();
});

describe('model spec parsing', () => {
  it('splits on only the first colon so Bedrock model ids remain intact', () => {
    expect(parseModelSpec('amazon-bedrock:us.anthropic.claude-opus-4-5-v1:0')).toEqual({
      providerId: 'amazon-bedrock',
      modelId: 'us.anthropic.claude-opus-4-5-v1:0',
    });
  });

  it.each(['claude-sonnet-4-6', ':model', 'provider:'])('rejects malformed spec %s', (spec) => {
    expect(() => parseModelSpec(spec)).toThrow(/<provider>:<model-id>/);
  });
});

describe('provider-compatible model resolution', () => {
  it('gives per-run provider configuration precedence without exposing its API key', () => {
    const selection = resolveModelSelection({
      modelTier: 'medium',
      providerConfig: {
        providerType: 'openai',
        apiKey: 'per-run-secret',
        baseUrl: 'https://gateway.test/v1',
        openAIFormat: 'responses',
        modelOverrides: { medium: 'gpt-5.2' },
      },
      env: {
        SHANNON_AI_MODEL: 'anthropic:claude-env',
        ANTHROPIC_MEDIUM_MODEL: 'claude-legacy',
      },
    });

    expect(selection).toMatchObject({
      providerId: 'openai',
      modelId: 'gpt-5.2',
      source: 'provider-config',
      baseUrl: 'https://gateway.test/v1',
      openAIFormat: 'responses',
      credential: { configured: true, source: 'provider-config', name: 'apiKey' },
    });
    expect(JSON.stringify(selection)).not.toContain('per-run-secret');
    expect(selection.environmentNames).toEqual([]);
  });

  it('uses the configured environment credential for a keyless model override', () => {
    const selection = resolveModelSelection({
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

    expect(selection).toMatchObject({
      providerId: 'openai',
      modelId: 'anthropic/claude-opus-4.6',
      source: 'provider-config',
      credential: { configured: true, source: 'environment', name: 'SHANNON_AI_API_KEY' },
    });
    expect(JSON.stringify(selection)).not.toContain('environment-openrouter-secret');
  });

  it('uses SHANNON_AI_MODEL before tier variables and warns once about the mixed configuration', () => {
    const warn = vi.fn();
    const env = {
      SHANNON_AI_MODEL: 'xai:grok-4:fast',
      SHANNON_AI_API_KEY: 'generic-secret',
      ANTHROPIC_MEDIUM_MODEL: 'claude-legacy',
    };

    const first = resolveModelSelection({ modelTier: 'medium', env, warn });
    const second = resolveModelSelection({ modelTier: 'medium', env, warn });

    expect(first).toMatchObject({
      providerId: 'xai',
      modelId: 'grok-4:fast',
      source: 'shannon-ai-model',
      credential: { configured: true, source: 'environment', name: 'SHANNON_AI_API_KEY' },
    });
    expect(first.environmentNames).toEqual(['SHANNON_AI_MODEL', 'SHANNON_AI_API_KEY']);
    expect(second.modelId).toBe('grok-4:fast');
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0]?.[0]).not.toContain('generic-secret');
  });

  it('preserves legacy Anthropic model tiers and defaults', () => {
    expect(
      resolveModelSelection({
        modelTier: 'small',
        env: { ANTHROPIC_SMALL_MODEL: 'claude-legacy-small', ANTHROPIC_API_KEY: 'secret' },
      }),
    ).toMatchObject({ providerId: 'anthropic', modelId: 'claude-legacy-small', source: 'legacy' });

    expect(resolveModelSelection({ modelTier: 'large', env: {} })).toMatchObject({
      providerId: 'anthropic',
      modelId: 'claude-opus-4-7',
      source: 'legacy',
    });
  });

  it('maps legacy LiteLLM and Bedrock settings to their runtime providers', () => {
    expect(
      resolveModelSelection({
        modelTier: 'medium',
        env: {
          ANTHROPIC_BASE_URL: 'https://litellm.test',
          ANTHROPIC_AUTH_TOKEN: 'router-secret',
          ANTHROPIC_MEDIUM_MODEL: 'router-model',
        },
      }),
    ).toMatchObject({
      providerId: 'anthropic',
      modelId: 'router-model',
      baseUrl: 'https://litellm.test',
      credential: { name: 'ANTHROPIC_AUTH_TOKEN' },
    });

    expect(
      resolveModelSelection({
        modelTier: 'large',
        env: {
          CLAUDE_CODE_USE_BEDROCK: '1',
          AWS_REGION: 'us-east-1',
          AWS_BEARER_TOKEN_BEDROCK: 'bedrock-secret',
          ANTHROPIC_LARGE_MODEL: 'us.anthropic.claude-opus-v1:0',
        },
      }),
    ).toMatchObject({
      providerId: 'amazon-bedrock',
      modelId: 'us.anthropic.claude-opus-v1:0',
      credential: { configured: true, name: 'AWS_BEARER_TOKEN_BEDROCK' },
    });
  });

  it('selects and scopes a Bedrock access-key pair with its optional session token', () => {
    const selection = resolveModelSelection({
      env: {
        SHANNON_AI_MODEL: 'amazon-bedrock:us.anthropic.claude-sonnet-4-6',
        AWS_DEFAULT_REGION: 'us-west-2',
        AWS_ACCESS_KEY_ID: 'access-key',
        AWS_SECRET_ACCESS_KEY: 'secret-key',
        AWS_SESSION_TOKEN: 'session-token',
        OPENAI_API_KEY: 'unrelated-secret',
      },
    });

    expect(selection.credential).toEqual({
      configured: true,
      source: 'environment',
      name: 'AWS_ACCESS_KEY_ID',
      names: ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN'],
    });
    expect(selection.environmentNames).toEqual([
      'SHANNON_AI_MODEL',
      'AWS_ACCESS_KEY_ID',
      'AWS_SECRET_ACCESS_KEY',
      'AWS_SESSION_TOKEN',
      'AWS_DEFAULT_REGION',
    ]);
  });

  it.each([
    {
      source: 'profile',
      env: {
        AWS_PROFILE: 'audit-role',
        AWS_SHARED_CREDENTIALS_FILE: '/tmp/.aws/credentials',
        AWS_CONFIG_FILE: '/tmp/.aws/config',
      },
      credentialName: 'AWS_PROFILE',
      credentialNames: ['AWS_PROFILE', 'AWS_SHARED_CREDENTIALS_FILE', 'AWS_CONFIG_FILE'],
    },
    {
      source: 'web identity',
      env: {
        AWS_WEB_IDENTITY_TOKEN_FILE: '/tmp/shannon-aws-web-identity-token',
        AWS_ROLE_ARN: 'arn:aws:iam::123456789012:role/audit',
        AWS_ROLE_SESSION_NAME: 'shannon',
      },
      credentialName: 'AWS_WEB_IDENTITY_TOKEN_FILE',
      credentialNames: ['AWS_WEB_IDENTITY_TOKEN_FILE', 'AWS_ROLE_ARN', 'AWS_ROLE_SESSION_NAME'],
    },
    {
      source: 'ECS task role',
      env: {
        AWS_CONTAINER_CREDENTIALS_FULL_URI: 'http://169.254.170.2/v2/credentials/id',
        AWS_CONTAINER_AUTHORIZATION_TOKEN: 'container-token',
      },
      credentialName: 'AWS_CONTAINER_CREDENTIALS_FULL_URI',
      credentialNames: ['AWS_CONTAINER_CREDENTIALS_FULL_URI', 'AWS_CONTAINER_AUTHORIZATION_TOKEN'],
    },
  ])('selects and scopes the Bedrock $source environment', ({ env, credentialName, credentialNames }) => {
    const selection = resolveModelSelection({
      env: {
        SHANNON_AI_MODEL: 'amazon-bedrock:us.anthropic.claude-sonnet-4-6',
        ...env,
      },
    });

    expect(selection.credential).toEqual({
      configured: true,
      source: 'environment',
      name: credentialName,
      names: credentialNames,
    });
    expect(selection.environmentNames).toEqual(['SHANNON_AI_MODEL', ...credentialNames]);
  });

  it('selects only the highest-priority Bedrock credential mechanism', () => {
    const selection = resolveModelSelection({
      env: {
        SHANNON_AI_MODEL: 'amazon-bedrock:us.anthropic.claude-sonnet-4-6',
        AWS_BEARER_TOKEN_BEDROCK: 'bearer-token',
        AWS_PROFILE: 'unused-profile',
        AWS_ACCESS_KEY_ID: 'unused-access-key',
        AWS_SECRET_ACCESS_KEY: 'unused-secret-key',
      },
    });

    expect(selection.credential).toMatchObject({
      name: 'AWS_BEARER_TOKEN_BEDROCK',
      names: ['AWS_BEARER_TOKEN_BEDROCK'],
    });
    expect(selection.environmentNames).toEqual(['SHANNON_AI_MODEL', 'AWS_BEARER_TOKEN_BEDROCK']);
  });

  it('supports OpenAI-compatible and generic provider settings', () => {
    const openai = resolveModelSelection({
      env: {
        SHANNON_AI_MODEL: 'openai:gateway-model',
        SHANNON_AI_API_KEY: 'gateway-secret',
        SHANNON_AI_BASE_URL: 'https://gateway.test/v1',
        SHANNON_AI_OPENAI_FORMAT: 'chat-completions',
      },
    });
    expect(openai).toMatchObject({
      providerId: 'openai',
      modelId: 'gateway-model',
      baseUrl: 'https://gateway.test/v1',
      openAIFormat: 'chat-completions',
      credential: { name: 'SHANNON_AI_API_KEY' },
    });

    const generic = resolveModelSelection({
      env: {
        SHANNON_AI_MODEL: 'private-router:team/security-model',
        SHANNON_AI_API_KEY: 'generic-secret',
        SHANNON_AI_BASE_URL: 'https://router.test/v1',
        SHANNON_AI_OPENAI_FORMAT: 'responses',
      },
    });
    expect(generic).toMatchObject({
      providerId: 'private-router',
      modelId: 'team/security-model',
      baseUrl: 'https://router.test/v1',
      openAIFormat: 'responses',
      credential: { configured: true, name: 'SHANNON_AI_API_KEY' },
    });

    expect(
      resolveModelSelection({
        env: { SHANNON_AI_MODEL: 'google:gemini-2.5-pro', SHANNON_AI_API_KEY: 'generic-secret' },
      }),
    ).toMatchObject({
      providerId: 'google',
      modelId: 'gemini-2.5-pro',
      credential: { configured: true, name: 'SHANNON_AI_API_KEY' },
    });
  });

  it('rejects legacy Vertex with a migration-focused error', () => {
    expect(() =>
      resolveModelSelection({
        env: { CLAUDE_CODE_USE_VERTEX: '1', ANTHROPIC_VERTEX_PROJECT_ID: 'legacy-project' },
      }),
    ).toThrow(/Vertex AI.*no longer supported.*SHANNON_AI_MODEL/i);
  });
});
