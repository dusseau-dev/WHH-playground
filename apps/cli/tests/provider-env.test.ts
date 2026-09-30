import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { buildEnvFlags, resolveProviderCredentialFiles, validateCredentials } from '../src/env.js';

const PROVIDER_ENV = [
  'SHANNON_AI_MODEL',
  'SHANNON_AI_API_KEY',
  'SHANNON_AI_BASE_URL',
  'SHANNON_AI_OPENAI_FORMAT',
  'ANTHROPIC_API_KEY',
  'ANTHROPIC_BASE_URL',
  'ANTHROPIC_AUTH_TOKEN',
  'CLAUDE_CODE_OAUTH_TOKEN',
  'OPENAI_API_KEY',
  'XAI_API_KEY',
  'CLAUDE_CODE_USE_BEDROCK',
  'AWS_REGION',
  'AWS_DEFAULT_REGION',
  'AWS_BEARER_TOKEN_BEDROCK',
  'AWS_ACCESS_KEY_ID',
  'AWS_SECRET_ACCESS_KEY',
  'AWS_SESSION_TOKEN',
  'AWS_PROFILE',
  'AWS_SHARED_CREDENTIALS_FILE',
  'AWS_CONFIG_FILE',
  'AWS_SDK_LOAD_CONFIG',
  'AWS_WEB_IDENTITY_TOKEN_FILE',
  'AWS_ROLE_ARN',
  'AWS_ROLE_SESSION_NAME',
  'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI',
  'AWS_CONTAINER_CREDENTIALS_FULL_URI',
  'AWS_CONTAINER_AUTHORIZATION_TOKEN',
  'AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE',
  'CLAUDE_CODE_USE_VERTEX',
  'ANTHROPIC_SMALL_MODEL',
  'ANTHROPIC_MEDIUM_MODEL',
  'ANTHROPIC_LARGE_MODEL',
] as const;

const original = Object.fromEntries(PROVIDER_ENV.map((name) => [name, process.env[name]]));

function cleanProviderEnv(): void {
  for (const name of PROVIDER_ENV) delete process.env[name];
}

afterEach(() => {
  cleanProviderEnv();
  for (const [name, value] of Object.entries(original)) {
    if (value !== undefined) process.env[name] = value;
  }
});

describe('provider-scoped Docker environment forwarding', () => {
  it('forwards names only for the selected provider and never puts secret values in argv', () => {
    cleanProviderEnv();
    process.env.SHANNON_AI_MODEL = 'openai:gpt-5.2';
    process.env.SHANNON_AI_BASE_URL = 'https://gateway.test/v1';
    process.env.OPENAI_API_KEY = 'selected-secret';
    process.env.ANTHROPIC_API_KEY = 'unused-anthropic-secret';
    process.env.XAI_API_KEY = 'unused-xai-secret';
    process.env.SHANNON_AI_API_KEY = 'unused-generic-secret';

    const args = buildEnvFlags();

    expect(args).toContain('SHANNON_AI_MODEL');
    expect(args).toContain('SHANNON_AI_BASE_URL');
    expect(args).toContain('OPENAI_API_KEY');
    expect(args).not.toContain('ANTHROPIC_API_KEY');
    expect(args).not.toContain('XAI_API_KEY');
    expect(args).not.toContain('SHANNON_AI_API_KEY');
    expect(args.join(' ')).not.toContain('selected-secret');
    expect(args.join(' ')).not.toContain('unused-anthropic-secret');
    expect(args).not.toContain('OPENAI_API_KEY=selected-secret');
  });

  it('forwards the generic credential only when it is the selected credential', () => {
    cleanProviderEnv();
    process.env.SHANNON_AI_MODEL = 'google:gemini-2.5-pro';
    process.env.SHANNON_AI_API_KEY = 'generic-secret';
    process.env.OPENAI_API_KEY = 'unused-secret';

    expect(buildEnvFlags()).toEqual([
      '-e',
      'TEMPORAL_ADDRESS=shannon-temporal:7233',
      '-e',
      'SHANNON_AI_MODEL',
      '-e',
      'SHANNON_AI_API_KEY',
    ]);
    expect(validateCredentials()).toMatchObject({ valid: true });
  });

  it('retains legacy Bedrock forwarding without forwarding unrelated providers', () => {
    cleanProviderEnv();
    process.env.CLAUDE_CODE_USE_BEDROCK = '1';
    process.env.AWS_REGION = 'us-east-1';
    process.env.AWS_BEARER_TOKEN_BEDROCK = 'bedrock-secret';
    process.env.ANTHROPIC_LARGE_MODEL = 'us.anthropic.claude-opus-v1:0';
    process.env.ANTHROPIC_API_KEY = 'unused-secret';

    const args = buildEnvFlags();
    expect(args).toContain('CLAUDE_CODE_USE_BEDROCK');
    expect(args).toContain('AWS_REGION');
    expect(args).toContain('AWS_BEARER_TOKEN_BEDROCK');
    expect(args).toContain('ANTHROPIC_LARGE_MODEL');
    expect(args).not.toContain('ANTHROPIC_API_KEY');
    expect(args.join(' ')).not.toContain('bedrock-secret');
  });

  it('accepts and forwards a Bedrock access-key pair with an optional session token', () => {
    cleanProviderEnv();
    process.env.SHANNON_AI_MODEL = 'amazon-bedrock:us.anthropic.claude-sonnet-4-6';
    process.env.AWS_DEFAULT_REGION = 'us-west-2';
    process.env.AWS_ACCESS_KEY_ID = 'access-key';
    process.env.AWS_SECRET_ACCESS_KEY = 'secret-key';
    process.env.AWS_SESSION_TOKEN = 'session-token';
    process.env.OPENAI_API_KEY = 'unused-secret';

    const args = buildEnvFlags();
    expect(validateCredentials()).toMatchObject({ valid: true, mode: 'bedrock' });
    expect(args).toEqual([
      '-e',
      'TEMPORAL_ADDRESS=shannon-temporal:7233',
      '-e',
      'SHANNON_AI_MODEL',
      '-e',
      'AWS_ACCESS_KEY_ID',
      '-e',
      'AWS_SECRET_ACCESS_KEY',
      '-e',
      'AWS_SESSION_TOKEN',
      '-e',
      'AWS_DEFAULT_REGION',
    ]);
    expect(args.join(' ')).not.toContain('secret-key');
    expect(args).not.toContain('OPENAI_API_KEY');
  });

  it.each([
    {
      name: 'profile',
      values: {
        AWS_PROFILE: 'audit-role',
        AWS_CONFIG_FILE: '/aws/config',
        AWS_SHARED_CREDENTIALS_FILE: '/aws/credentials',
      },
      expected: ['AWS_PROFILE', 'AWS_SHARED_CREDENTIALS_FILE', 'AWS_CONFIG_FILE'],
    },
    {
      name: 'web identity',
      values: {
        AWS_WEB_IDENTITY_TOKEN_FILE: '/var/run/secrets/aws/token',
        AWS_ROLE_ARN: 'arn:aws:iam::123456789012:role/audit',
        AWS_ROLE_SESSION_NAME: 'shannon',
      },
      expected: ['AWS_WEB_IDENTITY_TOKEN_FILE', 'AWS_ROLE_ARN', 'AWS_ROLE_SESSION_NAME'],
    },
    {
      name: 'ECS relative URI',
      values: {
        AWS_CONTAINER_CREDENTIALS_RELATIVE_URI: '/v2/credentials/id',
      },
      expected: ['AWS_CONTAINER_CREDENTIALS_RELATIVE_URI'],
    },
    {
      name: 'ECS full URI',
      values: {
        AWS_CONTAINER_CREDENTIALS_FULL_URI: 'http://169.254.170.2/v2/credentials/id',
        AWS_CONTAINER_AUTHORIZATION_TOKEN: 'container-token',
      },
      expected: ['AWS_CONTAINER_CREDENTIALS_FULL_URI', 'AWS_CONTAINER_AUTHORIZATION_TOKEN'],
    },
  ])('accepts and forwards the Bedrock $name credential environment', ({ values, expected }) => {
    cleanProviderEnv();
    process.env.SHANNON_AI_MODEL = 'amazon-bedrock:us.anthropic.claude-sonnet-4-6';
    Object.assign(process.env, values);

    const args = buildEnvFlags();
    expect(validateCredentials()).toMatchObject({ valid: true, mode: 'bedrock' });
    for (const name of expected) expect(args).toContain(name);
  });

  it('forwards only the highest-priority configured Bedrock credential source', () => {
    cleanProviderEnv();
    process.env.SHANNON_AI_MODEL = 'amazon-bedrock:us.anthropic.claude-sonnet-4-6';
    process.env.AWS_BEARER_TOKEN_BEDROCK = 'selected-token';
    process.env.AWS_ACCESS_KEY_ID = 'unused-access-key';
    process.env.AWS_SECRET_ACCESS_KEY = 'unused-secret-key';
    process.env.AWS_PROFILE = 'unused-profile';

    const args = buildEnvFlags();
    expect(args).toContain('AWS_BEARER_TOKEN_BEDROCK');
    expect(args).not.toContain('AWS_ACCESS_KEY_ID');
    expect(args).not.toContain('AWS_SECRET_ACCESS_KEY');
    expect(args).not.toContain('AWS_PROFILE');
  });

  it('resolves selected AWS profile files to fixed read-only container paths', () => {
    cleanProviderEnv();
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'shannon-aws-profile-'));
    const credentialsPath = path.join(directory, 'credentials');
    const configPath = path.join(directory, 'config');
    fs.writeFileSync(credentialsPath, '[audit-role]\naws_access_key_id = test\n');
    fs.writeFileSync(configPath, '[profile audit-role]\nregion = us-east-1\n');
    process.env.SHANNON_AI_MODEL = 'amazon-bedrock:us.anthropic.claude-sonnet-4-6';
    process.env.AWS_PROFILE = 'audit-role';
    process.env.AWS_SHARED_CREDENTIALS_FILE = credentialsPath;
    process.env.AWS_CONFIG_FILE = configPath;

    try {
      expect(resolveProviderCredentialFiles()).toEqual([
        {
          environmentName: 'AWS_SHARED_CREDENTIALS_FILE',
          hostPath: fs.realpathSync(credentialsPath),
          containerPath: '/tmp/.aws/credentials',
        },
        {
          environmentName: 'AWS_CONFIG_FILE',
          hostPath: fs.realpathSync(configPath),
          containerPath: '/tmp/.aws/config',
        },
      ]);
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });

  it('resolves a selected web-identity token to a fixed container path and rejects missing files', () => {
    cleanProviderEnv();
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'shannon-web-identity-'));
    const tokenPath = path.join(directory, 'token');
    fs.writeFileSync(tokenPath, 'token-value');
    process.env.SHANNON_AI_MODEL = 'amazon-bedrock:us.anthropic.claude-sonnet-4-6';
    process.env.AWS_WEB_IDENTITY_TOKEN_FILE = tokenPath;

    try {
      expect(resolveProviderCredentialFiles()).toEqual([
        {
          environmentName: 'AWS_WEB_IDENTITY_TOKEN_FILE',
          hostPath: fs.realpathSync(tokenPath),
          containerPath: '/tmp/shannon-aws-web-identity-token',
        },
      ]);
      process.env.AWS_WEB_IDENTITY_TOKEN_FILE = path.join(directory, 'missing-token');
      expect(() => resolveProviderCredentialFiles()).toThrow(/AWS_WEB_IDENTITY_TOKEN_FILE.*existing file/i);
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });

  it('returns a clear migration error for unsupported legacy Vertex settings', () => {
    cleanProviderEnv();
    process.env.CLAUDE_CODE_USE_VERTEX = '1';
    expect(validateCredentials()).toMatchObject({
      valid: false,
      error: expect.stringMatching(/Vertex AI.*no longer supported.*SHANNON_AI_MODEL/i),
    });
  });
});
