import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const state = vi.hoisted(() => ({ configPath: '' }));

vi.mock('../src/home.js', () => ({
  getConfigFile: () => state.configPath,
}));

vi.mock('@clack/prompts', () => ({
  cancel: vi.fn(),
  confirm: vi.fn(),
  intro: vi.fn(),
  isCancel: vi.fn(() => false),
  log: { info: vi.fn(), success: vi.fn() },
  outro: vi.fn(),
  password: vi.fn(),
  path: vi.fn(),
  select: vi.fn(),
  text: vi.fn(),
}));

import * as prompts from '@clack/prompts';
import { setup } from '../src/commands/setup.js';
import { resolveConfig } from '../src/config/resolver.js';
import { saveConfig } from '../src/config/writer.js';
import { setMode } from '../src/mode.js';

const CONFIG_ENV = [
  'SHANNON_AI_MODEL',
  'SHANNON_AI_BASE_URL',
  'SHANNON_AI_OPENAI_FORMAT',
  'SHANNON_AI_API_KEY',
  'ANTHROPIC_API_KEY',
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
  'CLOUD_ML_REGION',
  'ANTHROPIC_VERTEX_PROJECT_ID',
  'GOOGLE_APPLICATION_CREDENTIALS',
  'ANTHROPIC_BASE_URL',
  'ANTHROPIC_AUTH_TOKEN',
  'ANTHROPIC_SMALL_MODEL',
  'ANTHROPIC_MEDIUM_MODEL',
  'ANTHROPIC_LARGE_MODEL',
  'CLAUDE_CODE_MAX_OUTPUT_TOKENS',
  'CLAUDE_ADAPTIVE_THINKING',
] as const;

let temporaryDirectory: string;
const originalEnv = Object.fromEntries(CONFIG_ENV.map((name) => [name, process.env[name]]));

function cleanConfigEnv(): void {
  for (const name of CONFIG_ENV) delete process.env[name];
}

function writeConfig(content: string): void {
  fs.writeFileSync(state.configPath, content, { mode: 0o600 });
}

beforeEach(() => {
  temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'shannon-config-'));
  state.configPath = path.join(temporaryDirectory, 'config.toml');
  cleanConfigEnv();
  setMode('npx');
  vi.clearAllMocks();
  vi.mocked(prompts.isCancel).mockReturnValue(false);
});

afterEach(() => {
  fs.rmSync(temporaryDirectory, { recursive: true, force: true });
  cleanConfigEnv();
  for (const [name, value] of Object.entries(originalEnv)) {
    if (value !== undefined) process.env[name] = value;
  }
  vi.restoreAllMocks();
});

describe('TOML compatibility and provider scoping', () => {
  it('loads only the selected provider from the new format and preserves environment precedence', () => {
    writeConfig(`
[core]
model = "openai:gpt-5.6-sol"
base_url = "https://gateway.test/v1"

[anthropic]
api_key = "unused-anthropic"

[openai]
api_key = "toml-openai"
format = "responses"

[xai]
api_key = "unused-xai"

[provider]
api_key = "unused-generic"
`);
    process.env.OPENAI_API_KEY = 'environment-openai';

    resolveConfig();

    expect(process.env.SHANNON_AI_MODEL).toBe('openai:gpt-5.6-sol');
    expect(process.env.SHANNON_AI_BASE_URL).toBe('https://gateway.test/v1');
    expect(process.env.SHANNON_AI_OPENAI_FORMAT).toBe('responses');
    expect(process.env.OPENAI_API_KEY).toBe('environment-openai');
    expect(process.env.ANTHROPIC_API_KEY).toBeUndefined();
    expect(process.env.XAI_API_KEY).toBeUndefined();
    expect(process.env.SHANNON_AI_API_KEY).toBeUndefined();
  });

  it.each(['anthropic', 'openai', 'xai'])('accepts provider.api_key for curated %s models', (provider) => {
    writeConfig(`
[core]
model = "${provider}:test-model"

[provider]
api_key = "generic-key"
`);

    resolveConfig();

    expect(process.env.SHANNON_AI_API_KEY).toBe('generic-key');
    expect(process.env.ANTHROPIC_API_KEY).toBeUndefined();
    expect(process.env.OPENAI_API_KEY).toBeUndefined();
    expect(process.env.XAI_API_KEY).toBeUndefined();
  });

  it.each([
    'anthropic',
    'openai',
    'xai',
  ])('accepts an exported SHANNON_AI_API_KEY for curated %s models', (provider) => {
    writeConfig(`
[core]
model = "${provider}:test-model"
`);
    process.env.SHANNON_AI_API_KEY = 'exported-generic';

    resolveConfig();

    expect(process.env.SHANNON_AI_API_KEY).toBe('exported-generic');
  });

  it('preserves an exported SHANNON_AI_API_KEY over a provider-specific TOML key', () => {
    writeConfig(`
[core]
model = "openai:test-model"

[openai]
api_key = "toml-openai"
`);
    process.env.SHANNON_AI_API_KEY = 'exported-generic';

    resolveConfig();

    expect(process.env.SHANNON_AI_API_KEY).toBe('exported-generic');
    expect(process.env.OPENAI_API_KEY).toBeUndefined();
  });

  it('accepts ambient Bedrock access keys without injecting a configured bearer token or region', () => {
    writeConfig(`
[core]
model = "amazon-bedrock:us.anthropic.claude-sonnet-4-6"

[bedrock]
region = "us-east-1"
token = "toml-token"
`);
    process.env.AWS_DEFAULT_REGION = 'us-west-2';
    process.env.AWS_ACCESS_KEY_ID = 'access-key';
    process.env.AWS_SECRET_ACCESS_KEY = 'secret-key';
    process.env.AWS_SESSION_TOKEN = 'session-token';

    resolveConfig();

    expect(process.env.AWS_DEFAULT_REGION).toBe('us-west-2');
    expect(process.env.AWS_REGION).toBeUndefined();
    expect(process.env.AWS_BEARER_TOKEN_BEDROCK).toBeUndefined();
  });

  it.each([
    { name: 'profile', values: { AWS_PROFILE: 'audit-role' } },
    { name: 'web identity', values: { AWS_WEB_IDENTITY_TOKEN_FILE: '/var/run/secrets/aws/token' } },
    { name: 'ECS relative URI', values: { AWS_CONTAINER_CREDENTIALS_RELATIVE_URI: '/v2/credentials/id' } },
    {
      name: 'ECS full URI',
      values: { AWS_CONTAINER_CREDENTIALS_FULL_URI: 'http://169.254.170.2/v2/credentials/id' },
    },
  ])('accepts the ambient Bedrock $name credential source in package mode', ({ values }) => {
    writeConfig(`
[core]
model = "amazon-bedrock:us.anthropic.claude-sonnet-4-6"
`);
    Object.assign(process.env, values);

    expect(() => resolveConfig()).not.toThrow();
    expect(process.env.AWS_BEARER_TOKEN_BEDROCK).toBeUndefined();
  });

  it('uses legacy Bedrock sections and model tiers only when core.model is absent', () => {
    writeConfig(`
[core]
max_tokens = 64000
adaptive_thinking = true

[bedrock]
use = true
region = "us-east-1"
token = "legacy-bedrock"

[models]
small = "legacy-small"
medium = "legacy-medium"
large = "legacy-large"
`);

    resolveConfig();

    expect(process.env.SHANNON_AI_MODEL).toBeUndefined();
    expect(process.env.CLAUDE_CODE_USE_BEDROCK).toBe('1');
    expect(process.env.AWS_REGION).toBe('us-east-1');
    expect(process.env.AWS_BEARER_TOKEN_BEDROCK).toBe('legacy-bedrock');
    expect(process.env.ANTHROPIC_MEDIUM_MODEL).toBe('legacy-medium');
    expect(process.env.CLAUDE_CODE_MAX_OUTPUT_TOKENS).toBe('64000');
    expect(process.env.CLAUDE_ADAPTIVE_THINKING).toBe('true');
  });

  it('lets the new model selection win over legacy provider sections', () => {
    writeConfig(`
[core]
model = "openai:gpt-5.6-sol"

[openai]
api_key = "selected-openai"

[bedrock]
use = true
region = "us-east-1"
token = "legacy-bedrock"

[models]
small = "legacy-small"
medium = "legacy-medium"
large = "legacy-large"
`);

    resolveConfig();

    expect(process.env.SHANNON_AI_MODEL).toBe('openai:gpt-5.6-sol');
    expect(process.env.OPENAI_API_KEY).toBe('selected-openai');
    expect(process.env.CLAUDE_CODE_USE_BEDROCK).toBeUndefined();
    expect(process.env.AWS_BEARER_TOKEN_BEDROCK).toBeUndefined();
    expect(process.env.ANTHROPIC_MEDIUM_MODEL).toBeUndefined();
  });

  it('rejects legacy Vertex with a migration-focused error', () => {
    writeConfig(`
[vertex]
use = true
region = "us-east5"
project_id = "legacy-project"
key_path = "/tmp/key.json"

[models]
small = "small"
medium = "medium"
large = "large"
`);
    const errors: string[] = [];
    vi.spyOn(console, 'error').mockImplementation((message) => errors.push(String(message)));
    vi.spyOn(process, 'exit').mockImplementation((() => {
      throw new Error('process.exit(1)');
    }) as never);

    expect(() => resolveConfig()).toThrow('process.exit(1)');
    expect(errors.join('\n')).toMatch(/Vertex AI.*no longer supported.*SHANNON_AI_MODEL/i);
  });
});

describe('new config writer and setup', () => {
  it('writes the single-model TOML shape with mode 0600', () => {
    fs.writeFileSync(state.configPath, 'stale = true\n', { mode: 0o644 });
    fs.chmodSync(state.configPath, 0o644);
    saveConfig({
      core: { model: 'xai:grok-4.5', base_url: 'https://gateway.test/v1' },
      xai: { api_key: 'xai-secret' },
    });

    const content = fs.readFileSync(state.configPath, 'utf8');
    expect(content).toContain('[core]');
    expect(content).toContain('model = "xai:grok-4.5"');
    expect(content).toContain('[xai]');
    expect(content).not.toContain('[models]');
    expect(fs.statSync(state.configPath).mode & 0o777).toBe(0o600);
  });

  it('offers all supported routes and writes OpenAI without a subscription-auth prompt', async () => {
    vi.mocked(prompts.select).mockResolvedValueOnce('openai').mockResolvedValueOnce('gpt-5.6-sol');
    vi.mocked(prompts.password).mockResolvedValueOnce('openai-secret');

    await setup();

    const providerPrompt = vi.mocked(prompts.select).mock.calls[0]?.[0];
    expect(providerPrompt?.options.map((option) => option.label)).toEqual([
      'Anthropic',
      'OpenAI',
      'xAI',
      'AWS Bedrock',
      'Custom Base URL',
      'Other provider',
    ]);
    expect(
      vi.mocked(prompts.select).mock.calls.flatMap(([prompt]) => prompt.options.map((option) => option.label)),
    ).not.toContain('OAuth Token');
    expect(fs.readFileSync(state.configPath, 'utf8')).toContain('model = "openai:gpt-5.6-sol"');
    expect(fs.readFileSync(state.configPath, 'utf8')).toContain('api_key = "openai-secret"');
  });
});
