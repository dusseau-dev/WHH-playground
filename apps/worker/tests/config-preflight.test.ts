import { describe, expect, it } from 'vitest';
import { distributeConfig, parseConfigYAML } from '../src/config-parser.js';
import { ConfigLoaderService } from '../src/services/config-loader.js';
import { validatePiCredentials, validateSourceModeRules } from '../src/services/preflight.js';

describe('configuration compatibility', () => {
  it.each([
    ['safe_demonstration: true', true],
    ['safe_demonstration: false', false],
    ['safe_demonstration: "true"', true],
    ['safe_demonstration: "false"', false],
    ['exploit: true', true],
    ['exploit: false', false],
    ['exploit: "true"', true],
    ['exploit: "false"', false],
  ])('accepts %s', (yaml, expected) => {
    expect(distributeConfig(parseConfigYAML(yaml)).safeDemonstration).toBe(expected);
  });

  it('rejects conflicting safe_demonstration and legacy exploit values', () => {
    expect(() => parseConfigYAML('safe_demonstration: true\nexploit: false')).toThrow(/conflicting/);
  });

  it('retains numeric concurrency with JSON-compatible YAML scalars', () => {
    const config = parseConfigYAML('pipeline:\n  max_concurrent_pipelines: 2');
    expect(config.pipeline).toEqual({ max_concurrent_pipelines: 2 });
  });

  it('normalizes legacy quoted concurrency', () => {
    const config = parseConfigYAML('pipeline:\n  max_concurrent_pipelines: "3"');
    expect(config.pipeline).toEqual({ max_concurrent_pipelines: 3 });
  });
});

describe('source-mode preflight rules', () => {
  const codePathConfig = {
    rules: {
      focus: [{ description: 'checkout', type: 'code_path' as const, value: 'src/checkout' }],
    },
  };

  it('rejects code_path rules without a repository', () => {
    const result = validateSourceModeRules(codePathConfig, 'url-only');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.message).toMatch(/cannot use code_path rules/);
  });

  it('leaves source-assisted code path validation to repository preflight', () => {
    expect(validateSourceModeRules(codePathConfig, 'source-assisted')).toEqual({ ok: true, value: undefined });
  });
});

describe('Pi credential preflight', () => {
  it('resolves the configured Pi model instead of skipping providerConfig validation', async () => {
    const result = await validatePiCredentials(
      '/tmp',
      { info: () => undefined, warn: () => undefined, error: () => undefined },
      undefined,
      {
        providerType: 'generic',
        providerId: 'missing-provider',
        model: 'missing-model',
        apiKey: 'secret',
      },
    );

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.message).toMatch(/Model not found in Pi registry/);
  });

  it('describes every supported Bedrock credential route when credentials are missing', async () => {
    const names = [
      'SHANNON_AI_MODEL',
      'AWS_BEARER_TOKEN_BEDROCK',
      'AWS_ACCESS_KEY_ID',
      'AWS_SECRET_ACCESS_KEY',
      'AWS_PROFILE',
      'AWS_WEB_IDENTITY_TOKEN_FILE',
      'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI',
      'AWS_CONTAINER_CREDENTIALS_FULL_URI',
    ] as const;
    const previous = Object.fromEntries(names.map((name) => [name, process.env[name]]));
    for (const name of names) delete process.env[name];
    process.env.SHANNON_AI_MODEL = 'amazon-bedrock:us.anthropic.claude-sonnet-4-6';

    try {
      const result = await validatePiCredentials('/tmp', {
        info: () => undefined,
        warn: () => undefined,
        error: () => undefined,
      });

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.message).toMatch(/AWS_BEARER_TOKEN_BEDROCK/);
        expect(result.error.message).toMatch(/AWS_ACCESS_KEY_ID \+ AWS_SECRET_ACCESS_KEY/);
        expect(result.error.message).toMatch(/AWS_PROFILE/);
        expect(result.error.message).toMatch(/AWS_WEB_IDENTITY_TOKEN_FILE/);
        expect(result.error.message).toMatch(/AWS_CONTAINER_CREDENTIALS_RELATIVE_URI\/FULL_URI/);
        expect(result.error.message).not.toContain('AWS_BEARER_TOKEN_BEDROCK and AWS_REGION');
      }
    } finally {
      for (const [name, value] of Object.entries(previous)) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
    }
  });
});

describe('source-mode config loading rules', () => {
  const codePathYAML = `
rules:
  focus:
    - description: checkout
      type: code_path
      value: src/checkout
`;

  it('rejects inline YAML code_path rules for URL-only runs', async () => {
    const loader = new ConfigLoaderService();
    const result = await loader.loadOptional(undefined, undefined, codePathYAML, 'url-only');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.message).toMatch(/cannot use code_path rules/);
  });

  it('rejects pre-parsed code_path rules for URL-only runs', async () => {
    const loader = new ConfigLoaderService();
    const configData = distributeConfig(parseConfigYAML(codePathYAML));
    const result = await loader.loadOptional(undefined, configData, undefined, 'url-only');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.message).toMatch(/cannot use code_path rules/);
  });

  it('loads code_path rules for source-assisted runs', async () => {
    const loader = new ConfigLoaderService();
    const result = await loader.loadOptional(undefined, undefined, codePathYAML, 'source-assisted');
    expect(result.ok).toBe(true);
  });
});
