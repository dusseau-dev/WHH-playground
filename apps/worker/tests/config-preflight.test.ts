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

  it('normalizes granular checks and surfaces while deriving execution lanes', () => {
    const distributed = distributeConfig(
      parseConfigYAML(`
test_scopes: [reflected-xss, csrf]
test_surfaces: [api-graphql]
`),
    );
    expect(distributed.test_scopes).toEqual(['csrf', 'reflected-xss']);
    expect(distributed.test_surfaces).toEqual(['api-graphql']);
    expect(distributed.vuln_classes).toEqual(['xss', 'authz']);
  });

  it('normalizes assessment modules and module safety independently', () => {
    const distributed = distributeConfig(
      parseConfigYAML(`
assessment_modules: [passive-exposure, automated-dast]
module_safety:
  target_environment: staging
  allow_active_dast: true
  max_requests_per_second: 3
`),
    );
    expect(distributed.assessment_modules).toEqual(['passive-exposure', 'automated-dast']);
    expect(distributed.module_safety).toMatchObject({
      target_environment: 'staging',
      allow_active_dast: true,
      max_requests_per_second: 3,
    });
  });

  it('normalizes staging detection validation and keeps its token only in protected config data', () => {
    const distributed = distributeConfig(
      parseConfigYAML(`
test_scopes: [alerting-effectiveness]
module_safety:
  target_environment: staging
detection_validation:
  canary_path: /security/canary
  minimum_detection_rate: 0.8
  max_wait_seconds: 240
  splunk:
    management_url: https://splunk.example.test:8089
    telemetry_index: waf_events
    alert_index: security_alerts
    alert_sourcetype: notable
    token: splunk-secret
`),
    );

    expect(distributed.detection_validation).toEqual({
      canary_path: '/security/canary',
      minimum_detection_rate: 0.8,
      max_wait_seconds: 240,
      splunk: {
        management_url: 'https://splunk.example.test:8089',
        telemetry_index: 'waf_events',
        alert_index: 'security_alerts',
        alert_sourcetype: 'notable',
        token: 'splunk-secret',
      },
    });
  });

  it('requires a Splunk token for the selected detection validation scope', () => {
    expect(() =>
      parseConfigYAML(`
test_scopes: [alerting-effectiveness]
module_safety:
  target_environment: staging
detection_validation:
  splunk:
    management_url: https://splunk.example.test:8089
    telemetry_index: waf_events
    alert_index: security_alerts
`),
    ).toThrow(/Splunk token/i);
  });

  it('rejects encoded traversal in the detection validation canary path', () => {
    expect(() =>
      parseConfigYAML(`
test_scopes: [alerting-effectiveness]
module_safety:
  target_environment: staging
detection_validation:
  canary_path: /safe/%252e%252e/admin
  splunk:
    management_url: https://splunk.example.test:8089
    telemetry_index: waf_events
    alert_index: security_alerts
    token: splunk-secret
`),
    ).toThrow(/traversal/i);
  });

  it('expands legacy classes into granular checks', () => {
    const distributed = distributeConfig(parseConfigYAML('vuln_classes: [authz]'));
    expect(distributed.test_scopes).toContain('csrf');
    expect(distributed.test_scopes).toContain('object-access');
    expect(distributed.test_scopes).not.toContain('rate-limiting');
    expect(distributed.test_surfaces).toEqual(['browser', 'api-graphql']);
  });

  it('rejects conflicting, duplicate, empty, and unavailable scope configuration', () => {
    expect(() => parseConfigYAML('vuln_classes: [auth]\ntest_scopes: [csrf]')).toThrow(/conflict/i);
    expect(() => parseConfigYAML('test_scopes: [csrf, csrf]')).toThrow(/duplicate/i);
    expect(() => parseConfigYAML('test_scopes: []')).toThrow(/at least 1/i);
    expect(() => parseConfigYAML('test_surfaces: [websockets]')).toThrow(/coming soon/i);
    expect(() => parseConfigYAML('test_scopes: [dependency-risk]')).toThrow(/coming soon/i);
  });

  it('normalizes explicit HTTP load settings and safe defaults', () => {
    expect(distributeConfig(parseConfigYAML('test_scopes: [http-load-capacity]'))).toMatchObject({
      vuln_classes: [],
      test_scopes: ['http-load-capacity'],
      http_load: {
        concurrency: 5,
        requests_per_second: 10,
        duration_seconds: 15,
      },
    });

    expect(
      distributeConfig(
        parseConfigYAML(`
test_scopes: [http-load-capacity]
http_load:
  concurrency: 25
  requests_per_second: 75
  duration_seconds: 90
`),
      ).http_load,
    ).toEqual({ concurrency: 25, requests_per_second: 75, duration_seconds: 90 });
  });

  it('rejects orphaned or unsafe HTTP load configuration', () => {
    expect(() => parseConfigYAML('http_load:\n  concurrency: 5')).toThrow(/requires.*http-load-capacity/i);
    expect(() =>
      parseConfigYAML('test_scopes: [http-load-capacity]\nhttp_load:\n  requests_per_second: 10001'),
    ).toThrow(/10000|10,000/);
  });

  it('allows empty derived lanes only for explicit activity-backed scopes', () => {
    expect(() => parseConfigYAML('vuln_classes: []')).toThrow(/at least|empty/i);
    expect(() => parseConfigYAML('vuln_classes: []\ntest_scopes: [http-load-capacity]')).not.toThrow();
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
