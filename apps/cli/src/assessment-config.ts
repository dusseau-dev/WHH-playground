import { load as loadYaml } from 'js-yaml';
import { type AssessmentConfig, AssessmentConfigSchema, type TargetSecrets, TargetSecretsSchema } from './contracts.js';

function object(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
}

function takeString(target: Record<string, unknown>, key: string): string | undefined {
  const value = target[key];
  delete target[key];
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function booleanFlag(value: unknown): boolean | undefined {
  if (typeof value === 'boolean') return value;
  if (value === 'true') return true;
  if (value === 'false') return false;
  return undefined;
}

function safeDemonstrationAliases(raw: Record<string, unknown>): {
  safeDemonstration?: boolean;
  demonstrate?: boolean;
  exploit?: boolean;
} {
  const camel = booleanFlag(raw.safeDemonstration);
  const snake = booleanFlag(raw.safe_demonstration);
  if (camel !== undefined && snake !== undefined && camel !== snake) {
    throw new Error('safeDemonstration conflicts with safe_demonstration');
  }
  const safeDemonstration = camel ?? snake;
  const demonstrate = booleanFlag(raw.demonstrate);
  const exploit = booleanFlag(raw.exploit);
  return {
    ...(safeDemonstration !== undefined && { safeDemonstration }),
    ...(demonstrate !== undefined && { demonstrate }),
    ...(exploit !== undefined && { exploit }),
  };
}

/** Normalize current UI config objects and legacy snake_case worker YAML into one contract. */
export function normalizeAssessmentConfigObject(config: Record<string, unknown>): AssessmentConfig {
  if (
    'testCategories' in config ||
    'safeDemonstration' in config ||
    'demonstrate' in config ||
    'rulesOfEngagement' in config
  ) {
    const { safeDemonstration: _safeDemonstration, demonstrate: _demonstrate, exploit: _exploit, ...rest } = config;
    return AssessmentConfigSchema.parse({ ...rest, ...safeDemonstrationAliases(config) });
  }

  const authentication = object(config.authentication);
  const credentials = object(authentication?.credentials);
  const emailLogin = object(credentials?.email_login);
  const successCondition = object(authentication?.success_condition);
  const pipeline = object(config.pipeline);
  const report = object(config.report);

  return AssessmentConfigSchema.parse({
    ...(typeof config.description === 'string' && { description: config.description }),
    ...(Array.isArray(config.test_categories) && { testCategories: config.test_categories }),
    ...(Array.isArray(config.vuln_classes) &&
      !Array.isArray(config.test_categories) && { testCategories: config.vuln_classes }),
    ...safeDemonstrationAliases(config),
    ...(pipeline && {
      pipeline: {
        ...(typeof pipeline.retry_preset === 'string' && { retryPreset: pipeline.retry_preset }),
        ...(pipeline.max_concurrent_pipelines !== undefined && {
          maxConcurrentPipelines: Number(pipeline.max_concurrent_pipelines),
        }),
      },
    }),
    ...(object(config.rules) && { rules: config.rules }),
    ...(report && {
      report: {
        ...(typeof report.min_severity === 'string' && { minSeverity: report.min_severity }),
        ...(typeof report.min_confidence === 'string' && { minConfidence: report.min_confidence }),
        ...(typeof report.guidance === 'string' && { guidance: report.guidance }),
        ...(booleanFlag(report.sarif) !== undefined && { sarif: booleanFlag(report.sarif) }),
      },
    }),
    ...(typeof config.rules_of_engagement === 'string' && { rulesOfEngagement: config.rules_of_engagement }),
    ...(authentication &&
      credentials &&
      successCondition && {
        authentication: {
          loginType: authentication.login_type,
          loginUrl: authentication.login_url,
          username: credentials.username,
          ...(emailLogin && typeof emailLogin.address === 'string' && { emailAddress: emailLogin.address }),
          ...(Array.isArray(authentication.login_flow) && { loginFlow: authentication.login_flow }),
          successCondition: { type: successCondition.type, value: successCondition.value },
        },
      }),
  });
}

export function parseAssessmentConfigYaml(yaml: string): { config: AssessmentConfig; secrets: TargetSecrets } {
  const parsed = loadYaml(yaml);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Configuration YAML must contain an object');
  }
  const raw = JSON.parse(JSON.stringify(parsed)) as Record<string, unknown>;
  const authentication = object(raw.authentication);
  const credentials = object(authentication?.credentials);
  const emailLogin = object(credentials?.email_login);
  const suppliedSecrets = object(raw.secrets);

  const embeddedSecrets: TargetSecrets = {};
  if (credentials) {
    const password = takeString(credentials, 'password');
    const totpSecret = takeString(credentials, 'totp_secret');
    if (password) embeddedSecrets.password = password;
    if (totpSecret) embeddedSecrets.totpSecret = totpSecret;
  }
  if (emailLogin) {
    const emailPassword = takeString(emailLogin, 'password');
    const emailTotpSecret = takeString(emailLogin, 'totp_secret');
    if (emailPassword) embeddedSecrets.emailPassword = emailPassword;
    if (emailTotpSecret) embeddedSecrets.emailTotpSecret = emailTotpSecret;
  }
  const secrets = TargetSecretsSchema.parse({ ...(suppliedSecrets ?? {}), ...embeddedSecrets });

  const config = normalizeAssessmentConfigObject(raw);
  return { config, secrets };
}
