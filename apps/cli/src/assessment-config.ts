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

function moduleSafetyAliases(raw: unknown): Record<string, unknown> | undefined {
  const safety = object(raw);
  if (!safety) return;
  return {
    ...(typeof safety.targetEnvironment === 'string' && { targetEnvironment: safety.targetEnvironment }),
    ...(typeof safety.target_environment === 'string' && { targetEnvironment: safety.target_environment }),
    ...(booleanFlag(safety.allowActiveDast) !== undefined && { allowActiveDast: booleanFlag(safety.allowActiveDast) }),
    ...(booleanFlag(safety.allow_active_dast) !== undefined && {
      allowActiveDast: booleanFlag(safety.allow_active_dast),
    }),
    ...(booleanFlag(safety.acknowledgeLoadRisk) !== undefined && {
      acknowledgeLoadRisk: booleanFlag(safety.acknowledgeLoadRisk),
    }),
    ...(booleanFlag(safety.acknowledge_load_risk) !== undefined && {
      acknowledgeLoadRisk: booleanFlag(safety.acknowledge_load_risk),
    }),
    ...(safety.maxRequestsPerSecond !== undefined && { maxRequestsPerSecond: Number(safety.maxRequestsPerSecond) }),
    ...(safety.max_requests_per_second !== undefined && {
      maxRequestsPerSecond: Number(safety.max_requests_per_second),
    }),
    ...(safety.maxConcurrency !== undefined && { maxConcurrency: Number(safety.maxConcurrency) }),
    ...(safety.max_concurrency !== undefined && { maxConcurrency: Number(safety.max_concurrency) }),
    ...(safety.loadStageDurationSeconds !== undefined && {
      loadStageDurationSeconds: Number(safety.loadStageDurationSeconds),
    }),
    ...(safety.load_stage_duration_seconds !== undefined && {
      loadStageDurationSeconds: Number(safety.load_stage_duration_seconds),
    }),
    ...(safety.loadErrorRateThreshold !== undefined && {
      loadErrorRateThreshold: Number(safety.loadErrorRateThreshold),
    }),
    ...(safety.load_error_rate_threshold !== undefined && {
      loadErrorRateThreshold: Number(safety.load_error_rate_threshold),
    }),
    ...(safety.loadP95LatencyMsThreshold !== undefined && {
      loadP95LatencyMsThreshold: Number(safety.loadP95LatencyMsThreshold),
    }),
    ...(safety.load_p95_latency_ms_threshold !== undefined && {
      loadP95LatencyMsThreshold: Number(safety.load_p95_latency_ms_threshold),
    }),
  };
}

function httpLoadAliases(raw: unknown): Record<string, unknown> | undefined {
  const settings = object(raw);
  if (!settings) return;
  return {
    ...(settings.concurrency !== undefined && { concurrency: Number(settings.concurrency) }),
    ...(settings.requestsPerSecond !== undefined && { requestsPerSecond: Number(settings.requestsPerSecond) }),
    ...(settings.requests_per_second !== undefined && {
      requestsPerSecond: Number(settings.requests_per_second),
    }),
    ...(settings.durationSeconds !== undefined && { durationSeconds: Number(settings.durationSeconds) }),
    ...(settings.duration_seconds !== undefined && { durationSeconds: Number(settings.duration_seconds) }),
  };
}

function detectionValidationAliases(raw: unknown): Record<string, unknown> | undefined {
  const settings = object(raw);
  const splunk = object(settings?.splunk);
  if (!settings || !splunk) return;
  return {
    ...(typeof settings.canaryPath === 'string' && { canaryPath: settings.canaryPath }),
    ...(typeof settings.canary_path === 'string' && { canaryPath: settings.canary_path }),
    ...(settings.minimumDetectionRate !== undefined && {
      minimumDetectionRate: Number(settings.minimumDetectionRate),
    }),
    ...(settings.minimum_detection_rate !== undefined && {
      minimumDetectionRate: Number(settings.minimum_detection_rate),
    }),
    ...(settings.maxWaitSeconds !== undefined && { maxWaitSeconds: Number(settings.maxWaitSeconds) }),
    ...(settings.max_wait_seconds !== undefined && { maxWaitSeconds: Number(settings.max_wait_seconds) }),
    splunk: {
      managementUrl: splunk.managementUrl ?? splunk.management_url,
      telemetryIndex: splunk.telemetryIndex ?? splunk.telemetry_index,
      alertIndex: splunk.alertIndex ?? splunk.alert_index,
      ...(typeof (splunk.telemetrySourcetype ?? splunk.telemetry_sourcetype) === 'string' && {
        telemetrySourcetype: splunk.telemetrySourcetype ?? splunk.telemetry_sourcetype,
      }),
      ...(typeof (splunk.alertSourcetype ?? splunk.alert_sourcetype) === 'string' && {
        alertSourcetype: splunk.alertSourcetype ?? splunk.alert_sourcetype,
      }),
    },
  };
}

/** Normalize current UI config objects and legacy snake_case worker YAML into one contract. */
export function normalizeAssessmentConfigObject(config: Record<string, unknown>): AssessmentConfig {
  if (
    'testCategories' in config ||
    'testScopes' in config ||
    'testSurfaces' in config ||
    'httpLoad' in config ||
    'detectionValidation' in config ||
    'assessmentModules' in config ||
    'moduleSafety' in config ||
    'safeDemonstration' in config ||
    'demonstrate' in config ||
    'rulesOfEngagement' in config
  ) {
    const { safeDemonstration: _safeDemonstration, demonstrate: _demonstrate, exploit: _exploit, ...rest } = config;
    const httpLoad = httpLoadAliases(config.httpLoad);
    const detectionValidation = detectionValidationAliases(config.detectionValidation);
    const moduleSafety = moduleSafetyAliases(config.moduleSafety);
    return AssessmentConfigSchema.parse({
      ...rest,
      ...safeDemonstrationAliases(config),
      ...(httpLoad && { httpLoad }),
      ...(detectionValidation && { detectionValidation }),
      ...(moduleSafety && { moduleSafety }),
    });
  }

  const authentication = object(config.authentication);
  const credentials = object(authentication?.credentials);
  const emailLogin = object(credentials?.email_login);
  const successCondition = object(authentication?.success_condition);
  const pipeline = object(config.pipeline);
  const report = object(config.report);
  const httpLoad = httpLoadAliases(config.http_load);
  const detectionValidation = detectionValidationAliases(config.detection_validation);
  const moduleSafety = moduleSafetyAliases(config.module_safety);

  return AssessmentConfigSchema.parse({
    ...(typeof config.description === 'string' && { description: config.description }),
    ...(Array.isArray(config.test_categories) && { testCategories: config.test_categories }),
    ...(Array.isArray(config.vuln_classes) &&
      !Array.isArray(config.test_categories) && { testCategories: config.vuln_classes }),
    ...(Array.isArray(config.test_scopes) && { testScopes: config.test_scopes }),
    ...(Array.isArray(config.test_surfaces) && { testSurfaces: config.test_surfaces }),
    ...(httpLoad && { httpLoad }),
    ...(detectionValidation && { detectionValidation }),
    ...(Array.isArray(config.assessment_modules) && { assessmentModules: config.assessment_modules }),
    ...(moduleSafety && { moduleSafety }),
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
  const detectionValidation = object(raw.detection_validation) ?? object(raw.detectionValidation);
  const splunk = object(detectionValidation?.splunk);

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
  if (splunk) {
    const splunkToken = takeString(splunk, 'token');
    if (splunkToken) embeddedSecrets.splunkToken = splunkToken;
  }
  const secrets = TargetSecretsSchema.parse({ ...(suppliedSecrets ?? {}), ...embeddedSecrets });

  const config = normalizeAssessmentConfigObject(raw);
  return { config, secrets };
}
