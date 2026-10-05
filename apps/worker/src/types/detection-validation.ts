import type { AssessmentScope, TargetEnvironment } from './scopes.js';

export interface DetectionValidationSplunkInput {
  readonly managementUrl: string;
  readonly telemetryIndex: string;
  readonly alertIndex: string;
  readonly telemetrySourcetype?: string | undefined;
  readonly alertSourcetype?: string | undefined;
}

export interface DetectionValidationSettingsInput {
  readonly canaryPath?: string | undefined;
  readonly minimumDetectionRate?: number | undefined;
  readonly maxWaitSeconds?: number | undefined;
  readonly splunk: DetectionValidationSplunkInput;
}

export interface DetectionValidationSettings {
  readonly canaryPath: string;
  readonly minimumDetectionRate: number;
  readonly maxWaitSeconds: number;
  readonly splunk: DetectionValidationSplunkInput;
}

export type DetectionValidationStatus = 'passed' | 'failed' | 'partial' | 'unavailable';

export const DETECTION_VALIDATION_SCOPE = 'alerting-effectiveness' as const;
export const DETECTION_VALIDATION_DEFAULTS = {
  canaryPath: '/__shannon__/detection-simulation',
  minimumDetectionRate: 1,
  maxWaitSeconds: 180,
} as const;

const INDEX_PATTERN = /^[A-Za-z0-9_.-]+$/;
const SOURCETYPE_PATTERN = /^[A-Za-z0-9_.:-]+$/;

function normalizedManagementUrl(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error('Splunk management URL must be a valid HTTPS origin');
  }
  if (
    parsed.protocol !== 'https:' ||
    parsed.username ||
    parsed.password ||
    parsed.pathname !== '/' ||
    parsed.search ||
    parsed.hash
  ) {
    throw new Error('Splunk management URL must be an HTTPS origin without credentials, path, query, or fragment');
  }
  return parsed.origin;
}

function normalizedCanaryPath(value: string): string {
  if (value.length > 2_048 || !value.startsWith('/') || value.startsWith('//')) {
    throw new Error('Detection validation canary path must be a same-origin relative path');
  }
  let decoded = value;
  for (let depth = 0; depth < 8; depth += 1) {
    let next: string;
    try {
      next = decodeURIComponent(decoded);
    } catch {
      throw new Error('Detection validation canary path must be valid URL text');
    }
    if (next === decoded) break;
    if (depth === 7) throw new Error('Detection validation canary path is excessively encoded');
    decoded = next;
  }
  if (!decoded.startsWith('/') || decoded.startsWith('//')) {
    throw new Error('Detection validation canary path must be a same-origin relative path');
  }
  if (decoded.includes('?') || decoded.includes('#')) {
    throw new Error('Detection validation canary path cannot contain a query or fragment');
  }
  if (decoded.includes('\\')) throw new Error('Detection validation canary path must use URL path separators');
  if (decoded.split('/').some((segment) => segment === '.' || segment === '..')) {
    throw new Error('Detection validation canary path cannot contain traversal segments');
  }
  return value;
}

function assertIdentifier(value: string, label: string, pattern: RegExp): void {
  if (!value || value.length > 128 || !pattern.test(value)) {
    throw new Error(`Splunk ${label} contains unsupported characters`);
  }
}

export function normalizeDetectionValidationSettings(
  scopes: readonly AssessmentScope[],
  input: DetectionValidationSettingsInput | undefined,
  targetEnvironment: TargetEnvironment,
): DetectionValidationSettings | undefined {
  const selected = scopes.includes(DETECTION_VALIDATION_SCOPE);
  if (!selected) {
    if (input !== undefined)
      throw new Error(`Detection validation configuration requires the ${DETECTION_VALIDATION_SCOPE} scope`);
    return undefined;
  }
  if (!input) throw new Error('Alerting effectiveness requires detection validation configuration');
  if (targetEnvironment !== 'staging') throw new Error('Detection validation is allowed only against a staging target');

  const minimumDetectionRate = input.minimumDetectionRate ?? DETECTION_VALIDATION_DEFAULTS.minimumDetectionRate;
  if (!Number.isFinite(minimumDetectionRate) || minimumDetectionRate < 0 || minimumDetectionRate > 1) {
    throw new Error('Minimum detection rate must be between 0 and 1');
  }
  const maxWaitSeconds = input.maxWaitSeconds ?? DETECTION_VALIDATION_DEFAULTS.maxWaitSeconds;
  if (!Number.isInteger(maxWaitSeconds) || maxWaitSeconds < 30 || maxWaitSeconds > 600) {
    throw new Error('Detection validation maximum wait must be an integer between 30 and 600 seconds');
  }
  assertIdentifier(input.splunk.telemetryIndex, 'telemetry index', INDEX_PATTERN);
  assertIdentifier(input.splunk.alertIndex, 'alert index', INDEX_PATTERN);
  if (input.splunk.telemetrySourcetype !== undefined) {
    assertIdentifier(input.splunk.telemetrySourcetype, 'telemetry sourcetype', SOURCETYPE_PATTERN);
  }
  if (input.splunk.alertSourcetype !== undefined) {
    assertIdentifier(input.splunk.alertSourcetype, 'alert sourcetype', SOURCETYPE_PATTERN);
  }

  return {
    canaryPath: normalizedCanaryPath(input.canaryPath ?? DETECTION_VALIDATION_DEFAULTS.canaryPath),
    minimumDetectionRate,
    maxWaitSeconds,
    splunk: {
      managementUrl: normalizedManagementUrl(input.splunk.managementUrl),
      telemetryIndex: input.splunk.telemetryIndex,
      alertIndex: input.splunk.alertIndex,
      ...(input.splunk.telemetrySourcetype && { telemetrySourcetype: input.splunk.telemetrySourcetype }),
      ...(input.splunk.alertSourcetype && { alertSourcetype: input.splunk.alertSourcetype }),
    },
  };
}
