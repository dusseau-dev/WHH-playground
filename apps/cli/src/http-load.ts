import type { AssessmentModule, AssessmentTestScope } from './security-scopes.js';

export const HTTP_LOAD_SCOPE = 'http-load-capacity' as const;

export interface HttpLoadSettings {
  readonly concurrency: number;
  readonly requestsPerSecond: number;
  readonly durationSeconds: number;
}

export interface HttpLoadSettingsInput {
  readonly concurrency?: number | undefined;
  readonly requestsPerSecond?: number | undefined;
  readonly durationSeconds?: number | undefined;
}

export const HTTP_LOAD_DEFAULTS = {
  concurrency: 5,
  requestsPerSecond: 10,
  durationSeconds: 15,
} as const satisfies HttpLoadSettings;

export const HTTP_LOAD_ELEVATED_THRESHOLDS = {
  concurrency: 20,
  requestsPerSecond: 50,
  durationSeconds: 60,
} as const satisfies HttpLoadSettings;

export const HTTP_LOAD_EMERGENCY_LIMITS = {
  concurrency: 1_000,
  requestsPerSecond: 10_000,
  durationSeconds: 3_600,
} as const satisfies HttpLoadSettings;

function positiveInteger(label: string, value: number, maximum: number): number {
  if (!Number.isFinite(value) || !Number.isInteger(value) || value < 1) {
    throw new Error(`HTTP load ${label} must be a positive integer`);
  }
  if (value > maximum) {
    throw new Error(`HTTP load ${label} must not exceed ${maximum.toLocaleString('en-US')}`);
  }
  return value;
}

/** Normalize parameters only when the explicit HTTP load scope is selected. */
export function normalizeHttpLoadSettings(
  scopes: readonly AssessmentTestScope[],
  value?: HttpLoadSettingsInput,
): HttpLoadSettings | undefined {
  if (!scopes.includes(HTTP_LOAD_SCOPE)) {
    if (value !== undefined) throw new Error(`HTTP load configuration requires the ${HTTP_LOAD_SCOPE} scope`);
    return undefined;
  }

  return {
    concurrency: positiveInteger(
      'concurrency',
      value?.concurrency ?? HTTP_LOAD_DEFAULTS.concurrency,
      HTTP_LOAD_EMERGENCY_LIMITS.concurrency,
    ),
    requestsPerSecond: positiveInteger(
      'requests per second',
      value?.requestsPerSecond ?? HTTP_LOAD_DEFAULTS.requestsPerSecond,
      HTTP_LOAD_EMERGENCY_LIMITS.requestsPerSecond,
    ),
    durationSeconds: positiveInteger(
      'duration',
      value?.durationSeconds ?? HTTP_LOAD_DEFAULTS.durationSeconds,
      HTTP_LOAD_EMERGENCY_LIMITS.durationSeconds,
    ),
  };
}

/** Whether any configured value requires the elevated-load acknowledgement. */
export function isElevatedHttpLoad(settings: HttpLoadSettings): boolean {
  return (
    settings.concurrency > HTTP_LOAD_ELEVATED_THRESHOLDS.concurrency ||
    settings.requestsPerSecond > HTTP_LOAD_ELEVATED_THRESHOLDS.requestsPerSecond ||
    settings.durationSeconds > HTTP_LOAD_ELEVATED_THRESHOLDS.durationSeconds
  );
}

/** Validate launch-only authorization without persisting acknowledgements in config. */
export function assertHttpLoadAuthorization(
  settings: HttpLoadSettings | undefined,
  authorizationConfirmed: boolean,
  elevatedLoadConfirmed: boolean,
): void {
  if (!settings) return;
  if (!authorizationConfirmed) {
    throw new Error('HTTP load testing requires explicit ownership or written authorization confirmation');
  }
  if (isElevatedHttpLoad(settings) && !elevatedLoadConfirmed) {
    throw new Error('Elevated HTTP load settings require explicit elevated-load confirmation');
  }
}

/** Prevent two independent load generators from targeting the same run. */
export function assertExclusiveHttpLoadExecution(
  scopes: readonly AssessmentTestScope[],
  modules: readonly AssessmentModule[],
): void {
  if (scopes.includes(HTTP_LOAD_SCOPE) && modules.includes(HTTP_LOAD_SCOPE)) {
    throw new Error('HTTP load cannot be selected as both a granular scope and a controlled-load assessment module');
  }
}
