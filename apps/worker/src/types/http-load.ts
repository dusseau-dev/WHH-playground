import type { AssessmentModule, AssessmentScope } from './scopes.js';

export const HTTP_LOAD_SCOPE = 'http-load-capacity' as const;

export interface HttpLoadSettings {
  readonly concurrency: number;
  readonly requestsPerSecond: number;
  readonly durationSeconds: number;
}

export type HttpLoadStatus = 'completed' | 'interrupted' | 'incomplete';

/** Stable, redacted artifact emitted by the authorized load generator. */
export interface HttpLoadResult {
  readonly version: 1;
  readonly status: HttpLoadStatus;
  readonly started_at: string;
  readonly completed_at: string;
  readonly target: string;
  readonly concurrency: number;
  readonly requests_per_second: number;
  readonly duration_seconds: number;
  readonly elapsed_seconds: number;
  readonly sent: number;
  readonly completed: number;
  readonly success: number;
  readonly failure: number;
  readonly errors: number;
  readonly bytes_read: number;
  readonly average_latency_ms: number;
  readonly minimum_latency_ms: number | null;
  readonly maximum_latency_ms: number | null;
  readonly status_counts: Readonly<Record<string, number>>;
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

function normalizedPositiveInteger(label: string, value: number, maximum: number): number {
  if (!Number.isFinite(value) || !Number.isInteger(value) || value < 1) {
    throw new Error(`HTTP load ${label} must be a positive integer`);
  }
  if (value > maximum) {
    throw new Error(`HTTP load ${label} must not exceed ${maximum.toLocaleString('en-US')}`);
  }
  return value;
}

/** Normalize load parameters only for an explicitly selected HTTP load scope. */
export function normalizeHttpLoadSettings(
  scopes: readonly AssessmentScope[],
  value?: Partial<HttpLoadSettings>,
): HttpLoadSettings | undefined {
  const selected = scopes.includes(HTTP_LOAD_SCOPE);
  if (!selected) {
    if (value !== undefined) throw new Error(`HTTP load configuration requires the ${HTTP_LOAD_SCOPE} scope`);
    return undefined;
  }

  return {
    concurrency: normalizedPositiveInteger(
      'concurrency',
      value?.concurrency ?? HTTP_LOAD_DEFAULTS.concurrency,
      HTTP_LOAD_EMERGENCY_LIMITS.concurrency,
    ),
    requestsPerSecond: normalizedPositiveInteger(
      'requests per second',
      value?.requestsPerSecond ?? HTTP_LOAD_DEFAULTS.requestsPerSecond,
      HTTP_LOAD_EMERGENCY_LIMITS.requestsPerSecond,
    ),
    durationSeconds: normalizedPositiveInteger(
      'duration',
      value?.durationSeconds ?? HTTP_LOAD_DEFAULTS.durationSeconds,
      HTTP_LOAD_EMERGENCY_LIMITS.durationSeconds,
    ),
  };
}

/** Whether a run crosses any threshold that requires a second acknowledgement. */
export function isElevatedHttpLoad(settings: HttpLoadSettings): boolean {
  return (
    settings.concurrency > HTTP_LOAD_ELEVATED_THRESHOLDS.concurrency ||
    settings.requestsPerSecond > HTTP_LOAD_ELEVATED_THRESHOLDS.requestsPerSecond ||
    settings.durationSeconds > HTTP_LOAD_ELEVATED_THRESHOLDS.durationSeconds
  );
}

/** Reject selected load testing without the required run-time acknowledgements. */
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
  scopes: readonly AssessmentScope[],
  modules: readonly AssessmentModule[],
): void {
  if (scopes.includes(HTTP_LOAD_SCOPE) && modules.includes(HTTP_LOAD_SCOPE)) {
    throw new Error('HTTP load cannot be selected as both a granular scope and a controlled-load assessment module');
  }
}

function resultRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('HTTP load result must be an object');
  }
  return value as Record<string, unknown>;
}

function resultNumber(record: Record<string, unknown>, key: string, integer = false): number {
  const value = record[key];
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || (integer && !Number.isInteger(value))) {
    throw new Error(`HTTP load result ${key} is invalid`);
  }
  return value;
}

function resultTimestamp(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value))) {
    throw new Error(`HTTP load result ${key} is invalid`);
  }
  return value;
}

function nullableResultNumber(record: Record<string, unknown>, key: string): number | null {
  if (record[key] === null) return null;
  return resultNumber(record, key);
}

/** Parse an untrusted generator artifact before it is used for resume or reporting. */
export function parseHttpLoadResult(value: unknown): HttpLoadResult {
  const record = resultRecord(value);
  if (record.version !== 1) throw new Error('HTTP load result version is unsupported');
  if (!['completed', 'interrupted', 'incomplete'].includes(String(record.status))) {
    throw new Error('HTTP load result status is invalid');
  }
  if (typeof record.target !== 'string') throw new Error('HTTP load result target is invalid');
  let target: URL;
  try {
    target = new URL(record.target);
  } catch {
    throw new Error('HTTP load result target is invalid');
  }
  if (!['http:', 'https:'].includes(target.protocol) || target.username || target.password) {
    throw new Error('HTTP load result target is invalid');
  }

  const statusCountsRecord = resultRecord(record.status_counts);
  const status_counts: Record<string, number> = {};
  for (const [statusCode, count] of Object.entries(statusCountsRecord)) {
    if (!/^\d{3}$/.test(statusCode) || typeof count !== 'number' || !Number.isInteger(count) || count < 0) {
      throw new Error('HTTP load result status_counts is invalid');
    }
    status_counts[statusCode] = count;
  }

  const parsed: HttpLoadResult = {
    version: 1,
    status: record.status as HttpLoadStatus,
    started_at: resultTimestamp(record, 'started_at'),
    completed_at: resultTimestamp(record, 'completed_at'),
    target: target.href,
    concurrency: resultNumber(record, 'concurrency', true),
    requests_per_second: resultNumber(record, 'requests_per_second'),
    duration_seconds: resultNumber(record, 'duration_seconds'),
    elapsed_seconds: resultNumber(record, 'elapsed_seconds'),
    sent: resultNumber(record, 'sent', true),
    completed: resultNumber(record, 'completed', true),
    success: resultNumber(record, 'success', true),
    failure: resultNumber(record, 'failure', true),
    errors: resultNumber(record, 'errors', true),
    bytes_read: resultNumber(record, 'bytes_read', true),
    average_latency_ms: resultNumber(record, 'average_latency_ms'),
    minimum_latency_ms: nullableResultNumber(record, 'minimum_latency_ms'),
    maximum_latency_ms: nullableResultNumber(record, 'maximum_latency_ms'),
    status_counts,
  };
  if (parsed.concurrency < 1 || parsed.requests_per_second <= 0 || parsed.duration_seconds <= 0) {
    throw new Error('HTTP load result settings are invalid');
  }
  if (parsed.success + parsed.failure !== parsed.completed) {
    throw new Error('HTTP load result response counts are inconsistent');
  }
  return parsed;
}
