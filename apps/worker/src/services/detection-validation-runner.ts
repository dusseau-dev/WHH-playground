import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import type { DetectionValidationSettings, DetectionValidationStatus } from '../types/detection-validation.js';
import { atomicWrite, ensureDirectory, fileExists } from '../utils/file-io.js';
import {
  DETECTION_CORPUS_VERSION,
  DETECTION_VALIDATION_CORPUS,
  type DetectionValidationCohort,
  type DetectionValidationFixture,
} from './detection-validation-corpus.js';

const SPLUNK_RESULT_LIMIT_BYTES = 1024 * 1024;
const SPLUNK_POLL_SECONDS = 10;
const SPLUNK_REQUEST_TIMEOUT_MS = 30_000;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9_.-]+$/;
const SOURCETYPE_PATTERN = /^[A-Za-z0-9_.:-]+$/;
const MARKER_PATTERN = /^shn-(?:run|sim)-[a-z0-9-]{6,64}$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;

export const DETECTION_VALIDATION_RESULT_FILENAME = 'detection-validation.json';

export type DetectionEmissionStatus = 'sent' | 'error';

export interface DetectionValidationScenarioResult {
  readonly id: string;
  readonly pair_id: string;
  readonly cohort: DetectionValidationCohort;
  readonly technique: string;
  readonly fixture_sha256: string;
  readonly marker: string;
  readonly emission_status: DetectionEmissionStatus;
  readonly sent_at: string;
  readonly http_status?: number;
  readonly detected: boolean;
  readonly first_seen_at?: string;
  readonly latency_ms?: number;
}

export interface DetectionValidationCohortResult {
  readonly total: number;
  readonly detected: number;
  readonly detection_rate: number;
  readonly threshold: number;
  readonly passed: boolean;
  readonly median_latency_ms?: number;
}

export interface DetectionValidationResult {
  readonly schema_version: 1;
  readonly corpus_version: string;
  readonly corpus_sha256: string;
  readonly status: DetectionValidationStatus;
  readonly target: string;
  readonly started_at: string;
  readonly completed_at: string;
  readonly run_marker: string;
  readonly minimum_detection_rate: number;
  readonly calibration: {
    readonly sent_at: string;
    readonly http_status?: number;
    readonly telemetry_observed: boolean;
    readonly first_seen_at?: string;
    readonly latency_ms?: number;
  };
  readonly cohorts: Readonly<Record<DetectionValidationCohort, DetectionValidationCohortResult>>;
  readonly detection_gap_percentage_points: number;
  readonly scenarios: readonly DetectionValidationScenarioResult[];
  readonly failure_reason?: string;
}

export interface DetectionValidationRunOptions {
  readonly webUrl: string;
  readonly workflowId: string;
  readonly deliverablesPath: string;
  readonly settings: DetectionValidationSettings;
  readonly splunkToken: string;
  readonly signal?: AbortSignal;
}

export interface DetectionValidationRunnerDependencies {
  readonly fetch?: typeof fetch;
  readonly now?: () => Date;
  readonly sleep?: (milliseconds: number) => Promise<void>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Runtime guard for the persisted evidence and canonical report contract. */
export function isDetectionValidationResult(value: unknown): value is DetectionValidationResult {
  if (!isRecord(value)) return false;
  if (
    value.schema_version !== 1 ||
    typeof value.corpus_version !== 'string' ||
    typeof value.corpus_sha256 !== 'string' ||
    !SHA256_PATTERN.test(value.corpus_sha256) ||
    !['passed', 'failed', 'partial', 'unavailable'].includes(String(value.status)) ||
    typeof value.target !== 'string' ||
    typeof value.started_at !== 'string' ||
    typeof value.completed_at !== 'string' ||
    typeof value.run_marker !== 'string' ||
    typeof value.minimum_detection_rate !== 'number' ||
    typeof value.detection_gap_percentage_points !== 'number' ||
    !isRecord(value.calibration) ||
    typeof value.calibration.sent_at !== 'string' ||
    typeof value.calibration.telemetry_observed !== 'boolean' ||
    !isRecord(value.cohorts) ||
    !Array.isArray(value.scenarios)
  ) {
    return false;
  }
  for (const cohort of ['ai', 'human']) {
    const result = value.cohorts[cohort];
    if (
      !isRecord(result) ||
      typeof result.total !== 'number' ||
      typeof result.detected !== 'number' ||
      typeof result.detection_rate !== 'number' ||
      typeof result.threshold !== 'number' ||
      typeof result.passed !== 'boolean'
    ) {
      return false;
    }
  }
  return value.scenarios.every(
    (scenario) =>
      isRecord(scenario) &&
      typeof scenario.id === 'string' &&
      typeof scenario.pair_id === 'string' &&
      (scenario.cohort === 'ai' || scenario.cohort === 'human') &&
      typeof scenario.technique === 'string' &&
      typeof scenario.fixture_sha256 === 'string' &&
      SHA256_PATTERN.test(scenario.fixture_sha256) &&
      typeof scenario.marker === 'string' &&
      MARKER_PATTERN.test(scenario.marker) &&
      (scenario.emission_status === 'sent' || scenario.emission_status === 'error') &&
      typeof scenario.sent_at === 'string' &&
      typeof scenario.detected === 'boolean',
  );
}

interface SplunkEvent {
  readonly raw: string;
  readonly time?: string;
}

function sha256(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => `${JSON.stringify(key)}:${stableJson(nested)}`);
    return `{${entries.join(',')}}`;
  }
  return JSON.stringify(value);
}

function resultPath(deliverablesPath: string): string {
  return path.join(deliverablesPath, DETECTION_VALIDATION_RESULT_FILENAME);
}

function median(values: readonly number[]): number | undefined {
  if (values.length === 0) return;
  const sorted = [...values].sort((left, right) => left - right);
  const middle = Math.floor(sorted.length / 2);
  const value =
    sorted.length % 2 === 0
      ? ((sorted[middle - 1] as number) + (sorted[middle] as number)) / 2
      : (sorted[middle] as number);
  return Math.round(value);
}

function eventDate(value: string | undefined): Date | undefined {
  if (!value) return;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) ? new Date(milliseconds) : undefined;
}

function boundedIdentifier(value: string, label: string, pattern: RegExp): string {
  if (!value || value.length > 128 || !pattern.test(value)) throw new Error(`Invalid Splunk ${label}`);
  return value;
}

export function createDetectionRunMarker(workflowId: string): string {
  return `shn-run-${sha256(`${DETECTION_CORPUS_VERSION}\0${workflowId}`).slice(0, 24)}`;
}

export function createDetectionScenarioMarker(workflowId: string, scenarioId: string): string {
  return `shn-sim-${sha256(`${DETECTION_CORPUS_VERSION}\0${workflowId}\0${scenarioId}`).slice(0, 24)}`;
}

export function detectionFixtureHash(fixture: DetectionValidationFixture): string {
  return sha256(stableJson(fixture));
}

export function detectionCorpusHash(): string {
  return sha256(stableJson({ version: DETECTION_CORPUS_VERSION, fixtures: DETECTION_VALIDATION_CORPUS }));
}

export function buildSplunkSearch(index: string, sourcetype: string | undefined, marker: string): string {
  const safeIndex = boundedIdentifier(index, 'index', IDENTIFIER_PATTERN);
  const safeSourcetype = sourcetype
    ? ` sourcetype="${boundedIdentifier(sourcetype, 'sourcetype', SOURCETYPE_PATTERN)}"`
    : '';
  if (!MARKER_PATTERN.test(marker)) throw new Error('Invalid Shannon detection marker');
  return `search index="${safeIndex}"${safeSourcetype} "${marker}" | fields _time _raw | head 1000`;
}

async function readBoundedText(response: Response): Promise<string> {
  if (!response.body) return '';
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let total = 0;
  let output = '';
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > SPLUNK_RESULT_LIMIT_BYTES) {
      await reader.cancel();
      throw new Error('Splunk search response exceeded the evidence limit');
    }
    output += decoder.decode(value, { stream: true });
  }
  return output + decoder.decode();
}

function parseSplunkEvents(payload: string): SplunkEvent[] {
  const events: SplunkEvent[] = [];
  for (const line of payload.split('\n')) {
    if (!line.trim()) continue;
    const parsed = JSON.parse(line) as { result?: { _raw?: unknown; _time?: unknown } };
    if (typeof parsed.result?._raw !== 'string') continue;
    events.push({
      raw: parsed.result._raw,
      ...(typeof parsed.result._time === 'string' && { time: parsed.result._time }),
    });
  }
  return events;
}

function requestSignal(parent: AbortSignal | undefined): AbortSignal {
  const timeout = AbortSignal.timeout(SPLUNK_REQUEST_TIMEOUT_MS);
  return parent ? AbortSignal.any([parent, timeout]) : timeout;
}

async function querySplunk(
  options: DetectionValidationRunOptions,
  index: string,
  sourcetype: string | undefined,
  marker: string,
  earliest: Date,
  latest: Date,
  fetchImpl: typeof fetch,
): Promise<SplunkEvent[]> {
  const body = new URLSearchParams({
    search: buildSplunkSearch(index, sourcetype, marker),
    earliest_time: String(Math.floor(earliest.getTime() / 1000)),
    latest_time: String(Math.ceil(latest.getTime() / 1000)),
    output_mode: 'json',
  });
  const response = await fetchImpl(`${options.settings.splunk.managementUrl}/services/search/v2/jobs/export`, {
    method: 'POST',
    redirect: 'manual',
    headers: {
      Accept: 'application/json',
      Authorization: `Bearer ${options.splunkToken}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body,
    signal: requestSignal(options.signal),
  });
  if (!response.ok) throw new Error(`Splunk search failed with HTTP ${response.status}`);
  return parseSplunkEvents(await readBoundedText(response));
}

function canaryUrl(
  webUrl: string,
  canaryPath: string,
  runMarker: string,
  scenarioMarker: string,
  scenario: string,
): URL {
  const targetOrigin = new URL(webUrl).origin;
  const url = new URL(canaryPath, targetOrigin);
  if (url.origin !== targetOrigin) throw new Error('Detection validation canary must remain same-origin');
  url.searchParams.set('shannon_run_id', runMarker);
  url.searchParams.set('shannon_simulation_id', scenarioMarker);
  url.searchParams.set('shannon_scenario', scenario);
  return url;
}

async function emitCanary(
  options: DetectionValidationRunOptions,
  runMarker: string,
  scenarioMarker: string,
  scenario: string,
  body: Readonly<Record<string, unknown>>,
  fetchImpl: typeof fetch,
): Promise<Response> {
  return fetchImpl(canaryUrl(options.webUrl, options.settings.canaryPath, runMarker, scenarioMarker, scenario), {
    method: 'POST',
    redirect: 'manual',
    headers: {
      'Content-Type': 'application/json',
      'X-Shannon-Simulation-Id': scenarioMarker,
      'X-Shannon-Simulation-Run': runMarker,
    },
    body: JSON.stringify({ ...body, run_marker: runMarker, simulation_marker: scenarioMarker }),
    signal: requestSignal(options.signal),
  });
}

async function pollSplunk(
  options: DetectionValidationRunOptions,
  index: string,
  sourcetype: string | undefined,
  marker: string,
  earliest: Date,
  fetchImpl: typeof fetch,
  now: () => Date,
  sleep: (milliseconds: number) => Promise<void>,
  stop: (events: readonly SplunkEvent[]) => boolean,
): Promise<SplunkEvent[]> {
  const events: SplunkEvent[] = [];
  const attempts = Math.ceil(options.settings.maxWaitSeconds / SPLUNK_POLL_SECONDS) + 1;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    events.push(...(await querySplunk(options, index, sourcetype, marker, earliest, now(), fetchImpl)));
    if (stop(events)) break;
    if (attempt < attempts - 1) await sleep(SPLUNK_POLL_SECONDS * 1000);
  }
  return events;
}

function emptyCohorts(threshold: number): Readonly<Record<DetectionValidationCohort, DetectionValidationCohortResult>> {
  return {
    ai: { total: 5, detected: 0, detection_rate: 0, threshold, passed: false },
    human: { total: 5, detected: 0, detection_rate: 0, threshold, passed: false },
  };
}

function cohortResult(
  cohort: DetectionValidationCohort,
  scenarios: readonly DetectionValidationScenarioResult[],
  threshold: number,
): DetectionValidationCohortResult {
  const members = scenarios.filter((scenario) => scenario.cohort === cohort);
  const detected = members.filter((scenario) => scenario.detected);
  const detectionRate = members.length === 0 ? 0 : detected.length / members.length;
  const medianLatency = median(detected.flatMap(({ latency_ms }) => (latency_ms === undefined ? [] : [latency_ms])));
  return {
    total: members.length,
    detected: detected.length,
    detection_rate: detectionRate,
    threshold,
    passed: members.length > 0 && detectionRate >= threshold,
    ...(medianLatency !== undefined && { median_latency_ms: medianLatency }),
  };
}

async function saveResult(
  deliverablesPath: string,
  result: DetectionValidationResult,
): Promise<DetectionValidationResult> {
  await ensureDirectory(deliverablesPath);
  await atomicWrite(resultPath(deliverablesPath), result);
  return result;
}

function unavailableResult(
  options: DetectionValidationRunOptions,
  startedAt: Date,
  completedAt: Date,
  runMarker: string,
  calibration: DetectionValidationResult['calibration'],
  scenarios: readonly DetectionValidationScenarioResult[],
  reason: string,
): DetectionValidationResult {
  return {
    schema_version: 1,
    corpus_version: DETECTION_CORPUS_VERSION,
    corpus_sha256: detectionCorpusHash(),
    status: 'unavailable',
    target: new URL(options.webUrl).origin,
    started_at: startedAt.toISOString(),
    completed_at: completedAt.toISOString(),
    run_marker: runMarker,
    minimum_detection_rate: options.settings.minimumDetectionRate,
    calibration,
    cohorts: emptyCohorts(options.settings.minimumDetectionRate),
    detection_gap_percentage_points: 0,
    scenarios,
    failure_reason: reason,
  };
}

export async function loadDetectionValidationResult(
  deliverablesPath: string,
): Promise<DetectionValidationResult | null> {
  const filePath = resultPath(deliverablesPath);
  if (!(await fileExists(filePath))) return null;
  try {
    const parsed = JSON.parse(await fs.readFile(filePath, 'utf8')) as unknown;
    if (
      !isDetectionValidationResult(parsed) ||
      parsed.corpus_version !== DETECTION_CORPUS_VERSION ||
      parsed.corpus_sha256 !== detectionCorpusHash()
    ) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

export async function runDetectionValidation(
  options: DetectionValidationRunOptions,
  dependencies: DetectionValidationRunnerDependencies = {},
): Promise<DetectionValidationResult> {
  const prior = await loadDetectionValidationResult(options.deliverablesPath);
  if (prior?.status === 'passed' || prior?.status === 'failed') return prior;

  const fetchImpl = dependencies.fetch ?? fetch;
  const now = dependencies.now ?? (() => new Date());
  const sleep = dependencies.sleep ?? ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)));
  const startedAt = now();
  const earliest = new Date(startedAt.getTime() - 60_000);
  const runMarker = createDetectionRunMarker(options.workflowId);
  const calibrationMarker = createDetectionScenarioMarker(options.workflowId, 'calibration');
  const calibrationSentAt = now();
  let calibrationResponse: Response;
  try {
    calibrationResponse = await emitCanary(
      options,
      runMarker,
      calibrationMarker,
      'calibration',
      { simulation: 'shannon-inert', event: 'calibration' },
      fetchImpl,
    );
  } catch {
    const calibration = { sent_at: calibrationSentAt.toISOString(), telemetry_observed: false };
    return saveResult(
      options.deliverablesPath,
      unavailableResult(options, startedAt, now(), runMarker, calibration, [], 'Canary calibration request failed'),
    );
  }

  if (calibrationResponse.status !== 204) {
    const calibration = {
      sent_at: calibrationSentAt.toISOString(),
      http_status: calibrationResponse.status,
      telemetry_observed: false,
    };
    return saveResult(
      options.deliverablesPath,
      unavailableResult(
        options,
        startedAt,
        now(),
        runMarker,
        calibration,
        [],
        'Canary calibration must return HTTP 204',
      ),
    );
  }

  let calibrationEvents: SplunkEvent[];
  try {
    calibrationEvents = await pollSplunk(
      options,
      options.settings.splunk.telemetryIndex,
      options.settings.splunk.telemetrySourcetype,
      calibrationMarker,
      earliest,
      fetchImpl,
      now,
      sleep,
      (events) => events.some(({ raw }) => raw.includes(calibrationMarker)),
    );
  } catch {
    const calibration = {
      sent_at: calibrationSentAt.toISOString(),
      http_status: calibrationResponse.status,
      telemetry_observed: false,
    };
    return saveResult(
      options.deliverablesPath,
      unavailableResult(options, startedAt, now(), runMarker, calibration, [], 'Splunk telemetry query failed'),
    );
  }

  const calibrationEvent = calibrationEvents.find(({ raw }) => raw.includes(calibrationMarker));
  if (!calibrationEvent) {
    const calibration = {
      sent_at: calibrationSentAt.toISOString(),
      http_status: calibrationResponse.status,
      telemetry_observed: false,
    };
    return saveResult(
      options.deliverablesPath,
      unavailableResult(
        options,
        startedAt,
        now(),
        runMarker,
        calibration,
        [],
        'Telemetry calibration was not observed',
      ),
    );
  }

  const calibrationFirstSeen = eventDate(calibrationEvent.time);
  const calibrationLatency = calibrationFirstSeen
    ? Math.max(0, calibrationFirstSeen.getTime() - calibrationSentAt.getTime())
    : undefined;
  const calibration: DetectionValidationResult['calibration'] = {
    sent_at: calibrationSentAt.toISOString(),
    http_status: calibrationResponse.status,
    telemetry_observed: true,
    ...(calibrationFirstSeen && { first_seen_at: calibrationFirstSeen.toISOString() }),
    ...(calibrationLatency !== undefined && { latency_ms: calibrationLatency }),
  };

  const emitted: DetectionValidationScenarioResult[] = [];
  for (let index = 0; index < DETECTION_VALIDATION_CORPUS.length; index += 1) {
    await sleep(1000);
    const fixture = DETECTION_VALIDATION_CORPUS[index] as DetectionValidationFixture;
    const marker = createDetectionScenarioMarker(options.workflowId, fixture.id);
    const sentAt = now();
    try {
      const response = await emitCanary(options, runMarker, marker, fixture.id, fixture.body, fetchImpl);
      emitted.push({
        id: fixture.id,
        pair_id: fixture.pairId,
        cohort: fixture.cohort,
        technique: fixture.technique,
        fixture_sha256: detectionFixtureHash(fixture),
        marker,
        emission_status: response.status === 204 ? 'sent' : 'error',
        sent_at: sentAt.toISOString(),
        http_status: response.status,
        detected: false,
      });
    } catch {
      emitted.push({
        id: fixture.id,
        pair_id: fixture.pairId,
        cohort: fixture.cohort,
        technique: fixture.technique,
        fixture_sha256: detectionFixtureHash(fixture),
        marker,
        emission_status: 'error',
        sent_at: sentAt.toISOString(),
        detected: false,
      });
    }
  }

  const expectedMarkers = new Set(
    emitted.filter(({ emission_status }) => emission_status === 'sent').map(({ marker }) => marker),
  );
  let alertEvents: SplunkEvent[];
  try {
    alertEvents = await pollSplunk(
      options,
      options.settings.splunk.alertIndex,
      options.settings.splunk.alertSourcetype,
      runMarker,
      earliest,
      fetchImpl,
      now,
      sleep,
      (events) => [...expectedMarkers].every((marker) => events.some(({ raw }) => raw.includes(marker))),
    );
  } catch {
    return saveResult(
      options.deliverablesPath,
      unavailableResult(options, startedAt, now(), runMarker, calibration, emitted, 'Splunk alert query failed'),
    );
  }

  const scenarios = emitted.map((scenario): DetectionValidationScenarioResult => {
    const matchingEvents = alertEvents.filter(({ raw }) => raw.includes(scenario.marker));
    const matches = matchingEvents
      .flatMap(({ time }) => {
        const parsed = eventDate(time);
        return parsed ? [parsed] : [];
      })
      .sort((left, right) => left.getTime() - right.getTime());
    const firstSeen = matches[0];
    const latency = firstSeen ? Math.max(0, firstSeen.getTime() - new Date(scenario.sent_at).getTime()) : undefined;
    return {
      ...scenario,
      detected: matchingEvents.length > 0,
      ...(firstSeen && { first_seen_at: firstSeen.toISOString() }),
      ...(latency !== undefined && { latency_ms: latency }),
    };
  });
  const ai = cohortResult('ai', scenarios, options.settings.minimumDetectionRate);
  const human = cohortResult('human', scenarios, options.settings.minimumDetectionRate);
  const hasEmissionError = scenarios.some(({ emission_status }) => emission_status === 'error');
  const hasScoringError = scenarios.some(({ detected, first_seen_at }) => detected && !first_seen_at);
  const status: DetectionValidationStatus =
    hasEmissionError || hasScoringError ? 'partial' : ai.passed && human.passed ? 'passed' : 'failed';
  const result: DetectionValidationResult = {
    schema_version: 1,
    corpus_version: DETECTION_CORPUS_VERSION,
    corpus_sha256: detectionCorpusHash(),
    status,
    target: new URL(options.webUrl).origin,
    started_at: startedAt.toISOString(),
    completed_at: now().toISOString(),
    run_marker: runMarker,
    minimum_detection_rate: options.settings.minimumDetectionRate,
    calibration,
    cohorts: { ai, human },
    detection_gap_percentage_points: Math.round((human.detection_rate - ai.detection_rate) * 10_000) / 100,
    scenarios,
    ...(hasEmissionError
      ? { failure_reason: 'One or more simulations could not be emitted' }
      : hasScoringError
        ? { failure_reason: 'One or more detected simulations had no valid first-seen timestamp' }
        : {}),
  };
  return saveResult(options.deliverablesPath, result);
}
