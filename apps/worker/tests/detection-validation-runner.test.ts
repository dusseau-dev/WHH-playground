import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { DETECTION_VALIDATION_CORPUS } from '../src/services/detection-validation-corpus.js';
import {
  buildSplunkSearch,
  createDetectionRunMarker,
  createDetectionScenarioMarker,
  DETECTION_VALIDATION_RESULT_FILENAME,
  loadDetectionValidationResult,
  runDetectionValidation,
} from '../src/services/detection-validation-runner.js';
import type { DetectionValidationSettings } from '../src/types/detection-validation.js';

const temporaryDirectories: string[] = [];

async function temporaryDirectory(): Promise<string> {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'shannon-detection-validation-'));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) => fs.rm(directory, { recursive: true, force: true })),
  );
});

const settings: DetectionValidationSettings = {
  canaryPath: '/__shannon__/detection-simulation',
  minimumDetectionRate: 1,
  maxWaitSeconds: 30,
  splunk: {
    managementUrl: 'https://splunk.example.test:8089',
    telemetryIndex: 'waf_events',
    alertIndex: 'security_alerts',
    telemetrySourcetype: 'aws:waf',
    alertSourcetype: 'notable',
  },
};

function splunkResponse(rawEvents: string[], time = '2026-09-29T12:00:01.000Z'): Response {
  return new Response(rawEvents.map((raw) => JSON.stringify({ result: { _raw: raw, _time: time } })).join('\n'), {
    status: 200,
  });
}

describe('Splunk search construction', () => {
  it('builds a bounded search from validated identifiers and a Shannon marker', () => {
    expect(buildSplunkSearch('security_alerts', 'notable', 'shn-run-abc123')).toBe(
      'search index="security_alerts" sourcetype="notable" "shn-run-abc123" | fields _time _raw | head 1000',
    );
    expect(buildSplunkSearch('security_alerts', undefined, 'shn-run-abc123')).toBe(
      'search index="security_alerts" "shn-run-abc123" | fields _time _raw | head 1000',
    );
  });
});

describe('detection validation runner', () => {
  it('calibrates telemetry, emits ten simulations, and passes when both cohorts are fully detected', async () => {
    const deliverablesPath = await temporaryDirectory();
    const workflowId = 'workflow-123';
    const runMarker = createDetectionRunMarker(workflowId);
    const calibrationMarker = createDetectionScenarioMarker(workflowId, 'calibration');
    const scenarioMarkers = DETECTION_VALIDATION_CORPUS.map(({ id }) => createDetectionScenarioMarker(workflowId, id));
    const requests: Array<{ url: string; init?: RequestInit }> = [];
    const sleep = vi.fn(async () => undefined);
    let splunkCalls = 0;
    const fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input);
      requests.push({ url, ...(init && { init }) });
      if (!url.startsWith(settings.splunk.managementUrl)) return new Response(null, { status: 204 });
      splunkCalls += 1;
      return splunkCalls === 1
        ? splunkResponse([`telemetry ${runMarker} ${calibrationMarker}`])
        : splunkResponse(scenarioMarkers.map((marker) => `alert ${runMarker} ${marker}`));
    });

    const result = await runDetectionValidation(
      {
        webUrl: 'https://target.example.test/app',
        workflowId,
        deliverablesPath,
        settings,
        splunkToken: 'splunk-secret',
      },
      {
        fetch: fetchMock as typeof fetch,
        now: () => new Date('2026-09-29T12:00:00.000Z'),
        sleep,
      },
    );

    expect(result.status).toBe('passed');
    expect(result.cohorts.ai).toMatchObject({ total: 5, detected: 5, detection_rate: 1, passed: true });
    expect(result.cohorts.human).toMatchObject({ total: 5, detected: 5, detection_rate: 1, passed: true });
    expect(result.scenarios).toHaveLength(10);
    const targetRequests = requests.filter(({ url }) => !url.startsWith(settings.splunk.managementUrl));
    expect(targetRequests).toHaveLength(11);
    expect(targetRequests[0]?.init).toMatchObject({ method: 'POST', redirect: 'manual' });
    expect(sleep).toHaveBeenCalledTimes(10);
    for (const [index, marker] of scenarioMarkers.entries()) {
      const request = targetRequests[index + 1];
      expect(request).toBeDefined();
      expect(new URL(request?.url ?? '').searchParams.get('shannon_simulation_id')).toBe(marker);
      expect(request?.init?.headers).toMatchObject({ 'X-Shannon-Simulation-Id': marker });
    }
    const searches = requests.filter(({ url }) => url.startsWith(settings.splunk.managementUrl));
    expect(searches.every(({ url }) => url.endsWith('/services/search/v2/jobs/export'))).toBe(true);
    expect(searches.every(({ init }) => init?.redirect === 'manual')).toBe(true);
    expect(searches[0]?.init?.headers).toMatchObject({ Authorization: 'Bearer splunk-secret' });
    expect(String(searches[0]?.init?.body)).toContain(encodeURIComponent(calibrationMarker));
    expect(String(searches[0]?.init?.body)).toMatch(/earliest_time=\d+&latest_time=\d+/);

    const evidence = await fs.readFile(path.join(deliverablesPath, DETECTION_VALIDATION_RESULT_FILENAME), 'utf8');
    expect(evidence).not.toContain('splunk-secret');
    expect(evidence).not.toContain('SHANNON_FAKE_PASSWORD_DO_NOT_USE');
    await expect(loadDetectionValidationResult(deliverablesPath)).resolves.toEqual(result);

    const callCount = fetchMock.mock.calls.length;
    await expect(
      runDetectionValidation(
        {
          webUrl: 'https://target.example.test/app',
          workflowId,
          deliverablesPath,
          settings,
          splunkToken: 'splunk-secret',
        },
        { fetch: fetchMock as typeof fetch, sleep },
      ),
    ).resolves.toEqual(result);
    expect(fetchMock).toHaveBeenCalledTimes(callCount);

    await fs.writeFile(
      path.join(deliverablesPath, DETECTION_VALIDATION_RESULT_FILENAME),
      JSON.stringify({ ...result, corpus_sha256: '0'.repeat(64) }),
    );
    await expect(loadDetectionValidationResult(deliverablesPath)).resolves.toBeNull();
  });

  it('fails a complete score when one cohort misses its threshold', async () => {
    const deliverablesPath = await temporaryDirectory();
    const workflowId = 'workflow-miss';
    const runMarker = createDetectionRunMarker(workflowId);
    const calibrationMarker = createDetectionScenarioMarker(workflowId, 'calibration');
    const missed = DETECTION_VALIDATION_CORPUS.find(({ cohort }) => cohort === 'ai');
    expect(missed).toBeDefined();
    const alertMarkers = DETECTION_VALIDATION_CORPUS.filter(({ id }) => id !== missed?.id).map(({ id }) =>
      createDetectionScenarioMarker(workflowId, id),
    );
    let splunkCalls = 0;
    const result = await runDetectionValidation(
      {
        webUrl: 'https://target.example.test',
        workflowId,
        deliverablesPath,
        settings,
        splunkToken: 'token',
      },
      {
        fetch: (async (input) => {
          const url = String(input);
          if (!url.startsWith(settings.splunk.managementUrl)) return new Response(null, { status: 204 });
          splunkCalls += 1;
          return splunkCalls === 1
            ? splunkResponse([`telemetry ${runMarker} ${calibrationMarker}`])
            : splunkResponse(alertMarkers.map((marker) => `alert ${runMarker} ${marker}`));
        }) as typeof fetch,
        now: () => new Date('2026-09-29T12:00:00.000Z'),
        sleep: async () => undefined,
      },
    );

    expect(result.status).toBe('failed');
    expect(result.cohorts.ai).toMatchObject({ total: 5, detected: 4, detection_rate: 0.8, passed: false });
    expect(result.cohorts.human.passed).toBe(true);
  });

  it('stops as unavailable when calibration cannot be observed', async () => {
    const deliverablesPath = await temporaryDirectory();
    let targetCalls = 0;
    const result = await runDetectionValidation(
      {
        webUrl: 'https://target.example.test',
        workflowId: 'workflow-no-calibration',
        deliverablesPath,
        settings,
        splunkToken: 'token',
      },
      {
        fetch: (async (input) => {
          if (!String(input).startsWith(settings.splunk.managementUrl)) {
            targetCalls += 1;
            return new Response(null, { status: 204 });
          }
          return splunkResponse([]);
        }) as typeof fetch,
        now: () => new Date('2026-09-29T12:00:00.000Z'),
        sleep: async () => undefined,
      },
    );

    expect(result).toMatchObject({ status: 'unavailable', failure_reason: expect.stringMatching(/calibration/i) });
    expect(targetCalls).toBe(1);
  });

  it('returns partial evidence when a scenario cannot be emitted', async () => {
    const deliverablesPath = await temporaryDirectory();
    const workflowId = 'workflow-network-error';
    const runMarker = createDetectionRunMarker(workflowId);
    const calibrationMarker = createDetectionScenarioMarker(workflowId, 'calibration');
    let targetCalls = 0;
    const result = await runDetectionValidation(
      {
        webUrl: 'https://target.example.test',
        workflowId,
        deliverablesPath,
        settings,
        splunkToken: 'token',
      },
      {
        fetch: (async (input) => {
          if (String(input).startsWith(settings.splunk.managementUrl)) {
            return splunkResponse([`telemetry ${runMarker} ${calibrationMarker}`]);
          }
          targetCalls += 1;
          if (targetCalls === 2) throw new Error('target unavailable');
          return new Response(null, { status: 204 });
        }) as typeof fetch,
        now: () => new Date('2026-09-29T12:00:00.000Z'),
        sleep: async () => undefined,
      },
    );

    expect(result).toMatchObject({ status: 'partial', failure_reason: expect.stringMatching(/emit/i) });
    expect(result.scenarios.some(({ emission_status }) => emission_status === 'error')).toBe(true);
  });

  it('returns partial evidence when a simulation endpoint response is not 204', async () => {
    const deliverablesPath = await temporaryDirectory();
    const workflowId = 'workflow-bad-response';
    const runMarker = createDetectionRunMarker(workflowId);
    const calibrationMarker = createDetectionScenarioMarker(workflowId, 'calibration');
    let targetCalls = 0;
    const result = await runDetectionValidation(
      {
        webUrl: 'https://target.example.test',
        workflowId,
        deliverablesPath,
        settings,
        splunkToken: 'token',
      },
      {
        fetch: (async (input) => {
          if (String(input).startsWith(settings.splunk.managementUrl)) {
            return splunkResponse([`event ${runMarker} ${calibrationMarker}`]);
          }
          targetCalls += 1;
          return new Response(null, { status: targetCalls === 2 ? 202 : 204 });
        }) as typeof fetch,
        now: () => new Date('2026-09-29T12:00:00.000Z'),
        sleep: async () => undefined,
      },
    );

    expect(result.status).toBe('partial');
    expect(result.scenarios).toContainEqual(expect.objectContaining({ emission_status: 'error', http_status: 202 }));
  });

  it('returns partial evidence when detected alerts have no scoreable first-seen time', async () => {
    const deliverablesPath = await temporaryDirectory();
    const workflowId = 'workflow-missing-alert-time';
    const runMarker = createDetectionRunMarker(workflowId);
    const calibrationMarker = createDetectionScenarioMarker(workflowId, 'calibration');
    const scenarioMarkers = DETECTION_VALIDATION_CORPUS.map(({ id }) => createDetectionScenarioMarker(workflowId, id));
    let splunkCalls = 0;
    const result = await runDetectionValidation(
      {
        webUrl: 'https://target.example.test',
        workflowId,
        deliverablesPath,
        settings,
        splunkToken: 'token',
      },
      {
        fetch: (async (input) => {
          if (!String(input).startsWith(settings.splunk.managementUrl)) return new Response(null, { status: 204 });
          splunkCalls += 1;
          if (splunkCalls === 1) return splunkResponse([`telemetry ${runMarker} ${calibrationMarker}`]);
          return new Response(
            scenarioMarkers.map((marker) => JSON.stringify({ result: { _raw: `alert ${marker}` } })).join('\n'),
            { status: 200 },
          );
        }) as typeof fetch,
        now: () => new Date('2026-09-29T12:00:00.000Z'),
        sleep: async () => undefined,
      },
    );

    expect(result).toMatchObject({ status: 'partial', failure_reason: expect.stringMatching(/first-seen/i) });
    expect(result.scenarios.every(({ detected }) => detected)).toBe(true);
    expect(result.scenarios.every(({ latency_ms }) => latency_ms === undefined)).toBe(true);
  });

  it('classifies Splunk authentication failure as unavailable without leaking the token', async () => {
    const deliverablesPath = await temporaryDirectory();
    const result = await runDetectionValidation(
      {
        webUrl: 'https://target.example.test',
        workflowId: 'workflow-auth-failure',
        deliverablesPath,
        settings,
        splunkToken: 'secret-token',
      },
      {
        fetch: (async (input) =>
          String(input).startsWith(settings.splunk.managementUrl)
            ? new Response('permission denied secret-token', { status: 401 })
            : new Response(null, { status: 204 })) as typeof fetch,
        sleep: async () => undefined,
      },
    );

    expect(result).toMatchObject({ status: 'unavailable', failure_reason: 'Splunk telemetry query failed' });
    expect(JSON.stringify(result)).not.toContain('secret-token');
  });

  it('passes an abortable timeout signal to Splunk and classifies timeout as unavailable', async () => {
    const deliverablesPath = await temporaryDirectory();
    let searchSignal: AbortSignal | null | undefined;
    const result = await runDetectionValidation(
      {
        webUrl: 'https://target.example.test',
        workflowId: 'workflow-timeout',
        deliverablesPath,
        settings,
        splunkToken: 'token',
      },
      {
        fetch: (async (input, init) => {
          if (!String(input).startsWith(settings.splunk.managementUrl)) return new Response(null, { status: 204 });
          searchSignal = init?.signal;
          throw new DOMException('request timed out', 'TimeoutError');
        }) as typeof fetch,
        sleep: async () => undefined,
      },
    );

    expect(searchSignal).toBeInstanceOf(AbortSignal);
    expect(result).toMatchObject({ status: 'unavailable', failure_reason: 'Splunk telemetry query failed' });
    expect(JSON.stringify(result)).not.toContain('request timed out');
  });
});
