import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { DETECTION_VALIDATION_CORPUS } from '../../src/services/detection-validation-corpus.js';
import {
  createDetectionScenarioMarker,
  runDetectionValidation,
} from '../../src/services/detection-validation-runner.js';

const temporaryDirectories: string[] = [];
const servers: http.Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) => fs.rm(directory, { recursive: true, force: true })),
  );
});

async function listen(handler: http.RequestListener): Promise<{ server: http.Server; origin: string }> {
  const server = http.createServer(handler);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Fake server did not bind a TCP port');
  return { server, origin: `http://127.0.0.1:${address.port}` };
}

async function body(request: http.IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString('utf8');
}

describe('detection validation local-server flow', () => {
  it('calibrates, emits the fixed corpus, searches Splunk v2, and persists redacted evidence', async () => {
    const workflowId = 'integration-detection';
    const targetRequests: Array<{ url: string; marker?: string }> = [];
    const splunkRequests: Array<{ authorization?: string; search?: string }> = [];
    const target = await listen(async (request, response) => {
      await body(request);
      targetRequests.push({ url: request.url ?? '', marker: request.headers['x-shannon-simulation-id'] as string });
      response.writeHead(204).end();
    });
    const splunk = await listen(async (request, response) => {
      const form = new URLSearchParams(await body(request));
      const search = form.get('search') ?? '';
      splunkRequests.push({ authorization: request.headers.authorization, search });
      const searchedMarker = search.match(/"(shn-(?:run|sim)-[a-z0-9-]+)"/)?.[1];
      const events = search.includes('waf_events')
        ? [searchedMarker]
        : DETECTION_VALIDATION_CORPUS.map(({ id }) => createDetectionScenarioMarker(workflowId, id));
      response.writeHead(200, { 'Content-Type': 'application/x-ndjson' });
      response.end(
        events
          .filter((marker): marker is string => Boolean(marker))
          .map((marker) => JSON.stringify({ result: { _raw: `event ${marker}`, _time: '2026-09-29T12:00:02.000Z' } }))
          .join('\n'),
      );
    });
    const deliverablesPath = await fs.mkdtemp(path.join(os.tmpdir(), 'shannon-detection-e2e-'));
    temporaryDirectories.push(deliverablesPath);
    const bridgeFetch: typeof fetch = async (input, init) => {
      const original = new URL(String(input));
      const localOrigin = original.hostname === 'target.example.test' ? target.origin : splunk.origin;
      return fetch(`${localOrigin}${original.pathname}${original.search}`, init);
    };

    const result = await runDetectionValidation(
      {
        webUrl: 'https://target.example.test',
        workflowId,
        deliverablesPath,
        settings: {
          canaryPath: '/__shannon__/detection-simulation',
          minimumDetectionRate: 1,
          maxWaitSeconds: 30,
          splunk: {
            managementUrl: 'https://splunk.example.test:8089',
            telemetryIndex: 'waf_events',
            alertIndex: 'security_alerts',
          },
        },
        splunkToken: 'integration-secret',
      },
      {
        fetch: bridgeFetch,
        now: () => new Date('2026-09-29T12:00:00.000Z'),
        sleep: async () => undefined,
      },
    );

    expect(result.status).toBe('passed');
    expect(targetRequests).toHaveLength(11);
    expect(new Set(targetRequests.map(({ marker }) => marker))).toHaveLength(11);
    expect(splunkRequests).toHaveLength(2);
    expect(splunkRequests.every(({ authorization }) => authorization === 'Bearer integration-secret')).toBe(true);
    expect(splunkRequests.every(({ search }) => search?.includes('| fields _time _raw | head 1000'))).toBe(true);
    const evidence = await fs.readFile(path.join(deliverablesPath, 'detection-validation.json'), 'utf8');
    expect(evidence).not.toContain('integration-secret');
    expect(evidence).not.toContain('_raw');
  });
});
