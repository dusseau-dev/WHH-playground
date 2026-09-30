import { spawn } from 'node:child_process';
import { EventEmitter } from 'node:events';
import fs from 'node:fs/promises';
import { createServer } from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { HTTP_LOAD_RESULT_PATH, runHttpLoadCapacity } from '../src/services/http-load-runner.js';
import {
  assertHttpLoadAuthorization,
  HTTP_LOAD_DEFAULTS,
  type HttpLoadResult,
  isElevatedHttpLoad,
  normalizeHttpLoadSettings,
} from '../src/types/http-load.js';
import { atomicWrite } from '../src/utils/file-io.js';

const scriptPath = fileURLToPath(new URL('../scripts/http_flood_test.py', import.meta.url));
const temporaryDirectories: string[] = [];
const completedResult: HttpLoadResult = {
  version: 1,
  status: 'completed',
  started_at: '2026-09-01T12:00:00.000Z',
  completed_at: '2026-09-01T12:00:01.000Z',
  target: 'https://authorized.test/',
  concurrency: 5,
  requests_per_second: 10,
  duration_seconds: 15,
  elapsed_seconds: 15.01,
  sent: 150,
  completed: 150,
  success: 150,
  failure: 0,
  errors: 0,
  bytes_read: 15_000,
  average_latency_ms: 8.5,
  minimum_latency_ms: 5.2,
  maximum_latency_ms: 14.1,
  status_counts: { '200': 150 },
};

async function temporaryDirectory(): Promise<string> {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'shannon-load-script-'));
  temporaryDirectories.push(directory);
  return directory;
}

async function runPython(
  args: readonly string[],
): Promise<{ exitCode: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn('python3', [scriptPath, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => (stdout += chunk));
    child.stderr.on('data', (chunk: string) => (stderr += chunk));
    child.once('error', reject);
    child.once('exit', (exitCode) => resolve({ exitCode, stdout, stderr }));
  });
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) => fs.rm(directory, { recursive: true, force: true })),
  );
});

describe('HTTP load settings', () => {
  it('applies safe defaults only when the explicit scope is selected', () => {
    expect(normalizeHttpLoadSettings(['http-load-capacity'])).toEqual(HTTP_LOAD_DEFAULTS);
    expect(normalizeHttpLoadSettings(['csrf'])).toBeUndefined();
    expect(() =>
      normalizeHttpLoadSettings(['csrf'], {
        concurrency: 5,
        requestsPerSecond: 10,
        durationSeconds: 15,
      }),
    ).toThrow(/requires.*http-load-capacity/i);
  });

  it('normalizes partial settings and detects elevated load', () => {
    expect(normalizeHttpLoadSettings(['http-load-capacity'], { durationSeconds: 30 })).toEqual({
      concurrency: 5,
      requestsPerSecond: 10,
      durationSeconds: 30,
    });
    expect(isElevatedHttpLoad({ concurrency: 20, requestsPerSecond: 50, durationSeconds: 60 })).toBe(false);
    expect(isElevatedHttpLoad({ concurrency: 21, requestsPerSecond: 50, durationSeconds: 60 })).toBe(true);
    expect(isElevatedHttpLoad({ concurrency: 20, requestsPerSecond: 51, durationSeconds: 60 })).toBe(true);
    expect(isElevatedHttpLoad({ concurrency: 20, requestsPerSecond: 50, durationSeconds: 61 })).toBe(true);
  });

  it('rejects non-integers and values outside emergency ceilings', () => {
    expect(() => normalizeHttpLoadSettings(['http-load-capacity'], { concurrency: 0 })).toThrow(/concurrency/i);
    expect(() => normalizeHttpLoadSettings(['http-load-capacity'], { requestsPerSecond: 10.5 })).toThrow(
      /requests per second/i,
    );
    expect(() =>
      normalizeHttpLoadSettings(['http-load-capacity'], { durationSeconds: Number.POSITIVE_INFINITY }),
    ).toThrow(/duration/i);
    expect(() => normalizeHttpLoadSettings(['http-load-capacity'], { concurrency: 1_001 })).toThrow(/1,000/);
    expect(() => normalizeHttpLoadSettings(['http-load-capacity'], { requestsPerSecond: 10_001 })).toThrow(/10,000/);
    expect(() => normalizeHttpLoadSettings(['http-load-capacity'], { durationSeconds: 3_601 })).toThrow(/3,600/);
  });

  it('requires ownership and elevated-load acknowledgements', () => {
    expect(() => assertHttpLoadAuthorization(HTTP_LOAD_DEFAULTS, false, false)).toThrow(/authorization/i);
    expect(() => assertHttpLoadAuthorization(HTTP_LOAD_DEFAULTS, true, false)).not.toThrow();
    expect(() => assertHttpLoadAuthorization({ ...HTTP_LOAD_DEFAULTS, concurrency: 21 }, true, false)).toThrow(
      /elevated/i,
    );
    expect(() => assertHttpLoadAuthorization({ ...HTTP_LOAD_DEFAULTS, concurrency: 21 }, true, true)).not.toThrow();
    expect(() => assertHttpLoadAuthorization(undefined, false, false)).not.toThrow();
  });
});

describe('HTTP load generator', () => {
  it('enforces emergency ceilings when invoked directly', async () => {
    const result = await runPython([
      'http://127.0.0.1:9/',
      '--concurrency',
      '1001',
      '--rate',
      '1',
      '--duration',
      '1',
      '--i-own-this-target',
    ]);

    expect(result.exitCode).toBe(2);
    expect(result.stderr).toMatch(/concurrency.*1,?000/i);
  });

  it('refuses traffic without the ownership flag', async () => {
    let requestCount = 0;
    const server = createServer((_request, response) => {
      requestCount += 1;
      response.end('ok');
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('Loopback fixture did not expose a port');

    try {
      const result = await runPython([
        `http://127.0.0.1:${address.port}/`,
        '--concurrency',
        '1',
        '--rate',
        '1',
        '--duration',
        '1',
      ]);
      expect(result.exitCode).toBe(2);
      expect(result.stderr).toMatch(/refusing.*i-own-this-target/i);
      expect(requestCount).toBe(0);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
    }
  });

  it('writes a bounded machine-readable summary', async () => {
    let requestCount = 0;
    const server = createServer((_request, response) => {
      requestCount += 1;
      response.writeHead(200, { 'Content-Type': 'text/plain' });
      response.end('ok');
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('Loopback fixture did not expose a port');
    const outputPath = path.join(await temporaryDirectory(), 'result.json');

    try {
      const result = await runPython([
        `http://127.0.0.1:${address.port}/capacity?token=secret-value`,
        '--concurrency',
        '2',
        '--rate',
        '4',
        '--duration',
        '1',
        '--json-output',
        outputPath,
        '--i-own-this-target',
      ]);
      expect(result.exitCode).toBe(0);
      const summary = JSON.parse(await fs.readFile(outputPath, 'utf8')) as Record<string, unknown>;
      expect(summary).toMatchObject({
        version: 1,
        status: 'completed',
        concurrency: 2,
        requests_per_second: 4,
        duration_seconds: 1,
        sent: 4,
        completed: 4,
        success: 4,
        failure: 0,
        errors: 0,
        status_counts: { 200: 4 },
      });
      expect(summary.target).toBe(`http://127.0.0.1:${address.port}/capacity?token=%5BREDACTED%5D`);
      expect(requestCount).toBe(4);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
    }
  });
});

describe('HTTP load runner', () => {
  it('returns an existing valid completed artifact without starting a child', async () => {
    const workingDirectory = await temporaryDirectory();
    const resultPath = path.join(workingDirectory, HTTP_LOAD_RESULT_PATH);
    await fs.mkdir(path.dirname(resultPath), { recursive: true });
    await atomicWrite(resultPath, completedResult);
    const spawnProcess = vi.fn();

    await expect(
      runHttpLoadCapacity({
        webUrl: 'https://authorized.test/',
        workingDirectory,
        settings: HTTP_LOAD_DEFAULTS,
        authorizationConfirmed: true,
        elevatedLoadConfirmed: false,
        spawn: spawnProcess,
      }),
    ).resolves.toEqual(completedResult);
    expect(spawnProcess).not.toHaveBeenCalled();
  });

  it('forwards cancellation to the child process', async () => {
    class FakeChild extends EventEmitter {
      readonly stdout = new PassThrough();
      readonly stderr = new PassThrough();
      readonly kill = vi.fn((signalName?: NodeJS.Signals | number) => {
        queueMicrotask(() => this.emit('exit', signalName === 'SIGKILL' ? 137 : 130, signalName));
        return true;
      });
    }

    const workingDirectory = await temporaryDirectory();
    const child = new FakeChild();
    const spawnProcess = vi.fn(() => child);
    const controller = new AbortController();
    const running = runHttpLoadCapacity({
      webUrl: 'https://authorized.test/',
      workingDirectory,
      settings: HTTP_LOAD_DEFAULTS,
      authorizationConfirmed: true,
      elevatedLoadConfirmed: false,
      signal: controller.signal,
      spawn: spawnProcess,
    });
    await vi.waitFor(() => expect(spawnProcess).toHaveBeenCalledOnce());
    controller.abort();

    await expect(running).rejects.toMatchObject({ name: 'AbortError' });
    expect(child.kill).toHaveBeenCalledWith('SIGTERM');
  });
});
