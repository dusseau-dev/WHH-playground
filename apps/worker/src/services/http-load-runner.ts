import { spawn as nodeSpawn } from 'node:child_process';
import path from 'node:path';
import type { ActivityLogger } from '../types/activity-logger.js';
import {
  assertHttpLoadAuthorization,
  type HttpLoadResult,
  type HttpLoadSettings,
  parseHttpLoadResult,
} from '../types/http-load.js';
import { fileExists, readJson } from '../utils/file-io.js';
import { redactLogText } from '../utils/redactSecrets.js';

export const HTTP_LOAD_RESULT_PATH = path.join('.shannon', 'http-load-capacity.json');
const MAX_DIAGNOSTIC_LENGTH = 4_000;
const FORCE_KILL_DELAY_MS = 5_000;

interface ProcessStream {
  setEncoding(encoding: BufferEncoding): void;
  on(event: 'data', listener: (chunk: string | Buffer) => void): unknown;
}

export interface HttpLoadChildProcess {
  readonly stdout: ProcessStream;
  readonly stderr: ProcessStream;
  once(event: 'error', listener: (error: Error) => void): unknown;
  once(event: 'exit', listener: (code: number | null, signal: NodeJS.Signals | null) => void): unknown;
  kill(signal?: NodeJS.Signals | number): boolean;
}

export type HttpLoadSpawn = (
  command: string,
  args: readonly string[],
  options: { readonly cwd: string; stdio: ['ignore', 'pipe', 'pipe']; readonly shell: false },
) => HttpLoadChildProcess;

export interface RunHttpLoadCapacityOptions {
  readonly webUrl: string;
  readonly workingDirectory: string;
  readonly settings: HttpLoadSettings;
  readonly authorizationConfirmed: boolean;
  readonly elevatedLoadConfirmed: boolean;
  readonly signal?: AbortSignal;
  readonly logger?: ActivityLogger;
  readonly spawn?: HttpLoadSpawn;
  readonly scriptPath?: string;
}

function comparableTarget(value: string): string {
  const target = new URL(value);
  target.username = '';
  target.password = '';
  target.search = '';
  target.hash = '';
  return target.href;
}

function matchesRun(result: HttpLoadResult, options: RunHttpLoadCapacityOptions): boolean {
  return (
    comparableTarget(result.target) === comparableTarget(options.webUrl) &&
    result.concurrency === options.settings.concurrency &&
    result.requests_per_second === options.settings.requestsPerSecond &&
    result.duration_seconds === options.settings.durationSeconds
  );
}

/** Read any schema-valid load artifact, including an interrupted diagnostic. */
export async function readHttpLoadResult(workingDirectory: string): Promise<HttpLoadResult | undefined> {
  const resultPath = path.join(workingDirectory, HTTP_LOAD_RESULT_PATH);
  if (!(await fileExists(resultPath))) return;
  try {
    return parseHttpLoadResult(await readJson(resultPath));
  } catch {
    return;
  }
}

/** Read an idempotent completed artifact. Partial or malformed output is ignored. */
export async function readCompletedHttpLoadResult(workingDirectory: string): Promise<HttpLoadResult | undefined> {
  const result = await readHttpLoadResult(workingDirectory);
  return result?.status === 'completed' ? result : undefined;
}

function appendBounded(current: string, chunk: string | Buffer): string {
  if (current.length >= MAX_DIAGNOSTIC_LENGTH) return current;
  return `${current}${String(chunk)}`.slice(0, MAX_DIAGNOSTIC_LENGTH);
}

function streamProgress(stream: ProcessStream, level: 'info' | 'warn', logger: ActivityLogger | undefined): void {
  if (!logger) return;
  let pending = '';
  stream.on('data', (chunk) => {
    pending += String(chunk);
    const lines = pending.split(/\r?\n/);
    pending = lines.pop() ?? '';
    for (const line of lines) {
      const message = redactLogText(line);
      if (message) logger[level](message);
    }
  });
}

function abortReason(signal: AbortSignal): Error {
  if (signal.reason instanceof Error) return signal.reason;
  return new DOMException('HTTP load activity was cancelled', 'AbortError');
}

function waitForChild(
  child: HttpLoadChildProcess,
  signal: AbortSignal | undefined,
): Promise<{ code: number | null; signal: NodeJS.Signals | null; stderr: string }> {
  return new Promise((resolve, reject) => {
    let settled = false;
    let stderr = '';
    let forceKillTimer: ReturnType<typeof setTimeout> | undefined;

    child.stderr.on('data', (chunk) => {
      stderr = appendBounded(stderr, chunk);
    });

    const cleanup = () => {
      if (forceKillTimer) clearTimeout(forceKillTimer);
      signal?.removeEventListener('abort', onAbort);
    };
    const finishReject = (error: Error) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    };
    const onAbort = () => {
      child.kill('SIGTERM');
      forceKillTimer = setTimeout(() => child.kill('SIGKILL'), FORCE_KILL_DELAY_MS);
    };

    signal?.addEventListener('abort', onAbort, { once: true });
    if (signal?.aborted) onAbort();
    child.once('error', finishReject);
    child.once('exit', (code, exitSignal) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (signal?.aborted) {
        reject(abortReason(signal));
        return;
      }
      resolve({ code, signal: exitSignal, stderr });
    });
  });
}

/**
 * Execute the authorized single-host load generator and validate its artifact.
 *
 * A matching completed artifact is returned without starting another process,
 * which makes Temporal retries and workflow resume idempotent.
 */
export async function runHttpLoadCapacity(options: RunHttpLoadCapacityOptions): Promise<HttpLoadResult> {
  assertHttpLoadAuthorization(options.settings, options.authorizationConfirmed, options.elevatedLoadConfirmed);
  options.signal?.throwIfAborted();

  const existing = await readCompletedHttpLoadResult(options.workingDirectory);
  if (existing && matchesRun(existing, options)) return existing;

  const resultPath = path.join(options.workingDirectory, HTTP_LOAD_RESULT_PATH);
  const scriptPath = options.scriptPath ?? path.resolve(import.meta.dirname, '../../scripts/http_flood_test.py');
  const spawnProcess: HttpLoadSpawn =
    options.spawn ??
    ((command, args, spawnOptions) => {
      return nodeSpawn(command, [...args], spawnOptions) as HttpLoadChildProcess;
    });
  const args = [
    scriptPath,
    options.webUrl,
    '--concurrency',
    String(options.settings.concurrency),
    '--rate',
    String(options.settings.requestsPerSecond),
    '--duration',
    String(options.settings.durationSeconds),
    '--json-output',
    resultPath,
    '--i-own-this-target',
  ];

  const child = spawnProcess('python3', args, {
    cwd: options.workingDirectory,
    stdio: ['ignore', 'pipe', 'pipe'],
    shell: false,
  });
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  streamProgress(child.stdout, 'info', options.logger);
  streamProgress(child.stderr, 'warn', options.logger);

  const exit = await waitForChild(child, options.signal);
  options.signal?.throwIfAborted();
  const result = await readHttpLoadResult(options.workingDirectory);
  if (!result || !matchesRun(result, options)) {
    const diagnostic = redactLogText(
      exit.stderr || `exit code ${exit.code ?? 'unknown'} (${exit.signal ?? 'no signal'})`,
    );
    throw new Error(`HTTP load generator did not produce a valid result: ${diagnostic}`);
  }
  if (exit.code !== 0 && result.status === 'completed') {
    throw new Error(`HTTP load generator exited unexpectedly with code ${exit.code ?? 'unknown'}`);
  }
  return result;
}
