// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Preflight Validation Service
 *
 * Runs cheap, fast checks before any agent execution begins.
 * Catches configuration and credential problems early, saving
 * time and API costs compared to failing mid-pipeline.
 *
 * Checks run sequentially, cheapest first:
 * 1. Repository path exists and contains .git
 * 2. Config file parses and validates (if provided)
 * 3. code_path rules match real entries in the repo (filesystem only)
 * 4. The selected Pi model/runtime validates its configured credentials
 * 5. Target URL resolves, is not link-local (cloud metadata), and is reachable (DNS + HTTP)
 */

import type { LookupAddress } from 'node:dns';
import { lookup } from 'node:dns/promises';
import fs from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import net, { type LookupFunction } from 'node:net';
import type { AssistantMessage } from '@earendil-works/pi-ai';
import {
  type AgentSession,
  createAgentSession,
  SessionManager,
  SettingsManager,
} from '@earendil-works/pi-coding-agent';
import { glob } from 'zx';
import { attachCancellation } from '../ai/pi/cancellation.js';
import { type PiModelRuntime, resolvePiModelRuntime } from '../ai/pi/model-runtime.js';
import { PI_RETRY_SETTINGS } from '../ai/pi/retry-settings.js';
import { providerTurnError } from '../ai/pi/turn-error.js';
import { parseConfig, parseConfigYAML, validateConfigForSourceMode } from '../config-parser.js';
import type { ActivityLogger } from '../types/activity-logger.js';
import type { Config, DistributedConfig, Rule, SourceMode } from '../types/config.js';
import { ErrorCode } from '../types/errors.js';
import { err, ok, type Result } from '../types/result.js';
import { sanitizeUrlForDiagnostics } from '../utils/redactSecrets.js';
import { PentestError } from './error-handling.js';

const TARGET_URL_TIMEOUT_MS = 10_000;

function isLoopbackAddress(address: string): boolean {
  return address === '127.0.0.1' || address === '::1' || address === '0.0.0.0';
}

// 169.254.0.0/16 hosts the cloud metadata service. RFC1918 and loopback are
// intentionally allowed — scanning local targets is a supported Shannon use case.
const metadataBlockList = new net.BlockList();
metadataBlockList.addSubnet('169.254.0.0', 16, 'ipv4');

function isBlockedAddress(address: string): boolean {
  switch (net.isIP(address)) {
    case 4:
      return metadataBlockList.check(address, 'ipv4');
    case 6:
      return metadataBlockList.check(address, 'ipv6');
    default:
      return false;
  }
}

/** DNS lookup pinned to already-validated `addresses`, so the socket cannot be re-pointed after validation (DNS rebinding). */
function pinnedLookup(addresses: LookupAddress[]): LookupFunction {
  return (hostname, options, callback) => {
    const matching = options.family ? addresses.filter((a) => a.family === options.family) : addresses;
    const pool = matching.length > 0 ? matching : addresses;
    if (options.all) {
      callback(null, pool);
      return;
    }
    const first = pool[0];
    if (!first) {
      callback(new Error(`no resolved address for ${hostname}`), '', 0);
      return;
    }
    callback(null, first.address, first.family);
  };
}

// === Repository Validation ===

async function validateWorkingDirectory(
  workingDirectory: string,
  sourceMode: SourceMode,
  logger: ActivityLogger,
): Promise<Result<void, PentestError>> {
  logger.info('Checking working directory...', { workingDirectory, sourceMode });
  try {
    const stats = await fs.stat(workingDirectory);
    if (!stats.isDirectory()) {
      return err(
        new PentestError(
          `Working directory is not a directory: ${workingDirectory}`,
          'config',
          false,
          { workingDirectory, sourceMode },
          ErrorCode.REPO_NOT_FOUND,
        ),
      );
    }
    if (sourceMode === 'url-only') {
      await fs.access(workingDirectory, fs.constants.W_OK);
    }
  } catch {
    return err(
      new PentestError(
        sourceMode === 'url-only'
          ? `URL-only working directory does not exist or is not writable: ${workingDirectory}`
          : `Working directory does not exist: ${workingDirectory}`,
        'config',
        false,
        { workingDirectory, sourceMode },
        ErrorCode.REPO_NOT_FOUND,
      ),
    );
  }
  return ok(undefined);
}

async function validateRepo(
  repoPath: string,
  logger: ActivityLogger,
  skipGitCheck?: boolean,
): Promise<Result<void, PentestError>> {
  logger.info('Checking repository path...', { repoPath });

  // 1. Check repo directory exists
  try {
    const stats = await fs.stat(repoPath);
    if (!stats.isDirectory()) {
      return err(
        new PentestError(
          `Repository path is not a directory: ${repoPath}`,
          'config',
          false,
          { repoPath },
          ErrorCode.REPO_NOT_FOUND,
        ),
      );
    }
  } catch {
    return err(
      new PentestError(
        `Repository path does not exist: ${repoPath}`,
        'config',
        false,
        { repoPath },
        ErrorCode.REPO_NOT_FOUND,
      ),
    );
  }

  // 2. Check .git directory exists (skipped when consumer removes .git after clone)
  if (!skipGitCheck) {
    try {
      const gitStats = await fs.stat(`${repoPath}/.git`);
      if (!gitStats.isDirectory()) {
        return err(
          new PentestError(
            `Not a git repository (no .git directory): ${repoPath}`,
            'config',
            false,
            { repoPath },
            ErrorCode.REPO_NOT_FOUND,
          ),
        );
      }
    } catch {
      return err(
        new PentestError(
          `Not a git repository (no .git directory): ${repoPath}`,
          'config',
          false,
          { repoPath },
          ErrorCode.REPO_NOT_FOUND,
        ),
      );
    }
  } else {
    logger.info('Skipping .git check (skipGitCheck enabled)');
  }

  logger.info('Repository path OK');
  return ok(undefined);
}

// === Config Validation ===

async function validateConfig(configPath: string, logger: ActivityLogger): Promise<Result<Config, PentestError>> {
  logger.info('Validating configuration file...', { configPath });

  try {
    const config = await parseConfig(configPath);
    logger.info('Configuration file OK');
    return ok(config);
  } catch (error) {
    if (error instanceof PentestError) {
      return err(error);
    }
    const message = error instanceof Error ? error.message : String(error);
    return err(
      new PentestError(
        `Configuration validation failed: ${message}`,
        'config',
        false,
        { configPath },
        ErrorCode.CONFIG_VALIDATION_FAILED,
      ),
    );
  }
}

// === code_path Existence Validation ===

const CODE_PATH_IGNORE = ['.git/**', '.shannon/**'];

async function patternMatchesAny(repoPath: string, pattern: string): Promise<boolean> {
  const stream = glob.globbyStream(pattern, {
    cwd: repoPath,
    dot: true,
    onlyFiles: false,
    followSymbolicLinks: false,
    ignore: CODE_PATH_IGNORE,
  });
  for await (const _ of stream) {
    return true;
  }
  return false;
}

type RuleKind = 'avoid' | 'focus';
interface MissingCodePath {
  kind: RuleKind;
  value: string;
  description: string;
}

type ConfigWithRules = Config | DistributedConfig;

function rulesFromConfig(config: ConfigWithRules): { avoid: Rule[]; focus: Rule[] } {
  if ('avoid' in config || 'focus' in config) {
    const distributed = config as DistributedConfig;
    return { avoid: distributed.avoid ?? [], focus: distributed.focus ?? [] };
  }
  return { avoid: config.rules?.avoid ?? [], focus: config.rules?.focus ?? [] };
}

export function validateSourceModeRules(config: ConfigWithRules, sourceMode: SourceMode): Result<void, PentestError> {
  try {
    validateConfigForSourceMode(config, sourceMode);
    return ok(undefined);
  } catch (error) {
    return err(error instanceof PentestError ? error : new PentestError(String(error), 'config', false));
  }
}

async function validateCodePathsExist(
  config: ConfigWithRules,
  repoPath: string,
  logger: ActivityLogger,
): Promise<Result<void, PentestError>> {
  const tagged: Array<{ kind: RuleKind; rule: Rule }> = [
    ...rulesFromConfig(config).avoid.map((rule) => ({ kind: 'avoid' as const, rule })),
    ...rulesFromConfig(config).focus.map((rule) => ({ kind: 'focus' as const, rule })),
  ].filter(({ rule }) => rule.type === 'code_path');

  if (tagged.length === 0) {
    return ok(undefined);
  }

  logger.info(`Validating ${tagged.length} code_path rule(s) against repo...`);

  // ≥1 match is the only property enforced — malformed globs simply match nothing.
  const missing: MissingCodePath[] = [];
  for (const { kind, rule } of tagged) {
    if (!(await patternMatchesAny(repoPath, rule.value))) {
      missing.push({ kind, value: rule.value, description: rule.description });
    }
  }

  if (missing.length > 0) {
    const lines = missing.map((m) => `[${m.kind}] '${m.value}' — ${m.description}`);
    return err(
      new PentestError(
        `code_path rules don't match any file or directory in the repo:\n  - ${lines.join('\n  - ')}\n` +
          `Fix the patterns or remove the rules.`,
        'config',
        false,
        { missing },
        ErrorCode.CONFIG_VALIDATION_FAILED,
      ),
    );
  }

  logger.info('All code_path rules matched');
  return ok(undefined);
}

// === Credential Validation ===

function credentialHint(providerId: string): string {
  switch (providerId) {
    case 'anthropic':
      return 'ANTHROPIC_API_KEY, CLAUDE_CODE_OAUTH_TOKEN, or SHANNON_AI_API_KEY';
    case 'openai':
      return 'OPENAI_API_KEY or SHANNON_AI_API_KEY';
    case 'xai':
      return 'XAI_API_KEY or SHANNON_AI_API_KEY';
    case 'amazon-bedrock':
      return 'AWS_BEARER_TOKEN_BEDROCK, AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY, AWS_PROFILE, AWS_WEB_IDENTITY_TOKEN_FILE, or AWS_CONTAINER_CREDENTIALS_RELATIVE_URI/FULL_URI';
    default:
      return 'SHANNON_AI_API_KEY';
  }
}

function describeAuth(runtime: PiModelRuntime): string {
  const { providerId, baseUrl } = runtime.selection;
  return baseUrl ? `custom endpoint (${sanitizeUrlForDiagnostics(baseUrl)})` : `${providerId} credentials`;
}

function classifyPiCredentialError(error: Error, authType: string): PentestError {
  const lower = error.message.toLowerCase();
  if (/billing|credit|spending cap|rate.?limit|429/.test(lower)) {
    return new PentestError(
      `${authType} has a billing or rate-limit issue. Check the provider account and try again.`,
      'billing',
      true,
      { authType },
      ErrorCode.BILLING_ERROR,
    );
  }
  if (/401|403|invalid[ _-]?api[ _-]?key|unauthorized|authentication|forbidden|x-api-key/.test(lower)) {
    return new PentestError(
      `Invalid ${authType}. Check the configured credentials and try again.`,
      'config',
      false,
      { authType },
      ErrorCode.AUTH_FAILED,
    );
  }
  if (
    /network|timeout|enotfound|econnrefused|fetch failed|getaddrinfo|socket|overloaded|unavailable|50\d/.test(lower)
  ) {
    return new PentestError(
      `${authType} is unreachable or temporarily unavailable. Try again shortly.`,
      'network',
      true,
      { authType },
    );
  }
  return new PentestError(
    `${authType} validation failed: ${error.message.slice(0, 300)}`,
    'config',
    false,
    { authType },
    ErrorCode.AUTH_FAILED,
  );
}

async function probePiModelRuntime(
  workingDirectory: string,
  runtime: PiModelRuntime,
  authType: string,
  cancellationSignal?: AbortSignal,
): Promise<Result<void, PentestError>> {
  let failedTurn: AssistantMessage | undefined;
  let session: AgentSession | undefined;
  let cleanupCancellation = (): void => undefined;
  try {
    cancellationSignal?.throwIfAborted();
    ({ session } = await createAgentSession({
      cwd: workingDirectory,
      model: runtime.model,
      noTools: 'all',
      modelRuntime: runtime.modelRuntime,
      sessionManager: SessionManager.inMemory(workingDirectory),
      settingsManager: SettingsManager.inMemory({ retry: PI_RETRY_SETTINGS, compaction: { enabled: false } }),
    }));
    cleanupCancellation = attachCancellation(cancellationSignal, () => session?.abort());
    session.subscribe((event) => {
      if (event.type === 'turn_end' && event.message.role === 'assistant' && event.message.stopReason === 'error') {
        failedTurn = event.message;
      }
    });
    await session.prompt('Reply with OK.');
    cancellationSignal?.throwIfAborted();
  } catch (error) {
    if (cancellationSignal?.aborted) cancellationSignal.throwIfAborted();
    return err(classifyPiCredentialError(error instanceof Error ? error : new Error(String(error)), authType));
  } finally {
    cleanupCancellation();
    session?.dispose();
  }

  if (failedTurn) {
    return err(classifyPiCredentialError(providerTurnError(failedTurn, `${authType} validation failed`), authType));
  }
  return ok(undefined);
}

/** Resolve and probe exactly the Pi model/runtime selected for this run. */
export async function validatePiCredentials(
  workingDirectory: string,
  logger: ActivityLogger,
  apiKey?: string,
  providerConfig?: import('../types/config.js').ProviderConfig,
  cancellationSignal?: AbortSignal,
): Promise<Result<void, PentestError>> {
  const effectiveProviderConfig = providerConfig ?? (apiKey ? { providerType: 'anthropic', apiKey } : undefined);
  let runtime: PiModelRuntime;
  try {
    runtime = await resolvePiModelRuntime({
      modelTier: 'small',
      ...(effectiveProviderConfig && { providerConfig: effectiveProviderConfig }),
      warn: (message) => logger.warn(message),
    });
  } catch (error) {
    return err(
      new PentestError(
        error instanceof Error ? error.message : String(error),
        'config',
        false,
        {},
        ErrorCode.AUTH_FAILED,
      ),
    );
  }

  logger.info(`Model: ${runtime.selection.debugLabel}`);
  if (!runtime.selection.credential.configured) {
    return err(
      new PentestError(
        `No credentials found for provider "${runtime.selection.providerId}". Set ${credentialHint(runtime.selection.providerId)}.`,
        'config',
        false,
        { providerId: runtime.selection.providerId },
        ErrorCode.AUTH_FAILED,
      ),
    );
  }

  const authType = describeAuth(runtime);
  logger.info(`Validating ${authType} via Pi...`);
  const probe = await probePiModelRuntime(workingDirectory, runtime, authType, cancellationSignal);
  if (!probe.ok) return probe;
  logger.info(`${authType} OK`);
  return ok(undefined);
}

// === Target URL Validation ===

/** HTTP HEAD with TLS verification disabled — we check reachability, not certificate validity. */
function httpHead(url: string, timeoutMs: number, addresses: LookupAddress[]): Promise<number> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const isHttps = parsed.protocol === 'https:';
    const transport = isHttps ? https : http;

    const req = transport.request(
      url,
      {
        method: 'HEAD',
        timeout: timeoutMs,
        lookup: pinnedLookup(addresses),
        ...(isHttps && { rejectUnauthorized: false }),
      },
      (res) => {
        res.resume();
        resolve(res.statusCode ?? 0);
      },
    );

    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Connection timed out after ${timeoutMs}ms`));
    });
    req.on('error', reject);
    req.end();
  });
}

/** Check that the target URL is reachable from inside the container. */
async function validateTargetUrl(targetUrl: string, logger: ActivityLogger): Promise<Result<void, PentestError>> {
  logger.info('Checking target URL reachability...');

  // 1. Parse URL
  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return err(
      new PentestError(
        `Invalid target URL: ${targetUrl}`,
        'config',
        false,
        { targetUrl },
        ErrorCode.TARGET_UNREACHABLE,
      ),
    );
  }

  // 2. Resolve all records once — reused (pinned) for the connection below.
  const hostname = parsed.hostname;
  let addresses: LookupAddress[];
  try {
    addresses = await lookup(hostname, { all: true });
  } catch {
    return err(
      new PentestError(
        `Target URL ${targetUrl} is not reachable. Verify the URL is correct and the site is up.`,
        'network',
        false,
        { targetUrl, hostname },
        ErrorCode.TARGET_UNREACHABLE,
      ),
    );
  }

  // 3. Reject the link-local metadata range (169.254.0.0/16).
  const blocked = addresses.find((entry) => isBlockedAddress(entry.address));
  if (blocked) {
    return err(
      new PentestError(
        `Target URL ${targetUrl} resolves to ${blocked.address}, a link-local address ` +
          `(169.254.0.0/16). This range hosts the cloud instance metadata service and cannot be scanned.`,
        'config',
        false,
        { targetUrl, hostname, address: blocked.address },
        ErrorCode.TARGET_UNREACHABLE,
      ),
    );
  }

  // 4. HTTP reachability check (socket pinned to the resolved addresses).
  try {
    await httpHead(targetUrl, TARGET_URL_TIMEOUT_MS, addresses);

    logger.info('Target URL OK');
    return ok(undefined);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    const isLoopback = addresses.some((entry) => isLoopbackAddress(entry.address));

    if (isLoopback) {
      const suggestion = targetUrl.replace(hostname, 'host.docker.internal');
      return err(
        new PentestError(
          `Target URL ${targetUrl} resolves to a loopback address and is not reachable. ` +
            `For local services, use host.docker.internal instead of ${hostname} (e.g., ${suggestion})`,
          'network',
          false,
          { targetUrl, hostname },
          ErrorCode.TARGET_UNREACHABLE,
        ),
      );
    }

    return err(
      new PentestError(
        `Target URL ${targetUrl} is not reachable: ${detail}`,
        'network',
        false,
        { targetUrl },
        ErrorCode.TARGET_UNREACHABLE,
      ),
    );
  }
}

// === Preflight Orchestrator ===

/**
 * Run all preflight checks sequentially (cheapest first).
 *
 * 1. Repository path exists and contains .git
 * 2. Config file parses and validates (if configPath provided)
 * 3. code_path rules match at least one entry in the repo (skipped without config)
 * 4. Credentials validate for the selected Pi provider
 * 5. Target URL is reachable from the container
 *
 * Returns on first failure.
 */
export async function runPreflightChecks(
  targetUrl: string,
  workingDirectory: string,
  repoPath: string | undefined,
  sourceMode: SourceMode,
  configPath: string | undefined,
  logger: ActivityLogger,
  skipGitCheck?: boolean,
  apiKey?: string,
  providerConfig?: import('../types/config.js').ProviderConfig,
  configYAML?: string,
  configData?: DistributedConfig,
  cancellationSignal?: AbortSignal,
): Promise<Result<void, PentestError>> {
  // 1. Every run needs a real working directory; URL-only additionally requires it to be writable.
  const workingResult = await validateWorkingDirectory(workingDirectory, sourceMode, logger);
  if (!workingResult.ok) return workingResult;

  // 2. Source-assisted runs retain the existing repository validation. URL-only runs never fake it.
  if (sourceMode === 'source-assisted') {
    if (!repoPath) {
      return err(
        new PentestError(
          'Source-assisted mode requires a repository path.',
          'config',
          false,
          { sourceMode },
          ErrorCode.REPO_NOT_FOUND,
        ),
      );
    }
    const repoResult = await validateRepo(repoPath, logger, skipGitCheck);
    if (!repoResult.ok) return repoResult;
  }

  // 3. Config check (pre-parsed → inline YAML → file, matching ConfigLoaderService precedence).
  let parsedConfig: ConfigWithRules | null = configData ?? null;
  if (!parsedConfig && configYAML) {
    try {
      parsedConfig = parseConfigYAML(configYAML);
    } catch (error) {
      return err(error instanceof PentestError ? error : new PentestError(String(error), 'config', false));
    }
  } else if (!parsedConfig && configPath) {
    const configResult = await validateConfig(configPath, logger);
    if (!configResult.ok) {
      return configResult;
    }
    parsedConfig = configResult.value;
  }

  // 4. URL-only rejects code_path rules; source-assisted validates that they match real entries.
  if (parsedConfig) {
    const modeResult = validateSourceModeRules(parsedConfig, sourceMode);
    if (!modeResult.ok) return modeResult;
    if (sourceMode === 'source-assisted' && repoPath) {
      const codePathResult = await validateCodePathsExist(parsedConfig, repoPath, logger);
      if (!codePathResult.ok) return codePathResult;
    }
  }

  // 5. Resolve and probe the same Pi model/runtime used by agent execution.
  const credResult = await validatePiCredentials(workingDirectory, logger, apiKey, providerConfig, cancellationSignal);
  if (!credResult.ok) {
    return credResult;
  }

  // 6. Target URL reachability check (cheap — 1 HTTP round-trip)
  const urlResult = await validateTargetUrl(targetUrl, logger);
  if (!urlResult.ok) {
    return urlResult;
  }

  logger.info('All preflight checks passed');
  return ok(undefined);
}
