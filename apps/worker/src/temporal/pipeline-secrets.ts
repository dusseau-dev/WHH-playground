import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { generateInternalPath, type SessionMetadata } from '../audit/utils.js';
import type { DistributedConfig, ProviderConfig } from '../types/config.js';
import type { PipelineInput } from './shared.js';

const WORKFLOW_SECRET_DIR = 'workflow-secrets';
const SECRET_REF_PATTERN = /^ps_[a-f0-9]{32}$/;
const PROVIDER_CREDENTIAL_FIELDS = [
  'apiKey',
  'awsAccessKeyId',
  'awsSecretAccessKey',
  'awsSessionToken',
  'authToken',
] as const;

interface PipelineSecretInput {
  readonly sessionId: string;
  readonly webUrl: string;
  readonly outputPath?: string;
  readonly secretRef?: string;
  readonly apiKey?: string;
  readonly providerConfig?: ProviderConfig;
  readonly configYAML?: string;
  readonly configData?: DistributedConfig;
}

export interface ResolvedPipelineCredentials {
  readonly apiKey?: string;
  readonly providerConfig?: ProviderConfig;
  readonly configYAML?: string;
  readonly configData?: DistributedConfig;
}

interface StoredPipelineCredentials {
  readonly version: 1;
  readonly apiKey?: string;
  readonly providerConfig?: Partial<Record<(typeof PROVIDER_CREDENTIAL_FIELDS)[number], string>>;
  readonly configYAML?: string;
  readonly configData?: DistributedConfig;
}

const loadedCredentials = new Map<string, ResolvedPipelineCredentials>();

export type ProtectedPipelineInput = PipelineInput & { readonly sessionId: string; readonly secretRef: string };

async function atomicSecretWrite(filePath: string, value: StoredPipelineCredentials): Promise<void> {
  const directory = path.dirname(filePath);
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  if (process.platform !== 'win32') await fs.chmod(directory, 0o700);
  const temporaryPath = path.join(
    directory,
    `.${path.basename(filePath)}.${crypto.randomBytes(6).toString('hex')}.tmp`,
  );
  try {
    await fs.writeFile(temporaryPath, `${JSON.stringify(value)}\n`, { flag: 'wx', mode: 0o600 });
    await fs.rename(temporaryPath, filePath);
    if (process.platform !== 'win32') await fs.chmod(filePath, 0o600);
  } catch (error) {
    await fs.rm(temporaryPath, { force: true }).catch(() => undefined);
    throw error;
  }
}

/**
 * Compatibility helper for callers that previously placed credentials or raw
 * configuration in PipelineInput. Call this before starting the workflow.
 */
export async function protectPipelineInput(input: PipelineInput): Promise<PipelineInput | ProtectedPipelineInput> {
  const providerSecrets: Record<string, string> = {};
  const safeProviderConfig: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input.providerConfig ?? {})) {
    if ((PROVIDER_CREDENTIAL_FIELDS as readonly string[]).includes(key)) {
      if (typeof value !== 'string') throw new Error('Provider credential fields must be strings');
      providerSecrets[key] = value;
    } else {
      safeProviderConfig[key] = value;
    }
  }

  const needsProtection =
    input.apiKey !== undefined ||
    Object.keys(providerSecrets).length > 0 ||
    input.configYAML !== undefined ||
    input.configData !== undefined;
  if (!needsProtection) return input;
  if (input.secretRef) throw new Error('Pipeline input cannot combine inline credentials with secretRef');

  const sessionId = input.sessionId ?? input.resumeFromWorkspace ?? input.workflowId;
  if (!sessionId) throw new Error('sessionId is required to stage pipeline credentials');
  const secretRef = `ps_${crypto.randomBytes(16).toString('hex')}`;
  const filePath = secretPath({
    sessionId,
    webUrl: input.webUrl,
    ...(input.outputPath !== undefined && { outputPath: input.outputPath }),
    secretRef,
  });
  if (!filePath) throw new Error('Failed to create pipeline secret reference');

  await atomicSecretWrite(filePath, {
    version: 1,
    ...(input.apiKey !== undefined && { apiKey: input.apiKey }),
    ...(Object.keys(providerSecrets).length > 0 && { providerConfig: providerSecrets }),
    ...(input.configYAML !== undefined && { configYAML: input.configYAML }),
    ...(input.configData !== undefined && { configData: input.configData }),
  });

  const {
    apiKey: _apiKey,
    providerConfig: _providerConfig,
    configYAML: _configYAML,
    configData: _configData,
    ...safeInput
  } = input;
  return {
    ...safeInput,
    sessionId,
    secretRef,
    ...(Object.keys(safeProviderConfig).length > 0 && { providerConfig: safeProviderConfig as ProviderConfig }),
  };
}

function secretPath(input: PipelineSecretInput): string | undefined {
  if (!input.secretRef) return;
  if (!SECRET_REF_PATTERN.test(input.secretRef)) throw new Error('Invalid pipeline secret reference');
  const metadata: SessionMetadata = {
    id: input.sessionId,
    webUrl: input.webUrl,
    ...(input.outputPath !== undefined && { outputPath: input.outputPath }),
  };
  return path.join(generateInternalPath(metadata), 'runtime', WORKFLOW_SECRET_DIR, `${input.secretRef}.json`);
}

function parseStoredCredentials(value: unknown): StoredPipelineCredentials {
  if (!value || typeof value !== 'object') throw new Error('Pipeline credentials are unavailable');
  const candidate = value as Record<string, unknown>;
  if (candidate.version !== 1) throw new Error('Pipeline credentials are unavailable');
  if (candidate.apiKey !== undefined && typeof candidate.apiKey !== 'string') {
    throw new Error('Pipeline credentials are unavailable');
  }
  if (candidate.configYAML !== undefined && typeof candidate.configYAML !== 'string') {
    throw new Error('Pipeline credentials are unavailable');
  }
  if (
    candidate.configData !== undefined &&
    (!candidate.configData || typeof candidate.configData !== 'object' || Array.isArray(candidate.configData))
  ) {
    throw new Error('Pipeline credentials are unavailable');
  }

  const providerConfig: Record<string, string> = {};
  if (candidate.providerConfig !== undefined) {
    if (!candidate.providerConfig || typeof candidate.providerConfig !== 'object') {
      throw new Error('Pipeline credentials are unavailable');
    }
    for (const [key, credential] of Object.entries(candidate.providerConfig as Record<string, unknown>)) {
      if (!(PROVIDER_CREDENTIAL_FIELDS as readonly string[]).includes(key) || typeof credential !== 'string') {
        throw new Error('Pipeline credentials are unavailable');
      }
      providerConfig[key] = credential;
    }
  }

  return {
    version: 1,
    ...(candidate.apiKey !== undefined && { apiKey: candidate.apiKey as string }),
    ...(Object.keys(providerConfig).length > 0 && { providerConfig }),
    ...(candidate.configYAML !== undefined && { configYAML: candidate.configYAML as string }),
    ...(candidate.configData !== undefined && { configData: candidate.configData as DistributedConfig }),
  };
}

/** Load a local credential reference once, unlink it, and retain it only in worker memory. */
export async function resolvePipelineCredentials(input: PipelineSecretInput): Promise<ResolvedPipelineCredentials> {
  const filePath = secretPath(input);
  if (!filePath) {
    return {
      ...(input.apiKey !== undefined && { apiKey: input.apiKey }),
      ...(input.providerConfig !== undefined && { providerConfig: input.providerConfig }),
      ...(input.configYAML !== undefined && { configYAML: input.configYAML }),
      ...(input.configData !== undefined && { configData: input.configData }),
    };
  }

  const cached = loadedCredentials.get(filePath);
  if (cached) return cached;

  let raw: unknown;
  try {
    raw = JSON.parse(await fs.readFile(filePath, 'utf8')) as unknown;
  } catch {
    throw new Error('Pipeline credentials are unavailable');
  } finally {
    await fs.rm(filePath, { force: true }).catch(() => undefined);
  }

  const stored = parseStoredCredentials(raw);
  const resolved: ResolvedPipelineCredentials = {
    ...(stored.apiKey !== undefined && { apiKey: stored.apiKey }),
    ...((input.providerConfig !== undefined || stored.providerConfig !== undefined) && {
      providerConfig: { ...input.providerConfig, ...stored.providerConfig },
    }),
    ...(stored.configYAML !== undefined && { configYAML: stored.configYAML }),
    ...(stored.configData !== undefined && { configData: stored.configData }),
  };
  loadedCredentials.set(filePath, resolved);
  return resolved;
}

/** Remove the in-memory copy when the workflow reaches a terminal state. */
export function clearPipelineCredentials(input: PipelineSecretInput): void {
  const filePath = secretPath(input);
  if (filePath) loadedCredentials.delete(filePath);
}
