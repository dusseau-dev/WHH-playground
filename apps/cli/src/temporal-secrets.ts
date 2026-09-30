import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { INTERNAL_DIR } from './paths.js';
import { atomicWriteJson, ensureDirectory } from './storage.js';

export const WORKFLOW_SECRET_DIR = 'workflow-secrets';

const PROVIDER_CREDENTIAL_FIELDS = [
  'apiKey',
  'awsAccessKeyId',
  'awsSecretAccessKey',
  'awsSessionToken',
  'authToken',
] as const;

interface TemporalCredentialInput {
  readonly apiKey?: string;
  readonly providerConfig?: Record<string, unknown>;
  readonly configYAML?: string;
  readonly configData?: unknown;
  readonly secretRef?: string;
}

interface StoredWorkflowCredentials {
  readonly version: 1;
  readonly apiKey?: string;
  readonly providerConfig?: Record<string, string>;
  readonly configYAML?: string;
  readonly configData?: unknown;
}

export interface ProtectedTemporalInput<T> {
  readonly input: T;
  readonly stagedSecretPath?: string;
}

/**
 * Replace legacy inline provider credentials with an opaque reference before
 * the input reaches Temporal. The referenced file is local, mode-restricted,
 * and deleted by the worker immediately after loading.
 */
export async function protectTemporalInput<T extends TemporalCredentialInput>(
  input: T,
  workspacePath: string,
): Promise<ProtectedTemporalInput<T>> {
  const providerConfig = input.providerConfig;
  const providerSecrets: Record<string, string> = {};
  const safeProviderConfig: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(providerConfig ?? {})) {
    if ((PROVIDER_CREDENTIAL_FIELDS as readonly string[]).includes(key)) {
      if (typeof value !== 'string') throw new Error('Provider credential fields must be strings');
      providerSecrets[key] = value;
    } else {
      safeProviderConfig[key] = value;
    }
  }

  const hasSecrets =
    input.apiKey !== undefined ||
    Object.keys(providerSecrets).length > 0 ||
    input.configYAML !== undefined ||
    input.configData !== undefined;
  if (!hasSecrets) return { input };
  if (input.secretRef) throw new Error('Workflow input cannot combine inline credentials with secretRef');

  const secretRef = `ps_${crypto.randomBytes(16).toString('hex')}`;
  const secretDirectory = path.join(workspacePath, INTERNAL_DIR, 'runtime', WORKFLOW_SECRET_DIR);
  const secretPath = path.join(secretDirectory, `${secretRef}.json`);
  const stored: StoredWorkflowCredentials = {
    version: 1,
    ...(input.apiKey !== undefined && { apiKey: input.apiKey }),
    ...(Object.keys(providerSecrets).length > 0 && { providerConfig: providerSecrets }),
    ...(input.configYAML !== undefined && { configYAML: input.configYAML }),
    ...(input.configData !== undefined && { configData: input.configData }),
  };

  await ensureDirectory(secretDirectory, 0o700);
  await atomicWriteJson(secretPath, stored, 0o600);

  const {
    apiKey: _apiKey,
    providerConfig: _providerConfig,
    configYAML: _configYAML,
    configData: _configData,
    ...rest
  } = input;
  return {
    input: {
      ...rest,
      secretRef,
      ...(Object.keys(safeProviderConfig).length > 0 && { providerConfig: safeProviderConfig }),
    } as unknown as T,
    stagedSecretPath: secretPath,
  };
}

export async function discardStagedTemporalSecret(filePath: string | undefined): Promise<void> {
  if (!filePath) return;
  await fs.rm(filePath, { force: true });
}
