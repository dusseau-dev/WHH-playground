/**
 * Environment variable loading and credential validation.
 *
 * Local mode: loads ./.env via dotenv.
 * NPX mode: fills gaps from ~/.shannon/config.toml (no .env).
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import dotenv from 'dotenv';
import { resolveConfig } from './config/resolver.js';
import { getMode } from './mode.js';
import { resolveCliModelSelection, selectedProviderEnvNames } from './model-spec.js';

/** Non-provider runtime tuning retained for compatibility. */
const RUNTIME_FORWARD_VARS = ['CLAUDE_CODE_MAX_OUTPUT_TOKENS', 'CLAUDE_ADAPTIVE_THINKING'] as const;

export interface ProviderCredentialFile {
  readonly environmentName: 'AWS_SHARED_CREDENTIALS_FILE' | 'AWS_CONFIG_FILE' | 'AWS_WEB_IDENTITY_TOKEN_FILE';
  readonly hostPath: string;
  readonly containerPath: string;
}

function credentialFile(candidate: string, environmentName: ProviderCredentialFile['environmentName']): string {
  const resolved = path.resolve(candidate);
  let canonical: string;
  try {
    canonical = fs.realpathSync(resolved);
  } catch {
    throw new Error(`${environmentName} does not point to an existing file: ${resolved}`);
  }
  if (!fs.statSync(canonical).isFile()) {
    throw new Error(`${environmentName} must point to a regular file: ${resolved}`);
  }
  return canonical;
}

function optionalDefaultCredentialFile(
  hostPath: string,
  environmentName: ProviderCredentialFile['environmentName'],
  containerPath: string,
): ProviderCredentialFile | undefined {
  if (!fs.existsSync(hostPath)) return undefined;
  return { environmentName, hostPath: credentialFile(hostPath, environmentName), containerPath };
}

/** Resolve selected Bedrock credential files to fixed read-only container paths. */
export function resolveProviderCredentialFiles(): ProviderCredentialFile[] {
  const selection = resolveCliModelSelection();
  if (selection.providerId !== 'amazon-bedrock') return [];

  if (selection.credentialName === 'AWS_PROFILE') {
    const awsHome = path.join(os.homedir(), '.aws');
    const credentialsPath = process.env.AWS_SHARED_CREDENTIALS_FILE?.trim();
    const configPath = process.env.AWS_CONFIG_FILE?.trim();
    const files = [
      credentialsPath
        ? {
            environmentName: 'AWS_SHARED_CREDENTIALS_FILE',
            hostPath: credentialFile(credentialsPath, 'AWS_SHARED_CREDENTIALS_FILE'),
            containerPath: '/tmp/.aws/credentials',
          }
        : optionalDefaultCredentialFile(
            path.join(awsHome, 'credentials'),
            'AWS_SHARED_CREDENTIALS_FILE',
            '/tmp/.aws/credentials',
          ),
      configPath
        ? {
            environmentName: 'AWS_CONFIG_FILE',
            hostPath: credentialFile(configPath, 'AWS_CONFIG_FILE'),
            containerPath: '/tmp/.aws/config',
          }
        : optionalDefaultCredentialFile(path.join(awsHome, 'config'), 'AWS_CONFIG_FILE', '/tmp/.aws/config'),
    ].filter((file): file is ProviderCredentialFile => file !== undefined);
    if (files.length === 0) {
      throw new Error(
        `AWS_PROFILE "${process.env.AWS_PROFILE}" requires a readable ~/.aws/config or ~/.aws/credentials file.`,
      );
    }
    return files;
  }

  if (selection.credentialName === 'AWS_WEB_IDENTITY_TOKEN_FILE') {
    const tokenPath = process.env.AWS_WEB_IDENTITY_TOKEN_FILE?.trim();
    if (!tokenPath) return [];
    return [
      {
        environmentName: 'AWS_WEB_IDENTITY_TOKEN_FILE',
        hostPath: credentialFile(tokenPath, 'AWS_WEB_IDENTITY_TOKEN_FILE'),
        containerPath: '/tmp/shannon-aws-web-identity-token',
      },
    ];
  }

  return [];
}

/**
 * Load credentials into process.env.
 * Local mode: loads ./.env via dotenv.
 * NPX mode: fills gaps from ~/.shannon/config.toml.
 * Exported env vars always take precedence in both modes.
 */
export function loadEnv(): void {
  if (getMode() === 'local') {
    dotenv.config({ path: '.env', quiet: true });
  } else {
    resolveConfig();
  }
}

/**
 * Build Docker environment flags using names only. Docker reads each value from
 * its own environment, keeping credentials out of process argv and diagnostics.
 */
export function buildEnvFlags(): string[] {
  const flags: string[] = ['-e', 'TEMPORAL_ADDRESS=shannon-temporal:7233'];

  for (const key of [...selectedProviderEnvNames(), ...RUNTIME_FORWARD_VARS]) {
    if (process.env[key]) flags.push('-e', key);
  }

  return flags;
}

interface CredentialValidation {
  valid: boolean;
  error?: string;
  mode?: 'api-key' | 'oauth' | 'custom-base-url' | 'bedrock' | 'generic';
}

/**
 * Validate the selected provider only. Credentials for unrelated providers are
 * ignored and are not forwarded to the worker container.
 */
export function validateCredentials(): CredentialValidation {
  let selection: ReturnType<typeof resolveCliModelSelection>;
  try {
    selection = resolveCliModelSelection();
  } catch (error) {
    return {
      valid: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }

  if (selection.providerId === 'amazon-bedrock' && selection.source === 'legacy') {
    const missing = ['ANTHROPIC_SMALL_MODEL', 'ANTHROPIC_MEDIUM_MODEL', 'ANTHROPIC_LARGE_MODEL'].filter(
      (name) => !process.env[name],
    );
    if (missing.length > 0) {
      return { valid: false, mode: 'bedrock', error: `Bedrock mode requires: ${missing.join(', ')}` };
    }
  }

  if (selection.credentialConfigured) {
    const mode =
      selection.providerId === 'amazon-bedrock'
        ? 'bedrock'
        : selection.credentialName === 'CLAUDE_CODE_OAUTH_TOKEN'
          ? 'oauth'
          : selection.credentialName === 'ANTHROPIC_AUTH_TOKEN'
            ? 'custom-base-url'
            : selection.providerMode === 'generic'
              ? 'generic'
              : 'api-key';
    return { valid: true, mode };
  }

  const hint =
    getMode() === 'local'
      ? 'Set the selected provider credential or SHANNON_AI_API_KEY in .env (Bedrock accepts a bearer token or the AWS credential chain).'
      : `Authentication not configured. Export variables or run 'npx @keygraph/shannon setup'.`;
  return {
    valid: false,
    error: `No credentials found for provider "${selection.providerId}". ${hint}`,
  };
}
