import type { DistributedConfig, ProviderConfig } from '../types/config.js';
import { REDACTION_MARKER, redactSecrets } from '../utils/redactSecrets.js';

export { REDACTION_MARKER };

export interface ExactValueRedactor {
  readonly values: readonly string[];
  redactText(value: string): string;
  redactValue<T>(value: T): T;
}

function uniqueSecrets(values: ReadonlyArray<string | undefined>): string[] {
  return [...new Set(values.filter((value): value is string => typeof value === 'string' && value.length > 0))].sort(
    (a, b) => b.length - a.length,
  );
}

export function collectConfiguredSecrets(
  config: DistributedConfig | null | undefined,
  providerConfig?: ProviderConfig,
  apiKey?: string,
): string[] {
  const auth = config?.authentication?.credentials;
  return uniqueSecrets([
    auth?.password,
    auth?.totp_secret,
    auth?.email_login?.password,
    auth?.email_login?.totp_secret,
    config?.detection_validation?.splunk.token,
    apiKey,
    providerConfig?.apiKey,
    providerConfig?.awsAccessKeyId,
    providerConfig?.awsSecretAccessKey,
    providerConfig?.awsSessionToken,
    providerConfig?.authToken,
  ]);
}

export function collectRuntimeProviderSecrets(): string[] {
  return uniqueSecrets([
    process.env.ANTHROPIC_API_KEY,
    process.env.OPENAI_API_KEY,
    process.env.XAI_API_KEY,
    process.env.SHANNON_AI_API_KEY,
    process.env.CLAUDE_CODE_OAUTH_TOKEN,
    process.env.AWS_ACCESS_KEY_ID,
    process.env.AWS_SECRET_ACCESS_KEY,
    process.env.AWS_SESSION_TOKEN,
    process.env.AWS_BEARER_TOKEN_BEDROCK,
    process.env.AWS_CONTAINER_AUTHORIZATION_TOKEN,
    process.env.ANTHROPIC_AUTH_TOKEN,
  ]);
}

export function createExactValueRedactor(values: readonly string[]): ExactValueRedactor {
  const secrets = uniqueSecrets(values);

  return {
    values: secrets,
    redactText(value: string): string {
      return redactSecrets(value, { exactValues: secrets });
    },
    redactValue<T>(value: T): T {
      return redactSecrets(value, { exactValues: secrets });
    },
  };
}

export const EMPTY_REDACTOR = createExactValueRedactor([]);
