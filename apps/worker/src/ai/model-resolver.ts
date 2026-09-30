import type { ProviderConfig } from '../types/config.js';
import { DEFAULT_MODEL_SPEC, parseModelSpec } from './model-spec.js';

export type ModelTier = 'small' | 'medium' | 'large';
export type OpenAIFormat = 'chat-completions' | 'responses';
export type ModelSelectionSource = 'provider-config' | 'shannon-ai-model' | 'legacy';
export type ModelEnvironment = Readonly<Record<string, string | undefined>>;

export const CURATED_PROVIDER_IDS = ['anthropic', 'openai', 'xai', 'amazon-bedrock'] as const;

const DEFAULT_MODELS: Readonly<Record<ModelTier, string>> = {
  small: 'claude-haiku-4-5-20251001',
  medium: 'claude-sonnet-4-6',
  large: 'claude-opus-4-7',
};

const TIER_ENV: Readonly<Record<ModelTier, string>> = {
  small: 'ANTHROPIC_SMALL_MODEL',
  medium: 'ANTHROPIC_MEDIUM_MODEL',
  large: 'ANTHROPIC_LARGE_MODEL',
};

const LEGACY_SELECTION_ENV = [
  'ANTHROPIC_SMALL_MODEL',
  'ANTHROPIC_MEDIUM_MODEL',
  'ANTHROPIC_LARGE_MODEL',
  'ANTHROPIC_BASE_URL',
  'ANTHROPIC_AUTH_TOKEN',
  'CLAUDE_CODE_USE_BEDROCK',
  'CLAUDE_CODE_USE_VERTEX',
] as const;

const OPENAI_FORMATS = ['chat-completions', 'responses'] as const;

const BEDROCK_PROFILE_ENV = [
  'AWS_PROFILE',
  'AWS_SHARED_CREDENTIALS_FILE',
  'AWS_CONFIG_FILE',
  'AWS_SDK_LOAD_CONFIG',
] as const;
const BEDROCK_ACCESS_KEY_ENV = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN'] as const;
const BEDROCK_WEB_IDENTITY_ENV = ['AWS_WEB_IDENTITY_TOKEN_FILE', 'AWS_ROLE_ARN', 'AWS_ROLE_SESSION_NAME'] as const;
const BEDROCK_CONTAINER_AUTH_ENV = [
  'AWS_CONTAINER_AUTHORIZATION_TOKEN',
  'AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE',
] as const;

type WarningSink = (message: string) => void;
const warnedSinks = new Set<WarningSink>();

export interface CredentialMetadata {
  /** Whether all credentials required for the selected provider are present. */
  readonly configured: boolean;
  /** Where the credential came from. Secret values are deliberately omitted. */
  readonly source: 'provider-config' | 'environment' | 'none';
  /** Environment variable or ProviderConfig field carrying the credential. */
  readonly name?: string;
  /** Variables that together make up a selected ambient credential mechanism. */
  readonly names?: readonly string[];
}

export interface ModelSelection {
  readonly providerId: string;
  readonly modelId: string;
  readonly source: ModelSelectionSource;
  readonly credential: CredentialMetadata;
  readonly baseUrl?: string;
  readonly openAIFormat?: OpenAIFormat;
  /** Exact set of process environment variable names needed by this selection. */
  readonly environmentNames: readonly string[];
  /** Safe for logs: contains provider and model only, never credentials. */
  readonly debugLabel: string;
}

export interface ResolveModelSelectionOptions {
  readonly modelTier?: ModelTier;
  readonly providerConfig?: ProviderConfig;
  readonly env?: ModelEnvironment;
  readonly warn?: WarningSink;
}

function value(env: ModelEnvironment, name: string): string | undefined {
  const candidate = env[name]?.trim();
  return candidate ? candidate : undefined;
}

function configuredNames(env: ModelEnvironment, names: readonly string[]): string[] {
  return names.filter((name) => value(env, name));
}

function bedrockEnvironmentCredential(env: ModelEnvironment): CredentialMetadata {
  let name: string | undefined;
  let names: readonly string[] | undefined;
  if (value(env, 'AWS_BEARER_TOKEN_BEDROCK')) {
    name = 'AWS_BEARER_TOKEN_BEDROCK';
    names = [name];
  } else if (value(env, 'AWS_PROFILE')) {
    name = 'AWS_PROFILE';
    names = configuredNames(env, BEDROCK_PROFILE_ENV);
  } else if (value(env, 'AWS_ACCESS_KEY_ID') && value(env, 'AWS_SECRET_ACCESS_KEY')) {
    name = 'AWS_ACCESS_KEY_ID';
    names = configuredNames(env, BEDROCK_ACCESS_KEY_ENV);
  } else if (value(env, 'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI')) {
    name = 'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI';
    names = [name, ...configuredNames(env, BEDROCK_CONTAINER_AUTH_ENV)];
  } else if (value(env, 'AWS_CONTAINER_CREDENTIALS_FULL_URI')) {
    name = 'AWS_CONTAINER_CREDENTIALS_FULL_URI';
    names = [name, ...configuredNames(env, BEDROCK_CONTAINER_AUTH_ENV)];
  } else if (value(env, 'AWS_WEB_IDENTITY_TOKEN_FILE')) {
    name = 'AWS_WEB_IDENTITY_TOKEN_FILE';
    names = configuredNames(env, BEDROCK_WEB_IDENTITY_ENV);
  }
  return {
    configured: name !== undefined,
    source: name ? 'environment' : 'none',
    ...(name && { name, names: names ?? [name] }),
  };
}

function legacyModel(tier: ModelTier, env: ModelEnvironment): string {
  return value(env, TIER_ENV[tier]) ?? DEFAULT_MODELS[tier];
}

function providerIdFromConfig(config: ProviderConfig): string {
  const providerType = config.providerType?.trim() || 'anthropic_api';
  switch (providerType) {
    case 'anthropic':
    case 'anthropic_api':
      return 'anthropic';
    case 'openai':
    case 'openai_api':
      return 'openai';
    case 'xai':
    case 'xai_api':
      return 'xai';
    case 'bedrock':
    case 'amazon-bedrock':
      return 'amazon-bedrock';
    case 'litellm':
    case 'litellm_router':
      // The legacy integration exposes LiteLLM's Anthropic-compatible endpoint.
      return 'anthropic';
    case 'vertex':
    case 'vertex_ai':
      throw vertexMigrationError();
    case 'generic':
      if (!config.providerId?.trim()) {
        throw new Error('ProviderConfig providerType "generic" requires providerId.');
      }
      return config.providerId.trim();
    default:
      return config.providerId?.trim() || providerType;
  }
}

function vertexMigrationError(): Error {
  return new Error(
    'Vertex AI is no longer supported by this model runtime. Migrate to SHANNON_AI_MODEL=<provider>:<model-id> with SHANNON_AI_API_KEY, or use a supported gateway via SHANNON_AI_BASE_URL.',
  );
}

function providerConfigCredential(config: ProviderConfig, providerId: string): CredentialMetadata {
  if (providerId === 'amazon-bedrock') {
    const configured = Boolean(config.apiKey || (config.awsAccessKeyId && config.awsSecretAccessKey));
    return {
      configured,
      source: configured ? 'provider-config' : 'none',
      ...(config.apiKey
        ? { name: 'apiKey' }
        : config.awsAccessKeyId || config.awsSecretAccessKey
          ? { name: 'awsAccessKeyId/awsSecretAccessKey' }
          : {}),
    };
  }

  const name = config.authToken ? 'authToken' : config.apiKey ? 'apiKey' : undefined;
  return {
    configured: name !== undefined,
    source: name ? 'provider-config' : 'none',
    ...(name && { name }),
  };
}

function environmentCredential(
  providerId: string,
  env: ModelEnvironment,
  baseUrl: string | undefined,
): CredentialMetadata {
  if (providerId === 'amazon-bedrock') return bedrockEnvironmentCredential(env);

  let candidates: readonly string[];
  switch (providerId) {
    case 'anthropic':
      candidates = [
        ...(baseUrl ? ['ANTHROPIC_AUTH_TOKEN'] : []),
        'ANTHROPIC_API_KEY',
        'CLAUDE_CODE_OAUTH_TOKEN',
        'SHANNON_AI_API_KEY',
      ];
      break;
    case 'openai':
      candidates = ['OPENAI_API_KEY', 'SHANNON_AI_API_KEY'];
      break;
    case 'xai':
      candidates = ['XAI_API_KEY', 'SHANNON_AI_API_KEY'];
      break;
    default:
      candidates = ['SHANNON_AI_API_KEY'];
  }

  const name = candidates.find((candidate) => value(env, candidate));
  return {
    configured: name !== undefined,
    source: name ? 'environment' : 'none',
    ...(name && { name }),
  };
}

function resolveOpenAIFormat(
  providerId: string,
  baseUrl: string | undefined,
  configured: string | undefined,
): OpenAIFormat | undefined {
  if (!configured) return providerId === 'openai' && baseUrl ? 'chat-completions' : undefined;
  if (!(OPENAI_FORMATS as readonly string[]).includes(configured)) {
    throw new Error(`SHANNON_AI_OPENAI_FORMAT must be one of: ${OPENAI_FORMATS.join(', ')}.`);
  }
  if (!baseUrl) {
    throw new Error('SHANNON_AI_OPENAI_FORMAT requires SHANNON_AI_BASE_URL or ProviderConfig.baseUrl.');
  }
  return configured as OpenAIFormat;
}

function warnForMixedConfiguration(env: ModelEnvironment, warn: WarningSink): void {
  if (warnedSinks.has(warn)) return;
  const legacyNames = LEGACY_SELECTION_ENV.filter((name) => value(env, name));
  if (legacyNames.length === 0) return;
  warnedSinks.add(warn);
  warn(
    `SHANNON_AI_MODEL takes precedence over legacy provider/model variables (${legacyNames.join(', ')}); remove the legacy settings after migration.`,
  );
}

function configuredModel(config: ProviderConfig, providerId: string, tier: ModelTier, env: ModelEnvironment): string {
  const candidate = config.model?.trim() || config.modelOverrides?.[tier]?.trim();
  if (!candidate) return legacyModel(tier, env);

  // Accept a redundant provider prefix for callers migrating from SHANNON_AI_MODEL,
  // while leaving model ids containing colons (notably Bedrock ids) untouched.
  if (candidate.startsWith(`${providerId}:`)) return parseModelSpec(candidate).modelId;
  return candidate;
}

function environmentNamesForNewSelection(
  env: ModelEnvironment,
  credential: CredentialMetadata,
  providerId: string,
): string[] {
  const names = ['SHANNON_AI_MODEL'];
  if (value(env, 'SHANNON_AI_BASE_URL')) names.push('SHANNON_AI_BASE_URL');
  else if (providerId === 'anthropic' && value(env, 'ANTHROPIC_BASE_URL')) names.push('ANTHROPIC_BASE_URL');
  if (value(env, 'SHANNON_AI_OPENAI_FORMAT')) names.push('SHANNON_AI_OPENAI_FORMAT');
  if (credential.names) names.push(...credential.names);
  else if (credential.name) names.push(credential.name);
  if (providerId === 'amazon-bedrock') {
    const regionName = ['AWS_REGION', 'AWS_DEFAULT_REGION'].find((name) => value(env, name));
    if (regionName) names.push(regionName);
  }
  return [...new Set(names)];
}

function environmentNamesForLegacySelection(
  env: ModelEnvironment,
  providerId: string,
  credential: CredentialMetadata,
  baseUrl: string | undefined,
): string[] {
  const names: string[] = [];
  if (providerId === 'amazon-bedrock') names.push('CLAUDE_CODE_USE_BEDROCK');
  if (baseUrl) names.push('ANTHROPIC_BASE_URL');
  if (credential.names) names.push(...credential.names);
  else if (credential.name) names.push(credential.name);
  if (providerId === 'amazon-bedrock') {
    const regionName = ['AWS_REGION', 'AWS_DEFAULT_REGION'].find((name) => value(env, name));
    if (regionName) names.push(regionName);
  }
  for (const tierName of Object.values(TIER_ENV)) {
    if (value(env, tierName)) names.push(tierName);
  }
  return [...new Set(names)];
}

/** Resolve a run's provider/model without importing or initializing an AI runtime. */
export function resolveModelSelection(options: ResolveModelSelectionOptions = {}): ModelSelection {
  const tier = options.modelTier ?? 'medium';
  const env = options.env ?? process.env;
  const warn = options.warn ?? console.warn;

  if (options.providerConfig) {
    const providerId = providerIdFromConfig(options.providerConfig);
    const modelId = configuredModel(options.providerConfig, providerId, tier, env);
    const baseUrl = options.providerConfig.baseUrl?.trim() || undefined;
    const openAIFormat = resolveOpenAIFormat(providerId, baseUrl, options.providerConfig.openAIFormat?.trim());
    const configuredCredential = providerConfigCredential(options.providerConfig, providerId);
    const credential = configuredCredential.configured
      ? configuredCredential
      : environmentCredential(providerId, env, baseUrl);
    return {
      providerId,
      modelId,
      source: 'provider-config',
      credential,
      ...(baseUrl && { baseUrl }),
      ...(openAIFormat && { openAIFormat }),
      environmentNames: [],
      debugLabel: `${providerId}:${modelId}`,
    };
  }

  const shannonModel = value(env, 'SHANNON_AI_MODEL');
  if (shannonModel) {
    warnForMixedConfiguration(env, warn);
    const { providerId, modelId } = parseModelSpec(shannonModel);
    const baseUrl =
      value(env, 'SHANNON_AI_BASE_URL') ?? (providerId === 'anthropic' ? value(env, 'ANTHROPIC_BASE_URL') : undefined);
    const credential = environmentCredential(providerId, env, baseUrl);
    const openAIFormat = resolveOpenAIFormat(providerId, baseUrl, value(env, 'SHANNON_AI_OPENAI_FORMAT'));
    return {
      providerId,
      modelId,
      source: 'shannon-ai-model',
      credential,
      ...(baseUrl && { baseUrl }),
      ...(openAIFormat && { openAIFormat }),
      environmentNames: environmentNamesForNewSelection(env, credential, providerId),
      debugLabel: `${providerId}:${modelId}`,
    };
  }

  if (value(env, 'CLAUDE_CODE_USE_VERTEX') === '1') throw vertexMigrationError();

  const providerId = value(env, 'CLAUDE_CODE_USE_BEDROCK') === '1' ? 'amazon-bedrock' : 'anthropic';
  const baseUrl = providerId === 'anthropic' ? value(env, 'ANTHROPIC_BASE_URL') : undefined;
  const modelId = legacyModel(tier, env);
  const credential = environmentCredential(providerId, env, baseUrl);
  return {
    providerId,
    modelId,
    source: 'legacy',
    credential,
    ...(baseUrl && { baseUrl }),
    environmentNames: environmentNamesForLegacySelection(env, providerId, credential, baseUrl),
    debugLabel: `${providerId}:${modelId}`,
  };
}

/** Return a defensive copy of the environment-name allowlist for Docker forwarding. */
export function selectedProviderEnvironmentNames(selection: ModelSelection): string[] {
  return [...selection.environmentNames];
}

export { DEFAULT_MODEL_SPEC, parseModelSpec };
