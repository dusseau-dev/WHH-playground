/** CLI-side model parsing. Kept dependency-free because the CLI ships separately from the worker. */
export interface ModelSpec {
  readonly providerId: string;
  readonly modelId: string;
}

export type CliProviderMode = 'anthropic' | 'openai' | 'xai' | 'amazon-bedrock' | 'generic';
export type CliSelectionSource = 'shannon-ai-model' | 'legacy';

export interface CliModelSelection extends ModelSpec {
  readonly providerMode: CliProviderMode;
  readonly source: CliSelectionSource;
  readonly credentialName?: string;
  readonly credentialConfigured: boolean;
  readonly environmentNames: readonly string[];
}

export const DEFAULT_MODEL_SPEC = 'anthropic:claude-sonnet-4-6';

const TIER_ENV = ['ANTHROPIC_SMALL_MODEL', 'ANTHROPIC_MEDIUM_MODEL', 'ANTHROPIC_LARGE_MODEL'] as const;

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

interface CliCredentialSelection {
  readonly name: string;
  readonly environmentNames: readonly string[];
}

function envValue(env: NodeJS.ProcessEnv, name: string): string | undefined {
  const candidate = env[name]?.trim();
  return candidate ? candidate : undefined;
}

export function parseModelSpec(spec: string): ModelSpec {
  const trimmed = spec.trim();
  const separator = trimmed.indexOf(':');
  const malformed = `SHANNON_AI_MODEL must be "<provider>:<model-id>", got "${trimmed}". Example: ${DEFAULT_MODEL_SPEC}`;
  if (separator < 1) throw new Error(malformed);
  const providerId = trimmed.slice(0, separator).trim();
  const modelId = trimmed.slice(separator + 1).trim();
  if (!providerId || !modelId) throw new Error(malformed);
  return { providerId, modelId };
}

function providerMode(providerId: string): CliProviderMode {
  if (
    providerId === 'anthropic' ||
    providerId === 'openai' ||
    providerId === 'xai' ||
    providerId === 'amazon-bedrock'
  ) {
    return providerId;
  }
  return 'generic';
}

function configuredNames(env: NodeJS.ProcessEnv, names: readonly string[]): string[] {
  return names.filter((name) => envValue(env, name));
}

function selectedBedrockCredential(env: NodeJS.ProcessEnv): CliCredentialSelection | undefined {
  if (envValue(env, 'AWS_BEARER_TOKEN_BEDROCK')) {
    return { name: 'AWS_BEARER_TOKEN_BEDROCK', environmentNames: ['AWS_BEARER_TOKEN_BEDROCK'] };
  }
  if (envValue(env, 'AWS_PROFILE')) {
    return { name: 'AWS_PROFILE', environmentNames: configuredNames(env, BEDROCK_PROFILE_ENV) };
  }
  if (envValue(env, 'AWS_ACCESS_KEY_ID') && envValue(env, 'AWS_SECRET_ACCESS_KEY')) {
    return { name: 'AWS_ACCESS_KEY_ID', environmentNames: configuredNames(env, BEDROCK_ACCESS_KEY_ENV) };
  }
  if (envValue(env, 'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI')) {
    return {
      name: 'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI',
      environmentNames: ['AWS_CONTAINER_CREDENTIALS_RELATIVE_URI', ...configuredNames(env, BEDROCK_CONTAINER_AUTH_ENV)],
    };
  }
  if (envValue(env, 'AWS_CONTAINER_CREDENTIALS_FULL_URI')) {
    return {
      name: 'AWS_CONTAINER_CREDENTIALS_FULL_URI',
      environmentNames: ['AWS_CONTAINER_CREDENTIALS_FULL_URI', ...configuredNames(env, BEDROCK_CONTAINER_AUTH_ENV)],
    };
  }
  if (envValue(env, 'AWS_WEB_IDENTITY_TOKEN_FILE')) {
    return {
      name: 'AWS_WEB_IDENTITY_TOKEN_FILE',
      environmentNames: configuredNames(env, BEDROCK_WEB_IDENTITY_ENV),
    };
  }
  return undefined;
}

function credentialCandidates(providerId: string, baseUrl: string | undefined): readonly string[] {
  switch (providerId) {
    case 'anthropic':
      return [
        ...(baseUrl ? ['ANTHROPIC_AUTH_TOKEN'] : []),
        'ANTHROPIC_API_KEY',
        'CLAUDE_CODE_OAUTH_TOKEN',
        'SHANNON_AI_API_KEY',
      ];
    case 'openai':
      return ['OPENAI_API_KEY', 'SHANNON_AI_API_KEY'];
    case 'xai':
      return ['XAI_API_KEY', 'SHANNON_AI_API_KEY'];
    default:
      return ['SHANNON_AI_API_KEY'];
  }
}

/** Select one credential source for validation and provider-scoped forwarding. */
export function selectedCliProviderCredential(
  env: NodeJS.ProcessEnv,
  providerId: string,
  baseUrl: string | undefined,
): CliCredentialSelection | undefined {
  if (providerId === 'amazon-bedrock') return selectedBedrockCredential(env);
  const name = credentialCandidates(providerId, baseUrl).find((candidate) => envValue(env, candidate));
  return name ? { name, environmentNames: [name] } : undefined;
}

function selectedBedrockRegionName(env: NodeJS.ProcessEnv): string | undefined {
  return ['AWS_REGION', 'AWS_DEFAULT_REGION'].find((name) => envValue(env, name));
}

function newEnvironmentNames(
  env: NodeJS.ProcessEnv,
  providerId: string,
  credential: CliCredentialSelection | undefined,
): string[] {
  const names = ['SHANNON_AI_MODEL'];
  if (envValue(env, 'SHANNON_AI_BASE_URL')) names.push('SHANNON_AI_BASE_URL');
  else if (providerId === 'anthropic' && envValue(env, 'ANTHROPIC_BASE_URL')) names.push('ANTHROPIC_BASE_URL');
  if (envValue(env, 'SHANNON_AI_OPENAI_FORMAT')) names.push('SHANNON_AI_OPENAI_FORMAT');
  if (credential) names.push(...credential.environmentNames);
  const regionName = providerId === 'amazon-bedrock' ? selectedBedrockRegionName(env) : undefined;
  if (regionName) names.push(regionName);
  return [...new Set(names)];
}

function legacyEnvironmentNames(
  env: NodeJS.ProcessEnv,
  providerId: string,
  baseUrl: string | undefined,
  credential: CliCredentialSelection | undefined,
): string[] {
  const names: string[] = [];
  if (providerId === 'amazon-bedrock') names.push('CLAUDE_CODE_USE_BEDROCK');
  if (baseUrl) names.push('ANTHROPIC_BASE_URL');
  if (credential) names.push(...credential.environmentNames);
  const regionName = providerId === 'amazon-bedrock' ? selectedBedrockRegionName(env) : undefined;
  if (regionName) names.push(regionName);
  for (const name of TIER_ENV) {
    if (envValue(env, name)) names.push(name);
  }
  return [...new Set(names)];
}

function vertexMigrationError(): Error {
  return new Error(
    'Vertex AI is no longer supported by this model runtime. Migrate to SHANNON_AI_MODEL=<provider>:<model-id> with SHANNON_AI_API_KEY, or use SHANNON_AI_BASE_URL.',
  );
}

/** Resolve only the information needed for host-side validation and Docker forwarding. */
export function resolveCliModelSelection(env: NodeJS.ProcessEnv = process.env): CliModelSelection {
  const shannonModel = envValue(env, 'SHANNON_AI_MODEL');
  if (shannonModel) {
    const spec = parseModelSpec(shannonModel);
    const baseUrl =
      envValue(env, 'SHANNON_AI_BASE_URL') ??
      (spec.providerId === 'anthropic' ? envValue(env, 'ANTHROPIC_BASE_URL') : undefined);
    const credential = selectedCliProviderCredential(env, spec.providerId, baseUrl);
    return {
      ...spec,
      providerMode: providerMode(spec.providerId),
      source: 'shannon-ai-model',
      ...(credential && { credentialName: credential.name }),
      credentialConfigured: credential !== undefined,
      environmentNames: newEnvironmentNames(env, spec.providerId, credential),
    };
  }

  if (envValue(env, 'CLAUDE_CODE_USE_VERTEX') === '1') throw vertexMigrationError();
  const providerId = envValue(env, 'CLAUDE_CODE_USE_BEDROCK') === '1' ? 'amazon-bedrock' : 'anthropic';
  const baseUrl = providerId === 'anthropic' ? envValue(env, 'ANTHROPIC_BASE_URL') : undefined;
  const credential = selectedCliProviderCredential(env, providerId, baseUrl);
  return {
    providerId,
    modelId: envValue(env, 'ANTHROPIC_MEDIUM_MODEL') ?? parseModelSpec(DEFAULT_MODEL_SPEC).modelId,
    providerMode: providerMode(providerId),
    source: 'legacy',
    ...(credential && { credentialName: credential.name }),
    credentialConfigured: credential !== undefined,
    environmentNames: legacyEnvironmentNames(env, providerId, baseUrl, credential),
  };
}

/** Exact environment variable names safe to forward for the selected provider. */
export function selectedProviderEnvNames(env: NodeJS.ProcessEnv = process.env): string[] {
  return [...resolveCliModelSelection(env).environmentNames];
}
