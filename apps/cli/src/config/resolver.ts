/** Resolve package-mode configuration with environment-over-TOML precedence. */

import fs from 'node:fs';
import { parse as parseTOML } from 'smol-toml';
import { getConfigFile } from '../home.js';
import { getMode } from '../mode.js';
import { parseModelSpec, selectedCliProviderCredential } from '../model-spec.js';

type TOMLType = 'string' | 'number' | 'boolean';
type TOMLConfig = Record<string, unknown>;

interface ConfigMapping {
  readonly env: string;
  readonly toml: string;
  readonly type: TOMLType;
  readonly boolFormat?: 'numeric' | 'literal';
}

const NEW_MAP: readonly ConfigMapping[] = [
  { env: 'SHANNON_AI_MODEL', toml: 'core.model', type: 'string' },
  { env: 'SHANNON_AI_BASE_URL', toml: 'core.base_url', type: 'string' },
  { env: 'ANTHROPIC_API_KEY', toml: 'anthropic.api_key', type: 'string' },
  { env: 'CLAUDE_CODE_OAUTH_TOKEN', toml: 'anthropic.oauth_token', type: 'string' },
  { env: 'OPENAI_API_KEY', toml: 'openai.api_key', type: 'string' },
  { env: 'SHANNON_AI_OPENAI_FORMAT', toml: 'openai.format', type: 'string' },
  { env: 'XAI_API_KEY', toml: 'xai.api_key', type: 'string' },
  { env: 'AWS_REGION', toml: 'bedrock.region', type: 'string' },
  { env: 'AWS_BEARER_TOKEN_BEDROCK', toml: 'bedrock.token', type: 'string' },
  { env: 'SHANNON_AI_API_KEY', toml: 'provider.api_key', type: 'string' },
] as const;

const LEGACY_MAP: readonly ConfigMapping[] = [
  { env: 'CLAUDE_CODE_MAX_OUTPUT_TOKENS', toml: 'core.max_tokens', type: 'number' },
  { env: 'CLAUDE_ADAPTIVE_THINKING', toml: 'core.adaptive_thinking', type: 'boolean', boolFormat: 'literal' },
  { env: 'CLAUDE_CODE_USE_BEDROCK', toml: 'bedrock.use', type: 'boolean' },
  { env: 'CLAUDE_CODE_USE_VERTEX', toml: 'vertex.use', type: 'boolean' },
  { env: 'CLOUD_ML_REGION', toml: 'vertex.region', type: 'string' },
  { env: 'ANTHROPIC_VERTEX_PROJECT_ID', toml: 'vertex.project_id', type: 'string' },
  { env: 'GOOGLE_APPLICATION_CREDENTIALS', toml: 'vertex.key_path', type: 'string' },
  { env: 'ANTHROPIC_BASE_URL', toml: 'custom_base_url.base_url', type: 'string' },
  { env: 'ANTHROPIC_AUTH_TOKEN', toml: 'custom_base_url.auth_token', type: 'string' },
  { env: 'ANTHROPIC_SMALL_MODEL', toml: 'models.small', type: 'string' },
  { env: 'ANTHROPIC_MEDIUM_MODEL', toml: 'models.medium', type: 'string' },
  { env: 'ANTHROPIC_LARGE_MODEL', toml: 'models.large', type: 'string' },
] as const;

const ALL_MAP = [...NEW_MAP, ...LEGACY_MAP] as const;
const CURATED_PROVIDER_SECTION = {
  anthropic: 'anthropic',
  openai: 'openai',
  xai: 'xai',
  'amazon-bedrock': 'bedrock',
} as const;
type CuratedProvider = keyof typeof CURATED_PROVIDER_SECTION;

function section(config: TOMLConfig, name: string): Record<string, unknown> | undefined {
  const value = config[name];
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
}

function tomlValue(config: TOMLConfig, mapping: ConfigMapping | undefined): string | undefined {
  if (!mapping) return undefined;
  const [sectionName, key] = mapping.toml.split('.');
  if (!sectionName || !key) return undefined;
  const value = section(config, sectionName)?.[key];
  if (value === undefined || value === null) return undefined;
  if (typeof value === 'boolean') {
    if (mapping.boolFormat === 'literal') return value ? 'true' : 'false';
    return value ? '1' : '0';
  }
  return String(value);
}

function hasValue(config: TOMLConfig, path: string): boolean {
  const mapping = ALL_MAP.find((entry) => entry.toml === path);
  return mapping ? Boolean(tomlValue(config, mapping)?.trim()) : false;
}

function loadTOML(): TOMLConfig | null {
  const configPath = getConfigFile();
  if (!fs.existsSync(configPath)) return null;

  if (process.platform !== 'win32') {
    const mode = fs.statSync(configPath).mode;
    if (mode & 0o077) {
      const actual = (mode & 0o777).toString(8).padStart(3, '0');
      fail(`Insecure permissions (${actual}) on ${configPath}. Run: chmod 600 ${configPath}`);
    }
  }

  try {
    return parseTOML(fs.readFileSync(configPath, 'utf8')) as TOMLConfig;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    fail(`Failed to parse ${configPath}: ${message}`, `Run 'npx @keygraph/shannon setup' to reconfigure.`);
  }
}

function schema(): Map<string, Map<string, TOMLType>> {
  const result = new Map<string, Map<string, TOMLType>>();
  for (const mapping of ALL_MAP) {
    const [sectionName, key] = mapping.toml.split('.');
    if (!sectionName || !key) continue;
    const keys = result.get(sectionName) ?? new Map<string, TOMLType>();
    keys.set(key, mapping.type);
    result.set(sectionName, keys);
  }
  return result;
}

function validateShape(config: TOMLConfig): string[] {
  const allowed = schema();
  const errors: string[] = [];
  for (const [sectionName, value] of Object.entries(config)) {
    const keys = allowed.get(sectionName);
    if (!keys) {
      errors.push(`Unknown section [${sectionName}]. Valid sections: ${[...allowed.keys()].join(', ')}`);
      continue;
    }
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      errors.push(`[${sectionName}] must be a table, got ${typeof value}`);
      continue;
    }
    for (const [key, candidate] of Object.entries(value as Record<string, unknown>)) {
      const expected = keys.get(key);
      if (!expected) {
        errors.push(`Unknown key "${key}" in [${sectionName}]. Valid keys: ${[...keys.keys()].join(', ')}`);
      } else if (typeof candidate !== expected) {
        errors.push(`[${sectionName}].${key} must be ${expected}, got ${typeof candidate}`);
      } else if (typeof candidate === 'string' && !candidate.trim()) {
        errors.push(`[${sectionName}].${key} must not be empty`);
      }
    }
  }
  return errors;
}

function environmentHas(...names: string[]): boolean {
  return names.some((name) => Boolean(process.env[name]?.trim()));
}

function configuredBaseUrl(config: TOMLConfig, provider: string): string | undefined {
  return (
    process.env.SHANNON_AI_BASE_URL?.trim() ||
    tomlValue(config, NEW_MAP[1]) ||
    (provider === 'anthropic' ? process.env.ANTHROPIC_BASE_URL?.trim() : undefined)
  );
}

function environmentHasProviderCredential(config: TOMLConfig, provider: string): boolean {
  return selectedCliProviderCredential(process.env, provider, configuredBaseUrl(config, provider)) !== undefined;
}

function isCuratedProvider(provider: string): provider is CuratedProvider {
  return Object.hasOwn(CURATED_PROVIDER_SECTION, provider);
}

function validateNewProvider(config: TOMLConfig, provider: string): string[] {
  if (provider === 'vertex') return [vertexMigrationMessage()];
  if (!isCuratedProvider(provider)) {
    return environmentHas('SHANNON_AI_API_KEY') || hasValue(config, 'provider.api_key')
      ? []
      : [`[provider] requires api_key for provider "${provider}"`];
  }
  if (provider === 'amazon-bedrock') {
    return environmentHasProviderCredential(config, provider) || hasValue(config, 'bedrock.token')
      ? []
      : ['[bedrock] requires AWS credentials or a bearer token'];
  }
  const credentialPaths =
    provider === 'anthropic' ? ['anthropic.api_key', 'anthropic.oauth_token'] : [`${provider}.api_key`];
  const errors =
    environmentHasProviderCredential(config, provider) ||
    credentialPaths.some((candidate) => hasValue(config, candidate)) ||
    hasValue(config, 'provider.api_key')
      ? []
      : [`[${CURATED_PROVIDER_SECTION[provider]}] requires api_key`];
  if (provider === 'openai') {
    const format = process.env.SHANNON_AI_OPENAI_FORMAT ?? tomlValue(config, NEW_MAP[5]);
    if (format && format !== 'chat-completions' && format !== 'responses') {
      errors.push('[openai].format must be "chat-completions" or "responses"');
    }
  }
  return errors;
}

function validateLegacyProvider(config: TOMLConfig): string[] {
  const bedrock = process.env.CLAUDE_CODE_USE_BEDROCK === '1' || tomlValue(config, LEGACY_MAP[2]) === '1';
  if (!bedrock) return [];
  const missing: string[] = [];
  if (!environmentHasProviderCredential(config, 'amazon-bedrock') && !hasValue(config, 'bedrock.token')) {
    missing.push('credentials');
  }
  for (const tier of ['small', 'medium', 'large']) {
    const envName = `ANTHROPIC_${tier.toUpperCase()}_MODEL`;
    if (!environmentHas(envName) && !hasValue(config, `models.${tier}`)) missing.push(`models.${tier}`);
  }
  return missing.length ? [`Legacy [bedrock] configuration is missing: ${missing.join(', ')}`] : [];
}

function vertexMigrationMessage(): string {
  return 'Vertex AI is no longer supported by this model runtime. Migrate to SHANNON_AI_MODEL=<provider>:<model-id> with SHANNON_AI_API_KEY, or use SHANNON_AI_BASE_URL.';
}

function inject(config: TOMLConfig, mappings: readonly ConfigMapping[]): void {
  for (const mapping of mappings) {
    if (process.env[mapping.env]) continue;
    const value = tomlValue(config, mapping);
    if (value) process.env[mapping.env] = value;
  }
}

function injectNew(config: TOMLConfig, provider: string): void {
  inject(config, NEW_MAP.slice(0, 2));
  if (provider === 'openai') inject(config, NEW_MAP.slice(5, 6));

  if (provider === 'amazon-bedrock') {
    if (!environmentHas('AWS_REGION', 'AWS_DEFAULT_REGION')) inject(config, NEW_MAP.slice(7, 8));
    if (!environmentHasProviderCredential(config, provider)) inject(config, NEW_MAP.slice(8, 9));
    return;
  }

  if (!environmentHasProviderCredential(config, provider)) {
    if (provider === 'anthropic') inject(config, NEW_MAP.slice(2, 4));
    else if (provider === 'openai') inject(config, NEW_MAP.slice(4, 5));
    else if (provider === 'xai') inject(config, NEW_MAP.slice(6, 7));
  }
  if (!environmentHasProviderCredential(config, provider)) inject(config, NEW_MAP.slice(9, 10));
}

function injectLegacy(config: TOMLConfig): void {
  inject(config, LEGACY_MAP.slice(0, 2));
  const bedrock = process.env.CLAUDE_CODE_USE_BEDROCK === '1' || tomlValue(config, LEGACY_MAP[2]) === '1';
  if (bedrock) {
    inject(config, LEGACY_MAP.slice(2, 3));
    if (!environmentHas('AWS_REGION', 'AWS_DEFAULT_REGION')) inject(config, NEW_MAP.slice(7, 8));
    if (!environmentHasProviderCredential(config, 'amazon-bedrock')) inject(config, NEW_MAP.slice(8, 9));
    inject(config, LEGACY_MAP.slice(9));
  } else {
    const custom = section(config, 'custom_base_url');
    inject(
      config,
      custom ? [...LEGACY_MAP.slice(7, 9), ...LEGACY_MAP.slice(9)] : [...NEW_MAP.slice(2, 4), ...LEGACY_MAP.slice(9)],
    );
  }
}

function fail(...lines: string[]): never {
  console.error(`\n${lines.join('\n')}\n`);
  process.exit(1);
}

/** Fill missing process.env values from ~/.shannon/config.toml in package mode. */
export function resolveConfig(): void {
  if (getMode() === 'local') return;
  const config = loadTOML();
  if (!config) return;

  const errors = validateShape(config);
  const configuredModel = process.env.SHANNON_AI_MODEL?.trim() || tomlValue(config, NEW_MAP[0]);
  if (configuredModel) {
    let provider: string | undefined;
    try {
      provider = parseModelSpec(configuredModel).providerId;
    } catch (error) {
      errors.push(error instanceof Error ? error.message : String(error));
    }
    if (provider) errors.push(...validateNewProvider(config, provider));
    if (errors.length) fail('Invalid configuration:', ...errors.map((error) => `  - ${error}`));
    if (provider) injectNew(config, provider);
    return;
  }

  const legacyVertex =
    process.env.CLAUDE_CODE_USE_VERTEX === '1' ||
    tomlValue(config, LEGACY_MAP[3]) === '1' ||
    Boolean(section(config, 'vertex'));
  if (legacyVertex) errors.push(vertexMigrationMessage());
  errors.push(...validateLegacyProvider(config));
  if (errors.length) fail('Invalid configuration:', ...errors.map((error) => `  - ${error}`));
  injectLegacy(config);
}
