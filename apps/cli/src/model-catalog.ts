import { z } from 'zod';
import type { ProviderConfig } from './contracts.js';
import { resolveCliModelSelection } from './model-spec.js';

const CATALOG_TIMEOUT_MS = 10_000;

const OpenRouterCatalogSchema = z.object({
  data: z.array(
    z
      .object({
        id: z.string().trim().min(1),
        name: z.string().trim().min(1).optional(),
        context_length: z.number().int().positive().nullable().optional(),
      })
      .passthrough(),
  ),
});

export interface ConfiguredModelDescription {
  readonly providerId: string;
  readonly providerLabel: string;
  readonly modelId: string;
  readonly credentialConfigured: boolean;
  readonly catalogAvailable: boolean;
  /** Safe provider metadata used for a per-run model override. */
  readonly providerConfig: Omit<ProviderConfig, 'model' | 'apiKey' | 'authToken'>;
}

export interface ModelCatalogItem {
  readonly id: string;
  readonly name: string;
  readonly contextLength?: number;
}

interface ListConfiguredModelsOptions {
  readonly env?: NodeJS.ProcessEnv;
  readonly fetcher?: typeof fetch;
}

function normalizedBaseUrl(value: string | undefined): string | undefined {
  return value?.trim().replace(/\/+$/, '') || undefined;
}

interface CatalogProvider {
  readonly id: 'openrouter' | 'cheaper-inference';
  readonly label: 'OpenRouter' | 'Cheaper Inference';
}

function catalogProvider(baseUrl: string | undefined): CatalogProvider | undefined {
  if (!baseUrl) return undefined;
  try {
    const hostname = new URL(baseUrl).hostname.toLowerCase();
    if (hostname === 'openrouter.ai' || hostname.endsWith('.openrouter.ai')) {
      return { id: 'openrouter', label: 'OpenRouter' };
    }
    if (hostname === 'api.cheaperinference.com') {
      return { id: 'cheaper-inference', label: 'Cheaper Inference' };
    }
  } catch {
    return undefined;
  }
  return undefined;
}

function providerLabel(providerId: string): string {
  const labels: Readonly<Record<string, string>> = {
    anthropic: 'Anthropic',
    openai: 'OpenAI',
    xai: 'xAI',
    'amazon-bedrock': 'Amazon Bedrock',
  };
  return labels[providerId] ?? providerId;
}

function safeProviderConfig(env: NodeJS.ProcessEnv): ConfiguredModelDescription['providerConfig'] {
  const selection = resolveCliModelSelection(env);
  return {
    providerType: selection.providerMode,
    ...(selection.providerMode === 'generic' && { providerId: selection.providerId }),
    ...(selection.baseUrl && { baseUrl: selection.baseUrl }),
    ...(selection.openAIFormat && { openAIFormat: selection.openAIFormat }),
  };
}

/** Describe the active runner model without returning credential values. */
export function describeConfiguredModel(env: NodeJS.ProcessEnv = process.env): ConfiguredModelDescription {
  const selection = resolveCliModelSelection(env);
  const catalog = catalogProvider(selection.baseUrl);
  return {
    providerId: catalog?.id ?? selection.providerId,
    providerLabel: catalog?.label ?? providerLabel(selection.providerId),
    modelId: selection.modelId,
    credentialConfigured: selection.credentialConfigured,
    catalogAvailable: catalog !== undefined,
    providerConfig: safeProviderConfig(env),
  };
}

function providerIdFromConfig(config: ProviderConfig): string {
  const providerType = config.providerType?.trim() || 'anthropic';
  if (providerType === 'generic') return config.providerId?.trim() || '';
  if (providerType === 'anthropic_api') return 'anthropic';
  if (providerType === 'openai_api') return 'openai';
  if (providerType === 'xai_api') return 'xai';
  if (providerType === 'bedrock') return 'amazon-bedrock';
  return providerType;
}

/** Whether a keyless per-run model override can safely reuse the configured provider credential. */
export function providerConfigMatchesConfiguredModel(
  config: ProviderConfig,
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  const selection = resolveCliModelSelection(env);
  if (!selection.credentialConfigured || providerIdFromConfig(config) !== selection.providerId) return false;
  if (normalizedBaseUrl(config.baseUrl) !== normalizedBaseUrl(selection.baseUrl)) return false;
  return (config.openAIFormat ?? undefined) === (selection.openAIFormat ?? undefined);
}

/** Load model choices for the configured provider while keeping its credential on the server. */
export async function listConfiguredModels(options: ListConfiguredModelsOptions = {}): Promise<ModelCatalogItem[]> {
  const env = options.env ?? process.env;
  const selection = resolveCliModelSelection(env);
  if (!catalogProvider(selection.baseUrl)) {
    throw new Error('A model catalog is not available for the configured provider');
  }
  const credential = selection.credentialName ? env[selection.credentialName]?.trim() : undefined;
  if (!credential) throw new Error('The configured provider credential is unavailable');

  const endpoint = `${normalizedBaseUrl(selection.baseUrl)}/models`;
  let response: Response;
  try {
    response = await (options.fetcher ?? fetch)(endpoint, {
      headers: { Authorization: `Bearer ${credential}`, Accept: 'application/json' },
      signal: AbortSignal.timeout(CATALOG_TIMEOUT_MS),
    });
  } catch {
    throw new Error('Unable to reach the configured provider model catalog');
  }
  if (!response.ok) throw new Error('The configured provider model catalog returned an error');

  let parsed: z.infer<typeof OpenRouterCatalogSchema>;
  try {
    parsed = OpenRouterCatalogSchema.parse(await response.json());
  } catch {
    throw new Error('The configured provider returned an invalid model catalog');
  }

  const models = new Map<string, ModelCatalogItem>();
  for (const model of parsed.data) {
    if (models.has(model.id)) continue;
    models.set(model.id, {
      id: model.id,
      name: model.name ?? model.id,
      ...(model.context_length && { contextLength: model.context_length }),
    });
  }
  return [...models.values()].sort(
    (left, right) => left.name.localeCompare(right.name) || left.id.localeCompare(right.id),
  );
}
