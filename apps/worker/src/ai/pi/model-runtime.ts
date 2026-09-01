// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import type { Api, Credential, CredentialInfo, CredentialStore, Model } from '@earendil-works/pi-ai';
import { ModelRuntime } from '@earendil-works/pi-coding-agent';
import type { ProviderConfig } from '../../types/config.js';
import {
  type ModelEnvironment,
  type ModelSelection,
  type ModelTier,
  resolveModelSelection,
} from '../model-resolver.js';

const PI_CATALOG_URL = 'https://pi.dev/models';
const OPENAI_APIS = {
  'chat-completions': 'openai-completions',
  responses: 'openai-responses',
} as const satisfies Record<NonNullable<ModelSelection['openAIFormat']>, Api>;

/** App-owned credential storage. It never reads or writes pi's auth.json. */
export class InMemoryCredentialStore implements CredentialStore {
  readonly #credentials = new Map<string, Credential>();

  constructor(providerId: string, credential?: Credential) {
    if (credential) this.#credentials.set(providerId, credential);
  }

  /** Test/debug helper that returns only the API-key field, never credential metadata. */
  get(providerId: string): string | undefined {
    const credential = this.#credentials.get(providerId);
    return credential?.type === 'api_key' ? credential.key : undefined;
  }

  async read(providerId: string): Promise<Credential | undefined> {
    return this.#credentials.get(providerId);
  }

  async list(): Promise<readonly CredentialInfo[]> {
    return [...this.#credentials].map(([providerId, credential]) => ({ providerId, type: credential.type }));
  }

  async modify(
    providerId: string,
    update: (current: Credential | undefined) => Promise<Credential | undefined>,
  ): Promise<Credential | undefined> {
    const next = await update(this.#credentials.get(providerId));
    if (next !== undefined) this.#credentials.set(providerId, next);
    return this.#credentials.get(providerId);
  }

  async delete(providerId: string): Promise<void> {
    this.#credentials.delete(providerId);
  }

  toJSON(): { providers: string[] } {
    return { providers: [...this.#credentials.keys()] };
  }
}

export interface ResolvePiModelRuntimeOptions {
  readonly modelTier?: ModelTier;
  readonly providerConfig?: ProviderConfig;
  readonly env?: ModelEnvironment;
  readonly warn?: (message: string) => void;
}

export interface PiModelRuntime {
  readonly selection: ModelSelection;
  readonly model: Model<Api>;
  readonly modelRuntime: ModelRuntime;
  readonly credentials: InMemoryCredentialStore;
}

function environmentValue(env: ModelEnvironment, name: string | undefined): string | undefined {
  if (!name) return undefined;
  const candidate = env[name]?.trim();
  return candidate || undefined;
}

function bedrockEnvironmentCredential(selection: ModelSelection, env: ModelEnvironment): Credential | undefined {
  const key =
    selection.credential.name === 'AWS_BEARER_TOKEN_BEDROCK'
      ? environmentValue(env, 'AWS_BEARER_TOKEN_BEDROCK')
      : undefined;
  const providerEnv: Record<string, string> = {};
  for (const name of selection.credential.names ?? []) {
    if (name === 'AWS_BEARER_TOKEN_BEDROCK') continue;
    const configured = environmentValue(env, name);
    if (configured) providerEnv[name] = configured;
  }
  const regionName = ['AWS_REGION', 'AWS_DEFAULT_REGION'].find((name) => environmentValue(env, name));
  if (regionName) providerEnv[regionName] = environmentValue(env, regionName) as string;
  return key || Object.keys(providerEnv).length > 0
    ? { type: 'api_key', ...(key && { key }), ...(Object.keys(providerEnv).length > 0 && { env: providerEnv }) }
    : undefined;
}

function providerCredential(
  selection: ModelSelection,
  providerConfig: ProviderConfig | undefined,
  env: ModelEnvironment,
): Credential | undefined {
  if (providerConfig) {
    const key = providerConfig.authToken?.trim() || providerConfig.apiKey?.trim() || undefined;
    const providerEnv: Record<string, string> = {};
    if (providerConfig.awsRegion) providerEnv.AWS_REGION = providerConfig.awsRegion;
    if (providerConfig.awsAccessKeyId) providerEnv.AWS_ACCESS_KEY_ID = providerConfig.awsAccessKeyId;
    if (providerConfig.awsSecretAccessKey) providerEnv.AWS_SECRET_ACCESS_KEY = providerConfig.awsSecretAccessKey;
    if (providerConfig.awsSessionToken) providerEnv.AWS_SESSION_TOKEN = providerConfig.awsSessionToken;
    return key || Object.keys(providerEnv).length > 0
      ? { type: 'api_key', ...(key && { key }), ...(Object.keys(providerEnv).length > 0 && { env: providerEnv }) }
      : undefined;
  }

  if (selection.providerId === 'amazon-bedrock') return bedrockEnvironmentCredential(selection, env);

  const key = environmentValue(env, selection.credential.name);
  return key ? { type: 'api_key', key } : undefined;
}

function gatewayApi(selection: ModelSelection, providerConfig: ProviderConfig | undefined): Api | undefined {
  const format = selection.openAIFormat ?? providerConfig?.openAIFormat;
  if (format) return OPENAI_APIS[format];
  return selection.providerId === 'openai' && selection.baseUrl ? OPENAI_APIS['chat-completions'] : undefined;
}

function pointAtGateway(model: Model<Api>, baseUrl: string, api: Api | undefined): Model<Api> {
  if (!api) return { ...model, baseUrl };
  if (api === 'openai-responses') return { ...model, baseUrl, api };
  const { compat: _providerCompat, ...withoutCompat } = model;
  return { ...withoutCompat, baseUrl, api };
}

function syntheticGatewayModel(selection: ModelSelection, api: Api): Model<Api> {
  return {
    provider: selection.providerId,
    id: selection.modelId,
    name: selection.modelId,
    api,
    baseUrl: selection.baseUrl as string,
    reasoning: false,
    input: ['text', 'image'],
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    contextWindow: 128_000,
    maxTokens: 16_384,
  };
}

function resolveRuntimeModel(
  modelRuntime: ModelRuntime,
  selection: ModelSelection,
  providerConfig: ProviderConfig | undefined,
): Model<Api> | undefined {
  const found = modelRuntime.getModel(selection.providerId, selection.modelId);
  if (found) {
    return selection.baseUrl ? pointAtGateway(found, selection.baseUrl, gatewayApi(selection, providerConfig)) : found;
  }
  if (!selection.baseUrl) return undefined;

  const api = gatewayApi(selection, providerConfig);
  const reference = modelRuntime.getModels(selection.providerId)[0];
  if (reference)
    return pointAtGateway({ ...reference, id: selection.modelId, name: selection.modelId }, selection.baseUrl, api);

  // A private OpenAI-compatible gateway may intentionally use both an unknown
  // provider id and an unknown model id. Register a fully in-memory descriptor.
  const synthetic = syntheticGatewayModel(selection, api ?? OPENAI_APIS['chat-completions']);
  modelRuntime.registerProvider(selection.providerId, {
    name: selection.providerId,
    baseUrl: selection.baseUrl,
    api: synthetic.api,
    authHeader: true,
    models: [synthetic],
  });
  return modelRuntime.getModel(selection.providerId, selection.modelId) ?? synthetic;
}

/** Resolve U1's provider selection into a Pi model and in-memory auth runtime. */
export async function resolvePiModelRuntime(options: ResolvePiModelRuntimeOptions = {}): Promise<PiModelRuntime> {
  const env = options.env ?? process.env;
  const selection = resolveModelSelection({
    ...(options.modelTier && { modelTier: options.modelTier }),
    ...(options.providerConfig && { providerConfig: options.providerConfig }),
    env,
    ...(options.warn && { warn: options.warn }),
  });
  const credentials = new InMemoryCredentialStore(
    selection.providerId,
    providerCredential(selection, options.providerConfig, env),
  );
  const modelRuntime = await ModelRuntime.create({ credentials, allowModelNetwork: false });
  const model = resolveRuntimeModel(modelRuntime, selection, options.providerConfig);
  if (!model) {
    throw new Error(
      `Model not found in Pi registry: provider="${selection.providerId}" model="${selection.modelId}". ` +
        `Browse valid providers and models at ${PI_CATALOG_URL}, or configure a gateway base URL.`,
    );
  }
  return { selection, model, modelRuntime, credentials };
}
