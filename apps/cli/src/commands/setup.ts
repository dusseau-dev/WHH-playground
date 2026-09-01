/** Interactive one-model provider configuration for ~/.shannon/config.toml. */

import os from 'node:os';
import path from 'node:path';
import * as p from '@clack/prompts';
import { type ShannonConfig, saveConfig } from '../config/writer.js';

const SHANNON_HOME = path.join(os.homedir(), '.shannon');
const CURATED_PROVIDERS = ['anthropic', 'openai', 'xai', 'amazon-bedrock'] as const;
type CuratedProvider = (typeof CURATED_PROVIDERS)[number];
type OpenAiFormat = 'chat-completions' | 'responses';

const CUSTOM_MODEL = '__custom_model__';
const CUSTOM_GATEWAY = '__custom_gateway__';
const GENERIC_PROVIDER = '__generic_provider__';

const MODEL_SUGGESTIONS: Readonly<Record<CuratedProvider, readonly string[]>> = {
  anthropic: ['claude-sonnet-4-6', 'claude-opus-4-8', 'claude-opus-4-7', 'claude-haiku-4-5-20251001'],
  openai: ['gpt-5.6-sol', 'gpt-5.5', 'gpt-5.4'],
  xai: ['grok-4.5'],
  'amazon-bedrock': ['us.anthropic.claude-sonnet-4-6', 'us.anthropic.claude-opus-4-8', 'us.anthropic.claude-opus-4-7'],
};

const MODEL_PLACEHOLDER: Readonly<Record<CuratedProvider, string>> = {
  anthropic: 'claude-sonnet-4-6',
  openai: 'gpt-5.6-sol',
  xai: 'grok-4.5',
  'amazon-bedrock': 'us.anthropic.claude-opus-4-8',
};

interface Selection {
  provider: string;
  config: ShannonConfig;
  gateway?: { baseUrl: string; format?: OpenAiFormat };
}

export async function setup(): Promise<void> {
  p.intro('Shannon Setup');

  const selected = await p.select({
    message: 'Select your AI provider',
    options: [
      { value: 'anthropic' as const, label: 'Anthropic', hint: 'Claude models - recommended' },
      { value: 'openai' as const, label: 'OpenAI', hint: 'GPT models' },
      { value: 'xai' as const, label: 'xAI', hint: 'Grok models' },
      { value: 'amazon-bedrock' as const, label: 'AWS Bedrock', hint: 'Claude models via AWS' },
      { value: CUSTOM_GATEWAY, label: 'Custom Base URL', hint: 'your own proxy or gateway' },
      { value: GENERIC_PROVIDER, label: 'Other provider', hint: 'any other supported provider' },
    ],
  });
  if (p.isCancel(selected)) return cancelAndExit();

  const selection = await setupSelection(selected as CuratedProvider | typeof CUSTOM_GATEWAY | typeof GENERIC_PROVIDER);
  const modelId = await promptModel(selection.provider);
  selection.config.core = {
    model: `${selection.provider}:${modelId}`,
    ...(selection.gateway && { base_url: selection.gateway.baseUrl }),
  };
  saveConfig(selection.config);

  const summary = [`Provider   ${selection.provider}`, `Model      ${modelId}`];
  if (selection.gateway) summary.push(`Endpoint   ${selection.gateway.baseUrl}`);
  if (selection.gateway?.format) summary.push(`API        ${selection.gateway.format}`);
  p.log.success(`Configuration saved to ${path.join(SHANNON_HOME, 'config.toml')}`);
  p.log.info(summary.join('\n'));
  p.outro('Run `npx @keygraph/shannon start` to begin a scan.');
}

async function setupSelection(
  selected: CuratedProvider | typeof CUSTOM_GATEWAY | typeof GENERIC_PROVIDER,
): Promise<Selection> {
  if (selected === CUSTOM_GATEWAY) return setupGateway();
  if (selected === GENERIC_PROVIDER) return setupGenericProvider();
  return { provider: selected, config: await setupProvider(selected) };
}

async function setupProvider(provider: CuratedProvider): Promise<ShannonConfig> {
  switch (provider) {
    case 'anthropic':
      return { anthropic: { api_key: await promptSecret('Enter your Anthropic API key') } };
    case 'openai':
      return { openai: { api_key: await promptSecret('Enter your OpenAI API key') } };
    case 'xai':
      return { xai: { api_key: await promptSecret('Enter your xAI API key') } };
    case 'amazon-bedrock':
      return setupBedrock();
  }
}

async function setupBedrock(): Promise<ShannonConfig> {
  const region = await p.text({
    message: 'AWS Region',
    placeholder: 'us-east-1',
    validate: required('AWS Region is required'),
  });
  if (p.isCancel(region)) return cancelAndExit();
  const token = await promptSecret('Enter your AWS Bearer Token');
  return { bedrock: { region, token } };
}

async function setupGenericProvider(): Promise<Selection> {
  const provider = await p.text({
    message: 'Provider ID',
    validate: (value) => {
      const id = value?.trim();
      if (!id) return 'Provider ID is required';
      if ((CURATED_PROVIDERS as readonly string[]).includes(id)) return `${id} has its own option.`;
      if (id === 'vertex') return 'Vertex AI is no longer supported. Choose another provider or a custom gateway.';
      return undefined;
    },
  });
  if (p.isCancel(provider)) return cancelAndExit();
  const apiKey = await promptSecret('Enter the API key');
  return { provider: provider.trim(), config: { provider: { api_key: apiKey } } };
}

async function setupGateway(): Promise<Selection> {
  const format = await p.select({
    message: 'API format',
    options: [
      { value: 'anthropic' as const, label: 'Anthropic Messages' },
      { value: 'chat-completions' as const, label: 'OpenAI Chat Completions' },
      { value: 'responses' as const, label: 'OpenAI Responses' },
    ],
  });
  if (p.isCancel(format)) return cancelAndExit();

  const baseUrl = await p.text({
    message: 'Endpoint URL',
    placeholder: 'https://llm-gateway.example.com',
    validate: (value) => {
      if (!value) return 'Endpoint URL is required';
      try {
        new URL(value);
        return undefined;
      } catch {
        return 'Must be a valid URL';
      }
    },
  });
  if (p.isCancel(baseUrl)) return cancelAndExit();
  const apiKey = await promptSecret('Enter the API key for the endpoint');

  if (format === 'anthropic') {
    return {
      provider: 'anthropic',
      config: { anthropic: { api_key: apiKey } },
      gateway: { baseUrl },
    };
  }
  return {
    provider: 'openai',
    config: { openai: { api_key: apiKey, format } },
    gateway: { baseUrl, format },
  };
}

async function promptModel(provider: string): Promise<string> {
  const curated = (CURATED_PROVIDERS as readonly string[]).includes(provider)
    ? (provider as CuratedProvider)
    : undefined;
  if (!curated) return promptModelId(provider);

  const choice = await p.select({
    message: 'Model',
    options: [
      ...MODEL_SUGGESTIONS[curated].map((model) => ({ value: model, label: model })),
      { value: CUSTOM_MODEL, label: 'Enter a model ID…' },
    ],
  });
  if (p.isCancel(choice)) return cancelAndExit();
  return choice === CUSTOM_MODEL ? promptModelId(provider, MODEL_PLACEHOLDER[curated]) : (choice as string);
}

async function promptModelId(provider: string, placeholder?: string): Promise<string> {
  const value = await p.text({
    message: 'Model ID',
    ...(placeholder && { placeholder }),
    validate: (candidate) => {
      if (!candidate) return 'Model ID is required';
      const separator = candidate.indexOf(':');
      if (separator > 0) {
        const prefix = candidate.slice(0, separator);
        if (prefix !== provider && (CURATED_PROVIDERS as readonly string[]).includes(prefix)) {
          return `That model ID is for ${prefix}, but you selected ${provider}.`;
        }
      }
      return undefined;
    },
  });
  if (p.isCancel(value)) return cancelAndExit();
  return value.startsWith(`${provider}:`) ? value.slice(provider.length + 1) : value;
}

async function promptSecret(message: string): Promise<string> {
  const value = await p.password({
    message,
    validate: required(`${message.replace(/^Enter /, '')} is required`),
  });
  if (p.isCancel(value)) return cancelAndExit();
  return value;
}

function required(errorMessage: string): (value: string | undefined) => string | undefined {
  return (value) => (value ? undefined : errorMessage);
}

function cancelAndExit(): never {
  p.cancel('Setup cancelled.');
  process.exit(0);
}
