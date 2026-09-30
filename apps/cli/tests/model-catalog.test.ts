import { describe, expect, it, vi } from 'vitest';
import { describeConfiguredModel, listConfiguredModels } from '../src/model-catalog.js';

const openRouterEnvironment = {
  SHANNON_AI_MODEL: 'openai:anthropic/claude-sonnet-4.6',
  SHANNON_AI_BASE_URL: 'https://openrouter.ai/api/v1',
  SHANNON_AI_OPENAI_FORMAT: 'chat-completions',
  SHANNON_AI_API_KEY: 'server-side-openrouter-secret',
};

const cheaperInferenceEnvironment = {
  SHANNON_AI_MODEL: 'openai:claude-sonnet-4.6',
  SHANNON_AI_BASE_URL: 'https://api.cheaperinference.com/v1',
  SHANNON_AI_OPENAI_FORMAT: 'chat-completions',
  SHANNON_AI_API_KEY: 'server-side-cheaper-inference-secret',
};

describe('configured model catalog', () => {
  it('describes the configured OpenRouter provider without exposing its credential', () => {
    const configuration = describeConfiguredModel(openRouterEnvironment);

    expect(configuration).toEqual({
      providerId: 'openrouter',
      providerLabel: 'OpenRouter',
      modelId: 'anthropic/claude-sonnet-4.6',
      credentialConfigured: true,
      catalogAvailable: true,
      providerConfig: {
        providerType: 'openai',
        baseUrl: 'https://openrouter.ai/api/v1',
        openAIFormat: 'chat-completions',
      },
    });
    expect(JSON.stringify(configuration)).not.toContain('server-side-openrouter-secret');
  });

  it('recognizes the OpenRouter EU endpoint as the same configured provider', () => {
    expect(
      describeConfiguredModel({
        ...openRouterEnvironment,
        SHANNON_AI_BASE_URL: 'https://eu.openrouter.ai/api/v1',
      }),
    ).toMatchObject({ providerId: 'openrouter', providerLabel: 'OpenRouter', catalogAvailable: true });
  });

  it('describes Cheaper Inference without exposing its credential', () => {
    const configuration = describeConfiguredModel(cheaperInferenceEnvironment);

    expect(configuration).toEqual({
      providerId: 'cheaper-inference',
      providerLabel: 'Cheaper Inference',
      modelId: 'claude-sonnet-4.6',
      credentialConfigured: true,
      catalogAvailable: true,
      providerConfig: {
        providerType: 'openai',
        baseUrl: 'https://api.cheaperinference.com/v1',
        openAIFormat: 'chat-completions',
      },
    });
    expect(JSON.stringify(configuration)).not.toContain('server-side-cheaper-inference-secret');
  });

  it('does not trust a Cheaper Inference lookalike hostname', () => {
    expect(
      describeConfiguredModel({
        ...cheaperInferenceEnvironment,
        SHANNON_AI_BASE_URL: 'https://api.cheaperinference.com.attacker.test/v1',
      }),
    ).toMatchObject({ providerId: 'openai', providerLabel: 'OpenAI', catalogAvailable: false });
  });

  it('loads, normalizes, and sorts OpenRouter model choices with the credential kept server-side', async () => {
    const fetcher = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            data: [
              { id: 'openai/gpt-5.2', name: 'GPT 5.2', context_length: 400_000 },
              { id: 'anthropic/claude-sonnet-4.6', name: 'Claude Sonnet 4.6', context_length: 1_000_000 },
              { id: 'openai/gpt-5.2', name: 'Duplicate', context_length: 1 },
            ],
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
    );

    await expect(listConfiguredModels({ env: openRouterEnvironment, fetcher })).resolves.toEqual([
      { id: 'anthropic/claude-sonnet-4.6', name: 'Claude Sonnet 4.6', contextLength: 1_000_000 },
      { id: 'openai/gpt-5.2', name: 'GPT 5.2', contextLength: 400_000 },
    ]);
    expect(fetcher).toHaveBeenCalledWith('https://openrouter.ai/api/v1/models', {
      headers: { Authorization: 'Bearer server-side-openrouter-secret', Accept: 'application/json' },
      signal: expect.any(AbortSignal),
    });
  });

  it('loads Cheaper Inference models with the credential kept server-side', async () => {
    const fetcher = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            data: [
              { id: 'gpt-5.6-sol', name: 'GPT 5.6 Sol', context_length: 400_000 },
              { id: 'claude-sonnet-4.6', name: 'Claude Sonnet 4.6', context_length: 1_000_000 },
              { id: 'claude-sonnet-4.6', name: 'Duplicate' },
              { id: 'claude-opus-4.6' },
            ],
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
    );

    await expect(listConfiguredModels({ env: cheaperInferenceEnvironment, fetcher })).resolves.toEqual([
      { id: 'claude-sonnet-4.6', name: 'Claude Sonnet 4.6', contextLength: 1_000_000 },
      { id: 'claude-opus-4.6', name: 'claude-opus-4.6' },
      { id: 'gpt-5.6-sol', name: 'GPT 5.6 Sol', contextLength: 400_000 },
    ]);
    expect(fetcher).toHaveBeenCalledWith('https://api.cheaperinference.com/v1/models', {
      headers: { Authorization: 'Bearer server-side-cheaper-inference-secret', Accept: 'application/json' },
      signal: expect.any(AbortSignal),
    });
  });
});
