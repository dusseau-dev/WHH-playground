// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { render, screen, within } from '@testing-library/react';
import { useForm } from 'react-hook-form';
import { describe, expect, it } from 'vitest';
import {
  AssessmentConfigFields,
  type AssessmentFormValues,
  assessmentDefaults,
} from '../web/src/components/AssessmentConfigFields.js';
import type { ConfiguredModelDescription } from '../web/src/types/api.js';

const configuredModel: ConfiguredModelDescription = {
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
};

function ModelForm() {
  const form = useForm<AssessmentFormValues>({ defaultValues: assessmentDefaults });
  return (
    <AssessmentConfigFields
      form={form}
      showModelConfig
      modelConfiguration={configuredModel}
      modelOptions={[{ id: 'claude-opus-4.6', name: 'Claude Opus 4.6' }]}
    />
  );
}

function DetectionForm() {
  const defaults = structuredClone(assessmentDefaults);
  defaults.testScopes['alerting-effectiveness'] = true;
  defaults.targetEnvironment = 'staging';
  const form = useForm<AssessmentFormValues>({ defaultValues: defaults });
  return <AssessmentConfigFields form={form} />;
}

describe('assessment model configuration', () => {
  it('uses the configured source without exposing credential fields and groups manual overrides', () => {
    render(<ModelForm />);

    const sourceSelect = screen.getByLabelText('Model source');
    expect(sourceSelect).toHaveValue('environment');
    expect(screen.getByRole('option', { name: 'Cheaper Inference (configured)' })).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Model' })).toHaveAttribute('placeholder', 'claude-sonnet-4.6');
    expect(screen.queryByLabelText('Provider API key')).not.toBeInTheDocument();
    expect(screen.getByText('Cheaper Inference credential is configured on this runner.')).toBeInTheDocument();

    const overrideGroup = sourceSelect.querySelector('optgroup[label="Per-run override"]') as HTMLOptGroupElement;
    expect(overrideGroup).not.toBeNull();
    expect(within(overrideGroup).getAllByRole('option').map((option) => option.textContent)).toEqual([
      'OpenRouter',
      'Anthropic',
      'OpenAI',
      'xAI',
      'Custom gateway',
    ]);
  });

  it('reveals the staging-only detection validation fields conditionally', () => {
    render(<DetectionForm />);

    expect(screen.getByText('Detection validation')).toBeInTheDocument();
    expect(screen.getByLabelText('Canary path')).toHaveValue('/__shannon__/detection-simulation');
    expect(screen.getByLabelText('Splunk management URL')).toBeInTheDocument();
    expect(screen.getByLabelText('Splunk token')).toHaveAttribute('type', 'password');
    expect(screen.getByText(/fixed, inert paired corpus/i)).toBeInTheDocument();
  });
});
