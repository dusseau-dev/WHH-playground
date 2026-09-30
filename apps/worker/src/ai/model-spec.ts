/** A provider and model id, separated on the first colon in its string form. */
export interface ModelSpec {
  readonly providerId: string;
  readonly modelId: string;
}

export const DEFAULT_MODEL_SPEC = 'anthropic:claude-sonnet-4-6';

/**
 * Parse `<provider>:<model-id>`. Provider ids are intentionally open-ended so
 * callers can use providers supplied by the model runtime rather than only the
 * providers with first-class Shannon configuration.
 */
export function parseModelSpec(spec: string): ModelSpec {
  const trimmed = spec.trim();
  const separator = trimmed.indexOf(':');
  const malformed = `Model must be "<provider>:<model-id>", got "${trimmed}". Example: ${DEFAULT_MODEL_SPEC}`;
  if (separator < 1) throw new Error(malformed);

  const providerId = trimmed.slice(0, separator).trim();
  const modelId = trimmed.slice(separator + 1).trim();
  if (!providerId || !modelId) throw new Error(malformed);
  return { providerId, modelId };
}
