import { type AssistantMessage, isContextOverflow, isRetryableAssistantError } from '@earendil-works/pi-ai';
import { PentestError } from '../../services/error-handling.js';
import { ErrorCode } from '../../types/errors.js';

export function providerTurnError(message: AssistantMessage, label: string, contextWindow?: number): PentestError {
  const detail = (message.errorMessage ?? 'unknown provider error').slice(0, 300);
  if (contextWindow !== undefined && isContextOverflow(message, contextWindow)) {
    return new PentestError(
      `${label}: context window exceeded after compaction: ${detail}`,
      'unknown',
      false,
      { contextWindow },
      ErrorCode.AGENT_EXECUTION_FAILED,
    );
  }
  return new PentestError(
    `${label}: ${detail}`,
    'unknown',
    isRetryableAssistantError(message),
    {},
    ErrorCode.AGENT_EXECUTION_FAILED,
  );
}
