import type { ExtensionAPI, ToolCallEvent, ToolCallEventResult } from '@earendil-works/pi-coding-agent';
import { isToolCallEventType } from '@earendil-works/pi-coding-agent';

export const DEFAULT_TIMEOUT_SECONDS = 120;
export const MAX_TIMEOUT_SECONDS = 600;

export function evaluateBashTimeout(timeout: number | undefined): ToolCallEventResult | undefined {
  if (typeof timeout !== 'number' || !Number.isFinite(timeout) || timeout <= 0) {
    return {
      block: true,
      reason:
        `A timeout in seconds is required for bash. Use ${DEFAULT_TIMEOUT_SECONDS}s by default ` +
        `or at most ${MAX_TIMEOUT_SECONDS}s.`,
    };
  }
  if (timeout > MAX_TIMEOUT_SECONDS) {
    return {
      block: true,
      reason: `bash timeout ${timeout}s exceeds the ${MAX_TIMEOUT_SECONDS}s maximum.`,
    };
  }
  return undefined;
}

export default function bashTimeoutExtension(pi: ExtensionAPI): void {
  pi.on('tool_call', (event: ToolCallEvent): ToolCallEventResult | undefined => {
    if (!isToolCallEventType('bash', event)) return undefined;
    return evaluateBashTimeout(event.input.timeout);
  });
}
