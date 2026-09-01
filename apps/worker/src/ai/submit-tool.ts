import { defineTool, type ToolDefinition } from '@earendil-works/pi-coding-agent';
import { Type } from 'typebox';

export interface CapturedSubmitTool {
  readonly tool: ToolDefinition;
  readonly getCaptured: () => unknown | undefined;
  readonly directive?: string;
}

/** Build Pi's structured-output replacement from a caller-owned JSON Schema. */
export function createGenericSubmitTool(schema: Record<string, unknown>): CapturedSubmitTool {
  let captured: unknown | undefined;
  return {
    tool: defineTool({
      name: 'submit_result',
      label: 'Submit Result',
      description: 'Return your final structured answer. Call exactly once as your last action.',
      promptSnippet: 'submit_result: deliver your structured answer (call once)',
      promptGuidelines: [
        'You MUST call submit_result exactly once as your final action.',
        'Fill every required parameter. Do not output JSON as text.',
      ],
      parameters: Type.Unsafe(schema),
      async execute(_toolCallId, params) {
        captured = params;
        return {
          content: [{ type: 'text' as const, text: 'Result submitted.' }],
          details: params,
          terminate: true,
        };
      },
    }),
    getCaptured: () => captured,
    directive:
      '\n\nYou MUST call the submit_result tool exactly once as your final action to deliver your structured ' +
      'answer. Do not output JSON as text. Fill every required parameter.',
  };
}
