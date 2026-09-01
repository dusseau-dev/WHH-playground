import { type Api, type AssistantMessage, type Model, Type } from '@earendil-works/pi-ai';
import {
  createAgentSession,
  defineTool,
  getAgentDir,
  type ModelRuntime,
  type ResourceLoader,
  SessionManager,
  SettingsManager,
  type ToolDefinition,
} from '@earendil-works/pi-coding-agent';
import { attachCancellation } from './cancellation.js';
import { PI_RETRY_SETTINGS } from './retry-settings.js';

export interface PiUsage {
  cost: number;
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
}

export interface TaskToolContext {
  cwd: string;
  model: Model<Api>;
  modelRuntime: ModelRuntime;
  resourceLoader: ResourceLoader;
  cancellationSignal?: AbortSignal;
  onUsage?: (usage: PiUsage) => void;
  redactText?: (value: string) => string;
}

const CHILD_TOOLS = ['read', 'grep', 'find', 'ls', 'write', 'bash'];

function textResult(text: string) {
  return { content: [{ type: 'text' as const, text }], details: undefined };
}

/** Task delegation reuses the parent's model/runtime, cwd, policy loader, and cancellation. */
export function createTaskTool(config: TaskToolContext): ToolDefinition {
  return defineTool({
    name: 'task',
    label: 'Task',
    description: 'Delegate a focused task to an isolated in-memory child agent and return its result.',
    executionMode: 'parallel',
    promptSnippet: 'task: delegate focused work to a child agent',
    promptGuidelines: [
      'Pass all required context in the prompt; the child cannot see the parent conversation.',
      'The child has read, grep, find, ls, write, and bounded bash tools but cannot delegate again.',
    ],
    parameters: Type.Object({
      prompt: Type.String({ description: 'The complete child-agent task and context.' }),
      description: Type.Optional(Type.String({ description: 'A short description.' })),
    }),
    async execute(_toolCallId, params, toolSignal) {
      const { session } = await createAgentSession({
        cwd: config.cwd,
        agentDir: getAgentDir(),
        resourceLoader: config.resourceLoader,
        model: config.model,
        tools: CHILD_TOOLS,
        modelRuntime: config.modelRuntime,
        sessionManager: SessionManager.inMemory(config.cwd),
        settingsManager: SettingsManager.inMemory({ retry: PI_RETRY_SETTINGS, compaction: { enabled: true } }),
      });
      const abortChild = (): Promise<void> => session.abort();
      const cleanupParentCancellation = attachCancellation(config.cancellationSignal, abortChild);
      const cleanupToolCancellation = attachCancellation(toolSignal, abortChild);
      let resultText = '';
      let streamedCost = 0;
      session.subscribe((event) => {
        if (event.type !== 'turn_end') return;
        const message = event.message as AssistantMessage | undefined;
        for (const block of message?.content ?? []) {
          if (block.type === 'text' && block.text) resultText += `${resultText ? '\n' : ''}${block.text}`;
        }
        if (message?.usage?.cost?.total != null) streamedCost += message.usage.cost.total;
      });

      try {
        try {
          await session.prompt(params.prompt);
        } catch (error) {
          const detail =
            config.redactText?.(error instanceof Error ? error.message : String(error)) ??
            (error instanceof Error ? error.message : String(error));
          resultText += `\n[Sub-agent error: ${detail}]`;
        }
        const stateError = session.state.errorMessage;
        const stats = session.getSessionStats();
        config.onUsage?.({
          cost: Math.max(streamedCost, stats.cost),
          inputTokens: stats.tokens.input,
          outputTokens: stats.tokens.output,
          cacheReadTokens: stats.tokens.cacheRead,
          cacheWriteTokens: stats.tokens.cacheWrite,
        });
        if (stateError && !resultText.includes(stateError)) {
          resultText += `\n[Sub-agent error: ${config.redactText?.(stateError) ?? stateError}]`;
        }
        return textResult(resultText || '[Sub-agent produced no output]');
      } finally {
        cleanupParentCancellation();
        cleanupToolCancellation();
        session.dispose();
      }
    },
  });
}
