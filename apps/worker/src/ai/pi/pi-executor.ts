// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import type { AgentMessage } from '@earendil-works/pi-agent-core';
import {
  type AgentSession,
  type AgentSessionEvent,
  createAgentSession,
  DefaultResourceLoader,
  getAgentDir,
  type ResourceLoader,
  SessionManager,
  SettingsManager,
  type Skill,
  type ToolDefinition,
} from '@earendil-works/pi-coding-agent';
import { fs, path } from 'zx';
import type { AuditSession } from '../../audit/index.js';
import { DEFAULT_DELIVERABLES_SUBDIR, deliverablesDir } from '../../paths.js';
import { isRetryableError, PentestError } from '../../services/error-handling.js';
import {
  collectConfiguredSecrets,
  collectRuntimeProviderSecrets,
  createExactValueRedactor,
} from '../../services/redaction.js';
import { AGENT_VALIDATORS } from '../../session-manager.js';
import type { ActivityLogger } from '../../types/activity-logger.js';
import type { ProviderConfig } from '../../types/config.js';
import { ErrorCode } from '../../types/errors.js';
import { isBrowserAgent } from '../../utils/browser-agents.js';
import { formatTimestamp } from '../../utils/formatting.js';
import { Timer } from '../../utils/metrics.js';
import { createAuditLogger } from '../audit-logger.js';
import type { ModelEnvironment, ModelTier } from '../model-resolver.js';
import {
  detectExecutionContext,
  formatAssistantOutput,
  formatCompletionMessage,
  formatErrorOutput,
  formatToolUseOutput,
} from '../output-formatters.js';
import { createProgressManager } from '../progress-manager.js';
import type { CapturedSubmitTool } from '../submit-tool.js';
import { attachCancellation as attachCancellationSignal } from './cancellation.js';
import { resolvePiModelRuntime } from './model-runtime.js';
import { permissionSystemConfigExists, permissionSystemPackageDir } from './permission-system.js';
import { PI_RETRY_SETTINGS } from './retry-settings.js';
import { createGlobTool, createTodoWriteTool } from './session-tools.js';
import { createTaskTool, type PiUsage } from './task-tool.js';
import { providerTurnError } from './turn-error.js';

declare global {
  var SHANNON_DISABLE_LOADER: boolean | undefined;
}

const BUILTIN_TOOLS = ['read', 'bash', 'edit', 'write', 'grep', 'find', 'ls'];
const BASH_TIMEOUT_EXTENSION_DIR = path.join(import.meta.dirname, '..', 'extensions', 'bash-timeout');

export { attachCancellation } from './cancellation.js';

interface SessionStatsLike {
  cost: number;
  tokens: { input: number; output: number; cacheRead: number; cacheWrite: number };
}

export function aggregatePiUsage(parent: SessionStatsLike | undefined, child: PiUsage): PiUsage {
  return {
    cost: (parent?.cost ?? 0) + child.cost,
    inputTokens: (parent?.tokens.input ?? 0) + child.inputTokens,
    outputTokens: (parent?.tokens.output ?? 0) + child.outputTokens,
    cacheReadTokens: (parent?.tokens.cacheRead ?? 0) + child.cacheReadTokens,
    cacheWriteTokens: (parent?.tokens.cacheWrite ?? 0) + child.cacheWriteTokens,
  };
}

export interface PiExecutionPaths {
  cwd: string;
  deliverablesDir: string;
  playwrightOutputDir: string;
}

export function buildPiExecutionPaths(
  workingDirectory: string,
  deliverablesSubdir: string = DEFAULT_DELIVERABLES_SUBDIR,
): PiExecutionPaths {
  return {
    cwd: workingDirectory,
    deliverablesDir: deliverablesDir(workingDirectory, deliverablesSubdir),
    playwrightOutputDir: path.join(workingDirectory, path.dirname(deliverablesSubdir), '.playwright-cli'),
  };
}

function buildPlaywrightSkill(): Skill {
  const filePath =
    process.env.PLAYWRIGHT_CLI_SKILL_PATH ?? path.join(getAgentDir(), 'skills', 'playwright-cli', 'SKILL.md');
  const baseDir = path.dirname(filePath);
  return {
    name: 'playwright-cli',
    description: 'Drive a real browser via playwright-cli for navigation, interaction, screenshots, and live pages.',
    filePath,
    baseDir,
    sourceInfo: { path: filePath, source: 'custom', scope: 'user', origin: 'top-level', baseDir },
    disableModelInvocation: false,
  };
}

async function buildResourceLoader(
  cwd: string,
  logger: ActivityLogger,
  agentName: string | null,
): Promise<ResourceLoader> {
  const additionalExtensionPaths = [BASH_TIMEOUT_EXTENSION_DIR];
  if (permissionSystemConfigExists(getAgentDir())) {
    try {
      additionalExtensionPaths.push(permissionSystemPackageDir());
    } catch {
      logger.warn('code_path deny policy exists but the Pi permission extension is not resolvable');
    }
  }
  const loader = new DefaultResourceLoader({
    cwd,
    agentDir: getAgentDir(),
    additionalExtensionPaths,
    ...(isBrowserAgent(agentName)
      ? { skillsOverride: (base) => ({ skills: [buildPlaywrightSkill()], diagnostics: base.diagnostics }) }
      : { noSkills: true }),
  });
  await loader.reload();
  return loader;
}

export interface PiPromptResult {
  result?: string | null;
  success: boolean;
  duration: number;
  turns?: number;
  cost: number;
  inputTokens?: number;
  outputTokens?: number;
  cacheReadTokens?: number;
  cacheWriteTokens?: number;
  model?: string;
  error?: string;
  errorType?: string;
  prompt?: string;
  retryable?: boolean;
  structuredOutput?: unknown;
}

export interface PiPromptRuntimeOptions {
  readonly modelTier?: ModelTier | undefined;
  readonly providerConfig?: ProviderConfig | undefined;
  /** Legacy ContainerConfig API key, used only when ProviderConfig is absent. */
  readonly apiKey?: string | undefined;
  readonly env?: ModelEnvironment | undefined;
}

export interface RunPiPromptOptions {
  readonly prompt: string;
  readonly workingDirectory: string;
  readonly logger: ActivityLogger;
  readonly context?: string;
  readonly description?: string;
  readonly agentName?: string | null;
  readonly auditSession?: AuditSession | null;
  readonly callerTools?: ToolDefinition[];
  readonly deliverablesSubdir?: string;
  readonly cancellationSignal?: AbortSignal;
  readonly submitTool?: CapturedSubmitTool;
  readonly runtimeOptions?: PiPromptRuntimeOptions;
}

function outputLines(lines: readonly string[]): void {
  for (const line of lines) console.log(line);
}

function extractAssistantText(message: AgentMessage): string {
  if (message.role !== 'assistant') return '';
  return (message.content as Array<{ type: string; text?: string }>)
    .filter((block) => block.type === 'text')
    .map((block) => block.text ?? '')
    .join('\n');
}

function retryable(error: Error): boolean {
  return error instanceof PentestError ? error.retryable : isRetryableError(error);
}

async function writeErrorLog(
  error: Error & { code?: string; status?: number },
  paths: PiExecutionPaths,
  fullPrompt: string,
  duration: number,
): Promise<void> {
  try {
    await fs.ensureDir(paths.deliverablesDir);
    await fs.appendFile(
      path.join(paths.deliverablesDir, 'error.log'),
      `${JSON.stringify({
        timestamp: formatTimestamp(),
        agent: 'pi-executor',
        error: {
          name: error.name,
          message: error.message,
          code: error.code,
          status: error.status,
          stack: error.stack,
        },
        context: { workingDirectory: paths.cwd, prompt: `${fullPrompt.slice(0, 200)}...`, retryable: retryable(error) },
        duration,
      })}\n`,
    );
  } catch {
    // Error logging must never mask the original execution failure.
  }
}

export async function validateAgentOutput(
  result: PiPromptResult,
  agentName: string | null,
  workingDirectory: string,
  logger: ActivityLogger,
): Promise<boolean> {
  logger.info(`Validating ${agentName} agent output`);
  try {
    if (!result.success || (!result.result && result.structuredOutput === undefined)) return false;
    const validator = agentName ? AGENT_VALIDATORS[agentName as keyof typeof AGENT_VALIDATORS] : undefined;
    if (!validator) {
      logger.warn(`No validator found for agent "${agentName}" - assuming success`);
      return true;
    }
    return await validator(workingDirectory, logger);
  } catch (error) {
    logger.error(`Validation failed with error: ${error instanceof Error ? error.message : String(error)}`);
    return false;
  }
}

/**
 * Run one Pi session. Session, settings, and credentials are all in memory;
 * workingDirectory is the sole cwd and deliverablesSubdir changes only outputs.
 */
export async function runPiPrompt(options: RunPiPromptOptions): Promise<PiPromptResult> {
  const {
    prompt,
    workingDirectory,
    logger,
    context = '',
    description = 'Agent analysis',
    agentName = null,
    auditSession = null,
    callerTools,
    deliverablesSubdir,
    cancellationSignal,
    submitTool,
    runtimeOptions = {},
  } = options;
  const timer = new Timer(`agent-${description.toLowerCase().replace(/\s+/g, '-')}`);
  const basePrompt = context ? `${context}\n\n${prompt}` : prompt;
  const fullPrompt = submitTool?.directive ? basePrompt + submitTool.directive : basePrompt;
  const paths = buildPiExecutionPaths(workingDirectory, deliverablesSubdir);
  const providerConfig =
    runtimeOptions.providerConfig ??
    (runtimeOptions.apiKey ? { providerType: 'anthropic', apiKey: runtimeOptions.apiKey } : undefined);
  const localRedactor = createExactValueRedactor([
    ...collectConfiguredSecrets(null, providerConfig, runtimeOptions.apiKey),
    ...collectRuntimeProviderSecrets(),
  ]);
  const redactText = (value: string): string =>
    auditSession?.redactText(localRedactor.redactText(value)) ?? localRedactor.redactText(value);
  const redactValue = <T>(value: T): T =>
    auditSession?.redactValue(localRedactor.redactValue(value)) ?? localRedactor.redactValue(value);
  const execContext = detectExecutionContext(description);
  const progress = createProgressManager(
    { description, useCleanOutput: execContext.useCleanOutput },
    global.SHANNON_DISABLE_LOADER ?? false,
  );
  const auditLogger = createAuditLogger(auditSession);
  const childUsage: PiUsage = {
    cost: 0,
    inputTokens: 0,
    outputTokens: 0,
    cacheReadTokens: 0,
    cacheWriteTokens: 0,
  };
  const pendingAuditWrites = new Set<Promise<void>>();
  const trackAuditWrite = (write: Promise<void>): void => {
    pendingAuditWrites.add(write);
    void write.then(
      () => pendingAuditWrites.delete(write),
      () => pendingAuditWrites.delete(write),
    );
  };
  let turnCount = 0;
  let pendingError: PentestError | null = null;
  let session: AgentSession | undefined;
  let cleanupCancellation = (): void => undefined;
  let modelId: string | undefined;

  logger.info(`Running Pi agent: ${description}...`);
  process.env.PLAYWRIGHT_MCP_OUTPUT_DIR = paths.playwrightOutputDir;
  if (deliverablesSubdir) process.env.SHANNON_DELIVERABLES_SUBDIR = deliverablesSubdir;
  else delete process.env.SHANNON_DELIVERABLES_SUBDIR;
  progress.start();

  try {
    cancellationSignal?.throwIfAborted();
    const resolved = await resolvePiModelRuntime({
      ...(runtimeOptions.modelTier && { modelTier: runtimeOptions.modelTier }),
      ...(providerConfig && { providerConfig }),
      ...(runtimeOptions.env && { env: runtimeOptions.env }),
      warn: (message) => logger.warn(message),
    });
    modelId = resolved.model.id;
    const resourceLoader = await buildResourceLoader(paths.cwd, logger, agentName);
    const taskTool = createTaskTool({
      cwd: paths.cwd,
      model: resolved.model,
      modelRuntime: resolved.modelRuntime,
      resourceLoader,
      ...(cancellationSignal && { cancellationSignal }),
      redactText,
      onUsage: (usage) => {
        childUsage.cost += usage.cost;
        childUsage.inputTokens += usage.inputTokens;
        childUsage.outputTokens += usage.outputTokens;
        childUsage.cacheReadTokens += usage.cacheReadTokens;
        childUsage.cacheWriteTokens += usage.cacheWriteTokens;
      },
    });
    const customTools = [
      taskTool,
      createTodoWriteTool(auditLogger),
      createGlobTool(paths.cwd),
      ...(callerTools ?? []),
      ...(submitTool ? [submitTool.tool] : []),
    ];
    ({ session } = await createAgentSession({
      cwd: paths.cwd,
      model: resolved.model,
      modelRuntime: resolved.modelRuntime,
      tools: [...BUILTIN_TOOLS, ...customTools.map((tool) => tool.name)],
      customTools,
      sessionManager: SessionManager.inMemory(paths.cwd),
      settingsManager: SettingsManager.inMemory({ retry: PI_RETRY_SETTINGS, compaction: { enabled: true } }),
      resourceLoader,
    }));
    cleanupCancellation = attachCancellationSignal(cancellationSignal, () => session?.abort());
    cancellationSignal?.throwIfAborted();

    session.subscribe((event: AgentSessionEvent) => {
      switch (event.type) {
        case 'turn_end': {
          turnCount += 1;
          const text = extractAssistantText(event.message);
          if (text.trim()) {
            const safeText = redactText(text);
            trackAuditWrite(auditLogger.logLlmResponse(turnCount, safeText));
            progress.stop();
            outputLines(formatAssistantOutput(safeText, execContext, turnCount, description));
            progress.start();
          }
          if (event.message.role === 'assistant' && event.message.stopReason === 'error') {
            pendingError ??= providerTurnError(event.message, 'Agent error', resolved.model.contextWindow);
          }
          break;
        }
        case 'tool_execution_start': {
          const safeArgs = redactValue(event.args);
          trackAuditWrite(auditLogger.logToolStart(event.toolName, safeArgs));
          progress.stop();
          outputLines(formatToolUseOutput(event.toolName, safeArgs as Record<string, unknown>));
          progress.start();
          break;
        }
        case 'tool_execution_end':
          trackAuditWrite(auditLogger.logToolEnd(redactValue(event.result)));
          break;
        case 'compaction_end':
          if (!event.aborted && !event.willRetry && event.errorMessage) {
            pendingError ??= new PentestError(
              `Context compaction failed: ${redactText(event.errorMessage).slice(0, 200)}`,
              'unknown',
              true,
              {},
              ErrorCode.AGENT_EXECUTION_FAILED,
            );
          }
          break;
        default:
          break;
      }
    });

    await session.prompt(fullPrompt);
    cancellationSignal?.throwIfAborted();
    await Promise.allSettled([...pendingAuditWrites]);
    if (pendingError) throw pendingError;
    const usage = aggregatePiUsage(session.getSessionStats(), childUsage);
    const result = session.getLastAssistantText();
    const duration = timer.stop();
    progress.finish(formatCompletionMessage(execContext, description, turnCount, duration));
    const structuredOutput = submitTool?.getCaptured();
    return {
      result: result == null ? null : redactText(result),
      success: true,
      duration,
      turns: turnCount,
      ...usage,
      model: modelId,
      ...(structuredOutput !== undefined && { structuredOutput: redactValue(structuredOutput) }),
    };
  } catch (error) {
    if (cancellationSignal?.aborted) {
      progress.stop();
      await Promise.allSettled([...pendingAuditWrites]);
      cancellationSignal.throwIfAborted();
    }
    const duration = timer.stop();
    const raw = error as Error & { code?: string; status?: number };
    const safeError = Object.assign(new Error(redactText(raw.message)), {
      name: raw.name,
      ...(raw.code !== undefined && { code: raw.code }),
      ...(raw.status !== undefined && { status: raw.status }),
      ...(raw.stack && { stack: redactText(raw.stack) }),
    });
    trackAuditWrite(auditLogger.logError(safeError, duration, turnCount));
    await Promise.allSettled([...pendingAuditWrites]);
    progress.stop();
    outputLines(formatErrorOutput(safeError, execContext, description, duration, paths.cwd, retryable(raw)));
    await writeErrorLog(safeError, paths, redactText(fullPrompt), duration);
    const usage = aggregatePiUsage(session?.getSessionStats(), childUsage);
    return {
      error: safeError.message,
      errorType: raw instanceof PentestError && raw.code ? raw.code : raw.constructor.name,
      prompt: redactText(`${fullPrompt.slice(0, 100)}...`),
      success: false,
      duration,
      turns: turnCount,
      ...usage,
      retryable: retryable(raw),
      ...(modelId && { model: modelId }),
    };
  } finally {
    cleanupCancellation();
    session?.dispose();
  }
}
