// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Agent Execution Service
 *
 * Handles the full agent lifecycle:
 * - Load config via ConfigLoaderService
 * - Load prompt template using AGENTS[agentName].promptTemplate
 * - Create git checkpoint
 * - Start audit logging
 * - Invoke the Pi runtime via runPiPrompt
 * - Spending cap check using isSpendingCapBehavior
 * - Handle failure (rollback, audit)
 * - Validate output using AGENTS[agentName].deliverableFilename
 * - Commit on success, log metrics
 *
 * No Temporal dependencies - pure domain logic.
 */

import type { ToolDefinition } from '@earendil-works/pi-coding-agent';
import { path } from 'zx';
import { type PiPromptResult, runPiPrompt, validateAgentOutput } from '../ai/pi/pi-executor.js';
import { createQueueSubmitTool, getQueueFilename } from '../ai/queue-schemas.js';
import type { AuditSession } from '../audit/index.js';
import { authStateFile } from '../audit/utils.js';
import { AGENTS } from '../session-manager.js';
import type { ActivityLogger } from '../types/activity-logger.js';
import type { AgentName } from '../types/agents.js';
import type { AgentEndResult } from '../types/audit.js';
import { ErrorCode, type PentestErrorType } from '../types/errors.js';
import { err, isErr, ok, type Result } from '../types/result.js';
import { isSpendingCapBehavior } from '../utils/billing-detection.js';
import { atomicWrite, ensureDirectory } from '../utils/file-io.js';
import type { ConfigLoaderService } from './config-loader.js';
import { PentestError } from './error-handling.js';
import { commitGitSuccess, createGitCheckpoint, getGitCommitHash, rollbackGitWorkspace } from './git-manager.js';
import { loadPrompt } from './prompt-manager.js';
import { collectConfiguredSecrets, collectRuntimeProviderSecrets } from './redaction.js';

/**
 * Input for agent execution.
 */
export interface AgentExecutionInput {
  webUrl: string;
  workingDirectory: string;
  repoPath?: string | undefined;
  sourceMode: import('../types/config.js').SourceMode;
  deliverablesPath: string;
  configPath?: string | undefined;
  configData?: import('../types/config.js').DistributedConfig | undefined;
  configYAML?: string | undefined;
  testScopes?: import('../types/scopes.js').AssessmentScope[] | undefined;
  testSurfaces?: import('../types/scopes.js').AssessmentSurface[] | undefined;
  pipelineTestingMode?: boolean | undefined;
  attemptNumber: number;
  apiKey?: string | undefined;
  promptDir?: string | undefined;
  providerConfig?: import('../types/config.js').ProviderConfig | undefined;
  cancellationSignal?: AbortSignal | undefined;
  /** Additional in-memory tools owned by the caller (for example structured report collectors). */
  callerTools?: ToolDefinition[] | undefined;
  /** Runs after successful execution/queue persistence and before validation or commit. */
  postExecutionFinalizer?: ((context: AgentPostExecutionContext) => Promise<void>) | undefined;
}

export interface AgentPostExecutionContext {
  readonly result: PiPromptResult;
  readonly distributedConfig: import('../types/config.js').DistributedConfig | null;
  readonly logger: ActivityLogger;
}

interface FailAgentOpts {
  attemptNumber: number;
  result: PiPromptResult;
  rollbackReason: string;
  errorMessage: string;
  errorCode: ErrorCode;
  category: PentestErrorType;
  retryable: boolean;
  context: Record<string, unknown>;
}

function piUsageResult(
  result: PiPromptResult,
): Pick<
  AgentEndResult,
  'cost_usd' | 'input_tokens' | 'output_tokens' | 'cache_read_tokens' | 'cache_write_tokens' | 'num_turns'
> {
  return {
    cost_usd: result.cost || 0,
    ...(result.inputTokens !== undefined && { input_tokens: result.inputTokens }),
    ...(result.outputTokens !== undefined && { output_tokens: result.outputTokens }),
    ...(result.cacheReadTokens !== undefined && { cache_read_tokens: result.cacheReadTokens }),
    ...(result.cacheWriteTokens !== undefined && { cache_write_tokens: result.cacheWriteTokens }),
    ...(result.turns !== undefined && { num_turns: result.turns }),
  };
}

/**
 * Service for executing agents with full lifecycle management.
 *
 * NOTE: AuditSession is passed per-execution, NOT stored on the service.
 * This is critical for parallel agent execution - each agent needs its own
 * AuditSession instance because AuditSession uses instance state (currentAgentName)
 * to track which agent is currently logging.
 */
export class AgentExecutionService {
  private readonly configLoader: ConfigLoaderService;

  constructor(configLoader: ConfigLoaderService) {
    this.configLoader = configLoader;
  }

  /**
   * Execute an agent with full lifecycle management.
   *
   * @param agentName - Name of the agent to execute
   * @param input - Execution input parameters
   * @param auditSession - Audit session for this specific agent execution
   * @returns Result containing AgentEndResult on success, PentestError on failure
   */
  async execute(
    agentName: AgentName,
    input: AgentExecutionInput,
    auditSession: AuditSession,
    logger: ActivityLogger,
  ): Promise<Result<AgentEndResult, PentestError>> {
    const {
      webUrl,
      workingDirectory,
      repoPath,
      sourceMode,
      deliverablesPath,
      configPath,
      configData,
      configYAML,
      pipelineTestingMode = false,
      attemptNumber,
      apiKey,
      promptDir,
      providerConfig,
      cancellationSignal,
      callerTools,
      postExecutionFinalizer,
    } = input;

    cancellationSignal?.throwIfAborted();

    auditSession.setRedactionSecrets([
      ...collectConfiguredSecrets(null, providerConfig, apiKey),
      ...collectRuntimeProviderSecrets(),
    ]);

    // 1. Load config (pre-parsed configData → raw YAML → file path)
    const configResult = await this.configLoader.loadOptional(configPath, configData, configYAML, sourceMode);
    if (isErr(configResult)) {
      return configResult;
    }
    const distributedConfig = configResult.value;
    auditSession.setRedactionSecrets([
      ...collectConfiguredSecrets(distributedConfig, providerConfig, apiKey),
      ...collectRuntimeProviderSecrets(),
    ]);

    // 2. Load prompt
    const promptTemplate = AGENTS[agentName].promptTemplate;
    let prompt: string;
    try {
      prompt = await loadPrompt(
        promptTemplate,
        {
          webUrl,
          workingDirectory,
          ...(repoPath !== undefined && { repoPath }),
          AUTH_STATE_FILE: authStateFile(auditSession.sessionMetadata),
          ...(input.testScopes !== undefined && { testScopes: input.testScopes }),
          ...(input.testSurfaces !== undefined && { testSurfaces: input.testSurfaces }),
        },
        distributedConfig,
        pipelineTestingMode,
        logger,
        promptDir,
        sourceMode,
      );
    } catch (error) {
      const errorMessage = auditSession.redactText(error instanceof Error ? error.message : String(error));
      return err(
        new PentestError(
          `Failed to load prompt for ${agentName}: ${errorMessage}`,
          'prompt',
          false,
          { agentName, promptTemplate, originalError: errorMessage },
          ErrorCode.PROMPT_LOAD_FAILED,
        ),
      );
    }

    // 3. Create git checkpoint before execution
    try {
      await createGitCheckpoint(deliverablesPath, agentName, attemptNumber, logger);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      return err(
        new PentestError(
          `Failed to create git checkpoint for ${agentName}: ${errorMessage}`,
          'filesystem',
          false,
          { agentName, deliverablesPath, originalError: errorMessage },
          ErrorCode.GIT_CHECKPOINT_FAILED,
        ),
      );
    }

    let auditStarted = false;
    let lifecycleFinalizationStarted = false;
    let completedResult: PiPromptResult | undefined;
    const auditStartedAt = Date.now();
    const failExecution = async (opts: FailAgentOpts): Promise<Result<AgentEndResult, PentestError>> => {
      lifecycleFinalizationStarted = true;
      return this.failAgent(agentName, deliverablesPath, auditSession, logger, opts);
    };

    try {
      cancellationSignal?.throwIfAborted();

      // 4. Start audit logging
      await auditSession.startAgent(agentName, prompt, attemptNumber);
      auditStarted = true;

      // 5. Execute agent
      const submitTool = createQueueSubmitTool(
        agentName,
        distributedConfig?.safeDemonstration ?? (distributedConfig as { exploit?: boolean } | null)?.exploit ?? true,
      );
      const result: PiPromptResult = await runPiPrompt({
        prompt,
        workingDirectory,
        description: agentName,
        agentName,
        auditSession,
        logger,
        ...(callerTools && { callerTools }),
        deliverablesSubdir: path.relative(workingDirectory, deliverablesPath),
        ...(cancellationSignal && { cancellationSignal }),
        ...(submitTool && { submitTool }),
        runtimeOptions: { modelTier: AGENTS[agentName].modelTier, providerConfig, apiKey },
      });
      completedResult = result;
      cancellationSignal?.throwIfAborted();

      // 6. Spending cap check - defense-in-depth
      if (result.success && (result.turns ?? 0) <= 2 && (result.cost || 0) === 0) {
        const resultText = result.result || '';
        if (isSpendingCapBehavior(result.turns ?? 0, result.cost || 0, resultText)) {
          return failExecution({
            attemptNumber,
            result,
            rollbackReason: 'spending cap detected',
            errorMessage: `Spending cap likely reached: ${resultText.slice(0, 100)}`,
            errorCode: ErrorCode.SPENDING_CAP_REACHED,
            category: 'billing',
            retryable: true,
            context: { agentName, turns: result.turns, cost: result.cost },
          });
        }
      }

      // 7. Handle execution failure
      if (!result.success) {
        return failExecution({
          attemptNumber,
          result,
          rollbackReason: 'execution failure',
          errorMessage: result.error || 'Agent execution failed',
          errorCode: ErrorCode.AGENT_EXECUTION_FAILED,
          category: 'validation',
          retryable: result.retryable ?? true,
          context: { agentName, originalError: result.error },
        });
      }

      // 8. Write structured output to disk (vuln agents only)
      const queueFilename = getQueueFilename(agentName);
      if (submitTool && result.structuredOutput !== undefined && queueFilename) {
        cancellationSignal?.throwIfAborted();
        await ensureDirectory(deliverablesPath);
        cancellationSignal?.throwIfAborted();
        const queuePath = path.join(deliverablesPath, queueFilename);
        await atomicWrite(queuePath, result.structuredOutput === null ? 'null' : result.structuredOutput);
        cancellationSignal?.throwIfAborted();
        logger.info(`Wrote structured output queue to ${queueFilename}`);
        cancellationSignal?.throwIfAborted();
      }

      // Caller-owned structured outputs must exist before the normal deliverable validator runs.
      if (postExecutionFinalizer) {
        cancellationSignal?.throwIfAborted();
        try {
          await postExecutionFinalizer({ result, distributedConfig, logger });
        } catch (error) {
          cancellationSignal?.throwIfAborted();
          const rawMessage = error instanceof Error ? error.message : String(error);
          return failExecution({
            attemptNumber,
            result,
            rollbackReason: 'post-execution finalization failure',
            errorMessage: `Agent ${agentName} failed post-execution finalization: ${rawMessage}`,
            errorCode: ErrorCode.OUTPUT_VALIDATION_FAILED,
            category: 'validation',
            retryable: true,
            context: { agentName, originalError: rawMessage },
          });
        }
        cancellationSignal?.throwIfAborted();
      }

      // 9. Validate output
      const validationPassed = await validateAgentOutput(result, agentName, deliverablesPath, logger);
      cancellationSignal?.throwIfAborted();
      if (!validationPassed) {
        return failExecution({
          attemptNumber,
          result,
          rollbackReason: 'validation failure',
          errorMessage: `Agent ${agentName} failed output validation`,
          errorCode: ErrorCode.OUTPUT_VALIDATION_FAILED,
          category: 'validation',
          retryable: true,
          context: { agentName, deliverableFilename: AGENTS[agentName].deliverableFilename },
        });
      }

      // 10. Success - commit deliverables, then capture checkpoint hash
      cancellationSignal?.throwIfAborted();
      await commitGitSuccess(deliverablesPath, agentName, logger);
      const commitHash = await getGitCommitHash(deliverablesPath);

      const endResult: AgentEndResult = {
        attemptNumber,
        duration_ms: result.duration,
        ...piUsageResult(result),
        success: true,
        model: result.model,
        ...(commitHash && { checkpoint: commitHash }),
      };
      lifecycleFinalizationStarted = true;
      await auditSession.endAgent(agentName, endResult);

      return ok(endResult);
    } catch (error) {
      if (!cancellationSignal?.aborted || lifecycleFinalizationStarted) {
        throw error;
      }

      lifecycleFinalizationStarted = true;
      try {
        await rollbackGitWorkspace(deliverablesPath, 'agent execution cancellation', logger);
      } catch (cleanupError) {
        const message = auditSession.redactText(
          cleanupError instanceof Error ? cleanupError.message : String(cleanupError),
        );
        logger.error(`Failed to roll back cancelled agent execution: ${message}`);
      }

      if (auditStarted) {
        const cancellationReason = cancellationSignal.reason;
        const cancellationMessage = auditSession.redactText(
          cancellationReason instanceof Error ? cancellationReason.message : String(cancellationReason),
        );
        const endResult: AgentEndResult = {
          attemptNumber,
          duration_ms: completedResult?.duration ?? Date.now() - auditStartedAt,
          ...(completedResult ? piUsageResult(completedResult) : { cost_usd: 0 }),
          success: false,
          model: completedResult?.model,
          error: cancellationMessage,
        };

        try {
          await auditSession.endAgent(agentName, endResult);
        } catch (cleanupError) {
          const message = auditSession.redactText(
            cleanupError instanceof Error ? cleanupError.message : String(cleanupError),
          );
          logger.error(`Failed to close audit state for cancelled agent execution: ${message}`);
        }
      }

      // Preserve the signal's original reason for Temporal cancellation classification.
      cancellationSignal.throwIfAborted();
      throw error;
    }
  }

  private async failAgent(
    agentName: AgentName,
    deliverablesPath: string,
    auditSession: AuditSession,
    logger: ActivityLogger,
    opts: FailAgentOpts,
  ): Promise<Result<AgentEndResult, PentestError>> {
    await rollbackGitWorkspace(deliverablesPath, opts.rollbackReason, logger);

    const errorMessage = auditSession.redactText(opts.errorMessage);
    const context = auditSession.redactValue(opts.context);

    const endResult: AgentEndResult = {
      attemptNumber: opts.attemptNumber,
      duration_ms: opts.result.duration,
      ...piUsageResult(opts.result),
      success: false,
      model: opts.result.model,
      error: errorMessage,
    };
    await auditSession.endAgent(agentName, endResult);

    return err(new PentestError(errorMessage, opts.category, opts.retryable, context, opts.errorCode));
  }

  /**
   * Execute an agent, throwing PentestError on failure.
   *
   * This is the preferred method for Temporal activities, which need to
   * catch errors and classify them into ApplicationFailure. Avoids requiring
   * activities to import Result utilities, keeping the boundary clean.
   *
   * @param agentName - Name of the agent to execute
   * @param input - Execution input parameters
   * @param auditSession - Audit session for this specific agent execution
   * @returns AgentEndResult on success
   * @throws PentestError on failure
   */
  async executeOrThrow(
    agentName: AgentName,
    input: AgentExecutionInput,
    auditSession: AuditSession,
    logger: ActivityLogger,
  ): Promise<AgentEndResult> {
    const result = await this.execute(agentName, input, auditSession, logger);
    if (isErr(result)) {
      throw result.error;
    }
    return result.value;
  }
}
