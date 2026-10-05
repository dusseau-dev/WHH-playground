// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Temporal activities for Shannon agent execution.
 *
 * Each activity wraps service calls with Temporal-specific concerns:
 * - Heartbeat loop (2s interval) to signal worker liveness
 * - Error classification into ApplicationFailure
 * - Container lifecycle management
 *
 * Business logic is delegated to services in src/services/.
 */

import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { ApplicationFailure, Context, heartbeat } from '@temporalio/activity';
import { syncPermissionSystemConfig } from '../ai/pi/permission-system.js';
import { writePlaywrightStealthConfig } from '../ai/playwright-config-writer.js';
import { AuditSession } from '../audit/index.js';
import type { ResumeAttempt } from '../audit/metrics-tracker.js';
import { authStateFile, generateSessionJsonPath, type SessionMetadata } from '../audit/utils.js';
import type { WorkflowSummary } from '../audit/workflow-logger.js';
import type { CheckpointContext } from '../interfaces/checkpoint-provider.js';
import { DEFAULT_DELIVERABLES_SUBDIR, deliverablesDir, resolveSessionJsonPath } from '../paths.js';
import { loadAssessmentModuleResults, runAssessmentModules } from '../services/assessment-module-runner.js';
import { getContainer, getOrCreateContainer, removeContainer } from '../services/container.js';
import {
  type DetectionValidationResult,
  loadDetectionValidationResult,
  runDetectionValidation,
} from '../services/detection-validation-runner.js';
import { classifyErrorForTemporal, PentestError } from '../services/error-handling.js';
import { ExploitationCheckerService } from '../services/exploitation-checker.js';
import { renderFindingsFromQueues } from '../services/findings-renderer.js';
import { executeGitCommandWithRetry } from '../services/git-manager.js';
import { readHttpLoadResult, runHttpLoadCapacity } from '../services/http-load-runner.js';
import { runPreflightChecks } from '../services/preflight.js';
import type { ExploitationDecision, VulnType } from '../services/queue-validation.js';
import {
  collectConfiguredSecrets,
  collectRuntimeProviderSecrets,
  createExactValueRedactor,
} from '../services/redaction.js';
import { assembleFinalReport, injectAssessmentModeSections, injectModelIntoReport } from '../services/reporting.js';
import {
  createStructuredReportSession,
  synchronizeDetectionValidationReportFiles,
  synchronizeHttpLoadReportFiles,
} from '../services/structured-report.js';
import { validateAuthentication } from '../services/validate-authentication.js';
import { AGENTS } from '../session-manager.js';
import type { AgentName } from '../types/agents.js';
import { ALL_AGENTS } from '../types/agents.js';
import type { AgentEndResult } from '../types/audit.js';
import {
  ALL_VULN_CLASSES,
  type ContainerConfig,
  type DistributedConfig,
  type ProviderConfig,
  type SourceMode,
  type VulnClass,
} from '../types/config.js';
import type { DetectionValidationSettings } from '../types/detection-validation.js';
import { ErrorCode } from '../types/errors.js';
import { HTTP_LOAD_SCOPE, type HttpLoadResult, type HttpLoadSettings } from '../types/http-load.js';
import { isErr } from '../types/result.js';
import {
  type AssessmentModule,
  type AssessmentScope,
  type AssessmentSurface,
  type ModuleExecutionResult,
  type ModuleSafetyConfig,
  normalizeAssessmentModules,
  normalizeAssessmentScope,
} from '../types/scopes.js';
import { atomicWrite, fileExists, readJson } from '../utils/file-io.js';
import { redactLogText } from '../utils/redactSecrets.js';
import { createActivityLogger } from './activity-logger.js';
import { clearPipelineCredentials, resolvePipelineCredentials } from './pipeline-secrets.js';
import type { AgentMetrics, PipelineState, ResumeState } from './shared.js';

// Max lengths to prevent Temporal protobuf buffer overflow
const MAX_ERROR_MESSAGE_LENGTH = 2000;
const MAX_STACK_TRACE_LENGTH = 1000;

// Max retries for output validation errors (agent didn't save deliverables)
const MAX_OUTPUT_VALIDATION_RETRIES = 3;

const HEARTBEAT_INTERVAL_MS = 2000;

/** Preserve Temporal cancellation instead of classifying it as an activity failure. */
export function rethrowActivityCancellation(signal: AbortSignal): void {
  if (signal.aborted) signal.throwIfAborted();
}

/**
 * Input for all agent activities.
 *
 * Config fields are optional with sensible defaults. When provided, they
 * flow through to getOrCreateContainer() for path and credential configuration.
 */
export interface ActivityInput {
  webUrl: string;
  workingDirectory: string;
  sourceMode: SourceMode;
  repoPath?: string;
  configPath?: string;
  outputPath?: string;
  pipelineTestingMode?: boolean;
  workflowId: string;
  sessionId: string;

  // Config fields — serializable, read by getOrCreateContainer()
  configYAML?: string;
  configData?: DistributedConfig;
  apiKey?: string;
  deliverablesSubdir?: string;
  auditDir?: string;
  promptDir?: string;
  sastSarifPath?: string;
  skipGitCheck?: boolean;
  providerConfig?: ProviderConfig;
  /** Opaque reference to provider credentials staged outside Temporal. */
  secretRef?: string;
  /** Exact vulnerability classes selected by the workflow for this run. */
  vulnClasses?: VulnClass[];
  /** Exact granular checks selected by the workflow for this run. */
  testScopes?: AssessmentScope[];
  /** Exact interaction surfaces selected by the workflow for this run. */
  testSurfaces?: AssessmentSurface[];
  /** Exact assessment methods/modules selected by the workflow for this run. */
  assessmentModules?: AssessmentModule[];
  /** Normalized fail-closed module safety policy. */
  moduleSafety?: ModuleSafetyConfig;
  /** Normalized single-host HTTP load parameters. */
  httpLoad?: HttpLoadSettings;
  /** Ephemeral ownership or written-authorization acknowledgement. */
  httpLoadAuthorizationConfirmed?: boolean;
  /** Ephemeral acknowledgement for settings above elevated thresholds. */
  elevatedLoadConfirmed?: boolean;
  /** Normalized staging-only detection validation parameters. */
  detectionValidation?: DetectionValidationSettings;
  /** Ephemeral ownership or written-authorization acknowledgement. */
  detectionValidationAuthorizationConfirmed?: boolean;
}

interface AgentActivityExtensions {
  readonly callerTools?: import('@earendil-works/pi-coding-agent').ToolDefinition[];
  readonly postExecutionFinalizer?: import('../services/agent-execution.js').AgentExecutionInput['postExecutionFinalizer'];
}

/** Map the aggregate returned by Pi into the workflow's activity metric contract. */
export function toAgentMetrics(result: AgentEndResult, durationMs: number): AgentMetrics {
  return {
    durationMs,
    inputTokens: result.input_tokens ?? null,
    outputTokens: result.output_tokens ?? null,
    cacheReadTokens: result.cache_read_tokens ?? null,
    cacheWriteTokens: result.cache_write_tokens ?? null,
    costUsd: result.cost_usd,
    numTurns: result.num_turns ?? null,
    ...(result.model !== undefined && { model: result.model }),
  };
}

/**
 * Truncate error message to prevent buffer overflow in Temporal serialization.
 */
function truncateErrorMessage(message: string): string {
  if (message.length <= MAX_ERROR_MESSAGE_LENGTH) {
    return message;
  }
  return `${message.slice(0, MAX_ERROR_MESSAGE_LENGTH - 20)}\n[truncated]`;
}

/**
 * Truncate stack trace on an ApplicationFailure to prevent buffer overflow.
 */
function truncateStackTrace(failure: ApplicationFailure): void {
  if (failure.stack && failure.stack.length > MAX_STACK_TRACE_LENGTH) {
    failure.stack = `${failure.stack.slice(0, MAX_STACK_TRACE_LENGTH)}\n[stack truncated]`;
  }
}

/**
 * Build SessionMetadata from ActivityInput.
 */
function buildSessionMetadata(input: ActivityInput): SessionMetadata {
  const { webUrl, sourceMode, repoPath, outputPath, sessionId } = input;
  return {
    id: sessionId,
    webUrl,
    sourceMode,
    ...(repoPath !== undefined && { repoPath }),
    ...(outputPath && { outputPath }),
  };
}

/**
 * Build ContainerConfig from ActivityInput, falling back to defaults.
 */
function buildContainerConfig(input: ActivityInput): ContainerConfig {
  return {
    deliverablesSubdir: input.deliverablesSubdir ?? DEFAULT_DELIVERABLES_SUBDIR,
    auditDir: input.auditDir ?? './workspaces',
    ...(input.apiKey !== undefined && { apiKey: input.apiKey }),
    ...(input.promptDir !== undefined && { promptDir: input.promptDir }),
    ...(input.providerConfig !== undefined && { providerConfig: input.providerConfig }),
  };
}

async function hydratePipelineCredentials(input: ActivityInput): Promise<ActivityInput> {
  const credentials = await resolvePipelineCredentials(input);
  return {
    ...input,
    ...(credentials.apiKey !== undefined && { apiKey: credentials.apiKey }),
    ...(credentials.providerConfig !== undefined && { providerConfig: credentials.providerConfig }),
    ...(credentials.configYAML !== undefined && { configYAML: credentials.configYAML }),
    ...(credentials.configData !== undefined && { configData: credentials.configData }),
  };
}

/**
 * Core activity implementation using services.
 *
 * Executes a single agent with:
 * 1. Heartbeat loop for worker liveness
 * 2. Container creation/reuse
 * 3. Service-based agent execution
 * 4. Error classification for Temporal retry
 */
async function runAgentActivity(
  agentName: AgentName,
  rawInput: ActivityInput,
  extensions: AgentActivityExtensions = {},
): Promise<AgentMetrics> {
  const input = await hydratePipelineCredentials(rawInput);
  const { workingDirectory, sourceMode, repoPath, configPath, pipelineTestingMode = false, workflowId, webUrl } = input;
  const activityRedactor = createExactValueRedactor([
    ...collectConfiguredSecrets(input.configData, input.providerConfig, input.apiKey),
    ...collectRuntimeProviderSecrets(),
  ]);

  // Skip guard: the checkpoint provider decides whether to run the agent.
  // The default NoOp provider always returns { skip: false }.
  const skipContainer =
    getContainer(workflowId) ??
    getOrCreateContainer(workflowId, buildSessionMetadata(input), buildContainerConfig(input));
  const decision = await skipContainer.checkpointProvider.shouldSkipAgent(
    agentName,
    workingDirectory,
    input.deliverablesSubdir ?? DEFAULT_DELIVERABLES_SUBDIR,
  );
  if (decision.skip && decision.metrics) {
    return decision.metrics;
  }

  const startTime = Date.now();
  const attemptNumber = Context.current().info.attempt;

  // Heartbeat loop - signals worker is alive to Temporal server
  const heartbeatInterval = setInterval(() => {
    const elapsed = Math.floor((Date.now() - startTime) / 1000);
    heartbeat({ agent: agentName, elapsedSeconds: elapsed, attempt: attemptNumber });
  }, HEARTBEAT_INTERVAL_MS);

  try {
    const logger = createActivityLogger();

    // 1. Build session metadata and get/create container
    const sessionMetadata = buildSessionMetadata(input);
    const container = getOrCreateContainer(workflowId, sessionMetadata, buildContainerConfig(input));

    // 2. Create audit session for THIS agent execution
    // NOTE: Each agent needs its own AuditSession because AuditSession uses
    // instance state (currentAgentName) that cannot be shared across parallel agents
    const auditSession = new AuditSession(sessionMetadata);
    await auditSession.initialize(workflowId);

    // 3. Execute agent via service (throws PentestError on failure)
    const deliverablesPath = deliverablesDir(workingDirectory, container.config.deliverablesSubdir);
    const endResult = await container.agentExecution.executeOrThrow(
      agentName,
      {
        webUrl,
        workingDirectory,
        sourceMode,
        ...(repoPath !== undefined && { repoPath }),
        deliverablesPath,
        configPath,
        pipelineTestingMode,
        attemptNumber,
        ...(input.apiKey !== undefined && { apiKey: input.apiKey }),
        ...(input.providerConfig !== undefined && { providerConfig: input.providerConfig }),
        ...(input.promptDir !== undefined && { promptDir: input.promptDir }),
        ...(input.configYAML !== undefined && { configYAML: input.configYAML }),
        ...(input.configData !== undefined && { configData: input.configData }),
        ...(input.testScopes !== undefined && { testScopes: input.testScopes }),
        ...(input.testSurfaces !== undefined && { testSurfaces: input.testSurfaces }),
        ...(extensions.callerTools !== undefined && { callerTools: extensions.callerTools }),
        ...(extensions.postExecutionFinalizer !== undefined && {
          postExecutionFinalizer: extensions.postExecutionFinalizer,
        }),
        cancellationSignal: Context.current().cancellationSignal,
      },
      auditSession,
      logger,
    );

    // 4. Return metrics
    return toAgentMetrics(endResult, Date.now() - startTime);
  } catch (error) {
    rethrowActivityCancellation(Context.current().cancellationSignal);
    // If error is already an ApplicationFailure, re-throw directly
    if (error instanceof ApplicationFailure) {
      throw error;
    }

    // Check if output validation retry limit reached (PentestError with code)
    if (
      error instanceof PentestError &&
      error.code === ErrorCode.OUTPUT_VALIDATION_FAILED &&
      attemptNumber >= MAX_OUTPUT_VALIDATION_RETRIES
    ) {
      throw ApplicationFailure.nonRetryable(
        `Agent ${agentName} failed output validation after ${attemptNumber} attempts`,
        'OutputValidationError',
        [{ agentName, attemptNumber, elapsed: Date.now() - startTime }],
      );
    }

    // Classify error for Temporal retry behavior
    const classified = classifyErrorForTemporal(error);
    const rawMessage = activityRedactor.redactText(error instanceof Error ? error.message : String(error));
    const message = truncateErrorMessage(rawMessage);

    if (classified.retryable) {
      const failure = ApplicationFailure.create({
        message,
        type: classified.type,
        details: [{ agentName, attemptNumber, elapsed: Date.now() - startTime }],
      });
      truncateStackTrace(failure);
      throw failure;
    } else {
      const failure = ApplicationFailure.nonRetryable(message, classified.type, [
        { agentName, attemptNumber, elapsed: Date.now() - startTime },
      ]);
      truncateStackTrace(failure);
      throw failure;
    }
  } finally {
    clearInterval(heartbeatInterval);
  }
}

export async function runPreReconAgent(input: ActivityInput): Promise<AgentMetrics> {
  return runAgentActivity('pre-recon', input);
}

export async function runReconAgent(input: ActivityInput): Promise<AgentMetrics> {
  return runAgentActivity('recon', input);
}

export async function runInjectionVulnAgent(input: ActivityInput): Promise<AgentMetrics> {
  return runAgentActivity('injection-vuln', input);
}

export async function runXssVulnAgent(input: ActivityInput): Promise<AgentMetrics> {
  return runAgentActivity('xss-vuln', input);
}

export async function runAuthVulnAgent(input: ActivityInput): Promise<AgentMetrics> {
  return runAgentActivity('auth-vuln', input);
}

export async function runSsrfVulnAgent(input: ActivityInput): Promise<AgentMetrics> {
  return runAgentActivity('ssrf-vuln', input);
}

export async function runAuthzVulnAgent(input: ActivityInput): Promise<AgentMetrics> {
  return runAgentActivity('authz-vuln', input);
}

export async function runInjectionExploitAgent(input: ActivityInput): Promise<AgentMetrics> {
  return runAgentActivity('injection-exploit', input);
}

export async function runXssExploitAgent(input: ActivityInput): Promise<AgentMetrics> {
  return runAgentActivity('xss-exploit', input);
}

export async function runAuthExploitAgent(input: ActivityInput): Promise<AgentMetrics> {
  return runAgentActivity('auth-exploit', input);
}

export async function runSsrfExploitAgent(input: ActivityInput): Promise<AgentMetrics> {
  return runAgentActivity('ssrf-exploit', input);
}

export async function runAuthzExploitAgent(input: ActivityInput): Promise<AgentMetrics> {
  return runAgentActivity('authz-exploit', input);
}

export async function runReportAgent(
  input: ActivityInput,
  safeDemonstration: boolean,
  triageRan: boolean,
): Promise<AgentMetrics> {
  const httpLoadResult = input.httpLoad ? await readHttpLoadResult(input.workingDirectory) : undefined;
  const detectionValidationResult = input.detectionValidation
    ? await loadDetectionValidationResult(deliverablesDir(input.workingDirectory, input.deliverablesSubdir))
    : undefined;
  const reportSession = await createStructuredReportSession({
    deliverablesPath: deliverablesDir(input.workingDirectory, input.deliverablesSubdir),
    webUrl: input.webUrl,
    sourceMode: input.sourceMode,
    safeDemonstration,
    triageRan,
    selectedVulnClasses: input.vulnClasses ?? input.configData?.vuln_classes ?? ALL_VULN_CLASSES,
    ...(input.testScopes && { selectedTestScopes: input.testScopes }),
    ...(input.assessmentModules && { selectedAssessmentModules: input.assessmentModules }),
    ...(httpLoadResult && { httpLoadResult }),
    ...(detectionValidationResult && { detectionValidationResult }),
  });
  return runAgentActivity('report', input, {
    callerTools: reportSession.tools,
    postExecutionFinalizer: async ({ logger }) => {
      await reportSession.finalize(logger);
    },
  });
}

export async function runTriageAgent(input: ActivityInput): Promise<AgentMetrics> {
  return runAgentActivity('triage', input);
}

interface BrowserStorageState {
  readonly cookies?: ReadonlyArray<{
    readonly name?: unknown;
    readonly value?: unknown;
    readonly domain?: unknown;
    readonly path?: unknown;
    readonly expires?: unknown;
  }>;
}

async function authenticatedCookieHeader(input: ActivityInput): Promise<string | undefined> {
  const statePath = authStateFile(buildSessionMetadata(input));
  if (!(await fileExists(statePath))) return;
  try {
    const state = await readJson<BrowserStorageState>(statePath);
    const target = new URL(input.webUrl);
    const nowSeconds = Date.now() / 1_000;
    const cookies = (state.cookies ?? []).filter((cookie) => {
      if (typeof cookie.name !== 'string' || typeof cookie.value !== 'string' || typeof cookie.domain !== 'string') {
        return false;
      }
      const domain = cookie.domain.replace(/^\./, '').toLowerCase();
      if (target.hostname !== domain && !target.hostname.endsWith(`.${domain}`)) return false;
      if (typeof cookie.path === 'string' && !target.pathname.startsWith(cookie.path)) return false;
      return typeof cookie.expires !== 'number' || cookie.expires < 0 || cookie.expires > nowSeconds;
    });
    return cookies.length > 0
      ? cookies.map((cookie) => `${cookie.name as string}=${cookie.value as string}`).join('; ')
      : undefined;
  } catch {
    return;
  }
}

/** Run non-agent assessment methods and return only evidence-backed statuses. */
export async function runAssessmentModulesActivity(rawInput: ActivityInput): Promise<ModuleExecutionResult[]> {
  const input = await hydratePipelineCredentials(rawInput);
  const normalized = normalizeAssessmentModules({
    ...(input.assessmentModules && { assessmentModules: input.assessmentModules }),
    ...(input.moduleSafety && { moduleSafety: input.moduleSafety }),
    sourceMode: input.sourceMode,
  });
  const startedAt = Date.now();
  const heartbeatInterval = setInterval(() => {
    heartbeat({ phase: 'assessment-modules', elapsedSeconds: Math.floor((Date.now() - startedAt) / 1_000) });
  }, HEARTBEAT_INTERVAL_MS);
  try {
    const authenticationCookie = await authenticatedCookieHeader(input);
    return await runAssessmentModules({
      webUrl: input.webUrl,
      workingDirectory: input.workingDirectory,
      deliverablesPath: deliverablesDir(input.workingDirectory, input.deliverablesSubdir),
      sourceMode: input.sourceMode,
      assessmentModules: normalized.assessmentModules,
      moduleSafety: normalized.moduleSafety,
      ...(authenticationCookie && { authenticationCookie }),
    });
  } finally {
    clearInterval(heartbeatInterval);
  }
}

/** Read prior module evidence without executing scanners or generating target traffic. */
export async function loadAssessmentModuleResultsActivity(input: ActivityInput): Promise<ModuleExecutionResult[]> {
  return loadAssessmentModuleResults(deliverablesDir(input.workingDirectory, input.deliverablesSubdir));
}

/** Execute the fixed, inert detection-validation corpus without failing the workflow on a threshold miss. */
export async function runDetectionValidationActivity(rawInput: ActivityInput): Promise<DetectionValidationResult> {
  if (!rawInput.detectionValidation || rawInput.detectionValidationAuthorizationConfirmed !== true) {
    throw ApplicationFailure.nonRetryable(
      'Detection validation requires normalized settings and authorization confirmation',
      'DetectionValidationConfigurationError',
    );
  }
  const input = await hydratePipelineCredentials(rawInput);
  const container = getOrCreateContainer(input.workflowId, buildSessionMetadata(input), buildContainerConfig(input));
  const configResult = await container.configLoader.loadOptional(
    input.configPath,
    input.configData,
    input.configYAML,
    input.sourceMode,
  );
  if (isErr(configResult)) {
    throw ApplicationFailure.nonRetryable(configResult.error.message, 'DetectionValidationConfigurationError');
  }
  const splunkToken = configResult.value?.detection_validation?.splunk.token;
  if (!splunkToken) {
    throw ApplicationFailure.nonRetryable(
      'Detection validation requires a Splunk token in the protected run configuration',
      'DetectionValidationConfigurationError',
    );
  }

  const startedAt = Date.now();
  const heartbeatInterval = setInterval(() => {
    heartbeat({ phase: 'detection-validation', elapsedSeconds: Math.floor((Date.now() - startedAt) / 1_000) });
  }, HEARTBEAT_INTERVAL_MS);
  try {
    return await runDetectionValidation({
      webUrl: input.webUrl,
      workflowId: input.workflowId,
      deliverablesPath: deliverablesDir(input.workingDirectory, input.deliverablesSubdir),
      settings: rawInput.detectionValidation,
      splunkToken,
      signal: Context.current().cancellationSignal,
    });
  } finally {
    clearInterval(heartbeatInterval);
  }
}

/** Read prior evidence without re-emitting calibration or scenario traffic. */
export async function loadDetectionValidationResultActivity(
  input: ActivityInput,
): Promise<DetectionValidationResult | null> {
  return loadDetectionValidationResult(deliverablesDir(input.workingDirectory, input.deliverablesSubdir));
}

/** Execute the explicitly authorized, single-host HTTP load assessment once. */
export async function runHttpLoadCapacityActivity(input: ActivityInput): Promise<HttpLoadResult> {
  if (!input.httpLoad) {
    throw ApplicationFailure.nonRetryable(
      'HTTP load activity requires normalized settings',
      'HttpLoadConfigurationError',
    );
  }

  const startedAt = Date.now();
  const heartbeatInterval = setInterval(() => {
    heartbeat({ phase: 'http-load-capacity', elapsedSeconds: Math.floor((Date.now() - startedAt) / 1_000) });
  }, HEARTBEAT_INTERVAL_MS);
  const logger = createActivityLogger();
  try {
    return await runHttpLoadCapacity({
      webUrl: input.webUrl,
      workingDirectory: input.workingDirectory,
      settings: input.httpLoad,
      authorizationConfirmed: input.httpLoadAuthorizationConfirmed === true,
      elevatedLoadConfirmed: input.elevatedLoadConfirmed === true,
      signal: Context.current().cancellationSignal,
      logger,
    });
  } catch (error) {
    rethrowActivityCancellation(Context.current().cancellationSignal);
    const message = redactLogText(error);
    logger.error('HTTP load assessment failed', { message });
    throw ApplicationFailure.nonRetryable(
      `HTTP load assessment failed: ${truncateErrorMessage(message)}`,
      'HttpLoadExecutionError',
    );
  } finally {
    clearInterval(heartbeatInterval);
  }
}

/**
 * Create the writable root used by URL-only runs.
 *
 * Source-assisted runs must point at a real repository supplied by the caller,
 * so this intentionally does not create missing directories in that mode.
 */
export async function prepareWorkingDirectory(input: ActivityInput): Promise<void> {
  if (input.sourceMode !== 'url-only') return;

  try {
    await fs.mkdir(input.workingDirectory, { recursive: true });
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw ApplicationFailure.nonRetryable(
      `Failed to create URL-only working directory ${input.workingDirectory}: ${detail}`,
      'ConfigurationError',
      [{ workingDirectory: input.workingDirectory }],
    );
  }
}

/**
 * Preflight validation activity.
 *
 * Runs cheap checks before any agent execution:
 * 1. Repository path exists with .git
 * 2. Config file validates (if provided)
 * 3. Credential validation for the selected Pi provider
 * 4. Target URL reachable from the container
 *
 * NOT using runAgentActivity — preflight doesn't run a Pi agent.
 */
export async function runPreflightValidation(rawInput: ActivityInput): Promise<void> {
  const input = await hydratePipelineCredentials(rawInput);
  const startTime = Date.now();
  const attemptNumber = Context.current().info.attempt;
  let redactor = createExactValueRedactor([
    ...collectConfiguredSecrets(input.configData, input.providerConfig, input.apiKey),
    ...collectRuntimeProviderSecrets(),
  ]);

  const heartbeatInterval = setInterval(() => {
    const elapsed = Math.floor((Date.now() - startTime) / 1000);
    heartbeat({ phase: 'preflight', elapsedSeconds: elapsed, attempt: attemptNumber });
  }, HEARTBEAT_INTERVAL_MS);

  try {
    const logger = createActivityLogger();
    logger.info('Running preflight validation...', { attempt: attemptNumber });

    const container = getOrCreateContainer(input.workflowId, buildSessionMetadata(input), buildContainerConfig(input));
    const configResult = await container.configLoader.loadOptional(
      input.configPath,
      input.configData,
      input.configYAML,
      input.sourceMode,
    );
    if (!isErr(configResult)) {
      redactor = createExactValueRedactor([
        ...collectConfiguredSecrets(configResult.value, input.providerConfig, input.apiKey),
        ...collectRuntimeProviderSecrets(),
      ]);
    }

    const result = await runPreflightChecks(
      input.webUrl,
      input.workingDirectory,
      input.repoPath,
      input.sourceMode,
      input.configPath,
      logger,
      input.skipGitCheck,
      input.apiKey,
      input.providerConfig,
      input.configYAML,
      input.configData,
      Context.current().cancellationSignal,
    );

    if (isErr(result)) {
      const classified = classifyErrorForTemporal(result.error);
      const message = truncateErrorMessage(redactor.redactText(result.error.message));

      if (classified.retryable) {
        const failure = ApplicationFailure.create({
          message,
          type: classified.type,
          details: [{ phase: 'preflight', attemptNumber, elapsed: Date.now() - startTime }],
        });
        truncateStackTrace(failure);
        throw failure;
      } else {
        const failure = ApplicationFailure.nonRetryable(message, classified.type, [
          { phase: 'preflight', attemptNumber, elapsed: Date.now() - startTime },
        ]);
        truncateStackTrace(failure);
        throw failure;
      }
    }

    logger.info('Preflight validation passed');
  } catch (error) {
    rethrowActivityCancellation(Context.current().cancellationSignal);
    if (error instanceof ApplicationFailure) {
      throw error;
    }

    const classified = classifyErrorForTemporal(error);
    const rawMessage = redactor.redactText(error instanceof Error ? error.message : String(error));
    const message = truncateErrorMessage(rawMessage);

    const failure = ApplicationFailure.nonRetryable(message, classified.type, [
      { phase: 'preflight', attemptNumber, elapsed: Date.now() - startTime },
    ]);
    truncateStackTrace(failure);
    throw failure;
  } finally {
    clearInterval(heartbeatInterval);
  }
}

/**
 * Authentication validation activity. No-ops without an authentication
 * block; otherwise surfaces a classified failure (failurePoint +
 * failureDetail in ApplicationFailure.details) on credential rejection.
 */
export async function runAuthenticationValidation(rawInput: ActivityInput): Promise<void> {
  const input = await hydratePipelineCredentials(rawInput);
  const startTime = Date.now();
  const attemptNumber = Context.current().info.attempt;
  let redactor = createExactValueRedactor([
    ...collectConfiguredSecrets(input.configData, input.providerConfig, input.apiKey),
    ...collectRuntimeProviderSecrets(),
  ]);

  const heartbeatInterval = setInterval(() => {
    const elapsed = Math.floor((Date.now() - startTime) / 1000);
    heartbeat({ phase: 'auth-validation', elapsedSeconds: elapsed, attempt: attemptNumber });
  }, HEARTBEAT_INTERVAL_MS);

  try {
    const logger = createActivityLogger();

    const sessionMetadata = buildSessionMetadata(input);
    const container = getOrCreateContainer(input.workflowId, sessionMetadata, buildContainerConfig(input));
    const configResult = await container.configLoader.loadOptional(
      input.configPath,
      input.configData,
      input.configYAML,
      input.sourceMode,
    );
    if (isErr(configResult)) {
      // runPreflightValidation already validated parsing, so this is unexpected.
      logger.warn(`runAuthenticationValidation: config load failed unexpectedly: ${configResult.error.message}`);
      return;
    }

    const distributedConfig = configResult.value;
    redactor = createExactValueRedactor([
      ...collectConfiguredSecrets(distributedConfig, input.providerConfig, input.apiKey),
      ...collectRuntimeProviderSecrets(),
    ]);
    if (!distributedConfig?.authentication) {
      logger.info('No authentication configured — skipping credential validation');
      return;
    }

    const auditSession = new AuditSession(sessionMetadata);
    auditSession.setRedactionSecrets(redactor.values);
    await auditSession.initialize(input.workflowId);

    const result = await validateAuthentication({
      distributedConfig,
      workingDirectory: input.workingDirectory,
      sourceMode: input.sourceMode,
      ...(input.repoPath !== undefined && { repoPath: input.repoPath }),
      webUrl: input.webUrl,
      logger,
      auditSession,
      attemptNumber,
      ...(input.apiKey !== undefined && { apiKey: input.apiKey }),
      ...(input.providerConfig !== undefined && { providerConfig: input.providerConfig }),
      ...(input.deliverablesSubdir !== undefined && { deliverablesSubdir: input.deliverablesSubdir }),
      ...(input.promptDir !== undefined && { promptDir: input.promptDir }),
      ...(input.pipelineTestingMode !== undefined && { pipelineTestingMode: input.pipelineTestingMode }),
      cancellationSignal: Context.current().cancellationSignal,
    });

    if (isErr(result)) {
      const classified = classifyErrorForTemporal(result.error);
      const message = truncateErrorMessage(redactor.redactText(result.error.message));
      const ctx = result.error.context;
      const details = [
        {
          phase: 'auth-validation',
          attemptNumber,
          elapsed: Date.now() - startTime,
          ...(ctx.failurePoint !== undefined && { failurePoint: ctx.failurePoint }),
          ...(ctx.failureDetail !== undefined && { failureDetail: redactor.redactValue(ctx.failureDetail) }),
        },
      ];

      const failure = classified.retryable
        ? ApplicationFailure.create({ message, type: classified.type, details })
        : ApplicationFailure.nonRetryable(message, classified.type, details);
      truncateStackTrace(failure);
      throw failure;
    }
  } catch (error) {
    rethrowActivityCancellation(Context.current().cancellationSignal);
    if (error instanceof ApplicationFailure) {
      throw error;
    }

    const classified = classifyErrorForTemporal(error);
    const rawMessage = redactor.redactText(error instanceof Error ? error.message : String(error));
    const message = truncateErrorMessage(rawMessage);
    const details = [{ phase: 'auth-validation', attemptNumber, elapsed: Date.now() - startTime }];

    const failure = classified.retryable
      ? ApplicationFailure.create({ message, type: classified.type, details })
      : ApplicationFailure.nonRetryable(message, classified.type, details);
    truncateStackTrace(failure);
    throw failure;
  } finally {
    clearInterval(heartbeatInterval);
  }
}

/**
 * Initialize a private git repository inside the workspace deliverables directory.
 * Idempotent — skips if .git already exists (resume case).
 */
export async function initDeliverableGit(input: ActivityInput): Promise<void> {
  const deliverablesPath = deliverablesDir(input.workingDirectory, input.deliverablesSubdir);
  await fs.mkdir(deliverablesPath, { recursive: true });

  // Check for .git directly inside deliverables, not parent repo's .git
  const dotGitPath = path.join(deliverablesPath, '.git');
  try {
    await fs.stat(dotGitPath);
    return;
  } catch {
    // .git doesn't exist, proceed with init
  }

  await executeGitCommandWithRetry(['git', 'init'], deliverablesPath, 'init deliverables repo');
  await executeGitCommandWithRetry(
    ['git', 'commit', '--allow-empty', '-m', '📍 Initial deliverables checkpoint'],
    deliverablesPath,
    'initial checkpoint',
  );
}

/**
 * Drop a stealth cli.config.json into the working directory's .playwright/ directory so
 * `playwright-cli open` auto-loads anti-detection defaults from the agent's
 * cwd (disables the Blink AutomationControlled flag, drops the
 * --enable-automation default, and overrides the HeadlessChrome user agent).
 *
 * No-op when the repo already has its own .playwright/cli.config.json.
 */
export async function syncPlaywrightStealthConfig(input: ActivityInput): Promise<void> {
  const logger = createActivityLogger();
  const { result, configPath } = await writePlaywrightStealthConfig(input.workingDirectory);
  if (result === 'skipped-existing') {
    logger.info(`Playwright stealth config: leaving existing ${configPath} in place`);
  } else {
    logger.info(`Playwright stealth config: wrote ${configPath}`);
  }
}

/**
 * Sync code_path avoid rules into the Pi permission extension config so the
 * runtime enforces them at the tool layer for every agent in this run.
 *
 * Runs once per workflow before any agent fires. Config is fixed for the
 * lifetime of the workflow, so writing once avoids a parallel-agent race on
 * the global extension config.
 */
export async function syncCodePathDenyRules(rawInput: ActivityInput): Promise<void> {
  const input = await hydratePipelineCredentials(rawInput);
  const logger = createActivityLogger();
  if (input.sourceMode === 'url-only') {
    logger.info('Skipping code_path deny-rule sync in URL-only mode');
    return;
  }
  const container = getOrCreateContainer(input.workflowId, buildSessionMetadata(input), buildContainerConfig(input));

  const configResult = await container.configLoader.loadOptional(
    input.configPath,
    input.configData,
    input.configYAML,
    input.sourceMode,
  );
  if (isErr(configResult)) {
    logger.warn(`syncCodePathDenyRules: skipping (config load failed: ${configResult.error.message})`);
    return;
  }

  const config = configResult.value;
  const denyCount = (config?.avoid ?? []).filter((r) => r.type === 'code_path').length;
  syncPermissionSystemConfig(config);
  logger.info(`Synced code_path deny rules to Pi permissions (${denyCount} entries)`);
}

/**
 * Assemble the final report by concatenating per-class deliverables.
 *
 * When safeDemonstration=true, each demonstration agent has produced
 * `*_exploitation_evidence.md` directly. Otherwise those agents did not run;
 * we deterministically render `*_findings.md` from each queue first.
 */
export async function assembleReportActivity(
  input: ActivityInput,
  safeDemonstration: boolean,
  triageRan: boolean,
): Promise<void> {
  const { workingDirectory, sourceMode, deliverablesSubdir } = input;
  const logger = createActivityLogger();

  if (!safeDemonstration) {
    logger.info('Rendering per-class findings from analysis queues...');
    try {
      await renderFindingsFromQueues(workingDirectory, deliverablesSubdir, logger, sourceMode);
    } catch (error) {
      const err = error as Error;
      logger.warn(`Error rendering findings from queues: ${err.message}`);
    }
  }

  logger.info('Assembling deliverables from specialist agents...');
  try {
    await assembleFinalReport(workingDirectory, deliverablesSubdir, logger, triageRan);
  } catch (error) {
    const err = error as Error;
    logger.warn(`Error assembling final report: ${err.message}`);
  }
}

/**
 * Inject model metadata into the final report.
 */
export async function injectReportMetadataActivity(input: ActivityInput): Promise<void> {
  const { workingDirectory, sessionId, outputPath, deliverablesSubdir } = input;
  const logger = createActivityLogger();
  const effectiveOutputPath = outputPath ? path.join(outputPath, sessionId) : path.join('./workspaces', sessionId);
  try {
    await injectModelIntoReport(workingDirectory, deliverablesSubdir, effectiveOutputPath, logger);
  } catch (error) {
    const err = error as Error;
    logger.warn(`Error injecting model into report: ${err.message}`);
  }
}

/** Deterministically disclose assessment mode and coverage after the report agent has finished. */
export async function injectReportModeSectionsActivity(input: ActivityInput): Promise<void> {
  const logger = createActivityLogger();
  try {
    if (input.httpLoad) {
      const result = await readHttpLoadResult(input.workingDirectory);
      if (result) {
        const synchronized = await synchronizeHttpLoadReportFiles(
          deliverablesDir(input.workingDirectory, input.deliverablesSubdir),
          input.testScopes ?? [HTTP_LOAD_SCOPE],
          result,
        );
        if (synchronized) logger.info('Synchronized HTTP load evidence into the canonical report');
      }
    }
    if (input.detectionValidation) {
      const result = await loadDetectionValidationResult(
        deliverablesDir(input.workingDirectory, input.deliverablesSubdir),
      );
      if (result) {
        const synchronized = await synchronizeDetectionValidationReportFiles(
          deliverablesDir(input.workingDirectory, input.deliverablesSubdir),
          input.testScopes ?? ['alerting-effectiveness'],
          result,
        );
        if (synchronized) logger.info('Synchronized detection-validation evidence into the canonical report');
      }
    }
    await injectAssessmentModeSections(input.workingDirectory, input.deliverablesSubdir, input.sourceMode, logger);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new PentestError(
      `Failed to inject assessment mode sections: ${detail}`,
      'filesystem',
      false,
      { phase: 'reporting' },
      ErrorCode.DELIVERABLE_NOT_FOUND,
    );
  }
}

/**
 * Check if exploitation should run for a given vulnerability type.
 *
 * Uses existing container if available (from prior agent runs),
 * otherwise creates service directly (stateless, no dependencies).
 */
export async function checkExploitationQueue(input: ActivityInput, vulnType: VulnType): Promise<ExploitationDecision> {
  const { workingDirectory, workflowId } = input;
  const logger = createActivityLogger();

  // Reuse container's service if available (from prior vuln agent runs)
  const existingContainer = getContainer(workflowId);
  const checker = existingContainer?.exploitationChecker ?? new ExploitationCheckerService();

  // Pass deliverablesPath (not workingDirectory) — validators expect the deliverables directory
  const delivPath = deliverablesDir(workingDirectory, input.deliverablesSubdir);
  return checker.checkQueue(vulnType, delivPath, logger);
}

interface RunScope {
  vulnClasses: VulnClass[];
  testScopes?: AssessmentScope[];
  testSurfaces?: AssessmentSurface[];
  safeDemonstration?: boolean;
  /** Normalized settings for the explicit HTTP load scope. */
  httpLoad?: HttpLoadSettings;
  /** @deprecated Legacy session scope field. */
  exploit?: boolean;
  sourceMode: SourceMode;
  configHash?: string;
}

interface SessionJson {
  session: {
    id: string;
    webUrl: string;
    sourceMode?: SourceMode;
    repoPath?: string;
    originalWorkflowId?: string;
    resumeAttempts?: ResumeAttempt[];
    scope?: RunScope;
  };
  metrics: {
    agents: Record<
      string,
      {
        status: 'in-progress' | 'success' | 'failed';
        checkpoint?: string;
      }
    >;
  };
}

/**
 * Load resume state from an existing workspace.
 */
export async function loadResumeState(
  workspaceName: string,
  expectedUrl: string,
  expectedWorkingDirectory: string,
  expectedSourceMode: SourceMode,
  expectedRepoPath?: string,
  deliverablesSubdir?: string,
): Promise<ResumeState> {
  // 1. Validate workspace exists
  const sessionPath = resolveSessionJsonPath(path.join('./workspaces', workspaceName));

  const exists = await fileExists(sessionPath);
  if (!exists) {
    throw ApplicationFailure.nonRetryable(
      `Workspace not found: ${workspaceName}\nExpected path: ${sessionPath}`,
      'WorkspaceNotFoundError',
    );
  }

  // 2. Parse session.json and validate URL match
  let session: SessionJson;
  try {
    session = await readJson<SessionJson>(sessionPath);
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    throw ApplicationFailure.nonRetryable(
      `Corrupted session.json in workspace ${workspaceName}: ${errorMsg}`,
      'CorruptedSessionError',
    );
  }

  if (session.session.webUrl !== expectedUrl) {
    throw ApplicationFailure.nonRetryable(
      `URL mismatch with workspace\n  Workspace URL: ${session.session.webUrl}\n  Provided URL:  ${expectedUrl}`,
      'URLMismatchError',
    );
  }

  const recordedSourceMode =
    session.session.scope?.sourceMode ??
    session.session.sourceMode ??
    (session.session.repoPath ? 'source-assisted' : 'url-only');
  if (recordedSourceMode !== expectedSourceMode) {
    throw ApplicationFailure.nonRetryable(
      `Source mode mismatch with workspace\n  Workspace mode: ${recordedSourceMode}\n  Provided mode:  ${expectedSourceMode}`,
      'ScopeMismatchError',
    );
  }
  if (expectedSourceMode === 'source-assisted' && session.session.repoPath !== expectedRepoPath) {
    throw ApplicationFailure.nonRetryable(
      `Repository mismatch with workspace\n  Workspace repository: ${session.session.repoPath ?? '<missing>'}\n  Provided repository:  ${expectedRepoPath ?? '<missing>'}`,
      'ScopeMismatchError',
    );
  }

  // 3. Cross-check agent status with deliverables on disk
  const completedAgents: string[] = [];
  const agents = session.metrics.agents;

  for (const agentName of ALL_AGENTS) {
    const agentData = agents[agentName];
    if (!agentData || agentData.status !== 'success') {
      continue;
    }

    const deliverableFilename = AGENTS[agentName].deliverableFilename;
    const deliverablePath = path.join(
      deliverablesDir(expectedWorkingDirectory, deliverablesSubdir),
      deliverableFilename,
    );
    const deliverableExists = await fileExists(deliverablePath);

    if (!deliverableExists) {
      const logger = createActivityLogger();
      logger.warn(`Agent ${agentName} shows success but deliverable missing, will re-run`);
      continue;
    }

    completedAgents.push(agentName);
  }

  // 4. Collect git checkpoints and validate at least one exists
  const checkpoints = completedAgents
    .map((name) => agents[name]?.checkpoint)
    .filter((hash): hash is string => hash != null);

  if (checkpoints.length === 0) {
    const successAgents = Object.entries(agents)
      .filter(([, data]) => data.status === 'success')
      .map(([name]) => name);

    throw ApplicationFailure.nonRetryable(
      `Cannot resume workspace ${workspaceName}: ` +
        (successAgents.length > 0
          ? `${successAgents.length} agent(s) show success in session.json (${successAgents.join(', ')}) ` +
            `but their deliverable files are missing from disk. ` +
            `Start a fresh run instead.`
          : `No agents completed successfully. Start a fresh run instead.`),
      'NoCheckpointsError',
    );
  }

  // 5. Find the most recent checkpoint commit
  const deliverablesPath = deliverablesDir(expectedWorkingDirectory, deliverablesSubdir);
  const checkpointHash = await findLatestCommit(deliverablesPath, checkpoints);
  const originalWorkflowId = session.session.originalWorkflowId || session.session.id;

  // 6. Log summary and return resume state
  const logger = createActivityLogger();
  logger.info('Resume state loaded', {
    workspace: workspaceName,
    completedAgents: completedAgents.length,
    checkpoint: checkpointHash,
  });

  return {
    workspaceName,
    originalUrl: session.session.webUrl,
    completedAgents,
    checkpointHash,
    originalWorkflowId,
  };
}

function sortJsonValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortJsonValue);
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, nested]) => [key, sortJsonValue(nested)]),
    );
  }
  return value;
}

function stableStringify(value: unknown): string {
  return JSON.stringify(sortJsonValue(value));
}

function nonSecretRunConfig(config: DistributedConfig | null): unknown {
  if (!config) return config;
  const authentication = config.authentication;
  const detectionValidation = config.detection_validation;
  const safeDetectionValidation = detectionValidation
    ? {
        ...detectionValidation,
        splunk: {
          ...detectionValidation.splunk,
          token: undefined,
        },
      }
    : undefined;
  if (!authentication) {
    return {
      ...config,
      ...(safeDetectionValidation && { detection_validation: safeDetectionValidation }),
    };
  }
  const {
    email_login: emailLogin,
    password: _password,
    totp_secret: _totpSecret,
    ...credentials
  } = authentication.credentials;
  return {
    ...config,
    ...(safeDetectionValidation && { detection_validation: safeDetectionValidation }),
    authentication: {
      ...authentication,
      credentials: {
        ...credentials,
        ...(emailLogin && { email_login: { address: emailLogin.address } }),
      },
    },
  };
}

interface RunConfigHashes {
  current: string;
  preGranular: string;
}

function hashRunConfig(value: unknown): string {
  return crypto.createHash('sha256').update(stableStringify(value)).digest('hex');
}

function withoutGranularScopeFields(value: unknown): unknown {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return value;
  const { test_scopes: _testScopes, test_surfaces: _testSurfaces, ...legacyConfig } = value as Record<string, unknown>;
  return legacyConfig;
}

async function computeRunConfigHashes(
  input: ActivityInput,
  sessionMetadata: SessionMetadata,
): Promise<RunConfigHashes> {
  const container = getOrCreateContainer(input.workflowId, sessionMetadata, buildContainerConfig(input));
  const configResult = await container.configLoader.loadOptional(
    input.configPath,
    input.configData,
    input.configYAML,
    input.sourceMode,
  );
  if (isErr(configResult)) {
    throw ApplicationFailure.nonRetryable(configResult.error.message, 'ConfigurationError', [
      { phase: 'scope-validation' },
    ]);
  }
  const normalizedConfig = nonSecretRunConfig(configResult.value);
  const currentProjection = input.httpLoad ? { config: normalizedConfig, httpLoad: input.httpLoad } : normalizedConfig;
  return {
    current: hashRunConfig(currentProjection),
    preGranular: hashRunConfig(withoutGranularScopeFields(normalizedConfig)),
  };
}

/** First run records scope into session.json; resume runs throw if it differs. */
export async function persistOrValidateRunScope(
  rawInput: ActivityInput,
  vulnClasses: VulnClass[],
  safeDemonstration: boolean,
): Promise<void> {
  const input = await hydratePipelineCredentials(rawInput);
  const currentScope = normalizeAssessmentScope({
    ...(input.testScopes && { testScopes: input.testScopes }),
    ...(input.testSurfaces && { testSurfaces: input.testSurfaces }),
    vulnClasses,
  });
  const sessionMetadata = buildSessionMetadata(input);
  const configHashes = await computeRunConfigHashes(input, sessionMetadata);
  const configHash = configHashes.current;
  const auditSession = new AuditSession(sessionMetadata);
  await auditSession.initialize(input.workflowId);

  const sessionPath = generateSessionJsonPath(sessionMetadata);
  const session = await readJson<SessionJson>(sessionPath);

  if (session.session.webUrl !== input.webUrl) {
    throw ApplicationFailure.nonRetryable(
      `URL mismatch with workspace\n  Workspace URL: ${session.session.webUrl}\n  Provided URL:  ${input.webUrl}`,
      'URLMismatchError',
    );
  }
  if (input.sourceMode === 'source-assisted' && session.session.repoPath !== input.repoPath) {
    throw ApplicationFailure.nonRetryable(
      `Repository mismatch with workspace\n  Workspace repository: ${session.session.repoPath ?? '<missing>'}\n  Provided repository:  ${input.repoPath ?? '<missing>'}`,
      'ScopeMismatchError',
    );
  }

  if (session.session.scope) {
    const recorded = session.session.scope;
    const recordedScope = normalizeAssessmentScope({
      ...(recorded.testScopes && { testScopes: recorded.testScopes }),
      ...(recorded.testSurfaces && { testSurfaces: recorded.testSurfaces }),
      vulnClasses: recorded.vulnClasses,
    });
    const recordedSafeDemonstration = recorded.safeDemonstration ?? recorded.exploit ?? true;
    const loadSelected = currentScope.testScopes.includes('http-load-capacity');
    const sameHttpLoad = loadSelected
      ? recorded.httpLoad !== undefined &&
        input.httpLoad !== undefined &&
        recorded.httpLoad.concurrency === input.httpLoad.concurrency &&
        recorded.httpLoad.requestsPerSecond === input.httpLoad.requestsPerSecond &&
        recorded.httpLoad.durationSeconds === input.httpLoad.durationSeconds
      : recorded.httpLoad === undefined && input.httpLoad === undefined;
    const sameClasses =
      recordedScope.vulnClasses.length === currentScope.vulnClasses.length &&
      recordedScope.vulnClasses.every((value) => currentScope.vulnClasses.includes(value));
    const sameTestScopes =
      recordedScope.testScopes.length === currentScope.testScopes.length &&
      recordedScope.testScopes.every((value) => currentScope.testScopes.includes(value));
    const sameTestSurfaces =
      recordedScope.testSurfaces.length === currentScope.testSurfaces.length &&
      recordedScope.testSurfaces.every((value) => currentScope.testSurfaces.includes(value));

    const recordedSourceMode = recorded.sourceMode ?? (session.session.repoPath ? 'source-assisted' : 'url-only');
    const preGranularSession = recorded.testScopes === undefined && recorded.testSurfaces === undefined;
    const sameConfig =
      !recorded.configHash ||
      recorded.configHash === configHash ||
      (preGranularSession && recorded.configHash === configHashes.preGranular);
    if (
      !sameClasses ||
      !sameTestScopes ||
      !sameTestSurfaces ||
      !sameHttpLoad ||
      recordedSafeDemonstration !== safeDemonstration ||
      recordedSourceMode !== input.sourceMode ||
      !sameConfig
    ) {
      throw ApplicationFailure.nonRetryable(
        `Resume scope mismatch for workspace ${input.sessionId}.\n` +
          `  Original: source_mode=${recordedSourceMode}, vuln_classes=[${recordedScope.vulnClasses.join(', ')}], test_scopes=[${recordedScope.testScopes.join(', ')}], test_surfaces=[${recordedScope.testSurfaces.join(', ')}], http_load=${recorded.httpLoad ? stableStringify(recorded.httpLoad) : '<none>'}, safe_demonstration=${recordedSafeDemonstration}, config_hash=${recorded.configHash ?? '<missing>'}\n` +
          `  Provided: source_mode=${input.sourceMode}, vuln_classes=[${currentScope.vulnClasses.join(', ')}], test_scopes=[${currentScope.testScopes.join(', ')}], test_surfaces=[${currentScope.testSurfaces.join(', ')}], http_load=${input.httpLoad ? stableStringify(input.httpLoad) : '<none>'}, safe_demonstration=${safeDemonstration}, config_hash=${configHash}\n` +
          `Resume requires the same scope as the original run. Start a new workspace if you want different scope.`,
        'ScopeMismatchError',
      );
    }
    if (
      !recorded.sourceMode ||
      !recorded.configHash ||
      recorded.safeDemonstration === undefined ||
      !recorded.testScopes ||
      !recorded.testSurfaces
    ) {
      const { exploit: _legacyExploit, ...scopeWithoutLegacy } = recorded;
      session.session.scope = {
        ...scopeWithoutLegacy,
        safeDemonstration: recordedSafeDemonstration,
        sourceMode: recordedSourceMode,
        vulnClasses: recordedScope.vulnClasses,
        testScopes: recordedScope.testScopes,
        testSurfaces: recordedScope.testSurfaces,
        ...(input.httpLoad && { httpLoad: input.httpLoad }),
        configHash,
      };
      session.session.sourceMode = recordedSourceMode;
      await atomicWrite(sessionPath, session);
    }
    return;
  }

  session.session.sourceMode = input.sourceMode;
  session.session.scope = {
    vulnClasses: currentScope.vulnClasses,
    testScopes: currentScope.testScopes,
    testSurfaces: currentScope.testSurfaces,
    safeDemonstration,
    ...(input.httpLoad && { httpLoad: input.httpLoad }),
    sourceMode: input.sourceMode,
    configHash,
  };
  await atomicWrite(sessionPath, session);
}

async function findLatestCommit(gitDir: string, commitHashes: string[]): Promise<string> {
  if (commitHashes.length === 1) {
    const hash = commitHashes[0];
    if (!hash) {
      throw new PentestError(
        'Empty commit hash in array',
        'filesystem',
        false, // Non-retryable - corrupt workspace state
        { phase: 'resume' },
        ErrorCode.GIT_CHECKPOINT_FAILED,
      );
    }
    return hash;
  }

  const result = await executeGitCommandWithRetry(
    ['git', 'rev-list', '--max-count=1', ...commitHashes],
    gitDir,
    'find latest commit',
  );

  return result.stdout.trim();
}

/**
 * Restore deliverables git to a checkpoint.
 * Operates on the private git inside workspace deliverables, not the user's repo.
 */
export async function restoreGitCheckpoint(
  workingDirectory: string,
  checkpointHash: string,
  incompleteAgents: AgentName[],
  deliverablesSubdir?: string,
): Promise<void> {
  const deliverablesPath = deliverablesDir(workingDirectory, deliverablesSubdir);
  const logger = createActivityLogger();
  logger.info(`Restoring deliverables to ${checkpointHash}...`);

  // Validate hash exists in this clone before attempting reset
  try {
    await executeGitCommandWithRetry(
      ['git', 'rev-parse', '--verify', checkpointHash],
      deliverablesPath,
      'verify checkpoint hash exists',
    );
  } catch {
    logger.info(`Checkpoint hash not found in clone, skipping git reset: ${checkpointHash}`);
    return;
  }

  await executeGitCommandWithRetry(
    ['git', 'reset', '--hard', checkpointHash],
    deliverablesPath,
    'reset deliverables to checkpoint',
  );
  await executeGitCommandWithRetry(['git', 'clean', '-fd'], deliverablesPath, 'clean untracked deliverables');

  // Explicitly delete partial deliverables for incomplete agents
  for (const agentName of incompleteAgents) {
    const deliverableFilename = AGENTS[agentName].deliverableFilename;
    const deliverablePath = path.join(deliverablesPath, deliverableFilename);
    try {
      const exists = await fileExists(deliverablePath);
      if (exists) {
        logger.warn(`Cleaning partial deliverable: ${agentName}`);
        await fs.unlink(deliverablePath);
      }
    } catch (error) {
      logger.info(`Note: Failed to delete ${deliverablePath}: ${error}`);
    }
  }

  logger.info('Deliverables restored to clean state');
}

/**
 * Record a resume attempt in session.json and write resume header to workflow.log.
 */
export async function recordResumeAttempt(
  input: ActivityInput,
  terminatedWorkflows: string[],
  checkpointHash: string,
  previousWorkflowId: string,
  completedAgents: string[],
): Promise<void> {
  const sessionMetadata = buildSessionMetadata(input);
  const auditSession = new AuditSession(sessionMetadata);
  await auditSession.initialize();

  // Update session.json with resume attempt
  await auditSession.addResumeAttempt(input.workflowId, terminatedWorkflows, checkpointHash);

  // Write resume header to workflow.log
  await auditSession.logResumeHeader({
    previousWorkflowId,
    newWorkflowId: input.workflowId,
    checkpointHash,
    completedAgents,
  });
}

/**
 * Log phase transition to the unified workflow log.
 */
export async function logPhaseTransition(
  input: ActivityInput,
  phase: string,
  event: 'start' | 'complete',
): Promise<void> {
  const sessionMetadata = buildSessionMetadata(input);
  const auditSession = new AuditSession(sessionMetadata);
  await auditSession.initialize(input.workflowId);

  if (event === 'start') {
    await auditSession.logPhaseStart(phase);
  } else {
    await auditSession.logPhaseComplete(phase);
  }
}

/**
 * Log workflow completion with full summary.
 * Cleans up container when done.
 */
export async function logWorkflowComplete(input: ActivityInput, summary: WorkflowSummary): Promise<void> {
  const { workflowId } = input;
  const sessionMetadata = buildSessionMetadata(input);

  // 1. Initialize audit session and mark final status
  const auditSession = new AuditSession(sessionMetadata);
  await auditSession.initialize(workflowId);
  await auditSession.updateSessionStatus(summary.status);

  // 2. Load cumulative metrics from session.json
  const sessionData = (await auditSession.getMetrics()) as {
    metrics: {
      total_duration_ms: number;
      total_cost_usd: number;
      total_input_tokens?: number;
      total_output_tokens?: number;
      total_cache_read_tokens?: number;
      total_cache_write_tokens?: number;
      total_turns?: number;
      agents: Record<
        string,
        {
          final_duration_ms: number;
          total_cost_usd: number;
          total_input_tokens?: number;
          total_output_tokens?: number;
          total_cache_read_tokens?: number;
          total_cache_write_tokens?: number;
          total_turns?: number;
        }
      >;
    };
  };

  // 3. Replace activity-only metrics with cumulative attempt totals from session.json.
  const agentMetrics = { ...summary.agentMetrics };
  for (const agentName of summary.completedAgents) {
    const agentData = sessionData.metrics.agents[agentName];
    if (agentData) {
      const activityMetrics = agentMetrics[agentName];
      agentMetrics[agentName] = {
        durationMs: agentData.final_duration_ms,
        costUsd: agentData.total_cost_usd,
        inputTokens: agentData.total_input_tokens ?? activityMetrics?.inputTokens ?? null,
        outputTokens: agentData.total_output_tokens ?? activityMetrics?.outputTokens ?? null,
        cacheReadTokens: agentData.total_cache_read_tokens ?? activityMetrics?.cacheReadTokens ?? null,
        cacheWriteTokens: agentData.total_cache_write_tokens ?? activityMetrics?.cacheWriteTokens ?? null,
        numTurns: agentData.total_turns ?? activityMetrics?.numTurns ?? null,
      };
    }
  }

  // 4. Build cumulative summary with cross-run totals
  const cumulativeSummary: WorkflowSummary = {
    ...summary,
    totalDurationMs: sessionData.metrics.total_duration_ms,
    totalCostUsd: sessionData.metrics.total_cost_usd,
    totalInputTokens: sessionData.metrics.total_input_tokens ?? summary.totalInputTokens,
    totalOutputTokens: sessionData.metrics.total_output_tokens ?? summary.totalOutputTokens,
    totalCacheReadTokens: sessionData.metrics.total_cache_read_tokens ?? summary.totalCacheReadTokens,
    totalCacheWriteTokens: sessionData.metrics.total_cache_write_tokens ?? summary.totalCacheWriteTokens,
    totalTurns: sessionData.metrics.total_turns ?? summary.totalTurns,
    agentMetrics,
  };

  // 5. Write completion entry to workflow.log
  await auditSession.logWorkflowComplete(cumulativeSummary);

  // 6. Drop the authenticated browser session
  try {
    await fs.rm(authStateFile(sessionMetadata), { force: true });
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    console.warn(`Failed to clean up auth-state.json: ${detail}`);
  }

  // 7. Clean up container
  removeContainer(workflowId);
  clearPipelineCredentials(input);
}

/**
 * Merge external findings into the exploitation queue for a vulnerability type.
 *
 * Delegates to the FindingsProvider registered in the DI container.
 * Default: no-op returning { mergedCount: 0 }.
 * Consumers can override this activity at the worker level with custom findings integration.
 */
export async function mergeFindingsIntoQueue(
  input: ActivityInput,
  vulnType: VulnType,
): Promise<{ mergedCount: number }> {
  const container = getContainer(input.workflowId);
  if (!container?.findingsProvider) return { mergedCount: 0 };
  return container.findingsProvider.mergeFindingsIntoQueue(input.workingDirectory, vulnType, input);
}

/**
 * Persist pipeline state after an agent completes.
 *
 * Delegates to the CheckpointProvider registered in the DI container.
 * Default: no-op. Consumers can override this activity at the worker level with custom persistence.
 */
export async function saveCheckpoint(
  input: ActivityInput,
  agentName: string,
  phase: string,
  state: PipelineState,
): Promise<void> {
  const container = getContainer(input.workflowId);
  if (!container?.checkpointProvider) return;

  const context: CheckpointContext = {
    workingDirectory: input.workingDirectory,
    ...(input.repoPath !== undefined && { repoPath: input.repoPath }),
    sessionId: input.sessionId,
    deliverablesSubdir: input.deliverablesSubdir ?? DEFAULT_DELIVERABLES_SUBDIR,
    ...(input.outputPath !== undefined && { outputPath: input.outputPath }),
  };

  return container.checkpointProvider.onAgentComplete(agentName, phase, state, context);
}

/**
 * Generate secondary outputs from the canonical report.
 *
 * Delegates to the ReportOutputProvider registered in the DI container.
 * The default provider emits PDF and eligible SARIF artifacts; consumers may
 * inject another implementation.
 */
export async function generateReportOutputActivity(rawInput: ActivityInput): Promise<void> {
  const input = await hydratePipelineCredentials(rawInput);
  const container = getContainer(input.workflowId);
  if (!container?.reportOutputProvider) return;

  const logger = createActivityLogger();

  const result = await container.reportOutputProvider.generate(input, logger);
  if (result.artifacts) {
    for (const artifact of result.artifacts) {
      logger.info(`${artifact.kind.toUpperCase()} report written to ${artifact.outputPath}`);
    }
  } else if (result.outputPath) {
    // Backward compatibility for injected providers implementing the legacy single-output contract.
    logger.info(`Report output written to ${result.outputPath}`);
  }
}
