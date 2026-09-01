// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Temporal workflow for Shannon pentest pipeline.
 *
 * Orchestrates the penetration testing workflow:
 * 1. Pre-Reconnaissance (sequential)
 * 2. Reconnaissance (sequential)
 * 3-4. Vulnerability + Exploitation (5 pipelined pairs in parallel)
 *      Each pair: vuln agent → queue check → conditional exploit
 *      No synchronization barrier - exploits start when their vuln finishes
 * 5. Reporting (sequential)
 *
 * Features:
 * - Queryable state via getProgress
 * - Automatic retry with backoff for transient/billing errors
 * - Non-retryable classification for permanent errors
 * - Audit correlation via workflowId
 * - Graceful failure handling: pipelines continue if one fails
 */

import {
  ApplicationFailure,
  isCancellation,
  log,
  proxyActivities,
  type RetryPolicy,
  setHandler,
  workflowInfo,
} from '@temporalio/workflow';
import type { AgentName, VulnType } from '../types/agents.js';
import { ALL_AGENTS } from '../types/agents.js';
import { ALL_VULN_CLASSES, type VulnClass } from '../types/config.js';
import { redactLogText, redactSecrets } from '../utils/redactSecrets.js';
import type * as activities from './activities.js';
import type { ActivityInput } from './activities.js';
import {
  type AgentMetrics,
  computeExpectedAgents,
  getProgress,
  hasInlineProviderCredentials,
  hasInlineSensitiveConfiguration,
  normalizeSourceContext,
  type PipelineInput,
  type PipelineProgress,
  type PipelineState,
  type PipelineSummary,
  type ResumeState,
  resolveSafeDemonstrationInput,
  type VulnExploitPipelineResult,
  withoutProviderCredentials,
} from './shared.js';
import { toWorkflowSummary } from './summary-mapper.js';
import { classifyErrorCode, formatWorkflowError } from './workflow-errors.js';

const NON_RETRYABLE_ERROR_TYPES = [
  'AuthenticationError',
  'PermissionError',
  'InvalidRequestError',
  'RequestTooLargeError',
  'ConfigurationError',
  'InvalidTargetError',
  'ExecutionLimitError',
  'AuthLoginFailedError',
];

// Retry configuration for production (long intervals for billing recovery)
const PRODUCTION_RETRY: RetryPolicy = {
  initialInterval: '5 minutes',
  maximumInterval: '30 minutes',
  backoffCoefficient: 2,
  maximumAttempts: 50,
  nonRetryableErrorTypes: NON_RETRYABLE_ERROR_TYPES,
};

// Retry configuration for pipeline testing (fast iteration)
const TESTING_RETRY: RetryPolicy = {
  initialInterval: '10 seconds',
  maximumInterval: '30 seconds',
  backoffCoefficient: 2,
  maximumAttempts: 5,
  nonRetryableErrorTypes: NON_RETRYABLE_ERROR_TYPES,
};

// Activity proxy with production retry configuration (default)
const acts = proxyActivities<typeof activities>({
  startToCloseTimeout: '2 hours',
  heartbeatTimeout: '60 minutes', // Extended for sub-agent execution (SDK blocks event loop during Task tool calls)
  retry: PRODUCTION_RETRY,
});

// Activity proxy with testing retry configuration (fast)
const testActs = proxyActivities<typeof activities>({
  startToCloseTimeout: '30 minutes',
  heartbeatTimeout: '30 minutes', // Extended for sub-agent execution in testing
  retry: TESTING_RETRY,
});

// Retry configuration for subscription plans (5h+ rolling rate limit windows)
const SUBSCRIPTION_RETRY: RetryPolicy = {
  initialInterval: '5 minutes',
  maximumInterval: '6 hours',
  backoffCoefficient: 2,
  maximumAttempts: 100,
  nonRetryableErrorTypes: NON_RETRYABLE_ERROR_TYPES,
};

// Activity proxy for subscription plan recovery (extended timeouts)
const subscriptionActs = proxyActivities<typeof activities>({
  startToCloseTimeout: '8 hours',
  heartbeatTimeout: '2 hours',
  retry: SUBSCRIPTION_RETRY,
});

// Retry configuration for preflight validation (short timeout, few retries)
const PREFLIGHT_RETRY: RetryPolicy = {
  initialInterval: '10 seconds',
  maximumInterval: '1 minute',
  backoffCoefficient: 2,
  maximumAttempts: 3,
  nonRetryableErrorTypes: NON_RETRYABLE_ERROR_TYPES,
};

// Activity proxy for preflight validation (short timeout)
const preflightActs = proxyActivities<typeof activities>({
  startToCloseTimeout: '2 minutes',
  heartbeatTimeout: '2 minutes',
  retry: PREFLIGHT_RETRY,
});

// Credential rejection is not retryable; transient SDK errors get 3 attempts.
const AUTH_VALIDATION_RETRY: RetryPolicy = {
  initialInterval: '10 seconds',
  maximumInterval: '1 minute',
  backoffCoefficient: 2,
  maximumAttempts: 3,
  nonRetryableErrorTypes: NON_RETRYABLE_ERROR_TYPES,
};

// Browser-driving validation measured at 60–180s; 10 min start-to-close leaves headroom for slow SSO/MFA flows.
const authValidationActs = proxyActivities<typeof activities>({
  startToCloseTimeout: '10 minutes',
  heartbeatTimeout: '10 minutes',
  retry: AUTH_VALIDATION_RETRY,
});

/**
 * Compute aggregated metrics from the current pipeline state.
 * Called on both success and failure to provide partial metrics.
 */
function computeSummary(state: PipelineState): PipelineSummary {
  const metrics = Object.values(state.agentMetrics);
  return {
    totalCostUsd: metrics.reduce((sum, m) => sum + (m.costUsd ?? 0), 0),
    totalDurationMs: Date.now() - state.startTime,
    totalTurns: metrics.reduce((sum, m) => sum + (m.numTurns ?? 0), 0),
    totalInputTokens: metrics.reduce((sum, m) => sum + (m.inputTokens ?? 0), 0),
    totalOutputTokens: metrics.reduce((sum, m) => sum + (m.outputTokens ?? 0), 0),
    totalCacheReadTokens: metrics.reduce((sum, m) => sum + (m.cacheReadTokens ?? 0), 0),
    totalCacheWriteTokens: metrics.reduce((sum, m) => sum + (m.cacheWriteTokens ?? 0), 0),
    agentCount: state.completedAgents.length,
  };
}

/**
 * Core pipeline orchestration. Coordinates the pentest pipeline stages.
 *
 * IMPORTANT: This function uses Temporal workflow APIs internally (proxyActivities,
 * queries). It can ONLY be called from within a Temporal workflow execution.
 * Do not call from standalone scripts or activity code.
 */
export async function pentestPipeline(input: PipelineInput): Promise<PipelineState> {
  let sourceContext: ReturnType<typeof normalizeSourceContext>;
  try {
    sourceContext = normalizeSourceContext(input);
  } catch (error) {
    throw ApplicationFailure.nonRetryable(error instanceof Error ? error.message : String(error), 'ConfigurationError');
  }
  const { sourceMode, workingDirectory, repoPath } = sourceContext;

  if (hasInlineProviderCredentials(input)) {
    throw ApplicationFailure.nonRetryable(
      'Inline provider credentials are not allowed in Temporal input; stage them behind secretRef before starting the workflow',
      'ConfigurationError',
    );
  }
  if (hasInlineSensitiveConfiguration(input)) {
    throw ApplicationFailure.nonRetryable(
      'Inline configYAML/configData is not allowed in Temporal input because it may contain target credentials; use configPath or stage it behind secretRef before starting the workflow',
      'ConfigurationError',
    );
  }

  const { workflowId } = workflowInfo();

  // Select activity proxy based on mode: testing (fast), subscription (extended), or default
  function selectActivityProxy(pipelineInput: PipelineInput) {
    if (pipelineInput.pipelineTestingMode) return testActs;
    if (pipelineInput.pipelineConfig?.retry_preset === 'subscription') return subscriptionActs;
    return acts;
  }

  const a = selectActivityProxy(input);

  const selectedVulnClasses: readonly VulnClass[] =
    input.vulnClasses && input.vulnClasses.length > 0 ? input.vulnClasses : ALL_VULN_CLASSES;
  const selectedClassSet = new Set<VulnClass>(selectedVulnClasses);
  let safeDemonstration: boolean;
  try {
    safeDemonstration = resolveSafeDemonstrationInput(input);
  } catch (error) {
    throw ApplicationFailure.nonRetryable(error instanceof Error ? error.message : String(error), 'ConfigurationError');
  }
  const expectedAgents = computeExpectedAgents(sourceMode, selectedVulnClasses, safeDemonstration);

  const state: PipelineState = {
    status: 'running',
    currentPhase: null,
    currentAgent: null,
    activeAgents: [],
    activeTestCategories: [],
    expectedAgents,
    completedAgents: [],
    failedAgent: null,
    error: null,
    startTime: Date.now(),
    agentMetrics: {},
    triageRan: false,
    summary: null,
  };

  setHandler(
    getProgress,
    (): PipelineProgress => ({
      ...state,
      workflowId,
      elapsedMs: Date.now() - state.startTime,
    }),
  );

  // Build ActivityInput with required workflowId for audit correlation
  // Activities require workflowId (non-optional), PipelineInput has it optional
  // Use spread to conditionally include optional properties (exactOptionalPropertyTypes)
  // sessionId is workspace name for resume, or workflowId for new runs
  const sessionId = input.sessionId || input.resumeFromWorkspace || workflowId;
  const safeProviderConfig = withoutProviderCredentials(input.providerConfig);

  const activityInput: ActivityInput = {
    webUrl: input.webUrl,
    workingDirectory,
    sourceMode,
    ...(repoPath !== undefined && { repoPath }),
    workflowId,
    sessionId,
    ...(input.configPath !== undefined && { configPath: input.configPath }),
    ...(input.outputPath !== undefined && { outputPath: input.outputPath }),
    ...(input.pipelineTestingMode !== undefined && {
      pipelineTestingMode: input.pipelineTestingMode,
    }),
    // Config fields — flow through to getOrCreateContainer()
    ...(input.secretRef !== undefined && { secretRef: input.secretRef }),
    ...(input.deliverablesSubdir !== undefined && { deliverablesSubdir: input.deliverablesSubdir }),
    ...(input.auditDir !== undefined && { auditDir: input.auditDir }),
    ...(input.promptDir !== undefined && { promptDir: input.promptDir }),
    ...(input.sastSarifPath !== undefined && { sastSarifPath: input.sastSarifPath }),
    ...(input.skipGitCheck !== undefined && { skipGitCheck: input.skipGitCheck }),
    ...(safeProviderConfig !== undefined && { providerConfig: safeProviderConfig }),
    vulnClasses: [...selectedVulnClasses],
  };

  await preflightActs.prepareWorkingDirectory(activityInput);
  await a.persistOrValidateRunScope(activityInput, [...selectedVulnClasses], safeDemonstration);

  let resumeState: ResumeState | null = null;

  if (input.resumeFromWorkspace) {
    // 1. Load resume state (validates workspace, cross-checks deliverables)
    resumeState = await a.loadResumeState(
      input.resumeFromWorkspace,
      input.webUrl,
      workingDirectory,
      sourceMode,
      repoPath,
      input.deliverablesSubdir,
    );

    // 2. Restore git workspace and clean up incomplete deliverables
    const incompleteAgents = ALL_AGENTS.filter(
      (agentName) => !resumeState?.completedAgents.includes(agentName),
    ) as AgentName[];

    await a.restoreGitCheckpoint(
      workingDirectory,
      resumeState.checkpointHash,
      incompleteAgents,
      input.deliverablesSubdir,
    );

    // 3. Short-circuit when every agent expected by this run is done.
    // Uses dynamic expectedAgents (not ALL_AGENTS) so a class-scoped run completes sooner.
    const allExpectedDone = expectedAgents.every((a) => resumeState?.completedAgents.includes(a));
    if (allExpectedDone) {
      log.info(`All ${expectedAgents.length} expected agents already completed; regenerating report outputs.`);
      state.completedAgents = [...resumeState.completedAgents];
      state.triageRan = resumeState.completedAgents.includes('triage');

      // These activities are deterministic, so an all-complete resume can repair
      // missing metadata and secondary artifacts without rerunning an agent.
      await a.injectReportMetadataActivity(activityInput);
      await a.injectReportModeSectionsActivity(activityInput);
      await a.generateReportOutputActivity(activityInput);

      state.status = 'completed';
      state.currentPhase = null;
      state.currentAgent = null;
      state.summary = computeSummary(state);

      if (input.checkpointsEnabled) {
        await a.saveCheckpoint(activityInput, 'report-output', 'reporting', state);
      }
      await a.logWorkflowComplete(activityInput, toWorkflowSummary(state, 'completed'));
      return state;
    }

    // 4. Record this resume attempt in session.json and workflow.log
    await a.recordResumeAttempt(
      activityInput,
      input.terminatedWorkflows || [],
      resumeState.checkpointHash,
      resumeState.originalWorkflowId,
      resumeState.completedAgents,
    );

    log.info('Resume state loaded and workspace restored');
  }

  const shouldSkip = (agentName: string): boolean => {
    return resumeState?.completedAgents.includes(agentName) ?? false;
  };

  const activateAgent = (agentName: string): void => {
    if (!state.activeAgents.includes(agentName)) state.activeAgents.push(agentName);
  };

  const deactivateAgent = (agentName: string): void => {
    state.activeAgents = state.activeAgents.filter((active) => active !== agentName);
  };

  // Run a sequential agent phase (pre-recon, recon)
  async function runSequentialPhase(
    phaseName: string,
    agentName: AgentName,
    runAgent: (input: ActivityInput) => Promise<AgentMetrics>,
  ): Promise<void> {
    if (!shouldSkip(agentName)) {
      state.currentPhase = phaseName;
      state.currentAgent = agentName;
      activateAgent(agentName);
      await a.logPhaseTransition(activityInput, phaseName, 'start');
      try {
        state.agentMetrics[agentName] = await runAgent(activityInput);
        state.completedAgents.push(agentName);
        if (input.checkpointsEnabled) {
          await a.saveCheckpoint(activityInput, agentName, phaseName, state);
        }
        await a.logPhaseTransition(activityInput, phaseName, 'complete');
      } finally {
        deactivateAgent(agentName);
      }
    } else {
      log.info(`Skipping ${agentName} (already complete)`);
      state.completedAgents.push(agentName);
    }
  }

  // Build pipeline configs for the 5 vuln→exploit pairs
  function buildPipelineConfigs(): Array<{
    vulnType: VulnType;
    vulnAgent: string;
    exploitAgent: string;
    runVuln: () => Promise<AgentMetrics>;
    runExploit: () => Promise<AgentMetrics>;
  }> {
    return [
      {
        vulnType: 'injection',
        vulnAgent: 'injection-vuln',
        exploitAgent: 'injection-exploit',
        runVuln: () => a.runInjectionVulnAgent(activityInput),
        runExploit: () => a.runInjectionExploitAgent(activityInput),
      },
      {
        vulnType: 'xss',
        vulnAgent: 'xss-vuln',
        exploitAgent: 'xss-exploit',
        runVuln: () => a.runXssVulnAgent(activityInput),
        runExploit: () => a.runXssExploitAgent(activityInput),
      },
      {
        vulnType: 'auth',
        vulnAgent: 'auth-vuln',
        exploitAgent: 'auth-exploit',
        runVuln: () => a.runAuthVulnAgent(activityInput),
        runExploit: () => a.runAuthExploitAgent(activityInput),
      },
      {
        vulnType: 'ssrf',
        vulnAgent: 'ssrf-vuln',
        exploitAgent: 'ssrf-exploit',
        runVuln: () => a.runSsrfVulnAgent(activityInput),
        runExploit: () => a.runSsrfExploitAgent(activityInput),
      },
      {
        vulnType: 'authz',
        vulnAgent: 'authz-vuln',
        exploitAgent: 'authz-exploit',
        runVuln: () => a.runAuthzVulnAgent(activityInput),
        runExploit: () => a.runAuthzExploitAgent(activityInput),
      },
    ];
  }

  // Aggregate errors from settled pipeline promises.
  // Metrics and completedAgents are updated incrementally inside runVulnExploitPipeline
  // so that getProgress queries reflect real-time status during execution.
  function aggregatePipelineResults(results: PromiseSettledResult<VulnExploitPipelineResult>[]): void {
    const failedPipelines: string[] = [];

    for (const result of results) {
      if (result.status === 'rejected') {
        const errorMsg = result.reason instanceof Error ? result.reason.message : String(result.reason);
        failedPipelines.push(redactLogText(errorMsg));
      }
    }

    if (failedPipelines.length > 0) {
      log.warn(`${failedPipelines.length} pipeline(s) failed`, {
        failures: redactSecrets(failedPipelines),
      });
    }
  }

  // Run thunks with a concurrency limit, returning PromiseSettledResult for each.
  // When limit >= thunks.length (default), all launch concurrently — identical to Promise.allSettled.
  // NOTE: Results are in completion order, not input order. Callers must key on value fields, not index.
  async function runWithConcurrencyLimit(
    thunks: Array<() => Promise<VulnExploitPipelineResult>>,
    limit: number,
  ): Promise<PromiseSettledResult<VulnExploitPipelineResult>[]> {
    const results: PromiseSettledResult<VulnExploitPipelineResult>[] = [];
    const inFlight = new Set<Promise<void>>();

    for (const thunk of thunks) {
      const slot = thunk()
        .then(
          (value) => {
            results.push({ status: 'fulfilled', value });
          },
          (reason: unknown) => {
            results.push({ status: 'rejected', reason });
          },
        )
        .finally(() => {
          inFlight.delete(slot);
        });

      inFlight.add(slot);

      if (inFlight.size >= limit) {
        await Promise.race(inFlight);
      }
    }

    await Promise.allSettled(inFlight);
    return results;
  }

  try {
    // === Preflight Validation ===
    // Quick sanity checks before committing to expensive agent runs.
    // NOT using runSequentialPhase — preflight doesn't produce AgentMetrics.
    state.currentPhase = 'preflight';
    state.currentAgent = null;
    await preflightActs.runPreflightValidation(activityInput);
    log.info('Preflight validation passed');

    // === Playwright stealth config ===
    // Write the playwright-cli config before any browser session opens so the
    // validator and downstream agents inherit anti-detection defaults.
    await preflightActs.syncPlaywrightStealthConfig(activityInput);

    // === Authentication Validation ===
    state.currentPhase = 'auth-validation';
    state.currentAgent = 'validate-authentication';
    activateAgent('validate-authentication');
    try {
      await authValidationActs.runAuthenticationValidation(activityInput);
    } finally {
      deactivateAgent('validate-authentication');
      state.currentAgent = null;
    }
    log.info('Authentication validation passed');

    // === Initialize Deliverables Git ===
    await a.initDeliverableGit(activityInput);

    // === Sync SDK deny rules ===
    if (sourceMode === 'source-assisted') {
      await a.syncCodePathDenyRules(activityInput);
    }

    log.info(`Run scope: vuln_classes=[${selectedVulnClasses.join(', ')}] safeDemonstration=${safeDemonstration}`);

    // === Phase 1: Pre-Reconnaissance ===
    if (sourceMode === 'source-assisted') {
      await runSequentialPhase('pre-recon', 'pre-recon', a.runPreReconAgent);
    } else {
      log.info('Skipping source pre-reconnaissance in URL-only mode');
    }

    // === Phase 2: Reconnaissance ===
    await runSequentialPhase('recon', 'recon', a.runReconAgent);

    // === Phases 3-4: Vulnerability Analysis + Exploitation (Pipelined) ===
    // Each vuln type runs as an independent pipeline:
    // vuln agent → queue check → conditional exploit agent
    // Exploits start immediately when their vuln finishes, not waiting for all.
    state.currentPhase = 'vulnerability-exploitation';
    state.currentAgent = 'pipelines';
    await a.logPhaseTransition(activityInput, 'vulnerability-exploitation', 'start');

    // Closure over shouldSkip and activityInput by design (Temporal replay safety)
    async function runVulnExploitPipeline(
      vulnType: VulnType,
      runVulnAgent: () => Promise<AgentMetrics>,
      runExploitAgent: () => Promise<AgentMetrics>,
    ): Promise<VulnExploitPipelineResult> {
      const vulnAgentName = `${vulnType}-vuln`;
      const exploitAgentName = `${vulnType}-exploit`;
      if (!state.activeTestCategories.includes(vulnType)) state.activeTestCategories.push(vulnType);

      try {
        // 1. Run vulnerability analysis (or skip if resumed)
        let vulnMetrics: AgentMetrics | null = null;
        if (!shouldSkip(vulnAgentName)) {
          activateAgent(vulnAgentName);
          try {
            vulnMetrics = await runVulnAgent();
            state.agentMetrics[vulnAgentName] = vulnMetrics;
            state.completedAgents.push(vulnAgentName);
            if (input.checkpointsEnabled) {
              await a.saveCheckpoint(activityInput, vulnAgentName, 'vulnerability-analysis', state);
            }
          } finally {
            deactivateAgent(vulnAgentName);
          }
        } else {
          log.info(`Skipping ${vulnAgentName} (already complete)`);
          state.completedAgents.push(vulnAgentName);
        }

        // 1.5. Merge external findings from consumer provider into the demonstration queue.
        await a.mergeFindingsIntoQueue(activityInput, vulnType);

        // 2. Check the queue for findings that can be safely demonstrated.
        const decision = await a.checkExploitationQueue(activityInput, vulnType);

        // 3. Preserve completed demonstrations on resume; gate new work by operator choice.
        let exploitMetrics: AgentMetrics | null = null;
        if (shouldSkip(exploitAgentName)) {
          log.info(`Skipping ${exploitAgentName} (already complete)`);
          state.completedAgents.push(exploitAgentName);
        } else if (decision.shouldExploit && safeDemonstration) {
          activateAgent(exploitAgentName);
          try {
            exploitMetrics = await runExploitAgent();
            state.agentMetrics[exploitAgentName] = exploitMetrics;
            state.completedAgents.push(exploitAgentName);
            if (input.checkpointsEnabled) {
              await a.saveCheckpoint(activityInput, exploitAgentName, 'safe-demonstration', state);
            }
          } finally {
            deactivateAgent(exploitAgentName);
          }
        }

        return {
          vulnType,
          vulnMetrics,
          exploitMetrics,
          exploitDecision: {
            shouldExploit: decision.shouldExploit,
            vulnerabilityCount: decision.vulnerabilityCount,
          },
          error: null,
        };
      } finally {
        deactivateAgent(vulnAgentName);
        deactivateAgent(exploitAgentName);
        state.activeTestCategories = state.activeTestCategories.filter((active) => active !== vulnType);
      }
    }

    const maxConcurrent = input.pipelineConfig?.max_concurrent_pipelines ?? 5;

    const pipelineConfigs = buildPipelineConfigs();
    const pipelineThunks: Array<() => Promise<VulnExploitPipelineResult>> = [];

    for (const config of pipelineConfigs) {
      // Excluded classes drop entirely; any prior deliverables stay on disk but don't count this run.
      if (!selectedClassSet.has(config.vulnType)) {
        log.info(`Skipping ${config.vulnType} pipeline (class not selected this run)`);
        continue;
      }
      if (!shouldSkip(config.vulnAgent) || !shouldSkip(config.exploitAgent)) {
        pipelineThunks.push(() => runVulnExploitPipeline(config.vulnType, config.runVuln, config.runExploit));
      } else {
        log.info(`Skipping entire ${config.vulnType} pipeline (both agents complete)`);
        state.completedAgents.push(config.vulnAgent, config.exploitAgent);
      }
    }

    const pipelineResults = await runWithConcurrencyLimit(pipelineThunks, maxConcurrent);
    aggregatePipelineResults(pipelineResults);

    state.currentPhase = 'exploitation';
    state.currentAgent = null;
    await a.logPhaseTransition(activityInput, 'vulnerability-exploitation', 'complete');

    // === Phase 4.5: Triage Gate (fail-open) ===
    // Validates each finding before reporting. A triage failure must never lose a
    // completed exploitation run, so this is wrapped fail-open: on error the report
    // renders all findings under an UNVALIDATED banner (see services/reporting.ts).
    if (!shouldSkip('triage')) {
      state.currentPhase = 'triage';
      state.currentAgent = 'triage';
      activateAgent('triage');
      await a.logPhaseTransition(activityInput, 'triage', 'start');
      try {
        state.agentMetrics.triage = await a.runTriageAgent(activityInput);
        state.completedAgents.push('triage');
        state.triageRan = true;
        await a.logPhaseTransition(activityInput, 'triage', 'complete');
      } catch (error) {
        state.triageRan = false;
        const msg = redactLogText(error instanceof Error ? error.message : String(error));
        log.warn(`Triage gate failed — continuing fail-open (report will be UNVALIDATED): ${msg}`);
      } finally {
        deactivateAgent('triage');
      }
    } else {
      log.info('Skipping triage (already complete)');
      state.completedAgents.push('triage');
      state.triageRan = true;
    }

    // === Phase 5: Reporting ===
    if (!shouldSkip('report')) {
      state.currentPhase = 'reporting';
      state.currentAgent = 'report';
      activateAgent('report');
      await a.logPhaseTransition(activityInput, 'reporting', 'start');

      // First, assemble the concatenated report from per-class deliverables
      await a.assembleReportActivity(activityInput, safeDemonstration, state.triageRan);

      // Then run the report agent to add executive summary and clean up
      try {
        state.agentMetrics.report = await a.runReportAgent(activityInput, safeDemonstration, state.triageRan);
        state.completedAgents.push('report');
        if (input.checkpointsEnabled) {
          await a.saveCheckpoint(activityInput, 'report', 'reporting', state);
        }
      } finally {
        deactivateAgent('report');
      }

      // Inject model metadata into the final report
      await a.injectReportMetadataActivity(activityInput);
      await a.injectReportModeSectionsActivity(activityInput);

      await a.logPhaseTransition(activityInput, 'reporting', 'complete');
    } else {
      log.info('Skipping report (already complete)');
      state.completedAgents.push('report');
    }

    // Runs after the skip gate so consumer providers still execute on resume.
    await a.generateReportOutputActivity(activityInput);

    if (input.checkpointsEnabled) {
      await a.saveCheckpoint(activityInput, 'report-output', 'reporting', state);
    }

    state.status = 'completed';
    state.currentPhase = null;
    state.currentAgent = null;
    state.summary = computeSummary(state);

    // Log workflow completion summary
    await a.logWorkflowComplete(activityInput, toWorkflowSummary(state, 'completed'));

    return state;
  } catch (error) {
    // Cancellation: return structured state instead of throwing
    if (isCancellation(error)) {
      state.status = 'cancelled';
      state.error = `Cancelled during phase: ${state.currentPhase ?? 'unknown'}`;
      state.summary = computeSummary(state);
      await a.logWorkflowComplete(activityInput, toWorkflowSummary(state, 'cancelled'));
      return state;
    }

    state.status = 'failed';
    state.failedAgent = state.currentAgent;
    state.error = redactLogText(formatWorkflowError(error, state.currentPhase, state.currentAgent));
    const errorCode = classifyErrorCode(error);
    if (errorCode) {
      state.errorCode = errorCode;
    }
    state.summary = computeSummary(state);

    // Log workflow failure summary
    await a.logWorkflowComplete(activityInput, toWorkflowSummary(state, 'failed'));

    throw error;
  }
}

/** OSS workflow entry point — thin shell around the extracted pipeline function. */
export async function pentestPipelineWorkflow(input: PipelineInput): Promise<PipelineState> {
  return pentestPipeline(input);
}
