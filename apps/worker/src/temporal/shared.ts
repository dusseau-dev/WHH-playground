import { defineQuery } from '@temporalio/workflow';

export type { AgentMetrics } from '../types/metrics.js';

import type { DistributedConfig, PipelineConfig, ProviderConfig, SourceMode, VulnClass } from '../types/config.js';
import type { ErrorCode } from '../types/errors.js';
import type { AgentMetrics } from '../types/metrics.js';

export interface PipelineInput {
  webUrl: string;
  /** Source repository. Omitted for URL-only assessments. */
  repoPath?: string;
  /** Inferred from repoPath when omitted for backward compatibility. */
  sourceMode?: SourceMode;
  /** Writable cwd and artifact root. Defaults to repoPath for legacy callers. */
  workingDirectory?: string;
  configPath?: string;
  outputPath?: string;
  pipelineTestingMode?: boolean;
  pipelineConfig?: PipelineConfig;
  workflowId?: string; // Used for audit correlation
  sessionId?: string; // Workspace directory name (distinct from workflowId for named workspaces)
  resumeFromWorkspace?: string; // Workspace name to resume from
  terminatedWorkflows?: string[]; // Workflows terminated during resume

  // Config fields — serializable, flow through to ActivityInput → getOrCreateContainer()
  configYAML?: string; // Raw YAML string (parsed in activity, not workflow — workflow sandbox can't use Node.js)
  configData?: DistributedConfig; // Pre-parsed config (bypasses file loading)
  /** @deprecated Stage with an opaque secretRef before starting a Temporal workflow. */
  apiKey?: string;
  deliverablesSubdir?: string; // Override deliverables path (default: '.shannon/deliverables')
  auditDir?: string; // Override audit log directory (default: './workspaces')
  promptDir?: string; // Override prompt template directory
  sastSarifPath?: string; // Optional path for consumer-supplied findings input
  checkpointsEnabled?: boolean; // Enable checkpoint activities (default: false)
  skipGitCheck?: boolean; // Skip .git directory validation in preflight (e.g. when .git is removed after clone)
  /** Non-secret provider settings. Credential fields must be staged behind secretRef. */
  providerConfig?: ProviderConfig;
  /** Opaque reference to provider credentials in the worker-local run store. */
  secretRef?: string;
  vulnClasses?: VulnClass[]; // omitted = all five
  safeDemonstration?: boolean; // false skips the safe-demonstration phase
  /** @deprecated Use safeDemonstration. */
  exploit?: boolean;
}

export interface ResumeState {
  workspaceName: string;
  originalUrl: string;
  completedAgents: string[];
  checkpointHash: string;
  originalWorkflowId: string;
}

export interface PipelineSummary {
  totalCostUsd: number;
  totalDurationMs: number; // Wall-clock time (end - start)
  totalTurns: number;
  totalInputTokens: number;
  totalOutputTokens: number;
  totalCacheReadTokens: number;
  totalCacheWriteTokens: number;
  agentCount: number;
}

export interface PipelineState {
  status: 'running' | 'completed' | 'failed' | 'cancelled';
  currentPhase: string | null;
  currentAgent: string | null;
  /** Agents currently executing. Unlike currentAgent, this represents parallel pipelines. */
  activeAgents: string[];
  /** Security test categories currently executing in parallel. */
  activeTestCategories: VulnClass[];
  /** Configured execution plan, excluding preflight and authentication validation. */
  expectedAgents: string[];
  completedAgents: string[];
  failedAgent: string | null;
  error: string | null;
  errorCode?: ErrorCode;
  startTime: number;
  agentMetrics: Record<string, AgentMetrics>;
  /** False when the triage gate failed open — the report renders an UNVALIDATED banner. */
  triageRan: boolean;
  summary: PipelineSummary | null;
}

// Extended state returned by getProgress query (includes computed fields)
export interface PipelineProgress extends PipelineState {
  workflowId: string;
  elapsedMs: number;
}

// Result from a single vuln→exploit pipeline
export interface VulnExploitPipelineResult {
  vulnType: string;
  vulnMetrics: AgentMetrics | null;
  exploitMetrics: AgentMetrics | null;
  exploitDecision: {
    shouldExploit: boolean;
    vulnerabilityCount: number;
  } | null;
  error: string | null;
}

export interface NormalizedSourceContext {
  sourceMode: SourceMode;
  workingDirectory: string;
  repoPath?: string;
}

export type NormalizedPipelineInput =
  | (PipelineInput & { sourceMode: 'source-assisted'; workingDirectory: string; repoPath: string })
  | (PipelineInput & { sourceMode: 'url-only'; workingDirectory: string; repoPath?: never });

export const DEFAULT_URL_ONLY_WORKING_DIRECTORY = '/app/target';

const PROVIDER_CREDENTIAL_FIELDS = new Set<keyof ProviderConfig>([
  'apiKey',
  'awsAccessKeyId',
  'awsSecretAccessKey',
  'awsSessionToken',
  'authToken',
]);

/** True when a provider configuration still contains a credential value. */
export function hasInlineProviderCredentials(input: Pick<PipelineInput, 'apiKey' | 'providerConfig'>): boolean {
  if (input.apiKey !== undefined) return true;
  return Object.entries(input.providerConfig ?? {}).some(
    ([key, value]) => PROVIDER_CREDENTIAL_FIELDS.has(key as keyof ProviderConfig) && value !== undefined,
  );
}

/** Inline configuration may contain target authentication credentials. */
export function hasInlineSensitiveConfiguration(input: Pick<PipelineInput, 'configYAML' | 'configData'>): boolean {
  return input.configYAML !== undefined || input.configData !== undefined;
}

/** Keep provider routing/model settings while excluding credential-bearing fields. */
export function withoutProviderCredentials(providerConfig: ProviderConfig | undefined): ProviderConfig | undefined {
  if (!providerConfig) return;
  const safe = Object.fromEntries(
    Object.entries(providerConfig).filter(([key]) => !PROVIDER_CREDENTIAL_FIELDS.has(key as keyof ProviderConfig)),
  ) as ProviderConfig;
  return Object.keys(safe).length > 0 ? safe : undefined;
}

function validateAbsolutePath(name: string, value: string): void {
  if (!value.startsWith('/')) {
    throw new Error(`Invalid ${name}: absolute path required (received: ${value})`);
  }
  if (value.split('/').includes('..')) {
    throw new Error(`Invalid ${name}: path traversal not allowed (received: ${value})`);
  }
}

/** Normalize legacy source-assisted inputs and validate first-class URL-only inputs. */
export function normalizeSourceContext(input: PipelineInput): NormalizedSourceContext {
  const sourceMode: SourceMode = input.sourceMode ?? (input.repoPath ? 'source-assisted' : 'url-only');

  if (sourceMode === 'source-assisted' && !input.repoPath) {
    throw new Error('Invalid source context: source-assisted mode requires repoPath');
  }
  if (sourceMode === 'url-only' && input.repoPath) {
    throw new Error('Invalid source context: url-only mode must not include repoPath');
  }

  const workingDirectory = input.workingDirectory ?? input.repoPath;
  if (!workingDirectory) {
    throw new Error('Invalid source context: workingDirectory is required when repoPath is omitted');
  }

  validateAbsolutePath('workingDirectory', workingDirectory);
  if (input.repoPath) validateAbsolutePath('repoPath', input.repoPath);

  return {
    sourceMode,
    workingDirectory,
    ...(input.repoPath !== undefined && { repoPath: input.repoPath }),
  };
}

/**
 * Normalize worker CLI-style source input into the pipeline contract.
 *
 * CLI callers are allowed to omit sourceMode:
 * - repoPath present means source-assisted.
 * - repoPath absent means URL-only with /app/target as the writable workspace.
 *
 * This only normalizes source fields. Call protectPipelineInput before Temporal
 * submission when legacy inline credentials or configuration are present.
 */
export function normalizeCliPipelineInput(input: PipelineInput): NormalizedPipelineInput {
  const sourceMode: SourceMode = input.sourceMode ?? (input.repoPath ? 'source-assisted' : 'url-only');
  const workingDirectory =
    input.workingDirectory ?? (sourceMode === 'url-only' ? DEFAULT_URL_ONLY_WORKING_DIRECTORY : input.repoPath);
  const safeDemonstration = resolveSafeDemonstrationInput(input);
  const { exploit: _legacyExploit, ...inputWithoutLegacyFlag } = input;

  const normalized: PipelineInput = {
    ...inputWithoutLegacyFlag,
    sourceMode,
    safeDemonstration,
    ...(workingDirectory !== undefined && { workingDirectory }),
  };

  const sourceContext = normalizeSourceContext(normalized);
  return {
    ...normalized,
    sourceMode: sourceContext.sourceMode,
    workingDirectory: sourceContext.workingDirectory,
    ...(sourceContext.repoPath !== undefined && { repoPath: sourceContext.repoPath }),
  } as NormalizedPipelineInput;
}

/**
 * Resolve the canonical safe-demonstration workflow flag.
 *
 * `exploit` is accepted for callers that have not migrated yet, but conflicting
 * values are rejected before workflow execution starts.
 */
export function resolveSafeDemonstrationInput(input: { safeDemonstration?: boolean; exploit?: boolean }): boolean {
  if (
    input.safeDemonstration !== undefined &&
    input.exploit !== undefined &&
    input.safeDemonstration !== input.exploit
  ) {
    throw new Error('Invalid demonstration settings: safeDemonstration conflicts with legacy exploit');
  }
  return input.safeDemonstration ?? input.exploit ?? true;
}

/** Agents configured for a run. Safe-demonstration entries are conditional at runtime. */
export function computeExpectedAgents(
  sourceMode: SourceMode,
  vulnClasses: readonly VulnClass[],
  safeDemonstration: boolean,
): string[] {
  const expected: string[] = sourceMode === 'source-assisted' ? ['pre-recon', 'recon'] : ['recon'];
  for (const cls of vulnClasses) {
    expected.push(`${cls}-vuln`);
    if (safeDemonstration) expected.push(`${cls}-exploit`);
  }
  expected.push('triage', 'report');
  return expected;
}

export type { SourceMode } from '../types/config.js';

export const getProgress = defineQuery<PipelineProgress>('getProgress');
