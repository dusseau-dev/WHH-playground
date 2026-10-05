import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { dump as dumpYaml } from 'js-yaml';
import {
  type ActivityChunk,
  type AssessmentConfig,
  type DetectionValidationSummary,
  type LegacyRunRecord,
  LegacyRunRecordSchema,
  type LegacySession,
  LegacySessionSchema,
  type ManagedRunRecord,
  ManagedRunRecordSchema,
  type ProviderConfig,
  REPORT_ARTIFACT_KINDS,
  type ReportArtifact,
  type ReportArtifactKind,
  type ReportData,
  type RunAttempt,
  type RunDetail,
  type RunLaunchSpec,
  RunLaunchSpecSchema,
  type RunListItem,
  type RunSnapshot,
  RunSnapshotSchema,
  type RunStatus,
  SECRET_FIELDS,
  type SecretField,
  type SecretReferences,
  type TargetSecrets,
  TriageVerdictsSchema,
  type UnvalidatedFinding,
  type VulnerabilityClass,
  type WorkflowProgress,
  WorkflowProgressSchema,
} from './contracts.js';
import type { DetectionValidationSettings } from './detection-validation.js';
import { createDockerClient, type DockerContainerState, type WorkerOptions } from './docker.js';
import { buildEnvFlags, loadEnv, resolveProviderCredentialFiles, validateCredentials } from './env.js';
import { getWorkspacesDir, initHome } from './home.js';
import { assertHttpLoadAuthorization, type HttpLoadSettings } from './http-load.js';
import { isLocal } from './mode.js';
import { providerConfigMatchesConfiguredModel } from './model-catalog.js';
import { FINAL_REPORT_FILENAME, INTERNAL_DIR } from './paths.js';
import { SecretRedactor, safeErrorMessage, sanitizeReportMarkdown } from './redaction.js';
import type {
  AssessmentModule,
  AssessmentTestScope,
  AssessmentTestSurface,
  ModuleSafetyInput,
} from './security-scopes.js';
import {
  assertSafeIdentifier,
  atomicWriteFile,
  atomicWriteJson,
  ensureDirectory,
  pathExists,
  readFileChunk,
  readJsonIfExists,
  resolveExistingContainedPath,
} from './storage.js';
import { discardStagedTemporalSecret, protectTemporalInput, WORKFLOW_SECRET_DIR } from './temporal-secrets.js';

const RUN_FILE = 'run.json';
const SESSION_FILE = 'session.json';
const WORKFLOW_LOG = 'workflow.log';
const REPORT_FILE = 'comprehensive_security_assessment_report.md';
const REPORT_DATA_FILE = 'report.json';
const DETECTION_VALIDATION_FILE = 'detection-validation.json';
const PDF_REPORT_FILE = 'comprehensive_security_assessment_report.pdf';
const FINAL_PDF_REPORT_FILENAME = 'Security-Assessment-Report.pdf';
const SARIF_REPORT_FILE = 'report.sarif';
const TRIAGE_FILE = 'triage_verdicts.json';
const CANCEL_GRACE_MS = 10_000;
const CONTROL_CALL_TIMEOUT_MS = 5_000;
const TERMINAL_CONTAINER_GRACE_MS = 30_000;
const QUEUE_FILES: Readonly<Record<VulnerabilityClass, string>> = {
  injection: 'injection_exploitation_queue.json',
  xss: 'xss_exploitation_queue.json',
  auth: 'auth_exploitation_queue.json',
  authz: 'authz_exploitation_queue.json',
  ssrf: 'ssrf_exploitation_queue.json',
};

function detectionValidationSummary(value: unknown): DetectionValidationSummary | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return;
  const raw = value as Record<string, unknown>;
  if (
    !['passed', 'failed', 'partial', 'unavailable'].includes(String(raw.status)) ||
    typeof raw.detection_gap_percentage_points !== 'number' ||
    !raw.cohorts ||
    typeof raw.cohorts !== 'object' ||
    Array.isArray(raw.cohorts) ||
    !Array.isArray(raw.scenarios)
  ) {
    return;
  }
  const cohorts = raw.cohorts as Record<string, unknown>;
  const parseCohort = (name: 'ai' | 'human') => {
    const cohort = cohorts[name];
    if (!cohort || typeof cohort !== 'object' || Array.isArray(cohort)) return;
    const item = cohort as Record<string, unknown>;
    if (
      typeof item.total !== 'number' ||
      typeof item.detected !== 'number' ||
      typeof item.detection_rate !== 'number' ||
      typeof item.threshold !== 'number' ||
      typeof item.passed !== 'boolean'
    ) {
      return;
    }
    return {
      total: item.total,
      detected: item.detected,
      detectionRate: item.detection_rate,
      threshold: item.threshold,
      passed: item.passed,
      ...(typeof item.median_latency_ms === 'number' && { medianLatencyMs: item.median_latency_ms }),
    };
  };
  const ai = parseCohort('ai');
  const human = parseCohort('human');
  if (!ai || !human) return;
  const scenarios: DetectionValidationSummary['scenarios'][number][] = [];
  for (const scenario of raw.scenarios) {
    if (!scenario || typeof scenario !== 'object' || Array.isArray(scenario)) return;
    const item = scenario as Record<string, unknown>;
    if (
      typeof item.id !== 'string' ||
      (item.cohort !== 'ai' && item.cohort !== 'human') ||
      typeof item.technique !== 'string' ||
      (item.emission_status !== 'sent' && item.emission_status !== 'error') ||
      typeof item.detected !== 'boolean'
    ) {
      return;
    }
    const cohort = item.cohort as 'ai' | 'human';
    const emissionStatus = item.emission_status as 'sent' | 'error';
    scenarios.push({
      id: item.id,
      cohort,
      technique: item.technique,
      emissionStatus,
      detected: item.detected,
      ...(typeof item.latency_ms === 'number' && { latencyMs: item.latency_ms }),
    });
  }
  return {
    status: raw.status as DetectionValidationSummary['status'],
    detectionGapPercentagePoints: raw.detection_gap_percentage_points,
    cohorts: { ai, human },
    scenarios,
  };
}
const URL_ONLY_NOTICE =
  'URL-only mode used browser and API observations; code-level coverage and source-location attribution were unavailable.';
const URL_ONLY_REPORT_CONTEXT = [
  '## Mode',
  '',
  'URL-Only',
  '',
  '## Coverage',
  '',
  'This assessment used browser and API observations against the authorized live target. Code-level coverage and source-location attribution were unavailable in URL-only mode.',
].join('\n');

const REPORT_ARTIFACT_DEFINITIONS: Readonly<
  Record<ReportArtifactKind, { contentType: string; candidates: readonly string[] }>
> = {
  markdown: {
    contentType: 'text/markdown; charset=utf-8',
    candidates: [
      FINAL_REPORT_FILENAME,
      path.join(INTERNAL_DIR, 'deliverables', REPORT_FILE),
      path.join('deliverables', REPORT_FILE),
      REPORT_FILE,
    ],
  },
  pdf: {
    contentType: 'application/pdf',
    candidates: [
      FINAL_PDF_REPORT_FILENAME,
      path.join(INTERNAL_DIR, 'deliverables', FINAL_PDF_REPORT_FILENAME),
      path.join('deliverables', FINAL_PDF_REPORT_FILENAME),
      path.join(INTERNAL_DIR, 'deliverables', PDF_REPORT_FILE),
      path.join('deliverables', PDF_REPORT_FILE),
      PDF_REPORT_FILE,
    ],
  },
  sarif: {
    contentType: 'application/sarif+json; charset=utf-8',
    candidates: [
      SARIF_REPORT_FILE,
      path.join(INTERNAL_DIR, 'deliverables', SARIF_REPORT_FILE),
      path.join('deliverables', SARIF_REPORT_FILE),
    ],
  },
};

export type ContainerState = DockerContainerState;

export interface SpawnProcess {
  once(event: 'exit', listener: (code: number | null) => void): this;
  once(event: 'error', listener: (error: Error) => void): this;
}

export interface ScanRuntime {
  prepare(version: string): Promise<void>;
  spawn(options: WorkerOptions): SpawnProcess;
  inspectContainer(containerName: string): Promise<ContainerState | null>;
  listManagedContainers(): Promise<ContainerState[]>;
  stopContainer(containerName: string): Promise<void>;
}

export interface TemporalPipelineInput {
  webUrl: string;
  sourceMode: RunSnapshot['sourceMode'];
  workingDirectory: string;
  repoPath?: string;
  configPath?: string;
  workflowId: string;
  sessionId: string;
  resumeFromWorkspace?: string;
  pipelineTestingMode?: boolean;
  pipelineConfig?: {
    retry_preset?: 'default' | 'subscription';
    max_concurrent_pipelines?: number;
  };
  vulnClasses?: VulnerabilityClass[];
  testScopes?: AssessmentTestScope[];
  testSurfaces?: AssessmentTestSurface[];
  httpLoad?: HttpLoadSettings;
  httpLoadAuthorizationConfirmed?: boolean;
  detectionValidation?: DetectionValidationSettings;
  detectionValidationAuthorizationConfirmed?: boolean;
  elevatedLoadConfirmed?: boolean;
  assessmentModules?: AssessmentModule[];
  moduleSafety?: ModuleSafetyInput;
  safeDemonstration?: boolean;
  /** @deprecated Inline credentials are staged locally before Temporal submission. */
  apiKey?: string;
  /** Credential fields are staged locally before Temporal submission. */
  providerConfig?: ProviderConfig;
  /** Opaque reference to locally staged provider credentials. */
  secretRef?: string;
  /** @deprecated Inline configuration is staged locally before Temporal submission. */
  configYAML?: string;
  /** @deprecated Inline configuration is staged locally before Temporal submission. */
  configData?: unknown;
}

export interface TemporalWorkflowStart {
  workflowId: string;
  taskQueue: string;
  input: TemporalPipelineInput;
}

export interface StartedWorkflow {
  workflowId: string;
  temporalRunId: string;
}

export interface TemporalWorkflowState {
  workflowId: string;
  status: WorkflowProgress['status'];
  progress: WorkflowProgress;
}

export interface TemporalGateway {
  startWorkflow(request: TemporalWorkflowStart, timeoutMs?: number): Promise<StartedWorkflow>;
  getWorkflow(workflowId: string, timeoutMs?: number): Promise<TemporalWorkflowState | null>;
  cancelWorkflow(workflowId: string, timeoutMs?: number): Promise<boolean>;
}

export interface ScanControllerOptions {
  version: string;
  workspacesDir?: string;
  runtime?: ScanRuntime;
  temporal?: TemporalGateway;
  now?: () => Date;
  suffix?: () => string;
  credentialLoader?: () => void;
  secretResolver?: (references: SecretReferences) => Promise<TargetSecrets>;
  cancelGraceMs?: number;
}

interface TemporalWorkflowHandle {
  query<T>(query: string): Promise<T>;
  cancel(): Promise<unknown>;
  describe(): Promise<{ status: { name: string } }>;
  result(): Promise<unknown>;
}

interface TemporalStartedHandle extends TemporalWorkflowHandle {
  firstExecutionRunId: string;
}

interface TemporalConnection {
  close(): Promise<void>;
  withDeadline<T>(deadline: number | Date, operation: () => Promise<T>): Promise<T>;
}

interface TemporalClientModule {
  Connection: {
    connect(options: { address: string; connectTimeout: number }): Promise<TemporalConnection>;
  };
  Client: new (options: {
    connection: unknown;
  }) => {
    workflow: {
      start(
        workflowType: string,
        options: { taskQueue: string; workflowId: string; args: [TemporalPipelineInput] },
      ): Promise<TemporalStartedHandle>;
      getHandle(workflowId: string): TemporalWorkflowHandle;
    };
  };
}

type RunPatch = Partial<Pick<ManagedRunRecord, 'status' | 'attempts' | 'completedAt' | 'lastError'>>;
type ClearableRunField = 'completedAt' | 'lastError';

class ControlDeadlineExceededError extends Error {}

function isTerminal(status: RunStatus): boolean {
  return status === 'completed' || status === 'failed' || status === 'cancelled';
}

function normalizeTimestamp(value: string | undefined, fallback: string): string {
  if (!value) return fallback;
  const timestamp = new Date(value);
  return Number.isNaN(timestamp.getTime()) ? fallback : timestamp.toISOString();
}

function legacyStatus(status: LegacySession['session']['status']): RunStatus {
  return status === 'in-progress' ? 'running' : status;
}

function sortJsonValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortJsonValue);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => [key, sortJsonValue(nested)]),
  );
}

export function hashRunSnapshot(snapshot: RunSnapshot): string {
  const canonical = JSON.stringify(sortJsonValue(RunSnapshotSchema.parse(snapshot)));
  return `sha256:${crypto.createHash('sha256').update(canonical).digest('hex')}`;
}

function safeWorkspaceName(targetUrl: string, now: Date): string {
  const hostname = new URL(targetUrl).hostname.replace(/[^a-zA-Z0-9-]/g, '-').slice(0, 60) || 'target';
  return `${hostname}_shannon-${now.getTime()}-${crypto.randomBytes(2).toString('hex')}`;
}

function requiredSecrets(secrets: TargetSecrets, references: SecretReferences): SecretField[] {
  return SECRET_FIELDS.filter((field) => Boolean(secrets[field] || references[field]));
}

const PROVIDER_CREDENTIAL_FIELDS = [
  'apiKey',
  'authToken',
  'awsAccessKeyId',
  'awsSecretAccessKey',
  'awsSessionToken',
] as const;

function providerCredentialValues(providerConfig: ProviderConfig | undefined): string[] {
  if (!providerConfig) return [];
  return PROVIDER_CREDENTIAL_FIELDS.map((field) => providerConfig[field]).filter(
    (value): value is string => typeof value === 'string' && value.length > 0,
  );
}

function withoutProviderCredentials(providerConfig: ProviderConfig | undefined): ProviderConfig | undefined {
  if (!providerConfig) return undefined;
  const safe = Object.fromEntries(
    Object.entries(providerConfig).filter(([key]) => !(PROVIDER_CREDENTIAL_FIELDS as readonly string[]).includes(key)),
  );
  return Object.keys(safe).length > 0 ? (safe as ProviderConfig) : undefined;
}

function sameProviderConfig(left: ProviderConfig, right: ProviderConfig): boolean {
  return JSON.stringify(sortJsonValue(left)) === JSON.stringify(sortJsonValue(right));
}

function mergeAttemptProviderConfig(
  snapshotProviderConfig: ProviderConfig | undefined,
  runtimeProviderConfig: ProviderConfig | undefined,
): ProviderConfig | undefined {
  if (!snapshotProviderConfig && !runtimeProviderConfig) return undefined;
  const safeRuntime = withoutProviderCredentials(runtimeProviderConfig);
  if (snapshotProviderConfig && safeRuntime && !sameProviderConfig(snapshotProviderConfig, safeRuntime)) {
    throw new Error('Provider configuration cannot be changed during resume');
  }
  const credentials = Object.fromEntries(
    Object.entries(runtimeProviderConfig ?? {}).filter(([key]) =>
      (PROVIDER_CREDENTIAL_FIELDS as readonly string[]).includes(key),
    ),
  );
  return {
    ...(snapshotProviderConfig ?? safeRuntime),
    ...credentials,
  } as ProviderConfig;
}

function hasProviderCredentials(providerConfig: ProviderConfig | undefined): boolean {
  return Boolean(
    providerConfig?.apiKey ||
      providerConfig?.authToken ||
      (providerConfig?.awsAccessKeyId && providerConfig.awsSecretAccessKey),
  );
}

function createRunSnapshot(spec: RunLaunchSpec): RunSnapshot {
  const {
    secrets = {},
    secretRefs = {},
    workspace: _workspace,
    authorizationConfirmed: _authorizationConfirmed,
    elevatedLoadConfirmed: _elevatedLoadConfirmed,
    ...safe
  } = spec;
  const providerConfig = withoutProviderCredentials(spec.providerConfig);
  return RunSnapshotSchema.parse({
    ...safe,
    ...(providerConfig && { providerConfig }),
    secretRefs,
    requiredSecretFields: requiredSecrets(secrets, secretRefs),
  });
}

function containsCodePathRules(config: AssessmentConfig): boolean {
  return [...(config.rules?.avoid ?? []), ...(config.rules?.focus ?? [])].some((rule) => rule.type === 'code_path');
}

function workerConfig(config: AssessmentConfig, secrets: TargetSecrets): Record<string, unknown> {
  const authentication = config.authentication;
  return {
    ...(config.description && { description: config.description }),
    ...(config.testCategories && { vuln_classes: config.testCategories }),
    ...(config.testScopes && { test_scopes: config.testScopes }),
    ...(config.testSurfaces && { test_surfaces: config.testSurfaces }),
    ...(config.httpLoad && {
      http_load: {
        concurrency: config.httpLoad.concurrency,
        requests_per_second: config.httpLoad.requestsPerSecond,
        duration_seconds: config.httpLoad.durationSeconds,
      },
    }),
    ...(config.detectionValidation && {
      detection_validation: {
        canary_path: config.detectionValidation.canaryPath,
        minimum_detection_rate: config.detectionValidation.minimumDetectionRate,
        max_wait_seconds: config.detectionValidation.maxWaitSeconds,
        splunk: {
          management_url: config.detectionValidation.splunk.managementUrl,
          telemetry_index: config.detectionValidation.splunk.telemetryIndex,
          alert_index: config.detectionValidation.splunk.alertIndex,
          ...(config.detectionValidation.splunk.telemetrySourcetype && {
            telemetry_sourcetype: config.detectionValidation.splunk.telemetrySourcetype,
          }),
          ...(config.detectionValidation.splunk.alertSourcetype && {
            alert_sourcetype: config.detectionValidation.splunk.alertSourcetype,
          }),
          ...(secrets.splunkToken && { token: secrets.splunkToken }),
        },
      },
    }),
    ...(config.assessmentModules && { assessment_modules: config.assessmentModules }),
    ...(config.moduleSafety && {
      module_safety: {
        target_environment: config.moduleSafety.targetEnvironment,
        allow_active_dast: config.moduleSafety.allowActiveDast,
        acknowledge_load_risk: config.moduleSafety.acknowledgeLoadRisk,
        max_requests_per_second: config.moduleSafety.maxRequestsPerSecond,
        max_concurrency: config.moduleSafety.maxConcurrency,
        load_stage_duration_seconds: config.moduleSafety.loadStageDurationSeconds,
        load_error_rate_threshold: config.moduleSafety.loadErrorRateThreshold,
        load_p95_latency_ms_threshold: config.moduleSafety.loadP95LatencyMsThreshold,
      },
    }),
    ...(config.safeDemonstration !== undefined && { safe_demonstration: config.safeDemonstration }),
    ...(config.pipeline && {
      pipeline: {
        ...(config.pipeline.retryPreset && { retry_preset: config.pipeline.retryPreset }),
        ...(config.pipeline.maxConcurrentPipelines !== undefined && {
          max_concurrent_pipelines: config.pipeline.maxConcurrentPipelines,
        }),
      },
    }),
    ...(config.rules && { rules: config.rules }),
    ...(config.report && {
      report: {
        ...(config.report.minSeverity && { min_severity: config.report.minSeverity }),
        ...(config.report.minConfidence && { min_confidence: config.report.minConfidence }),
        ...(config.report.guidance && { guidance: config.report.guidance }),
        ...(config.report.sarif !== undefined && { sarif: config.report.sarif }),
      },
    }),
    ...(config.rulesOfEngagement && { rules_of_engagement: config.rulesOfEngagement }),
    ...(authentication && {
      authentication: {
        login_type: authentication.loginType,
        login_url: authentication.loginUrl,
        credentials: {
          username: authentication.username,
          ...(secrets.password && { password: secrets.password }),
          ...(secrets.totpSecret && { totp_secret: secrets.totpSecret }),
          ...(authentication.emailAddress && {
            email_login: {
              address: authentication.emailAddress,
              ...(secrets.emailPassword && { password: secrets.emailPassword }),
              ...(secrets.emailTotpSecret && { totp_secret: secrets.emailTotpSecret }),
            },
          }),
        },
        ...(authentication.loginFlow && { login_flow: authentication.loginFlow }),
        success_condition: {
          type: authentication.successCondition.type,
          value: authentication.successCondition.value,
        },
      },
    }),
  };
}

function hasWorkerConfig(config: Record<string, unknown>): boolean {
  return Object.keys(config).length > 0;
}

function workflowProgress(
  workflowId: string,
  status: WorkflowProgress['status'],
  error: string | null = null,
): WorkflowProgress {
  return {
    workflowId,
    status,
    currentPhase: null,
    currentAgent: null,
    activeAgents: [],
    activeTestCategories: [],
    activeModules: [],
    moduleResults: [],
    httpLoadStatus: null,
    detectionValidationStatus: null,
    completedAgents: [],
    failedAgent: null,
    error,
  };
}

function temporalStatus(name: string): WorkflowProgress['status'] {
  switch (name) {
    case 'RUNNING':
    case 'CONTINUED_AS_NEW':
    case 'PAUSED':
      return 'running';
    case 'COMPLETED':
      return 'completed';
    case 'CANCELLED':
      return 'cancelled';
    default:
      return 'failed';
  }
}

function isWorkflowNotFound(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  return error.name === 'WorkflowNotFoundError' || /workflow.*not found/i.test(error.message);
}

function candidateText(value: unknown, fallback: string, maxLength = 500): string {
  if (typeof value !== 'string' || value.trim().length === 0) return fallback;
  return new SecretRedactor().redactText(value.trim()).slice(0, maxLength);
}

function labelsMatch(container: ContainerState, attempt: RunAttempt): boolean {
  return Object.entries(attempt.dockerLabels).every(([key, value]) => container.labels[key] === value);
}

function callBeforeDeadline<T>(deadline: number, operation: (timeoutMs: number) => Promise<T>): Promise<T> {
  const timeoutMs = Math.max(1, deadline - Date.now());
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const finish = (callback: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      callback();
    };
    const timer = setTimeout(
      () => finish(() => reject(new ControlDeadlineExceededError('Temporal control call exceeded its deadline'))),
      timeoutMs,
    );
    Promise.resolve()
      .then(() => operation(timeoutMs))
      .then(
        (value) => finish(() => resolve(value)),
        (error: unknown) => finish(() => reject(error)),
      );
  });
}

async function waitForSpawn(process: SpawnProcess): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const finish = (error?: Error): void => {
      if (settled) return;
      settled = true;
      if (error) reject(error);
      else resolve();
    };
    process.once('error', finish);
    process.once('exit', (code) =>
      finish(code === 0 ? undefined : new Error(`docker run exited with code ${code ?? 1}`)),
    );
  });
}

export class DefaultScanRuntime implements ScanRuntime {
  private readonly client = createDockerClient();

  prepare(version: string): Promise<void> {
    return this.client.prepare(version);
  }

  spawn(options: WorkerOptions): SpawnProcess {
    return this.client.spawn(options);
  }

  inspectContainer(containerName: string): Promise<ContainerState | null> {
    return this.client.inspectContainer(containerName);
  }

  listManagedContainers(): Promise<ContainerState[]> {
    return this.client.listManagedContainers();
  }

  stopContainer(containerName: string): Promise<void> {
    return this.client.stopContainer(containerName);
  }
}

export class DynamicTemporalGateway implements TemporalGateway {
  constructor(
    private readonly address = process.env.TEMPORAL_ADDRESS ?? '127.0.0.1:7233',
    private readonly importer: (specifier: string) => Promise<unknown> = (specifier) => import(specifier),
    private readonly workspacePathForInput: (input: TemporalPipelineInput) => string = (input) =>
      path.join(getWorkspacesDir(), input.sessionId),
  ) {}

  async startWorkflow(request: TemporalWorkflowStart, timeoutMs = CONTROL_CALL_TIMEOUT_MS): Promise<StartedWorkflow> {
    const protectedInput = await protectTemporalInput(request.input, this.workspacePathForInput(request.input));
    try {
      return await this.withClient(async (client) => {
        const handle = await client.workflow.start('pentestPipelineWorkflow', {
          taskQueue: request.taskQueue,
          workflowId: request.workflowId,
          args: [protectedInput.input],
        });
        return { workflowId: request.workflowId, temporalRunId: handle.firstExecutionRunId };
      }, timeoutMs);
    } catch (error) {
      await discardStagedTemporalSecret(protectedInput.stagedSecretPath);
      throw error;
    }
  }

  async getWorkflow(workflowId: string, timeoutMs = CONTROL_CALL_TIMEOUT_MS): Promise<TemporalWorkflowState | null> {
    try {
      return await this.withClient(async (client) => {
        const handle = client.workflow.getHandle(workflowId);
        const description = await handle.describe();
        const describedStatus = temporalStatus(description.status.name);

        if (description.status.name === 'COMPLETED') {
          try {
            const result = WorkflowProgressSchema.safeParse(await handle.result());
            if (result.success) {
              return { workflowId, status: result.data.status, progress: { ...result.data, workflowId } };
            }
          } catch {
            // The description remains authoritative when a completed result cannot be decoded.
          }
        }

        if (describedStatus === 'running') {
          try {
            const queried = WorkflowProgressSchema.parse(await handle.query<unknown>('getProgress'));
            return { workflowId, status: queried.status, progress: { ...queried, workflowId } };
          } catch {
            // The query handler may not be registered until the worker begins polling.
          }
        }

        const error =
          describedStatus === 'failed' ? `Temporal workflow ${description.status.name.toLowerCase()}` : null;
        return { workflowId, status: describedStatus, progress: workflowProgress(workflowId, describedStatus, error) };
      }, timeoutMs);
    } catch (error) {
      if (isWorkflowNotFound(error)) return null;
      throw error;
    }
  }

  async cancelWorkflow(workflowId: string, timeoutMs = CONTROL_CALL_TIMEOUT_MS): Promise<boolean> {
    try {
      return await this.withClient(async (client) => {
        await client.workflow.getHandle(workflowId).cancel();
        return true;
      }, timeoutMs);
    } catch (error) {
      if (isWorkflowNotFound(error)) return false;
      throw error;
    }
  }

  private async withClient<T>(
    operation: (client: InstanceType<TemporalClientModule['Client']>) => Promise<T>,
    timeoutMs: number,
  ): Promise<T> {
    const module = (await this.importer('@temporalio/client')) as TemporalClientModule;
    const connection = await module.Connection.connect({ address: this.address, connectTimeout: timeoutMs });
    try {
      const client = new module.Client({ connection });
      return await connection.withDeadline(Date.now() + Math.max(1, timeoutMs), () => operation(client));
    } finally {
      await connection.close();
    }
  }
}

export class ScanController {
  readonly workspacesDir: string;
  private readonly version: string;
  private readonly runtime: ScanRuntime;
  private readonly temporal: TemporalGateway;
  private readonly now: () => Date;
  private readonly suffix: () => string;
  private readonly credentialLoader: () => void;
  private readonly secretResolver: (references: SecretReferences) => Promise<TargetSecrets>;
  private readonly cancelGraceMs: number;
  private readonly managesDefaultHome: boolean;
  private readonly activeMutations = new Set<string>();

  constructor(options: ScanControllerOptions) {
    this.version = options.version;
    this.managesDefaultHome = options.workspacesDir === undefined;
    this.workspacesDir = path.resolve(options.workspacesDir ?? getWorkspacesDir());
    this.runtime = options.runtime ?? new DefaultScanRuntime();
    this.temporal =
      options.temporal ??
      new DynamicTemporalGateway(undefined, undefined, (input) => path.join(this.workspacesDir, input.sessionId));
    this.now = options.now ?? (() => new Date());
    this.suffix = options.suffix ?? (() => crypto.randomBytes(4).toString('hex'));
    this.cancelGraceMs = options.cancelGraceMs ?? CANCEL_GRACE_MS;
    this.secretResolver = options.secretResolver ?? (async () => ({}));
    this.credentialLoader =
      options.credentialLoader ??
      (() => {
        loadEnv();
        const validation = validateCredentials();
        if (!validation.valid) throw new Error(validation.error ?? 'Provider credentials are not configured');
      });
  }

  private requireProviderCredentials(providerConfig: ProviderConfig | undefined): void {
    if (hasProviderCredentials(providerConfig)) return;
    this.credentialLoader();
    if (providerConfig && !providerConfigMatchesConfiguredModel(providerConfig)) {
      throw new Error('Provider credentials must be supplied again for this model selection');
    }
  }

  async initialize(): Promise<RunListItem[]> {
    if (this.managesDefaultHome) initHome();
    await ensureDirectory(this.workspacesDir, 0o777);
    const runs = await this.reconcileRuns();
    await this.cleanupEphemeralConfigs();
    return runs;
  }

  async startRun(value: RunLaunchSpec): Promise<ManagedRunRecord> {
    const parsed = RunLaunchSpecSchema.parse(value);
    if (parsed.sourceMode === 'url-only' && containsCodePathRules(parsed.config)) {
      throw new Error('code_path rules require a source-assisted assessment');
    }

    const referencedSecrets = await this.secretResolver(parsed.secretRefs ?? {});
    const effectiveSecrets = { ...referencedSecrets, ...(parsed.secrets ?? {}) };
    const missingReferences = SECRET_FIELDS.filter((field) => parsed.secretRefs?.[field] && !effectiveSecrets[field]);
    if (missingReferences.length > 0) {
      throw new Error(`Target secrets must be supplied again: ${missingReferences.join(', ')}`);
    }
    if (parsed.config.detectionValidation && !effectiveSecrets.splunkToken) {
      throw new Error('Detection validation requires a Splunk token');
    }

    this.requireProviderCredentials(parsed.providerConfig);
    const repoPath = parsed.repoPath ? await this.resolveRepository(parsed.repoPath) : undefined;
    const normalized = RunLaunchSpecSchema.parse({
      ...parsed,
      secrets: effectiveSecrets,
      ...(repoPath && { repoPath }),
      ...(parsed.outputPath && { outputPath: path.resolve(parsed.outputPath) }),
    });
    const runId = parsed.workspace ?? safeWorkspaceName(parsed.targetUrl, this.now());
    assertSafeIdentifier(runId, 'run ID');

    return this.withMutation(runId, async () => {
      const workspacePath = this.workspacePath(runId);
      if (await pathExists(workspacePath)) throw new Error(`Workspace already exists: ${runId}`);
      await this.createWorkspaceDirectories(workspacePath);

      const timestamp = this.now().toISOString();
      const snapshot = createRunSnapshot(normalized);
      let run = ManagedRunRecordSchema.parse({
        kind: 'managed',
        version: 1,
        runId,
        workspacePath,
        status: 'pending',
        snapshot,
        snapshotHash: hashRunSnapshot(snapshot),
        attempts: [],
        createdAt: timestamp,
        updatedAt: timestamp,
      });
      await this.writeRun(run);

      try {
        await this.runtime.prepare(this.version);
      } catch (error) {
        const message = safeErrorMessage(error, new SecretRedactor(Object.values(effectiveSecrets)));
        run = await this.updateRun(run, {
          status: 'failed',
          completedAt: this.now().toISOString(),
          lastError: message,
        });
        throw new Error(message);
      }
      return this.launchAttempt(run, effectiveSecrets, normalized.providerConfig, {
        authorizationConfirmed: normalized.authorizationConfirmed === true,
        elevatedLoadConfirmed: normalized.elevatedLoadConfirmed === true,
      });
    });
  }

  async cancelRun(runId: string): Promise<ManagedRunRecord> {
    return this.withMutation(runId, async () => {
      let run = await this.requireManagedRun(runId);
      if (isTerminal(run.status)) return run;
      const attempt = run.attempts.at(-1);
      if (!attempt) {
        return this.updateRun(run, {
          status: 'cancelled',
          completedAt: this.now().toISOString(),
        });
      }

      const deadline = Date.now() + this.cancelGraceMs;
      let cancellationTimedOut = false;
      try {
        await callBeforeDeadline(deadline, (timeoutMs) => this.temporal.cancelWorkflow(attempt.workflowId, timeoutMs));
      } catch (error) {
        cancellationTimedOut = error instanceof ControlDeadlineExceededError;
        // The labeled worker is the cancellation fallback when Temporal is unavailable.
      }

      let workflow: TemporalWorkflowState | null = null;
      if (!cancellationTimedOut) {
        try {
          workflow = await callBeforeDeadline(deadline, (timeoutMs) =>
            this.temporal.getWorkflow(attempt.workflowId, timeoutMs),
          );
          while (workflow?.status === 'running' && Date.now() < deadline) {
            await new Promise((resolve) => setTimeout(resolve, Math.min(250, Math.max(1, deadline - Date.now()))));
            workflow = await callBeforeDeadline(deadline, (timeoutMs) =>
              this.temporal.getWorkflow(attempt.workflowId, timeoutMs),
            );
          }
        } catch {
          workflow = null;
        }
      }

      if (workflow && workflow.status !== 'running') {
        run = await this.applyWorkflowState(run, workflow);
        await this.cleanupRuntimeConfig(run.runId);
        return run;
      }

      await this.stopExpectedContainer(attempt);
      run = await this.finishRun(run, 'cancelled', undefined, 'user');
      await this.cleanupRuntimeConfig(run.runId);
      return run;
    });
  }

  async resumeRun(
    runId: string,
    suppliedSecrets: TargetSecrets = {},
    suppliedProviderConfig?: ProviderConfig,
    loadAuthorization: { authorizationConfirmed?: boolean; elevatedLoadConfirmed?: boolean } = {},
  ): Promise<ManagedRunRecord> {
    return this.withMutation(runId, async () => {
      let run = await this.requireManagedRun(runId);
      if (run.status !== 'failed' && run.status !== 'cancelled') {
        throw new Error(`Run cannot be resumed while ${run.status}`);
      }
      this.assertSnapshotIntegrity(run);

      const referencedSecrets = await this.secretResolver(run.snapshot.secretRefs);
      const secrets = { ...referencedSecrets, ...suppliedSecrets };
      const missing = run.snapshot.requiredSecretFields.filter((field) => !secrets[field]);
      if (missing.length > 0) throw new Error(`Target secrets must be supplied again: ${missing.join(', ')}`);

      if (run.snapshot.sourceMode === 'source-assisted') {
        const repository = await this.resolveRepository(run.snapshot.repoPath as string);
        if (repository !== run.snapshot.repoPath) {
          throw new Error('The repository snapshot path no longer resolves to the original directory');
        }
      }

      const providerConfig = mergeAttemptProviderConfig(run.snapshot.providerConfig, suppliedProviderConfig);
      assertHttpLoadAuthorization(
        run.snapshot.config.httpLoad,
        loadAuthorization.authorizationConfirmed === true,
        loadAuthorization.elevatedLoadConfirmed === true,
      );
      if (run.snapshot.config.detectionValidation && loadAuthorization.authorizationConfirmed !== true) {
        throw new Error('Detection validation requires ownership or written authorization confirmation');
      }
      this.requireProviderCredentials(providerConfig);
      await this.runtime.prepare(this.version);
      run = await this.updateRun(run, { status: 'pending' }, ['completedAt', 'lastError']);
      return this.launchAttempt(run, secrets, providerConfig, loadAuthorization);
    });
  }

  async getRunProgress(runId: string): Promise<WorkflowProgress | null> {
    const item = await this.readRunItem(runId);
    if (item.kind === 'legacy') return null;
    const attempt = item.attempts.at(-1);
    if (!attempt) return null;

    try {
      const workflow = await this.temporal.getWorkflow(attempt.workflowId, CONTROL_CALL_TIMEOUT_MS);
      if (!workflow) return null;
      if (!this.activeMutations.has(runId)) {
        const updated = await this.applyWorkflowState(item, workflow);
        if (isTerminal(updated.status)) await this.cleanupRuntimeConfig(updated.runId);
      }
      return workflow.progress;
    } catch {
      return null;
    }
  }

  async listRuns(): Promise<RunListItem[]> {
    return this.reconcileRuns();
  }

  async reconcileRuns(): Promise<RunListItem[]> {
    await ensureDirectory(this.workspacesDir, 0o777);
    const records = await this.readAllRunItems();
    const managed = records.filter((record): record is ManagedRunRecord => record.kind === 'managed');
    const legacy = records.filter((record): record is LegacyRunRecord => record.kind === 'legacy');

    let containers: ContainerState[] | null = null;
    try {
      containers = await this.runtime.listManagedContainers();
    } catch {
      // Docker outages must not be interpreted as missing containers.
    }

    const reconciled: ManagedRunRecord[] = [];
    for (const run of managed) {
      if (this.activeMutations.has(run.runId)) {
        reconciled.push(run);
        continue;
      }
      try {
        reconciled.push(await this.reconcileManagedRun(run, containers));
      } catch {
        reconciled.push(run);
      }
    }

    if (containers) await this.stopOrphanContainers(containers, reconciled);
    return [...reconciled, ...legacy].sort((left, right) => right.createdAt.localeCompare(left.createdAt));
  }

  async getRunDetail(runId: string): Promise<RunDetail> {
    const progress = await this.getRunProgress(runId);
    const run = await this.readRunItem(runId);
    const deliverables = await this.resolveDeliverablesPath(runId);
    const triage = await this.readTriage(deliverables);
    const unvalidatedFindings = triage ? [] : await this.readUnvalidatedFindings(deliverables);
    const evidenceFiles = [...new Set((triage?.verdicts ?? []).map((entry) => entry.evidenceFile))].filter((filename) =>
      this.isSafeArtifactName(filename),
    );
    const session = await this.readSession(runId);
    const reportArtifacts = await this.getReportArtifacts(runId);
    let detectionValidation: DetectionValidationSummary | undefined;
    try {
      detectionValidation = detectionValidationSummary(
        await readJsonIfExists(path.join(deliverables, DETECTION_VALIDATION_FILE)),
      );
    } catch {
      // Detection evidence is optional; a malformed artifact must not hide the rest of Run Detail.
    }
    return {
      run,
      progress,
      metrics: session?.metrics ?? null,
      triage,
      unvalidatedFindings,
      reportAvailable: reportArtifacts.some((artifact) => artifact.kind === 'markdown'),
      reportArtifacts,
      evidenceFiles,
      ...(detectionValidation && { detectionValidation }),
    };
  }

  async readActivity(runId: string, offset: number): Promise<ActivityChunk> {
    const run = await this.readRunItem(runId);
    const logPath = await this.resolveWorkspaceFile(runId, WORKFLOW_LOG);
    const chunk = await readFileChunk(logPath, offset);
    return {
      offset: chunk.offset,
      text: new SecretRedactor().redactText(chunk.text),
      done: isTerminal(run.status),
    };
  }

  async getReport(runId: string): Promise<ReportData> {
    const run = await this.readRunItem(runId);
    const reportPath = await this.resolveReportPath(runId);
    if (!reportPath) throw new Error('Report not found');
    const rawMarkdown = await fs.readFile(reportPath, 'utf8');
    const sourceMode = run.kind === 'managed' ? run.snapshot.sourceMode : (run.sourceMode ?? 'source-assisted');
    const markdown =
      sourceMode === 'url-only' && !/assessment mode:\s*url-only|## Mode\s+URL-Only/i.test(rawMarkdown)
        ? `${URL_ONLY_REPORT_CONTEXT}\n\n${rawMarkdown}`
        : rawMarkdown;
    return {
      filename: path.basename(reportPath),
      markdown: sanitizeReportMarkdown(markdown),
      sourceMode,
      coverageNotice: sourceMode === 'url-only' ? URL_ONLY_NOTICE : null,
    };
  }

  async getArtifactPath(runId: string, filename: string): Promise<string> {
    assertSafeIdentifier(runId, 'run ID');
    if ([REPORT_DATA_FILE, PDF_REPORT_FILE, FINAL_PDF_REPORT_FILENAME, SARIF_REPORT_FILE].includes(filename)) {
      throw new Error('Report artifacts require the fixed report download endpoint');
    }
    if (!this.isSafeArtifactName(filename)) throw new Error('Artifact is not allowlisted');
    if (filename === REPORT_FILE || filename === FINAL_REPORT_FILENAME) {
      const reportPath = await this.resolveReportPath(runId);
      if (!reportPath) throw new Error('Report not found');
      return reportPath;
    }

    const deliverables = await this.resolveDeliverablesPath(runId);
    const triage = await this.readTriage(deliverables);
    const allowedEvidence = new Set((triage?.verdicts ?? []).map((entry) => entry.evidenceFile));
    if (!allowedEvidence.has(filename)) throw new Error('Artifact is not referenced by triage');
    return resolveExistingContainedPath(deliverables, filename);
  }

  async getReportArtifactPath(runId: string, kind: ReportArtifactKind): Promise<string> {
    if (!REPORT_ARTIFACT_KINDS.includes(kind)) throw new Error('Invalid report artifact kind');
    await this.readRunItem(runId);
    const filePath = await this.resolveReportArtifactPath(runId, kind);
    if (!filePath) throw new Error(`${kind} report artifact not found`);
    return filePath;
  }

  private async launchAttempt(
    run: ManagedRunRecord,
    secrets: TargetSecrets,
    runtimeProviderConfig?: ProviderConfig,
    loadAuthorization: { authorizationConfirmed?: boolean; elevatedLoadConfirmed?: boolean } = {},
  ): Promise<ManagedRunRecord> {
    this.assertSnapshotIntegrity(run);
    const attemptNumber = run.attempts.length + 1;
    const suffix = this.suffix();
    const taskQueue = `shannon-${suffix}`;
    const workflowId = `${run.runId}-attempt-${attemptNumber}-${suffix}`;
    const containerName = `shannon-worker-${suffix}`;
    const dockerLabels = {
      'shannon.managed': 'true',
      'shannon.run': run.runId,
      'shannon.workspace': run.runId,
      'shannon.attempt': String(attemptNumber),
      'shannon.workflow': workflowId,
    };
    const createdAt = this.now().toISOString();
    const attempt: RunAttempt = {
      attemptNumber,
      taskQueue,
      workflowId,
      containerName,
      dockerLabels,
      createdAt,
      status: 'pending',
    };
    run = await this.updateRun(run, { status: 'pending', attempts: [...run.attempts, attempt] });

    try {
      const workingRoot =
        run.snapshot.sourceMode === 'source-assisted'
          ? (run.snapshot.repoPath as string)
          : path.join(this.internalPath(run.runId), 'runtime', 'target');
      const containerRoot =
        run.snapshot.sourceMode === 'source-assisted' ? `/repos/${path.basename(workingRoot)}` : '/app/target';
      const config = workerConfig(run.snapshot.config, secrets);
      const configPath = hasWorkerConfig(config) ? await this.materializeConfig(run.runId, config) : undefined;
      const containerConfigPath = configPath ? `/app/configs/${run.runId}.yaml` : undefined;
      const providerConfig = mergeAttemptProviderConfig(run.snapshot.providerConfig, runtimeProviderConfig);
      const usesConfiguredCredentials = !providerConfig || !hasProviderCredentials(providerConfig);
      const providerCredentialFiles = usesConfiguredCredentials ? resolveProviderCredentialFiles() : [];

      const started = await this.temporal.startWorkflow(
        {
          workflowId,
          taskQueue,
          input: this.temporalInput(
            run,
            attemptNumber,
            workflowId,
            containerRoot,
            containerConfigPath,
            providerConfig,
            loadAuthorization,
          ),
        },
        CONTROL_CALL_TIMEOUT_MS,
      );
      run = await this.updateRun(run, {
        attempts: this.updateAttempt(run.attempts, attemptNumber, { temporalRunId: started.temporalRunId }),
      });

      const outputDir = run.snapshot.outputPath;
      if (outputDir) await ensureDirectory(outputDir, 0o755);
      if (run.snapshot.sourceMode === 'source-assisted') await this.prepareRepositoryOverlayMounts(workingRoot);
      const promptsDir = isLocal() ? path.resolve('apps/worker/prompts') : undefined;
      const options: WorkerOptions = {
        version: this.version,
        repo: { hostPath: workingRoot, containerPath: containerRoot },
        workspacesDir: this.workspacesDir,
        taskQueue,
        workflowId,
        containerName,
        envFlags: buildEnvFlags({ includeProvider: usesConfiguredCredentials }),
        ...(providerCredentialFiles.length > 0 && { providerCredentialFiles }),
        workspace: run.runId,
        workingDirectory: containerRoot,
        sourceMode: run.snapshot.sourceMode,
        labels: dockerLabels,
        ...(configPath && { config: { hostPath: configPath, containerPath: containerConfigPath as string } }),
        ...(promptsDir && { promptsDir }),
        ...(outputDir && { outputDir }),
        ...(run.snapshot.debug && { debug: true }),
      };
      await waitForSpawn(this.runtime.spawn(options));

      const startedAt = this.now().toISOString();
      return this.updateRun(run, {
        status: 'running',
        attempts: this.updateAttempt(run.attempts, attemptNumber, { status: 'running', startedAt }),
      });
    } catch (error) {
      try {
        await this.temporal.cancelWorkflow(workflowId, CONTROL_CALL_TIMEOUT_MS);
      } catch {
        // The workflow may not have been created or Temporal may be unavailable.
      }
      await this.stopExpectedContainer(attempt);
      const message = safeErrorMessage(
        error,
        new SecretRedactor([...Object.values(secrets), ...providerCredentialValues(runtimeProviderConfig)]),
      );
      const failed = await this.updateRun(run, {
        status: 'failed',
        completedAt: this.now().toISOString(),
        lastError: message,
        attempts: this.updateAttempt(run.attempts, attemptNumber, {
          status: 'failed',
          cancellationReason: 'start-failure',
          completedAt: this.now().toISOString(),
          error: message,
        }),
      });
      await this.cleanupRuntimeConfig(failed.runId);
      throw new Error(message);
    }
  }

  private temporalInput(
    run: ManagedRunRecord,
    attemptNumber: number,
    workflowId: string,
    containerRoot: string,
    configPath: string | undefined,
    providerConfig: ProviderConfig | undefined,
    loadAuthorization: { authorizationConfirmed?: boolean; elevatedLoadConfirmed?: boolean },
  ): TemporalPipelineInput {
    const pipeline = run.snapshot.config.pipeline;
    return {
      webUrl: run.snapshot.targetUrl,
      sourceMode: run.snapshot.sourceMode,
      workingDirectory: containerRoot,
      ...(run.snapshot.sourceMode === 'source-assisted' && { repoPath: containerRoot }),
      ...(configPath && { configPath }),
      ...(providerConfig && { providerConfig }),
      workflowId,
      sessionId: run.runId,
      ...(attemptNumber > 1 && { resumeFromWorkspace: run.runId }),
      ...(run.snapshot.pipelineTesting && { pipelineTestingMode: true }),
      ...(pipeline && {
        pipelineConfig: {
          ...(pipeline.retryPreset && { retry_preset: pipeline.retryPreset }),
          ...(pipeline.maxConcurrentPipelines !== undefined && {
            max_concurrent_pipelines: pipeline.maxConcurrentPipelines,
          }),
        },
      }),
      ...(run.snapshot.config.testCategories && { vulnClasses: [...run.snapshot.config.testCategories] }),
      ...(run.snapshot.config.testScopes && { testScopes: [...run.snapshot.config.testScopes] }),
      ...(run.snapshot.config.testSurfaces && { testSurfaces: [...run.snapshot.config.testSurfaces] }),
      ...(run.snapshot.config.httpLoad && {
        httpLoad: { ...run.snapshot.config.httpLoad },
        httpLoadAuthorizationConfirmed: loadAuthorization.authorizationConfirmed === true,
        elevatedLoadConfirmed: loadAuthorization.elevatedLoadConfirmed === true,
      }),
      ...(run.snapshot.config.detectionValidation && {
        detectionValidation: { ...run.snapshot.config.detectionValidation },
        detectionValidationAuthorizationConfirmed: loadAuthorization.authorizationConfirmed === true,
      }),
      ...(run.snapshot.config.assessmentModules && {
        assessmentModules: [...run.snapshot.config.assessmentModules],
      }),
      ...(run.snapshot.config.moduleSafety && { moduleSafety: { ...run.snapshot.config.moduleSafety } }),
      ...(run.snapshot.config.safeDemonstration !== undefined && {
        safeDemonstration: run.snapshot.config.safeDemonstration,
      }),
    };
  }

  private async reconcileManagedRun(
    current: ManagedRunRecord,
    containers: ContainerState[] | null,
  ): Promise<ManagedRunRecord> {
    let run = current;
    const attempt = run.attempts.at(-1);
    if (!attempt) {
      if (run.status === 'pending') {
        run = await this.updateRun(run, {
          status: 'failed',
          completedAt: this.now().toISOString(),
          lastError: 'Run did not create a workflow attempt',
        });
      }
      return run;
    }

    if (containers) {
      for (const oldAttempt of run.attempts.slice(0, -1)) {
        const oldContainer = containers.find((container) => container.name === oldAttempt.containerName);
        const canStop = !isTerminal(oldAttempt.status) || this.terminalContainerGraceElapsed(oldAttempt);
        if (canStop && oldContainer?.running && labelsMatch(oldContainer, oldAttempt)) {
          await this.runtime.stopContainer(oldContainer.name);
        }
      }
    }

    const acknowledgedTerminal =
      run.status === 'completed' ||
      (run.status === 'failed' && attempt.cancellationReason !== 'orphaned-worker') ||
      (run.status === 'cancelled' && attempt.cancellationReason !== 'user');
    if (acknowledgedTerminal) {
      if (containers && this.terminalContainerGraceElapsed(attempt)) {
        await this.stopAttemptContainerFromList(attempt, containers);
      }
      await this.cleanupRuntimeConfig(run.runId);
      return run;
    }

    let workflow: TemporalWorkflowState | null;
    try {
      workflow = await this.temporal.getWorkflow(attempt.workflowId, CONTROL_CALL_TIMEOUT_MS);
    } catch {
      return run;
    }

    if (!workflow) {
      if (!isTerminal(run.status)) {
        if (containers) await this.stopAttemptContainerFromList(attempt, containers);
        run = await this.finishRun(run, 'failed', 'Temporal workflow was not found');
      }
      return run;
    }

    if (workflow.status !== 'running') {
      run = await this.applyWorkflowState(run, workflow);
      if (containers && this.terminalContainerGraceElapsed(run.attempts.at(-1))) {
        await this.stopAttemptContainerFromList(attempt, containers);
      }
      if (isTerminal(run.status)) await this.cleanupRuntimeConfig(run.runId);
      return run;
    }

    if (run.status === 'cancelled' || attempt.cancellationReason === 'orphaned-worker') {
      try {
        await this.temporal.cancelWorkflow(attempt.workflowId, CONTROL_CALL_TIMEOUT_MS);
      } catch {
        // Preserve the recorded terminal intent during a Temporal outage.
      }
      if (containers) await this.stopAttemptContainerFromList(attempt, containers);
      return run;
    }

    if (containers) {
      const container = containers.find((candidate) => candidate.name === attempt.containerName);
      if (!container?.running || !labelsMatch(container, attempt)) {
        try {
          await this.temporal.cancelWorkflow(attempt.workflowId, CONTROL_CALL_TIMEOUT_MS);
        } catch {
          // The failed record preserves the explicit-resume recovery path.
        }
        return this.finishRun(run, 'failed', 'Worker container is missing for an open workflow', 'orphaned-worker');
      }
    }

    if (run.status === 'pending') run = await this.updateRun(run, { status: 'running' });
    return run;
  }

  private async applyWorkflowState(run: ManagedRunRecord, workflow: TemporalWorkflowState): Promise<ManagedRunRecord> {
    const attempt = run.attempts.at(-1);
    if (!attempt) return run;
    let status: RunStatus = workflow.status;
    if (workflow.status === 'cancelled' && attempt.cancellationReason === 'orphaned-worker') status = 'failed';
    if (status === 'running') {
      if (run.status === 'pending') return this.updateRun(run, { status: 'running' });
      return run;
    }
    if (run.status === status && attempt.status === status) return run;
    return this.finishRun(run, status, workflow.progress.error ?? undefined, attempt.cancellationReason);
  }

  private terminalContainerGraceElapsed(attempt: RunAttempt | undefined): boolean {
    if (!attempt?.completedAt) return false;
    return this.now().getTime() - new Date(attempt.completedAt).getTime() >= TERMINAL_CONTAINER_GRACE_MS;
  }

  private async finishRun(
    run: ManagedRunRecord,
    status: Exclude<RunStatus, 'pending' | 'running'>,
    error?: string,
    cancellationReason?: RunAttempt['cancellationReason'],
  ): Promise<ManagedRunRecord> {
    const attempt = run.attempts.at(-1);
    const completedAt = this.now().toISOString();
    const attempts = attempt
      ? this.updateAttempt(run.attempts, attempt.attemptNumber, {
          status,
          completedAt,
          ...(error && { error: safeErrorMessage(error) }),
          ...(cancellationReason && { cancellationReason }),
        })
      : run.attempts;
    return this.updateRun(
      run,
      {
        status,
        attempts,
        completedAt,
        ...(error && { lastError: safeErrorMessage(error) }),
      },
      error ? [] : ['lastError'],
    );
  }

  private async stopExpectedContainer(attempt: RunAttempt): Promise<void> {
    try {
      const container = await this.runtime.inspectContainer(attempt.containerName);
      if (container?.running && labelsMatch(container, attempt))
        await this.runtime.stopContainer(attempt.containerName);
    } catch {
      // Stopping is best-effort when Docker is unavailable.
    }
  }

  private async stopAttemptContainerFromList(attempt: RunAttempt, containers: ContainerState[]): Promise<void> {
    const container = containers.find((candidate) => candidate.name === attempt.containerName);
    if (container?.running && labelsMatch(container, attempt)) await this.runtime.stopContainer(container.name);
  }

  private async stopOrphanContainers(containers: ContainerState[], runs: ManagedRunRecord[]): Promise<void> {
    const knownAttempts = runs.flatMap((run) => run.attempts);
    for (const container of containers) {
      if (!container.running) continue;
      const matchingAttempt = knownAttempts.some(
        (attempt) => attempt.containerName === container.name && labelsMatch(container, attempt),
      );
      if (!matchingAttempt) await this.runtime.stopContainer(container.name);
    }
  }

  private updateAttempt(attempts: RunAttempt[], attemptNumber: number, patch: Partial<RunAttempt>): RunAttempt[] {
    return attempts.map((attempt) =>
      attempt.attemptNumber === attemptNumber ? ({ ...attempt, ...patch } as RunAttempt) : attempt,
    );
  }

  private async updateRun(
    current: ManagedRunRecord,
    patch: RunPatch,
    clear: readonly ClearableRunField[] = [],
  ): Promise<ManagedRunRecord> {
    const value: Record<string, unknown> = {
      ...current,
      ...patch,
      updatedAt: this.now().toISOString(),
    };
    for (const field of clear) delete value[field];
    const next = ManagedRunRecordSchema.parse(value);
    this.assertSnapshotIntegrity(next);
    await this.writeRun(next);
    return next;
  }

  private async writeRun(run: ManagedRunRecord): Promise<void> {
    await atomicWriteJson(path.join(this.internalPath(run.runId), RUN_FILE), run, 0o600);
    await ensureDirectory(this.internalPath(run.runId), 0o777);
  }

  private assertSnapshotIntegrity(run: ManagedRunRecord): void {
    if (hashRunSnapshot(run.snapshot) !== run.snapshotHash) {
      throw new Error(`Run snapshot integrity check failed for ${run.runId}: snapshot hash does not match`);
    }
  }

  private async requireManagedRun(runId: string): Promise<ManagedRunRecord> {
    const item = await this.readRunItem(runId);
    if (item.kind === 'legacy') throw new Error('Legacy workspaces are read-only and cannot be managed');
    return item;
  }

  private async readRunItem(runId: string): Promise<RunListItem> {
    assertSafeIdentifier(runId, 'run ID');
    const managed = await this.readManagedRun(runId);
    if (managed) return managed;
    const legacy = await this.readLegacyRun(runId);
    if (legacy) return legacy;
    throw new Error(`Run not found: ${runId}`);
  }

  private async readManagedRun(runId: string): Promise<ManagedRunRecord | null> {
    const raw = await readJsonIfExists(path.join(this.internalPath(runId), RUN_FILE));
    if (!raw) return null;
    const run = ManagedRunRecordSchema.parse(raw);
    if (run.workspacePath !== this.workspacePath(runId))
      throw new Error('Run workspace path does not match its run ID');
    this.assertSnapshotIntegrity(run);
    return run;
  }

  private async readAllRunItems(): Promise<RunListItem[]> {
    const entries = await fs.readdir(this.workspacesDir, { withFileTypes: true });
    const records: RunListItem[] = [];
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      try {
        const managed = await this.readManagedRun(entry.name);
        if (managed) records.push(managed);
        else {
          const legacy = await this.readLegacyRun(entry.name);
          if (legacy) records.push(legacy);
        }
      } catch {
        // A corrupt or unrelated directory is isolated from the rest of the control plane.
      }
    }
    return records;
  }

  private async readLegacyRun(runId: string): Promise<LegacyRunRecord | null> {
    const session = await this.readSession(runId);
    const reportPath = await this.resolveReportPath(runId);
    if (!session && !reportPath) return null;
    const workspacePath = this.workspacePath(runId);
    const stat = await fs.stat(workspacePath);
    const fallback = stat.birthtime.toISOString();
    const createdAt = normalizeTimestamp(session?.session.createdAt, fallback);
    const completedAt = session?.session.completedAt
      ? normalizeTimestamp(session.session.completedAt, stat.mtime.toISOString())
      : reportPath
        ? stat.mtime.toISOString()
        : undefined;
    const status = session ? legacyStatus(session.session.status) : 'completed';
    return LegacyRunRecordSchema.parse({
      kind: 'legacy',
      runId,
      workspacePath,
      status,
      targetUrl: session?.session.webUrl ?? null,
      sourceMode: session ? (session.session.repoPath ? 'source-assisted' : 'url-only') : null,
      ...(session?.session.repoPath && { repoPath: session.session.repoPath }),
      createdAt,
      updatedAt: completedAt ?? createdAt,
      ...(completedAt && { completedAt }),
      readOnly: true,
    });
  }

  private async readSession(runId: string): Promise<LegacySession | null> {
    try {
      const sessionPath = await this.resolveWorkspaceFile(runId, SESSION_FILE, true);
      const raw = await readJsonIfExists(sessionPath);
      return raw ? LegacySessionSchema.parse(raw) : null;
    } catch {
      return null;
    }
  }

  private async resolveWorkspaceFile(runId: string, filename: string, allowMissing = false): Promise<string> {
    const workspace = this.workspacePath(runId);
    const current = path.join(workspace, INTERNAL_DIR, filename);
    if (await pathExists(current)) return current;
    const legacy = path.join(workspace, filename);
    if (await pathExists(legacy)) return legacy;
    if (allowMissing) return current;
    return current;
  }

  private async resolveDeliverablesPath(runId: string): Promise<string> {
    const current = path.join(this.internalPath(runId), 'deliverables');
    if (await pathExists(current)) return current;
    const legacy = path.join(this.workspacePath(runId), 'deliverables');
    return (await pathExists(legacy)) ? legacy : current;
  }

  private async resolveReportPath(runId: string): Promise<string | null> {
    return this.resolveReportArtifactPath(runId, 'markdown');
  }

  private async getReportArtifacts(runId: string): Promise<ReportArtifact[]> {
    const artifacts: ReportArtifact[] = [];
    for (const kind of REPORT_ARTIFACT_KINDS) {
      const filePath = await this.resolveReportArtifactPath(runId, kind);
      if (!filePath) continue;
      artifacts.push({
        kind,
        filename: path.basename(filePath),
        contentType: REPORT_ARTIFACT_DEFINITIONS[kind].contentType,
      });
    }
    return artifacts;
  }

  private async resolveReportArtifactPath(runId: string, kind: ReportArtifactKind): Promise<string | null> {
    assertSafeIdentifier(runId, 'run ID');
    const definition = REPORT_ARTIFACT_DEFINITIONS[kind];
    if (!definition) throw new Error('Invalid report artifact kind');

    let workspacesRoot: string;
    let workspaceRoot: string;
    try {
      workspacesRoot = await fs.realpath(this.workspacesDir);
      const workspace = path.join(workspacesRoot, runId);
      if ((await fs.lstat(workspace)).isSymbolicLink()) return null;
      workspaceRoot = await fs.realpath(workspace);
      const relativeWorkspace = path.relative(workspacesRoot, workspaceRoot);
      if (relativeWorkspace.startsWith('..') || path.isAbsolute(relativeWorkspace)) return null;
    } catch {
      return null;
    }

    for (const relativePath of definition.candidates) {
      let current = workspaceRoot;
      let rejected = false;
      try {
        for (const segment of relativePath.split(path.sep)) {
          current = path.join(current, segment);
          if ((await fs.lstat(current)).isSymbolicLink()) {
            rejected = true;
            break;
          }
        }
        if (rejected) continue;
        return await resolveExistingContainedPath(workspaceRoot, relativePath);
      } catch {
        // Missing, non-file, and symlinked candidates are unavailable; try the next fixed legacy location.
      }
    }
    return null;
  }

  private async readTriage(deliverables: string): Promise<RunDetail['triage']> {
    try {
      const raw = await readJsonIfExists(path.join(deliverables, TRIAGE_FILE));
      return raw ? TriageVerdictsSchema.parse(raw) : null;
    } catch {
      return null;
    }
  }

  private async readUnvalidatedFindings(deliverables: string): Promise<UnvalidatedFinding[]> {
    const findings: UnvalidatedFinding[] = [];
    for (const [vulnType, filename] of Object.entries(QUEUE_FILES) as Array<[VulnerabilityClass, string]>) {
      try {
        const raw = await readJsonIfExists(path.join(deliverables, filename));
        if (!raw || typeof raw !== 'object' || Array.isArray(raw)) continue;
        const entries = (raw as { vulnerabilities?: unknown }).vulnerabilities;
        if (!Array.isArray(entries)) continue;
        for (const [index, value] of entries.slice(0, 100).entries()) {
          if (!value || typeof value !== 'object' || Array.isArray(value)) continue;
          const candidate = value as Record<string, unknown>;
          findings.push({
            id: candidateText(candidate.ID, `${vulnType}-${index + 1}`, 128),
            vulnType,
            title: candidateText(candidate.vulnerability_type, `${vulnType.toUpperCase()} candidate`, 200),
            reason: candidateText(
              candidate.notes ??
                candidate.mismatch_reason ??
                candidate.exploitation_hypothesis ??
                candidate.missing_defense ??
                candidate.guard_evidence ??
                candidate.reason,
              'Candidate was produced by analysis but did not receive a triage verdict.',
            ),
          });
        }
      } catch {
        // A malformed queue is isolated and remains available only as a raw workspace artifact.
      }
    }
    return findings;
  }

  private async resolveRepository(repoPath: string): Promise<string> {
    let candidate = repoPath;
    if (isLocal() && !repoPath.startsWith('/') && !repoPath.startsWith('.'))
      candidate = path.resolve('repos', repoPath);
    else candidate = path.resolve(repoPath);
    let realPath: string;
    try {
      realPath = await fs.realpath(candidate);
    } catch {
      throw new Error(`Repository not found: ${candidate}`);
    }
    if (!(await fs.stat(realPath)).isDirectory()) throw new Error(`Repository is not a directory: ${realPath}`);
    return realPath;
  }

  private async createWorkspaceDirectories(workspacePath: string): Promise<void> {
    await ensureDirectory(workspacePath, 0o777);
    const internal = path.join(workspacePath, INTERNAL_DIR);
    await ensureDirectory(internal, 0o777);
    for (const relative of [
      'deliverables',
      'scratchpad',
      '.playwright-cli',
      '.playwright',
      path.join('runtime', 'target', '.shannon', 'deliverables'),
      path.join('runtime', 'target', '.shannon', 'scratchpad'),
      path.join('runtime', 'target', '.shannon', '.playwright-cli'),
      path.join('runtime', 'target', '.playwright'),
    ]) {
      await ensureDirectory(path.join(internal, relative), 0o777);
    }
  }

  private async prepareRepositoryOverlayMounts(repoPath: string): Promise<void> {
    for (const relative of [
      path.join('.shannon', 'deliverables'),
      path.join('.shannon', 'scratchpad'),
      path.join('.shannon', '.playwright-cli'),
      '.playwright',
    ]) {
      await ensureDirectory(path.join(repoPath, relative), 0o755);
    }
  }

  private async materializeConfig(runId: string, config: Record<string, unknown>): Promise<string> {
    const configPath = path.join(this.internalPath(runId), 'runtime', 'worker-config.yaml');
    await atomicWriteFile(configPath, dumpYaml(config, { noRefs: true, lineWidth: 120 }), 0o600);
    return configPath;
  }

  private async cleanupEphemeralConfigs(): Promise<void> {
    const records = await this.readAllRunItems();
    await Promise.all(
      records
        .filter((record): record is ManagedRunRecord => record.kind === 'managed' && isTerminal(record.status))
        .map((record) => this.cleanupRuntimeConfig(record.runId)),
    );
  }

  private async cleanupRuntimeConfig(runId: string): Promise<void> {
    await fs.rm(path.join(this.internalPath(runId), 'runtime', 'worker-config.yaml'), { force: true });
    await fs.rm(path.join(this.internalPath(runId), 'runtime', WORKFLOW_SECRET_DIR), {
      force: true,
      recursive: true,
    });
  }

  private async withMutation<T>(runId: string, operation: () => Promise<T>): Promise<T> {
    assertSafeIdentifier(runId, 'run ID');
    if (this.activeMutations.has(runId)) throw new Error(`Run is already being modified: ${runId}`);
    this.activeMutations.add(runId);
    try {
      return await operation();
    } finally {
      this.activeMutations.delete(runId);
    }
  }

  private workspacePath(runId: string): string {
    assertSafeIdentifier(runId, 'run ID');
    return path.join(this.workspacesDir, runId);
  }

  private internalPath(runId: string): string {
    return path.join(this.workspacePath(runId), INTERNAL_DIR);
  }

  private isSafeArtifactName(filename: string): boolean {
    return (
      filename === path.basename(filename) &&
      filename.length <= 255 &&
      /\.(?:md|json|txt|png|jpe?g|webp)$/i.test(filename)
    );
  }
}
