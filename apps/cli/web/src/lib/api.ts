import type {
  ActivityEntry,
  ApiErrorBody,
  BootstrapResponse,
  CreateRunRequest,
  Finding,
  PaginatedRuns,
  PipelineStage,
  Profile,
  ProfileSummary,
  ReportArtifactKind,
  ReportSeverity,
  RunDetail,
  RunStatus,
  RunStreamEvent,
  SaveProfileRequest,
  SecretPersistence,
  SecurityTestCategory,
  Severity,
  SourceMode,
  TargetSecretField,
  TargetSecrets,
} from '../types/api';
import { securityTestCategories } from '../types/api';

const API_ROOT = '/api/v1';

interface RawConfig {
  testCategories?: SecurityTestCategory[];
  safeDemonstration?: boolean;
  /** @deprecated Use safeDemonstration. */
  demonstrate?: boolean;
  pipeline?: { maxConcurrentPipelines?: number; retryPreset?: string };
  rules?: { focus?: RawRule[]; avoid?: RawRule[] };
  report?: { minSeverity?: string; minConfidence?: string; guidance?: string; sarif?: boolean };
  rulesOfEngagement?: string;
  authentication?: {
    loginType: 'form' | 'sso' | 'api' | 'basic';
    loginUrl: string;
    username: string;
    emailAddress?: string;
    loginFlow?: string[];
    successCondition: {
      type: 'url_contains' | 'element_present' | 'url_equals_exactly' | 'text_contains';
      value: string;
    };
  };
}

interface RawRule {
  description: string;
  type: string;
  value: string;
}

interface RawRunSnapshot {
  targetUrl: string;
  sourceMode: SourceMode;
  repoPath?: string;
  config: RawConfig;
  requiredSecretFields: TargetSecretField[];
}

interface RawRunAttempt {
  attemptNumber: number;
  startedAt?: string;
}

interface RawManagedRunRecord {
  kind: 'managed';
  runId: string;
  workspacePath: string;
  status: RunStatus;
  snapshot: RawRunSnapshot;
  attempts: RawRunAttempt[];
  createdAt: string;
  updatedAt: string;
  completedAt?: string;
  lastError?: string;
}

interface RawLegacyRunRecord {
  kind: 'legacy';
  runId: string;
  workspacePath: string;
  status: RunStatus;
  targetUrl: string | null;
  sourceMode: SourceMode | null;
  repoPath?: string;
  createdAt: string;
  updatedAt: string;
  completedAt?: string;
  readOnly: true;
}

type RawRunRecord = RawManagedRunRecord | RawLegacyRunRecord;

interface RawProgress {
  status: 'running' | 'completed' | 'failed' | 'cancelled';
  currentPhase: string | null;
  currentAgent: string | null;
  activeAgents?: string[];
  activeTestCategories?: SecurityTestCategory[];
  expectedAgents?: string[];
  completedAgents: string[];
  failedAgent: string | null;
  error: string | null;
  elapsedMs?: number;
  triageRan?: boolean;
  summary?: { totalCostUsd: number; totalDurationMs: number } | null;
}

interface RawVerdict {
  id: string;
  vulnType: string;
  title: string;
  verdict: 'PASS' | 'DOWNGRADE' | 'KILL' | 'CHAIN_REQUIRED';
  severity: Severity;
  claimedSeverity?: Severity;
  reason: string;
  evidenceFile: string;
}

interface RawRunDetail {
  run: RawRunRecord;
  progress: RawProgress | null;
  metrics: { total_duration_ms?: number; total_cost_usd?: number } | null;
  triage: { version: 1; verdicts: RawVerdict[] } | null;
  unvalidatedFindings?: Array<{ id: string; vulnType: SecurityTestCategory; title: string; reason: string }>;
  reportAvailable: boolean;
  reportArtifacts?: Array<{
    kind: ReportArtifactKind;
    filename: string;
    contentType: string;
  }>;
  evidenceFiles: string[];
}

interface RawProfile {
  version: 1;
  id: string;
  name: string;
  targetUrl: string;
  sourceMode: SourceMode;
  repoPath?: string;
  config: RawConfig;
  hasSecret: Partial<Record<'password' | 'totpSecret' | 'emailPassword' | 'emailTotpSecret', boolean>>;
  updatedAt: string;
}

interface RawBootstrap {
  csrfToken: string;
  version: string;
  platform: string;
  secretStore: { persistence: 'keychain' | 'memory'; available: boolean };
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string | undefined;
  readonly fieldErrors: Record<string, string[]> | undefined;

  constructor(message: string, status: number, body?: ApiErrorBody) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = body?.error?.code;
    this.fieldErrors = body?.error?.fieldErrors;
  }
}

let bootstrapPromise: Promise<BootstrapResponse> | undefined;
let bootstrapValue: BootstrapResponse | undefined;

async function parseError(response: Response): Promise<ApiError> {
  let body: ApiErrorBody | undefined;
  try {
    body = (await response.json()) as ApiErrorBody;
  } catch {
    body = undefined;
  }
  return new ApiError(
    body?.error?.message ?? body?.message ?? `Request failed (${response.status})`,
    response.status,
    body,
  );
}

function persistence(value: 'keychain' | 'memory' | undefined): SecretPersistence {
  return value === 'keychain' ? 'keychain' : 'session';
}

export async function bootstrap(force = false): Promise<BootstrapResponse> {
  if (force) {
    bootstrapPromise = undefined;
    bootstrapValue = undefined;
  }
  bootstrapPromise ??= fetch(`${API_ROOT}/bootstrap`, {
    credentials: 'same-origin',
    headers: { Accept: 'application/json' },
  }).then(async (response) => {
    if (!response.ok) throw await parseError(response);
    const envelope = (await response.json()) as { data: RawBootstrap };
    const raw = envelope.data;
    const secretPersistence = persistence(raw.secretStore.persistence);
    bootstrapValue = {
      csrfToken: raw.csrfToken,
      version: raw.version,
      platform: raw.platform,
      secretStore: {
        persistence: secretPersistence,
        label: secretPersistence === 'keychain' ? 'macOS Keychain' : 'Session-only secrets',
        available: raw.secretStore.available,
      },
    };
    return bootstrapValue;
  });
  return bootstrapPromise;
}

function isMutation(method: string): boolean {
  return !['GET', 'HEAD', 'OPTIONS'].includes(method.toUpperCase());
}

async function request<T>(path: string, init: RequestInit = {}, retry = true): Promise<T> {
  const method = init.method ?? 'GET';
  const headers = new Headers(init.headers);
  headers.set('Accept', 'application/json');
  if (init.body && !(init.body instanceof FormData)) headers.set('Content-Type', 'application/json');
  if (isMutation(method)) {
    const session = bootstrapValue ?? (await bootstrap());
    headers.set('X-Shannon-CSRF', session.csrfToken);
  }
  const response = await fetch(`${API_ROOT}${path}`, { ...init, headers, credentials: 'same-origin' });
  if ((response.status === 401 || response.status === 403) && retry) {
    await bootstrap(true);
    return request<T>(path, init, false);
  }
  if (!response.ok) throw await parseError(response);
  if (response.status === 204) return undefined as T;
  const body = (await response.json()) as { data?: T } | T;
  return typeof body === 'object' && body !== null && 'data' in body ? (body.data as T) : (body as T);
}

function jsonBody(value: unknown): RequestInit {
  return { body: JSON.stringify(value) };
}

function expectedAgents(run: RawRunRecord): string[] {
  const spec = runSpec(run);
  const categories = spec.config.testCategories ?? [...securityTestCategories];
  const agents = spec.sourceMode === 'source-assisted' ? ['pre-recon', 'recon'] : ['recon'];
  const safeDemonstration = spec.config.safeDemonstration ?? spec.config.demonstrate ?? true;
  for (const category of categories) {
    agents.push(`${category}-vuln`);
    if (safeDemonstration) agents.push(`${category}-exploit`);
  }
  agents.push('triage', 'report');
  return agents;
}

function runSpec(run: RawRunRecord): RawRunSnapshot {
  if (run.kind === 'managed') return run.snapshot;
  return {
    targetUrl: run.targetUrl ?? 'Unknown legacy target',
    sourceMode: run.sourceMode ?? 'source-assisted',
    ...(run.repoPath && { repoPath: run.repoPath }),
    config: {},
    requiredSecretFields: [],
  };
}

function stageLabel(agent: string): string {
  const labels: Record<string, string> = {
    'pre-recon': 'Source pre-recon',
    recon: 'Live reconnaissance',
    triage: 'Evidence triage',
    report: 'Final report',
  };
  if (labels[agent]) return labels[agent];
  const [category, phase] = agent.split('-');
  const categoryLabel =
    category === 'authz' ? 'Authorization' : category === 'auth' ? 'Authentication' : category?.toUpperCase();
  return `${categoryLabel ?? agent} ${phase === 'exploit' ? 'demonstration' : 'testing'}`;
}

function stageLane(agent: string): string {
  const category = agent.split('-')[0];
  const labels: Record<SecurityTestCategory, string> = {
    injection: 'Injection',
    xss: 'Cross-site scripting',
    auth: 'Authentication',
    authz: 'Authorization',
    ssrf: 'Server-side request forgery',
  };
  return securityTestCategories.includes(category as SecurityTestCategory)
    ? labels[category as SecurityTestCategory]
    : 'Core';
}

function toStages(raw: RawRunDetail): PipelineStage[] {
  const progress = raw.progress;
  const planned = progress?.expectedAgents ?? expectedAgents(raw.run);
  const completed = new Set(progress?.completedAgents ?? []);
  const active = new Set(progress?.activeAgents ?? []);
  return planned.map((agent) => {
    let status: PipelineStage['status'] = 'pending';
    if (!progress && raw.run.status === 'completed') status = 'unavailable';
    else if (completed.has(agent)) status = 'completed';
    else if (active.has(agent) || progress?.currentAgent === agent) status = 'running';
    else if (raw.run.status === 'completed') status = 'skipped';
    else if (raw.run.status === 'cancelled') status = 'cancelled';
    else if (raw.run.status === 'failed' && progress?.failedAgent === agent) status = 'failed';
    return {
      id: agent,
      label: stageLabel(agent),
      lane: stageLane(agent),
      status,
      ...(status === 'unavailable' && { detail: 'Status unavailable' }),
    };
  });
}

function toFinding(verdict: RawVerdict): Finding {
  const mappedVerdict: Finding['verdict'] =
    verdict.verdict === 'KILL' ? 'ruled-out' : verdict.verdict === 'CHAIN_REQUIRED' ? 'needs-review' : 'confirmed';
  return {
    id: verdict.id,
    title: verdict.title,
    vulnType: verdict.vulnType,
    severity: verdict.severity,
    ...(verdict.claimedSeverity && { claimedSeverity: verdict.claimedSeverity }),
    verdict: mappedVerdict,
    reason: verdict.reason,
    evidence: [{ id: verdict.evidenceFile, name: verdict.evidenceFile }],
  };
}

function toUnvalidatedFinding(finding: NonNullable<RawRunDetail['unvalidatedFindings']>[number]): Finding {
  return {
    id: finding.id,
    title: finding.title,
    vulnType: finding.vulnType,
    severity: 'info',
    verdict: 'unvalidated',
    reason: finding.reason,
  };
}

function toRunSummary(run: RawRunRecord, detail?: RawRunDetail): RunDetail {
  const spec = runSpec(run);
  const attempts = run.kind === 'managed' ? run.attempts : [];
  const progress = detail?.progress;
  const plan = progress?.expectedAgents ?? expectedAgents(run);
  const completedCount = run.status === 'completed' ? plan.length : (progress?.completedAgents.length ?? 0);
  const findings =
    detail?.triage?.verdicts.map(toFinding) ?? detail?.unvalidatedFindings?.map(toUnvalidatedFinding) ?? [];
  const activeAgents = progress?.activeAgents ?? [];
  const elapsedMs = progress?.elapsedMs ?? detail?.metrics?.total_duration_ms;
  const costUsd = progress?.summary?.totalCostUsd ?? detail?.metrics?.total_cost_usd;
  const result: RunDetail = {
    id: run.runId,
    workspaceId: run.runId,
    targetUrl: spec.targetUrl,
    status: run.status,
    sourceMode: spec.sourceMode,
    ...(spec.repoPath && { repoPath: spec.repoPath }),
    scope: {
      testCategories: spec.config.testCategories ?? [...securityTestCategories],
      safeDemonstration: spec.config.safeDemonstration ?? spec.config.demonstrate ?? true,
      concurrency: spec.config.pipeline?.maxConcurrentPipelines ?? 5,
    },
    progress: {
      completed: completedCount,
      total: plan.length,
      percent: plan.length > 0 ? (completedCount / plan.length) * 100 : 0,
      activeAgents,
      activeTestCategories: progress?.activeTestCategories ?? [],
    },
    metrics: {
      ...(elapsedMs !== undefined && { elapsedMs }),
      ...(costUsd !== undefined && { costUsd }),
      findings: findings.filter((finding) => finding.verdict !== 'ruled-out').length,
      activeAgents: activeAgents.length,
    },
    createdAt: run.createdAt,
    ...(attempts[0]?.startedAt && { startedAt: attempts[0].startedAt }),
    updatedAt: run.updatedAt,
    ...(run.completedAt && { completedAt: run.completedAt }),
    canCancel: run.kind === 'managed' && ['pending', 'running'].includes(run.status),
    canResume: run.kind === 'managed' && ['failed', 'cancelled'].includes(run.status),
    stages: detail ? toStages(detail) : [],
    findings,
    activity: [],
    attempt: Math.max(1, attempts.length),
    ...(spec.sourceMode === 'url-only' && {
      coverageNotice:
        'URL-only mode used browser and API observations; code-level coverage and source-location attribution were unavailable.',
    }),
    triageValidated: detail?.triage !== null && detail?.triage !== undefined,
    reportAvailable: detail?.reportAvailable ?? false,
    reportArtifacts:
      detail?.reportArtifacts ??
      (detail?.reportAvailable
        ? [
            {
              kind: 'markdown',
              filename: 'comprehensive_security_assessment_report.md',
              contentType: 'text/markdown; charset=utf-8',
            },
          ]
        : []),
    requiredSecretFields: spec.requiredSecretFields,
    ...(((run.kind === 'managed' && run.lastError) || progress?.error) && {
      failure: {
        message: (run.kind === 'managed' ? run.lastError : undefined) ?? progress?.error ?? 'Run failed',
      },
    }),
  };
  return result;
}

function toProfile(raw: RawProfile): Profile {
  const secretPersistence = bootstrapValue?.secretStore.persistence ?? 'session';
  const auth = raw.config.authentication;
  return {
    version: 1,
    id: raw.id,
    name: raw.name,
    targetUrl: raw.targetUrl,
    sourceMode: raw.sourceMode,
    ...(raw.repoPath && { repoPath: raw.repoPath }),
    updatedAt: raw.updatedAt,
    secretState: {
      password: { present: raw.hasSecret.password === true, persistence: secretPersistence },
      totp: { present: raw.hasSecret.totpSecret === true, persistence: secretPersistence },
    },
    scope: {
      testCategories: raw.config.testCategories ?? [...securityTestCategories],
      safeDemonstration: raw.config.safeDemonstration ?? raw.config.demonstrate ?? true,
      concurrency: raw.config.pipeline?.maxConcurrentPipelines ?? 5,
    },
    ...(auth && {
      authentication: {
        enabled: true,
        loginType: auth.loginType,
        loginUrl: auth.loginUrl,
        username: auth.username,
        ...(auth.emailAddress && { email: auth.emailAddress }),
        ...(auth.loginFlow && { loginFlow: auth.loginFlow }),
        successCondition: auth.successCondition,
      },
    }),
    rules: {
      focus: (raw.config.rules?.focus ?? []).map((rule) => rule.value),
      avoid: (raw.config.rules?.avoid ?? []).map((rule) => rule.value),
      ...(raw.config.rulesOfEngagement && { rulesOfEngagement: raw.config.rulesOfEngagement }),
    },
    report: {
      ...(raw.config.report?.minSeverity && { minSeverity: raw.config.report.minSeverity as ReportSeverity }),
      ...(raw.config.report?.minConfidence && {
        minConfidence: raw.config.report.minConfidence as NonNullable<Profile['report']['minConfidence']>,
      }),
      ...(raw.config.report?.guidance && { guidance: raw.config.report.guidance }),
      sarif: raw.config.report?.sarif ?? false,
    },
  };
}

function configBody(input: CreateRunRequest | SaveProfileRequest): RawConfig {
  const auth = input.authentication;
  const rule = (value: string): RawRule => ({ description: value, type: 'url_path', value });
  return {
    testCategories: input.scope.testCategories,
    safeDemonstration: input.scope.safeDemonstration,
    pipeline: { maxConcurrentPipelines: input.scope.concurrency },
    rules: { focus: input.rules.focus.map(rule), avoid: input.rules.avoid.map(rule) },
    report: input.report,
    ...(input.rules.rulesOfEngagement && { rulesOfEngagement: input.rules.rulesOfEngagement }),
    ...(auth && {
      authentication: {
        loginType: auth.loginType,
        loginUrl: auth.loginUrl,
        username: auth.username,
        ...(auth.email && { emailAddress: auth.email }),
        ...(auth.loginFlow?.length && { loginFlow: auth.loginFlow }),
        successCondition: auth.successCondition,
      },
    }),
  };
}

function targetSecrets(input: CreateRunRequest | SaveProfileRequest) {
  const password = input.secrets?.password ?? input.authentication?.password;
  const totpSecret = input.secrets?.totpSecret ?? input.authentication?.totpSecret;
  return { ...(password && { password }), ...(totpSecret && { totpSecret }) };
}

function profileBody(input: SaveProfileRequest) {
  return {
    name: input.name,
    targetUrl: input.targetUrl,
    sourceMode: input.sourceMode,
    ...(input.repoPath && { repoPath: input.repoPath }),
    config: configBody(input),
    secrets: targetSecrets(input),
    ...(input.clearSecrets?.length && { clearSecrets: input.clearSecrets }),
  };
}

async function getRun(id: string): Promise<RunDetail> {
  const raw = await request<RawRunDetail>(`/runs/${encodeURIComponent(id)}`);
  return toRunSummary(raw.run, raw);
}

async function createRun(input: CreateRunRequest): Promise<RunDetail> {
  let profileId = input.profileId;
  if (input.saveProfile) {
    const profile = await api.createProfile({ ...input, name: input.saveProfile.name });
    profileId = profile.id;
  }
  const run = await request<RawRunRecord>('/runs', {
    method: 'POST',
    ...jsonBody({
      ...(profileId && { profileId }),
      targetUrl: input.targetUrl,
      sourceMode: input.sourceMode,
      ...(input.repoPath && { repoPath: input.repoPath }),
      config: configBody(input),
      secrets: targetSecrets(input),
      authorizationConfirmed: true,
    }),
  });
  return getRun(run.runId);
}

export const api = {
  bootstrap,
  listRuns: async (search = ''): Promise<PaginatedRuns> => {
    const raw = await request<RawRunRecord[]>('/runs');
    const needle = search.toLowerCase();
    const items = raw
      .map((run) => toRunSummary(run))
      .filter((run) => !needle || `${run.targetUrl} ${run.id}`.toLowerCase().includes(needle));
    return { items, total: items.length };
  },
  getRun,
  createRun,
  cancelRun: async (id: string) => {
    const run = await request<RawRunRecord>(`/runs/${encodeURIComponent(id)}/cancel`, { method: 'POST' });
    return getRun(run.runId);
  },
  resumeRun: async (id: string, secrets: TargetSecrets = {}) => {
    const run = await request<RawRunRecord>(`/runs/${encodeURIComponent(id)}/resume`, {
      method: 'POST',
      ...jsonBody({ ...(Object.keys(secrets).length > 0 && { secrets }) }),
    });
    return getRun(run.runId);
  },
  getReport: async (id: string) =>
    (await request<{ markdown: string }>(`/runs/${encodeURIComponent(id)}/report`)).markdown,
  reportDownloadUrl: (id: string) => `${API_ROOT}/runs/${encodeURIComponent(id)}/report?download=1`,
  reportArtifactDownloadUrl: (id: string, kind: ReportArtifactKind) =>
    `${API_ROOT}/runs/${encodeURIComponent(id)}/reports/${kind}`,
  artifactUrl: (runId: string, artifactId: string) =>
    `${API_ROOT}/runs/${encodeURIComponent(runId)}/artifacts/${encodeURIComponent(artifactId)}`,
  listProfiles: async (): Promise<{ items: ProfileSummary[] }> => ({
    items: (await request<RawProfile[]>('/profiles')).map(toProfile),
  }),
  getProfile: async (id: string) => toProfile(await request<RawProfile>(`/profiles/${encodeURIComponent(id)}`)),
  createProfile: async (input: SaveProfileRequest) =>
    toProfile(await request<RawProfile>('/profiles', { method: 'POST', ...jsonBody(profileBody(input)) })),
  updateProfile: async (id: string, input: SaveProfileRequest) =>
    toProfile(
      await request<RawProfile>(`/profiles/${encodeURIComponent(id)}`, {
        method: 'PUT',
        ...jsonBody(profileBody(input)),
      }),
    ),
  deleteProfile: (id: string) => request<void>(`/profiles/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  importProfile: async (yaml: string) =>
    toProfile(await request<RawProfile>('/profiles/import', { method: 'POST', ...jsonBody({ yaml }) })),
  profileExportUrl: (id: string) => `${API_ROOT}/profiles/${encodeURIComponent(id)}/export`,
};

export interface RunSubscription {
  close: () => void;
}

function activityEntries(text: string, offset: number): ActivityEntry[] {
  return text
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line, index) => {
      const timestampMatch = line.match(/^\[([^\]]+)\]\s*(.*)$/);
      const message = timestampMatch?.[2] ?? line;
      const lower = message.toLowerCase();
      const level: ActivityEntry['level'] =
        lower.includes('error') || lower.includes('failed')
          ? 'error'
          : lower.includes('warn') || lower.includes('unvalidated')
            ? 'warning'
            : lower.includes('complete') || lower.includes('success')
              ? 'success'
              : 'info';
      return {
        id: `${offset}-${index}`,
        timestamp:
          timestampMatch?.[1] && !Number.isNaN(Date.parse(timestampMatch[1]))
            ? timestampMatch[1]
            : new Date().toISOString(),
        level,
        source: 'workflow',
        message,
      };
    });
}

export function subscribeToRun(
  runId: string,
  handlers: { onOpen: () => void; onEvent: (event: RunStreamEvent) => void; onError: () => void },
): RunSubscription {
  const source = new EventSource(`${API_ROOT}/runs/${encodeURIComponent(runId)}/events`, { withCredentials: true });
  source.onopen = handlers.onOpen;
  source.onerror = handlers.onError;
  source.addEventListener('snapshot', (event) => {
    const raw = JSON.parse(event.data) as RawRunDetail;
    handlers.onEvent({ type: 'snapshot', run: toRunSummary(raw.run, raw) });
  });
  source.addEventListener('activity', (event) => {
    const raw = JSON.parse(event.data) as { offset: number; text: string };
    handlers.onEvent({ type: 'activity', entries: activityEntries(raw.text, raw.offset) });
  });
  source.addEventListener('heartbeat', () => {
    handlers.onEvent({ type: 'heartbeat', timestamp: new Date().toISOString() });
  });
  return { close: () => source.close() };
}
