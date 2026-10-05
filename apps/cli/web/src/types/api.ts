import type {
  AssessmentModule,
  AssessmentTestScope,
  AssessmentTestSurface,
  ModuleSafetyConfig,
  OwaspCategory,
  TargetEnvironment,
} from '../../../src/security-scopes';

export type { HttpLoadSettings } from '../../../src/http-load';
export {
  HTTP_LOAD_DEFAULTS,
  HTTP_LOAD_ELEVATED_THRESHOLDS,
  HTTP_LOAD_EMERGENCY_LIMITS,
  HTTP_LOAD_SCOPE,
  isElevatedHttpLoad,
} from '../../../src/http-load';
export {
  assessmentModuleDefinitions,
  assessmentModuleIds,
  assessmentScopeCatalog,
  assessmentScopeDefinitions,
  assessmentTestScopeIds,
  assessmentTestSurfaceIds,
  availableTestScopes,
  availableTestSurfaces,
  defaultAssessmentModules,
  deriveTestCategories,
  expandTestCategories,
  getOwaspCategorySelection,
  normalizeAssessmentModules,
  normalizeTestScopeSelection,
  selectableTestScopes,
  setOwaspCategorySelected,
  testSurfaceDefinitions,
} from '../../../src/security-scopes';
export type {
  AssessmentModule,
  AssessmentTestScope,
  AssessmentTestSurface,
  ModuleSafetyConfig,
  OwaspCategory,
  TargetEnvironment,
};

export const securityTestCategories = ['injection', 'xss', 'auth', 'authz', 'ssrf'] as const;
export type SecurityTestCategory = (typeof securityTestCategories)[number];

export const severities = ['critical', 'high', 'medium', 'low'] as const;
export type Severity = (typeof severities)[number] | 'info';
export type ReportSeverity = (typeof severities)[number];
export type Confidence = 'low' | 'medium' | 'high';

export type SourceMode = 'source-assisted' | 'url-only';
export type RunStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
export type StageStatus =
  | 'pending'
  | 'running'
  | 'completed'
  | 'partial'
  | 'failed'
  | 'skipped'
  | 'cancelled'
  | 'unavailable';
export type ModuleExecutionStatus = 'completed' | 'partial' | 'failed' | 'skipped' | 'unavailable';
export type FindingVerdict = 'confirmed' | 'unvalidated' | 'needs-review' | 'ruled-out';
export type SecretPersistence = 'keychain' | 'session' | 'unavailable';
export type TargetSecretField = 'password' | 'totpSecret' | 'emailPassword' | 'emailTotpSecret' | 'splunkToken';
export type TargetSecrets = Partial<Record<TargetSecretField, string>>;
export type OpenAIFormat = 'chat-completions' | 'responses';

export interface BootstrapResponse {
  csrfToken: string;
  version: string;
  platform: string;
  secretStore: {
    persistence: SecretPersistence;
    label: string;
    available: boolean;
  };
  model: ConfiguredModelDescription;
}

export interface ConfiguredModelDescription {
  providerId: string;
  providerLabel: string;
  modelId: string;
  credentialConfigured: boolean;
  catalogAvailable: boolean;
  providerConfig: Omit<ProviderConfig, 'model' | 'apiKey' | 'authToken'>;
}

export interface ModelCatalogItem {
  id: string;
  name: string;
  contextLength?: number;
}

export interface ModelCatalog {
  provider: ConfiguredModelDescription;
  items: ModelCatalogItem[];
}

export interface RunScope {
  testCategories: SecurityTestCategory[];
  testScopes: AssessmentTestScope[];
  testSurfaces: AssessmentTestSurface[];
  safeDemonstration: boolean;
  concurrency: number;
  httpLoad?: import('../../../src/http-load').HttpLoadSettings;
  detectionValidation?: DetectionValidationSettings;
  assessmentModules: AssessmentModule[];
  moduleSafety: ModuleSafetyConfig;
}

export interface DetectionValidationSettings {
  canaryPath: string;
  minimumDetectionRate: number;
  maxWaitSeconds: number;
  splunk: {
    managementUrl: string;
    telemetryIndex: string;
    alertIndex: string;
    telemetrySourcetype?: string;
    alertSourcetype?: string;
  };
}

export interface DetectionValidationSummary {
  status: 'passed' | 'failed' | 'partial' | 'unavailable';
  detectionGapPercentagePoints: number;
  cohorts: Record<
    'ai' | 'human',
    {
      total: number;
      detected: number;
      detectionRate: number;
      threshold: number;
      passed: boolean;
      medianLatencyMs?: number;
    }
  >;
  scenarios: Array<{
    id: string;
    cohort: 'ai' | 'human';
    technique: string;
    emissionStatus: 'sent' | 'error';
    detected: boolean;
    latencyMs?: number;
  }>;
}

export interface RunProgress {
  completed: number;
  total: number;
  percent: number;
  activeAgents: string[];
  activeTestCategories: SecurityTestCategory[];
  activeModules: AssessmentModule[];
  moduleResults: Array<{
    id: AssessmentModule;
    status: ModuleExecutionStatus;
    evidencePath?: string;
  }>;
  httpLoadStatus: 'completed' | 'interrupted' | 'incomplete' | null;
  detectionValidationStatus: DetectionValidationSummary['status'] | null;
}

export interface RunMetrics {
  elapsedMs?: number;
  costUsd?: number;
  findings?: number;
  activeAgents?: number;
}

export interface RunSummary {
  id: string;
  workspaceId: string;
  targetUrl: string;
  status: RunStatus;
  sourceMode: SourceMode;
  repoPath?: string;
  scope: RunScope;
  progress: RunProgress;
  metrics?: RunMetrics;
  createdAt: string;
  startedAt?: string;
  updatedAt: string;
  completedAt?: string;
  canCancel: boolean;
  canResume: boolean;
}

export interface PipelineStage {
  id: string;
  label: string;
  lane: string;
  status: StageStatus;
  detail?: string;
  durationMs?: number;
}

export interface EvidenceArtifact {
  id: string;
  name: string;
  sizeBytes?: number;
}

export interface Finding {
  id: string;
  title: string;
  vulnType: string;
  severity: Severity;
  claimedSeverity?: Severity;
  verdict: FindingVerdict;
  description?: string;
  reason?: string;
  evidence?: EvidenceArtifact[];
}

export interface ActivityEntry {
  id: string;
  timestamp: string;
  level: 'info' | 'success' | 'warning' | 'error';
  source?: string;
  message: string;
}

export interface RunDetail extends RunSummary {
  stages: PipelineStage[];
  findings: Finding[];
  activity: ActivityEntry[];
  attempt: number;
  coverageNotice?: string;
  triageValidated: boolean;
  reportAvailable: boolean;
  reportArtifacts: ReportArtifact[];
  requiredSecretFields: TargetSecretField[];
  detectionValidation?: DetectionValidationSummary;
  failure?: { code?: string; message: string };
}

export type ReportArtifactKind = 'markdown' | 'pdf' | 'sarif';

export interface ReportArtifact {
  kind: ReportArtifactKind;
  filename: string;
  contentType: string;
}

export interface PaginatedRuns {
  items: RunSummary[];
  total: number;
}

export interface SecretState {
  present: boolean;
  persistence: SecretPersistence;
}

export interface AuthenticationConfig {
  enabled: boolean;
  loginType: 'form' | 'sso' | 'api' | 'basic';
  loginUrl: string;
  username: string;
  email?: string;
  loginFlow?: string[];
  successCondition: {
    type: 'url_contains' | 'element_present' | 'url_equals_exactly' | 'text_contains';
    value: string;
  };
  password?: string;
  totpSecret?: string;
}

export interface AssessmentRules {
  focus: string[];
  avoid: string[];
  rulesOfEngagement?: string;
}

export interface ReportFilters {
  minSeverity?: ReportSeverity;
  minConfidence?: Confidence;
  guidance?: string;
  sarif?: boolean;
}

export interface AssessmentConfiguration {
  targetUrl: string;
  sourceMode: SourceMode;
  repoPath?: string;
  scope: RunScope;
  authentication?: AuthenticationConfig;
  rules: AssessmentRules;
  report: ReportFilters;
  secrets?: TargetSecrets;
}

export interface ProviderConfig {
  providerType?: string;
  providerId?: string;
  model: string;
  apiKey?: string;
  authToken?: string;
  awsRegion?: string;
  awsAccessKeyId?: string;
  awsSecretAccessKey?: string;
  awsSessionToken?: string;
  baseUrl?: string;
  openAIFormat?: OpenAIFormat;
  supportsStructuredOutput?: boolean;
}

export interface CreateRunRequest extends AssessmentConfiguration {
  profileId?: string;
  providerConfig?: ProviderConfig;
  saveProfile?: { name: string };
  authorizationConfirmed: true;
  elevatedLoadConfirmed?: true;
}

export interface ProfileSummary {
  id: string;
  name: string;
  targetUrl: string;
  sourceMode: SourceMode;
  updatedAt: string;
  secretState: { password: SecretState; totp: SecretState; splunkToken: SecretState };
}

export interface Profile extends ProfileSummary {
  version: 1;
  repoPath?: string;
  scope: RunScope;
  authentication?: Omit<AuthenticationConfig, 'password' | 'totpSecret'>;
  rules: AssessmentRules;
  report: ReportFilters;
}

export interface SaveProfileRequest extends AssessmentConfiguration {
  name: string;
  clearSecrets?: TargetSecretField[];
}

export interface ApiErrorBody {
  error?: { code?: string; message?: string; fieldErrors?: Record<string, string[]> };
  message?: string;
}

export type RunStreamEvent =
  | { type: 'snapshot'; run: RunDetail }
  | { type: 'activity'; entries: ActivityEntry[] }
  | { type: 'heartbeat'; timestamp: string };
