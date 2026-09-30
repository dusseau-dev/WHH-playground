import { z } from 'zod';
import {
  assertExclusiveHttpLoadExecution,
  assertHttpLoadAuthorization,
  HTTP_LOAD_EMERGENCY_LIMITS,
  normalizeHttpLoadSettings,
} from './http-load.js';
import {
  assessmentModuleIds,
  assessmentTestScopeIds,
  assessmentTestSurfaceIds,
  normalizeAssessmentModules,
  normalizeTestScopeSelection,
} from './security-scopes.js';

export const SOURCE_MODES = ['source-assisted', 'url-only'] as const;
export const SourceModeSchema = z.enum(SOURCE_MODES);
export type SourceMode = z.infer<typeof SourceModeSchema>;

export const VULNERABILITY_CLASSES = ['injection', 'xss', 'auth', 'authz', 'ssrf'] as const;
export const VulnerabilityClassSchema = z.enum(VULNERABILITY_CLASSES);
export type VulnerabilityClass = z.infer<typeof VulnerabilityClassSchema>;

export const SECRET_FIELDS = ['password', 'totpSecret', 'emailPassword', 'emailTotpSecret'] as const;
export const SecretFieldSchema = z.enum(SECRET_FIELDS);
export type SecretField = z.infer<typeof SecretFieldSchema>;

const identifierSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[a-zA-Z0-9][a-zA-Z0-9_-]*$/);
const httpUrlSchema = z
  .string()
  .url()
  .max(2048)
  .superRefine((value, context) => {
    const parsed = new URL(value);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      context.addIssue({ code: 'custom', message: 'Only http and https URLs are supported' });
    }
    if (parsed.username || parsed.password) {
      context.addIssue({ code: 'custom', message: 'URLs must not contain credentials or userinfo' });
    }
  });

export const RuleSchema = z
  .object({
    description: z.string().trim().min(1).max(200),
    type: z.enum(['url_path', 'subdomain', 'domain', 'method', 'header', 'parameter', 'code_path']),
    value: z.string().trim().min(1).max(1000),
  })
  .strict();
export type AssessmentRule = z.infer<typeof RuleSchema>;

export const PublicAuthenticationSchema = z
  .object({
    loginType: z.enum(['form', 'sso', 'api', 'basic']),
    loginUrl: httpUrlSchema,
    username: z.string().min(1).max(255),
    emailAddress: z.string().email().max(320).optional(),
    loginFlow: z.array(z.string().trim().min(1).max(500)).min(1).max(20).optional(),
    successCondition: z
      .object({
        type: z.enum(['url_contains', 'element_present', 'url_equals_exactly', 'text_contains']),
        value: z.string().min(1).max(500),
      })
      .strict(),
  })
  .strict();
export type PublicAuthentication = z.infer<typeof PublicAuthenticationSchema>;

const providerTextSchema = z.string().trim().min(1).max(500);
const providerIdSchema = z
  .string()
  .trim()
  .min(1)
  .max(100)
  .regex(/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/);

const ProviderConfigBaseSchema = z
  .object({
    providerType: providerIdSchema.optional(),
    providerId: providerIdSchema.optional(),
    model: providerTextSchema,
    apiKey: z.string().trim().min(1).max(4096).optional(),
    authToken: z.string().trim().min(1).max(4096).optional(),
    awsRegion: z.string().trim().min(1).max(100).optional(),
    awsAccessKeyId: z.string().trim().min(1).max(4096).optional(),
    awsSecretAccessKey: z.string().trim().min(1).max(4096).optional(),
    awsSessionToken: z.string().trim().min(1).max(4096).optional(),
    baseUrl: httpUrlSchema.optional(),
    openAIFormat: z.enum(['chat-completions', 'responses']).optional(),
    supportsStructuredOutput: z.boolean().optional(),
  })
  .strict();

function validateProviderConfig(value: z.infer<typeof ProviderConfigBaseSchema>, context: z.RefinementCtx): void {
  if (value.apiKey && value.authToken) {
    context.addIssue({
      code: 'custom',
      path: ['apiKey'],
      message: 'Use either apiKey or authToken, not both',
    });
  }
  if (Boolean(value.awsAccessKeyId) !== Boolean(value.awsSecretAccessKey)) {
    context.addIssue({
      code: 'custom',
      path: ['awsAccessKeyId'],
      message: 'AWS access-key provider configs require both awsAccessKeyId and awsSecretAccessKey',
    });
  }
  if (value.openAIFormat && !value.baseUrl) {
    context.addIssue({
      code: 'custom',
      path: ['openAIFormat'],
      message: 'openAIFormat requires baseUrl',
    });
  }
  if ((value.providerType === 'generic' || value.providerType === 'custom') && !value.providerId) {
    context.addIssue({
      code: 'custom',
      path: ['providerId'],
      message: 'providerId is required for generic provider configs',
    });
  }
}

export const ProviderConfigSchema = ProviderConfigBaseSchema.superRefine(validateProviderConfig);
export type ProviderConfig = z.infer<typeof ProviderConfigSchema>;

const SafeProviderConfigSchema = ProviderConfigBaseSchema.omit({
  apiKey: true,
  authToken: true,
  awsAccessKeyId: true,
  awsSecretAccessKey: true,
  awsSessionToken: true,
}).superRefine(validateProviderConfig);

const AssessmentConfigBaseSchema = z
  .object({
    description: z.string().trim().min(1).max(500).optional(),
    testCategories: z.array(VulnerabilityClassSchema).max(5).optional(),
    testScopes: z.array(z.enum(assessmentTestScopeIds)).min(1).optional(),
    testSurfaces: z.array(z.enum(assessmentTestSurfaceIds)).min(1).optional(),
    httpLoad: z
      .object({
        concurrency: z.number().int().min(1).max(HTTP_LOAD_EMERGENCY_LIMITS.concurrency).optional(),
        requestsPerSecond: z.number().int().min(1).max(HTTP_LOAD_EMERGENCY_LIMITS.requestsPerSecond).optional(),
        durationSeconds: z.number().int().min(1).max(HTTP_LOAD_EMERGENCY_LIMITS.durationSeconds).optional(),
      })
      .strict()
      .optional(),
    assessmentModules: z.array(z.enum(assessmentModuleIds)).optional(),
    moduleSafety: z
      .object({
        targetEnvironment: z.enum(['production', 'staging']).optional(),
        allowActiveDast: z.boolean().optional(),
        acknowledgeLoadRisk: z.boolean().optional(),
        maxRequestsPerSecond: z.number().int().min(1).max(10).optional(),
        maxConcurrency: z.number().int().min(1).max(25).optional(),
        loadStageDurationSeconds: z.number().int().min(10).max(600).optional(),
        loadErrorRateThreshold: z.number().min(0.001).max(0.5).optional(),
        loadP95LatencyMsThreshold: z.number().int().min(100).max(60000).optional(),
      })
      .strict()
      .optional(),
    safeDemonstration: z.boolean().optional(),
    /** @deprecated Use safeDemonstration. */
    demonstrate: z.boolean().optional(),
    /** @deprecated Use safeDemonstration. */
    exploit: z.boolean().optional(),
    pipeline: z
      .object({
        retryPreset: z.enum(['default', 'subscription']).optional(),
        maxConcurrentPipelines: z.number().int().min(1).max(5).optional(),
      })
      .strict()
      .optional(),
    rules: z
      .object({
        avoid: z.array(RuleSchema).max(50).optional(),
        focus: z.array(RuleSchema).max(50).optional(),
      })
      .strict()
      .optional(),
    report: z
      .object({
        minSeverity: z.enum(['low', 'medium', 'high', 'critical']).optional(),
        minConfidence: z.enum(['low', 'medium', 'high']).optional(),
        guidance: z.string().trim().min(1).max(500).optional(),
        sarif: z
          .preprocess((value) => (value === 'true' ? true : value === 'false' ? false : value), z.boolean())
          .optional(),
      })
      .strict()
      .optional(),
    rulesOfEngagement: z.string().trim().min(1).max(1000).optional(),
    authentication: PublicAuthenticationSchema.optional(),
  })
  .strict()
  .superRefine((value, context) => {
    const provided = [
      ['safeDemonstration', value.safeDemonstration],
      ['demonstrate', value.demonstrate],
      ['exploit', value.exploit],
    ].filter((entry): entry is [string, boolean] => typeof entry[1] === 'boolean');
    const expected = provided[0]?.[1];
    if (provided.length >= 2 && provided.some(([, current]) => current !== expected)) {
      context.addIssue({
        code: 'custom',
        path: ['safeDemonstration'],
        message: 'safeDemonstration conflicts with legacy demonstration flags',
      });
    }
    try {
      const scope = normalizeTestScopeSelection({
        ...(value.testScopes && { testScopes: value.testScopes }),
        ...(value.testSurfaces && { testSurfaces: value.testSurfaces }),
        ...(value.testCategories && { testCategories: value.testCategories }),
      });
      assertExclusiveHttpLoadExecution(scope.testScopes, value.assessmentModules ?? []);
      normalizeHttpLoadSettings(scope.testScopes, value.httpLoad);
    } catch (error) {
      context.addIssue({
        code: 'custom',
        path: ['testScopes'],
        message: error instanceof Error ? error.message : String(error),
      });
    }
    try {
      normalizeAssessmentModules({
        ...(value.assessmentModules && { assessmentModules: value.assessmentModules }),
        ...(value.moduleSafety && { moduleSafety: value.moduleSafety }),
      });
    } catch (error) {
      context.addIssue({
        code: 'custom',
        path: ['moduleSafety'],
        message: error instanceof Error ? error.message : String(error),
      });
    }
  });

export const AssessmentConfigSchema = AssessmentConfigBaseSchema.transform(
  ({
    safeDemonstration,
    demonstrate,
    exploit,
    httpLoad: httpLoadInput,
    assessmentModules,
    moduleSafety,
    ...config
  }) => {
    const resolvedSafeDemonstration = safeDemonstration ?? demonstrate ?? exploit;
    const scope = normalizeTestScopeSelection({
      ...(config.testScopes && { testScopes: config.testScopes }),
      ...(config.testSurfaces && { testSurfaces: config.testSurfaces }),
      ...(config.testCategories && { testCategories: config.testCategories }),
    });
    const httpLoad = normalizeHttpLoadSettings(scope.testScopes, httpLoadInput);
    const modules =
      assessmentModules !== undefined || moduleSafety !== undefined
        ? normalizeAssessmentModules({
            ...(assessmentModules && { assessmentModules }),
            ...(moduleSafety && { moduleSafety }),
          })
        : undefined;
    assertExclusiveHttpLoadExecution(scope.testScopes, modules?.assessmentModules ?? []);
    return {
      ...config,
      testCategories: scope.testCategories,
      testScopes: scope.testScopes,
      testSurfaces: scope.testSurfaces,
      ...(httpLoad && { httpLoad }),
      ...(modules && modules),
      ...(resolvedSafeDemonstration !== undefined && { safeDemonstration: resolvedSafeDemonstration }),
    };
  },
);
export type AssessmentConfig = z.infer<typeof AssessmentConfigSchema>;

export const TargetSecretsSchema = z
  .object({
    password: z.string().min(1).max(255).optional(),
    totpSecret: z
      .string()
      .regex(/^[A-Za-z2-7]+=*$/)
      .optional(),
    emailPassword: z.string().min(1).max(255).optional(),
    emailTotpSecret: z
      .string()
      .regex(/^[A-Za-z2-7]+=*$/)
      .optional(),
  })
  .strict();
export type TargetSecrets = z.infer<typeof TargetSecretsSchema>;

function validateSourceMode(
  value: { sourceMode: SourceMode; repoPath?: string | undefined },
  context: z.RefinementCtx,
): void {
  if (value.sourceMode === 'source-assisted' && !value.repoPath) {
    context.addIssue({
      code: 'custom',
      path: ['repoPath'],
      message: 'Repository path is required in source-assisted mode',
    });
  }
  if (value.sourceMode === 'url-only' && value.repoPath) {
    context.addIssue({
      code: 'custom',
      path: ['repoPath'],
      message: 'Repository path is not accepted in URL-only mode',
    });
  }
}

export const ProfileDraftSchema = z
  .object({
    name: z.string().trim().min(1).max(80),
    targetUrl: httpUrlSchema,
    sourceMode: SourceModeSchema,
    repoPath: z.string().trim().min(1).max(4096).optional(),
    config: AssessmentConfigSchema.optional(),
    secrets: TargetSecretsSchema.optional(),
    clearSecrets: z.array(SecretFieldSchema).max(4).optional(),
  })
  .strict()
  .superRefine(validateSourceMode);
export type ProfileDraft = z.infer<typeof ProfileDraftSchema>;

export const SecretReferencesSchema = z
  .object({
    password: z.string().min(1).optional(),
    totpSecret: z.string().min(1).optional(),
    emailPassword: z.string().min(1).optional(),
    emailTotpSecret: z.string().min(1).optional(),
  })
  .strict();
export type SecretReferences = z.infer<typeof SecretReferencesSchema>;

const ProfileFileBaseSchema = z
  .object({
    version: z.literal(1),
    id: identifierSchema,
    name: z.string().trim().min(1).max(80),
    targetUrl: httpUrlSchema,
    sourceMode: SourceModeSchema,
    repoPath: z.string().trim().min(1).max(4096).optional(),
    config: AssessmentConfigSchema,
    secretRefs: SecretReferencesSchema,
    createdAt: z.string().datetime(),
    updatedAt: z.string().datetime(),
  })
  .strict();

export const ProfileFileSchema = ProfileFileBaseSchema.superRefine(validateSourceMode);
export type ProfileFile = z.infer<typeof ProfileFileSchema>;

export const SecretPresenceSchema = z.partialRecord(SecretFieldSchema, z.boolean());
export type SecretPresence = z.infer<typeof SecretPresenceSchema>;

export const ProfileResponseSchema = ProfileFileBaseSchema.omit({ secretRefs: true })
  .extend({
    hasSecret: SecretPresenceSchema,
  })
  .superRefine(validateSourceMode);
export type ProfileResponse = z.infer<typeof ProfileResponseSchema>;

export const StartRunRequestSchema = z
  .object({
    profileId: identifierSchema.optional(),
    targetUrl: httpUrlSchema.optional(),
    sourceMode: SourceModeSchema.optional(),
    repoPath: z.string().trim().min(1).max(4096).optional(),
    config: AssessmentConfigSchema.optional(),
    secrets: TargetSecretsSchema.optional(),
    providerConfig: ProviderConfigSchema.optional(),
    workspace: identifierSchema.optional(),
    outputPath: z.string().trim().min(1).max(4096).optional(),
    pipelineTesting: z.boolean().optional(),
    debug: z.boolean().optional(),
    authorizationConfirmed: z.literal(true),
    elevatedLoadConfirmed: z.literal(true).optional(),
  })
  .strict()
  .superRefine((value, context) => {
    if (!value.profileId && (!value.targetUrl || !value.sourceMode)) {
      context.addIssue({
        code: 'custom',
        message: 'A profile or an explicit target URL and source mode is required',
      });
    }
    if (value.sourceMode) validateSourceMode({ sourceMode: value.sourceMode, repoPath: value.repoPath }, context);
  });
export type StartRunRequest = z.infer<typeof StartRunRequestSchema>;

export const ResumeRunRequestSchema = z
  .object({
    secrets: TargetSecretsSchema.optional(),
    providerConfig: ProviderConfigSchema.optional(),
    authorizationConfirmed: z.literal(true).optional(),
    elevatedLoadConfirmed: z.literal(true).optional(),
  })
  .strict();
export type ResumeRunRequest = z.infer<typeof ResumeRunRequestSchema>;

export const ProfileReferenceSchema = z
  .object({
    id: identifierSchema,
    version: z.literal(1),
    updatedAt: z.string().datetime(),
  })
  .strict();
export type ProfileReference = z.infer<typeof ProfileReferenceSchema>;

const RunLaunchSpecBaseSchema = z
  .object({
    targetUrl: httpUrlSchema,
    sourceMode: SourceModeSchema,
    repoPath: z.string().trim().min(1).max(4096).optional(),
    profileRef: ProfileReferenceSchema.optional(),
    config: AssessmentConfigSchema,
    secrets: TargetSecretsSchema.optional(),
    secretRefs: SecretReferencesSchema.optional(),
    providerConfig: ProviderConfigSchema.optional(),
    workspace: identifierSchema.optional(),
    outputPath: z.string().trim().min(1).max(4096).optional(),
    pipelineTesting: z.boolean().optional(),
    debug: z.boolean().optional(),
    authorizationConfirmed: z.literal(true).optional(),
    elevatedLoadConfirmed: z.literal(true).optional(),
  })
  .strict();

export const RunLaunchSpecSchema = RunLaunchSpecBaseSchema.superRefine((value, context) => {
  validateSourceMode(value, context);
  try {
    normalizeAssessmentModules({
      ...(value.config.assessmentModules && { assessmentModules: value.config.assessmentModules }),
      ...(value.config.moduleSafety && { moduleSafety: value.config.moduleSafety }),
      sourceMode: value.sourceMode,
    });
  } catch (error) {
    context.addIssue({
      code: 'custom',
      path: ['config', 'moduleSafety'],
      message: error instanceof Error ? error.message : String(error),
    });
  }
  try {
    assertHttpLoadAuthorization(
      value.config.httpLoad,
      value.authorizationConfirmed === true,
      value.elevatedLoadConfirmed === true,
    );
  } catch (error) {
    context.addIssue({
      code: 'custom',
      path: ['authorizationConfirmed'],
      message: error instanceof Error ? error.message : String(error),
    });
  }
});
export type RunLaunchSpec = z.infer<typeof RunLaunchSpecSchema>;

export const RUN_STATUSES = ['pending', 'running', 'completed', 'failed', 'cancelled'] as const;
export const RunStatusSchema = z.enum(RUN_STATUSES);
export type RunStatus = z.infer<typeof RunStatusSchema>;

export const RunSnapshotSchema = RunLaunchSpecBaseSchema.omit({
  secrets: true,
  workspace: true,
  secretRefs: true,
  authorizationConfirmed: true,
  elevatedLoadConfirmed: true,
})
  .extend({
    providerConfig: SafeProviderConfigSchema.optional(),
    secretRefs: SecretReferencesSchema,
    requiredSecretFields: z.array(SecretFieldSchema),
  })
  .superRefine(validateSourceMode);
export type RunSnapshot = z.infer<typeof RunSnapshotSchema>;

export const RunAttemptSchema = z
  .object({
    attemptNumber: z.number().int().positive(),
    taskQueue: z.string().min(1),
    containerName: z.string().min(1),
    workflowId: z.string().min(1),
    temporalRunId: z.string().min(1).optional(),
    dockerLabels: z.record(z.string(), z.string()),
    createdAt: z.string().datetime(),
    startedAt: z.string().datetime().optional(),
    cancellationReason: z.enum(['user', 'orphaned-worker', 'start-failure']).optional(),
    completedAt: z.string().datetime().optional(),
    status: RunStatusSchema,
    error: z.string().optional(),
  })
  .strict();
export type RunAttempt = z.infer<typeof RunAttemptSchema>;

export const ManagedRunRecordSchema = z
  .object({
    kind: z.literal('managed'),
    version: z.literal(1),
    runId: identifierSchema,
    workspacePath: z.string().min(1).max(4096),
    status: RunStatusSchema,
    snapshot: RunSnapshotSchema,
    snapshotHash: z.string().regex(/^sha256:[a-f0-9]{64}$/),
    attempts: z.array(RunAttemptSchema),
    createdAt: z.string().datetime(),
    updatedAt: z.string().datetime(),
    completedAt: z.string().datetime().optional(),
    lastError: z.string().optional(),
  })
  .strict();
export type ManagedRunRecord = z.infer<typeof ManagedRunRecordSchema>;

export const LegacyRunRecordSchema = z
  .object({
    kind: z.literal('legacy'),
    runId: identifierSchema,
    workspacePath: z.string().min(1).max(4096),
    status: RunStatusSchema,
    targetUrl: httpUrlSchema.nullable(),
    sourceMode: SourceModeSchema.nullable(),
    repoPath: z.string().optional(),
    createdAt: z.string().datetime(),
    updatedAt: z.string().datetime(),
    completedAt: z.string().datetime().optional(),
    readOnly: z.literal(true),
  })
  .strict();
export type LegacyRunRecord = z.infer<typeof LegacyRunRecordSchema>;

export const RunListItemSchema = z.discriminatedUnion('kind', [ManagedRunRecordSchema, LegacyRunRecordSchema]);
export type RunListItem = z.infer<typeof RunListItemSchema>;

export const AgentMetricsSchema = z
  .object({
    status: z.enum(['in-progress', 'success', 'failed']).optional(),
    final_duration_ms: z.number().optional(),
    total_cost_usd: z.number().optional(),
  })
  .passthrough();

export const LegacySessionSchema = z
  .object({
    session: z
      .object({
        id: z.string().min(1),
        webUrl: httpUrlSchema,
        repoPath: z.string().optional(),
        status: z.enum(['in-progress', 'completed', 'failed', 'cancelled']),
        createdAt: z.string(),
        completedAt: z.string().optional(),
        originalWorkflowId: z.string().optional(),
        resumeAttempts: z.array(z.object({ workflowId: z.string() }).passthrough()).optional(),
      })
      .passthrough(),
    metrics: z
      .object({
        total_duration_ms: z.number().optional(),
        total_cost_usd: z.number().optional(),
        agents: z.record(z.string(), AgentMetricsSchema).optional(),
      })
      .passthrough(),
  })
  .passthrough();
export type LegacySession = z.infer<typeof LegacySessionSchema>;

export const WorkflowProgressSchema = z
  .object({
    status: z.enum(['running', 'completed', 'failed', 'cancelled']),
    currentPhase: z.string().nullable(),
    currentAgent: z.string().nullable(),
    activeAgents: z.array(z.string()).optional(),
    activeTestCategories: z.array(VulnerabilityClassSchema).optional(),
    activeModules: z.array(z.enum(assessmentModuleIds)).optional(),
    moduleResults: z
      .array(
        z.object({
          id: z.enum(assessmentModuleIds),
          status: z.enum(['completed', 'partial', 'failed', 'skipped', 'unavailable']),
          evidencePath: z.string().optional(),
        }),
      )
      .optional(),
    httpLoadStatus: z.enum(['completed', 'interrupted', 'incomplete']).nullable().optional(),
    completedAgents: z.array(z.string()),
    failedAgent: z.string().nullable(),
    error: z.string().nullable(),
    workflowId: z.string().optional(),
    elapsedMs: z.number().nonnegative().optional(),
    startTime: z.number().optional(),
    triageRan: z.boolean().optional(),
    summary: z
      .object({
        totalCostUsd: z.number(),
        totalDurationMs: z.number(),
        totalTurns: z.number(),
        agentCount: z.number(),
      })
      .nullable()
      .optional(),
  })
  .passthrough();
export type WorkflowProgress = z.infer<typeof WorkflowProgressSchema>;

export const TriageVerdictSchema = z
  .object({
    id: z.string().min(1),
    vulnType: z.string().min(1),
    title: z.string().min(1),
    verdict: z.enum(['PASS', 'DOWNGRADE', 'KILL', 'CHAIN_REQUIRED']),
    severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
    claimedSeverity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
    reason: z.string().min(1),
    evidenceFile: z.string().min(1),
  })
  .strict();

export const TriageVerdictsSchema = z
  .object({
    version: z.literal(1),
    verdicts: z.array(TriageVerdictSchema),
  })
  .strict();
export type TriageVerdicts = z.infer<typeof TriageVerdictsSchema>;

export interface RunDetail {
  run: RunListItem;
  progress: WorkflowProgress | null;
  metrics: LegacySession['metrics'] | null;
  triage: TriageVerdicts | null;
  unvalidatedFindings: UnvalidatedFinding[];
  reportAvailable: boolean;
  reportArtifacts: ReportArtifact[];
  evidenceFiles: string[];
}

export const REPORT_ARTIFACT_KINDS = ['markdown', 'pdf', 'sarif'] as const;
export type ReportArtifactKind = (typeof REPORT_ARTIFACT_KINDS)[number];

export interface ReportArtifact {
  kind: ReportArtifactKind;
  filename: string;
  contentType: string;
}

export interface UnvalidatedFinding {
  id: string;
  vulnType: VulnerabilityClass;
  title: string;
  reason: string;
}

export interface ActivityChunk {
  offset: number;
  text: string;
  done: boolean;
}

export interface ReportData {
  filename: string;
  markdown: string;
  sourceMode: SourceMode;
  coverageNotice: string | null;
}
