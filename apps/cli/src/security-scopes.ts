export type ExecutionLane = 'injection' | 'xss' | 'auth' | 'authz' | 'ssrf';
export type ScopeAvailability = 'available' | 'partial' | 'coming-soon';

const scopeDefinitions = [
  ['object-access', 'Object access and IDOR', 'A01:2025', 'authz'],
  ['privilege-boundaries', 'Privilege boundaries', 'A01:2025', 'authz'],
  ['tenant-isolation', 'Tenant isolation', 'A01:2025', 'authz'],
  ['csrf', 'Cross-site request forgery', 'A01:2025', 'authz'],
  ['ssrf', 'Server-side request forgery', 'A01:2025', 'ssrf'],
  ['cors', 'Cross-origin resource sharing', 'A02:2025', 'authz'],
  ['security-headers', 'Security headers', 'A02:2025', 'xss'],
  ['open-redirects', 'Open redirects', 'A02:2025', 'ssrf'],
  ['dependency-risk', 'Dependency risk', 'A03:2025', null],
  ['package-provenance', 'Package provenance', 'A03:2025', null],
  ['build-pipeline-integrity', 'Build-pipeline integrity', 'A03:2025', null],
  ['sensitive-data-exposure', 'Sensitive-data exposure', 'A04:2025', 'authz'],
  ['transport-session-protection', 'Transport and session protection', 'A04:2025', 'auth'],
  ['sql-nosql-injection', 'SQL and NoSQL injection', 'A05:2025', 'injection'],
  ['command-injection', 'Command injection', 'A05:2025', 'injection'],
  ['template-injection', 'Template injection', 'A05:2025', 'injection'],
  ['xxe', 'XML external entities', 'A05:2025', 'injection'],
  ['path-traversal-file-inclusion', 'Path traversal and file inclusion', 'A05:2025', 'injection'],
  ['reflected-xss', 'Reflected XSS', 'A05:2025', 'xss'],
  ['stored-xss', 'Stored XSS', 'A05:2025', 'xss'],
  ['dom-xss', 'DOM-based XSS', 'A05:2025', 'xss'],
  ['business-logic', 'Business logic', 'A06:2025', 'authz'],
  ['workflow-bypass', 'Workflow bypass', 'A06:2025', 'authz'],
  ['file-upload', 'File upload handling', 'A06:2025', 'injection'],
  ['rate-limiting', 'Rate limiting', 'A06:2025', 'auth'],
  ['http-load-capacity', 'HTTP load and capacity', 'A06:2025', null],
  ['account-enumeration', 'Account enumeration', 'A07:2025', 'auth'],
  ['login-controls', 'Login controls', 'A07:2025', 'auth'],
  ['account-recovery-mfa', 'Account recovery and MFA', 'A07:2025', 'auth'],
  ['session-lifecycle', 'Session lifecycle', 'A07:2025', 'auth'],
  ['unsafe-deserialization', 'Unsafe deserialization', 'A08:2025', 'injection'],
  ['upload-integrity', 'Upload integrity', 'A08:2025', 'injection'],
  ['security-event-logging', 'Security-event logging', 'A09:2025', null],
  ['alerting-effectiveness', 'Alerting effectiveness', 'A09:2025', null],
  ['audit-trail-integrity', 'Audit-trail integrity', 'A09:2025', null],
  ['verbose-errors', 'Verbose errors', 'A10:2025', 'injection'],
  ['fail-open', 'Fail-open behavior', 'A10:2025', 'authz'],
] as const;

export type AssessmentTestScope = (typeof scopeDefinitions)[number][0];
export const assessmentTestScopeIds = scopeDefinitions.map(([id]) => id) as [
  AssessmentTestScope,
  ...AssessmentTestScope[],
];

export const assessmentScopeCatalog = [
  { id: 'A01:2025', title: 'Broken Access Control', availability: 'available' },
  { id: 'A02:2025', title: 'Security Misconfiguration', availability: 'partial' },
  { id: 'A03:2025', title: 'Software Supply Chain Failures', availability: 'coming-soon' },
  { id: 'A04:2025', title: 'Cryptographic Failures', availability: 'partial' },
  { id: 'A05:2025', title: 'Injection', availability: 'available' },
  { id: 'A06:2025', title: 'Insecure Design', availability: 'partial' },
  { id: 'A07:2025', title: 'Authentication Failures', availability: 'available' },
  { id: 'A08:2025', title: 'Software or Data Integrity Failures', availability: 'partial' },
  { id: 'A09:2025', title: 'Security Logging and Alerting Failures', availability: 'coming-soon' },
  { id: 'A10:2025', title: 'Mishandling of Exceptional Conditions', availability: 'partial' },
] as const satisfies readonly { id: string; title: string; availability: ScopeAvailability }[];

export type OwaspCategory = (typeof assessmentScopeCatalog)[number]['id'];

export const assessmentScopeDefinitions = scopeDefinitions.map(([id, label, owaspId, agent]) => {
  const isHttpLoad = id === 'http-load-capacity';
  return {
    id,
    label,
    owaspId,
    availability: agent || isHttpLoad ? ('available' as const) : ('coming-soon' as const),
    ...(agent && { agent }),
    ...(isHttpLoad && { executor: 'http-load' as const, bulkSelectable: false as const }),
  };
});

export const availableTestScopes: AssessmentTestScope[] = assessmentScopeDefinitions
  .filter(({ availability, bulkSelectable }) => availability === 'available' && bulkSelectable !== false)
  .map(({ id }) => id);

/** Every individually selectable check, including explicit opt-in checks omitted from bulk actions. */
export const selectableTestScopes: AssessmentTestScope[] = assessmentScopeDefinitions
  .filter(({ availability }) => availability === 'available')
  .map(({ id }) => id);

export const testSurfaceDefinitions = [
  { id: 'browser', label: 'Browser', availability: 'available' },
  { id: 'api-graphql', label: 'API / GraphQL', availability: 'available' },
  { id: 'websockets', label: 'WebSockets', availability: 'coming-soon' },
] as const;

export type AssessmentTestSurface = (typeof testSurfaceDefinitions)[number]['id'];
export const assessmentTestSurfaceIds = testSurfaceDefinitions.map(({ id }) => id) as [
  AssessmentTestSurface,
  ...AssessmentTestSurface[],
];
export const availableTestSurfaces: AssessmentTestSurface[] = ['browser', 'api-graphql'];

export const assessmentModuleDefinitions = [
  {
    id: 'passive-exposure',
    title: 'Passive exposure review',
    description:
      'Headers, TLS, DNS, public assets, source maps, robots.txt, exposed routes, and leaked-secret indicators.',
    tools: ['native'],
    sourceModes: ['source-assisted', 'url-only'],
    stagingOnly: false,
  },
  {
    id: 'automated-dast',
    title: 'Automated vulnerability scan',
    description:
      'OWASP ZAP passive scanning followed by optional bounded active scanning and curated Nuclei templates.',
    tools: ['owasp-zap', 'nuclei'],
    sourceModes: ['source-assisted', 'url-only'],
    stagingOnly: false,
  },
  {
    id: 'supply-chain',
    title: 'Dependency and supply-chain review',
    description: 'Package audit, lockfile review, secret scanning, and repository security configuration checks.',
    tools: ['package-audit', 'gitleaks'],
    sourceModes: ['source-assisted'],
    stagingOnly: false,
  },
  {
    id: 'http-load-capacity',
    title: 'Controlled load test',
    description: 'Staging-only k6 ramp with explicit traffic limits and threshold-based automatic aborts.',
    tools: ['k6'],
    sourceModes: ['source-assisted', 'url-only'],
    stagingOnly: true,
  },
] as const;

export type AssessmentModule = (typeof assessmentModuleDefinitions)[number]['id'];
export const assessmentModuleIds = assessmentModuleDefinitions.map(({ id }) => id) as [
  AssessmentModule,
  ...AssessmentModule[],
];
export type TargetEnvironment = 'production' | 'staging';
export const defaultAssessmentModules: AssessmentModule[] = ['passive-exposure'];

export interface ModuleSafetyInput {
  readonly targetEnvironment?: TargetEnvironment | undefined;
  readonly allowActiveDast?: boolean | undefined;
  readonly acknowledgeLoadRisk?: boolean | undefined;
  readonly maxRequestsPerSecond?: number | undefined;
  readonly maxConcurrency?: number | undefined;
  readonly loadStageDurationSeconds?: number | undefined;
  readonly loadErrorRateThreshold?: number | undefined;
  readonly loadP95LatencyMsThreshold?: number | undefined;
}

export interface ModuleSafetyConfig {
  readonly targetEnvironment: TargetEnvironment;
  readonly allowActiveDast: boolean;
  readonly acknowledgeLoadRisk: boolean;
  readonly maxRequestsPerSecond: number;
  readonly maxConcurrency: number;
  readonly loadStageDurationSeconds: number;
  readonly loadErrorRateThreshold: number;
  readonly loadP95LatencyMsThreshold: number;
}

export interface NormalizedAssessmentModules {
  readonly assessmentModules: AssessmentModule[];
  readonly moduleSafety: ModuleSafetyConfig;
}

const defaultModuleSafety: ModuleSafetyConfig = {
  targetEnvironment: 'production',
  allowActiveDast: false,
  acknowledgeLoadRisk: false,
  maxRequestsPerSecond: 2,
  maxConcurrency: 2,
  loadStageDurationSeconds: 60,
  loadErrorRateThreshold: 0.05,
  loadP95LatencyMsThreshold: 2000,
};

function boundedNumber(value: number, name: string, minimum: number, maximum: number): void {
  if (!Number.isFinite(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be between ${minimum} and ${maximum}`);
  }
}

export function normalizeAssessmentModules(input: {
  readonly assessmentModules?: readonly AssessmentModule[];
  readonly moduleSafety?: ModuleSafetyInput;
  readonly sourceMode?: 'source-assisted' | 'url-only';
}): NormalizedAssessmentModules {
  const requested = input.assessmentModules ?? defaultAssessmentModules;
  rejectDuplicates(requested, 'assessmentModules');
  const known = new Set(assessmentModuleDefinitions.map(({ id }) => id));
  for (const value of requested) {
    if (!known.has(value)) throw new Error(`Unknown assessment module: ${value}`);
  }
  const assessmentModules = assessmentModuleDefinitions.filter(({ id }) => requested.includes(id)).map(({ id }) => id);
  const moduleSafety: ModuleSafetyConfig = {
    targetEnvironment: input.moduleSafety?.targetEnvironment ?? defaultModuleSafety.targetEnvironment,
    allowActiveDast: input.moduleSafety?.allowActiveDast ?? defaultModuleSafety.allowActiveDast,
    acknowledgeLoadRisk: input.moduleSafety?.acknowledgeLoadRisk ?? defaultModuleSafety.acknowledgeLoadRisk,
    maxRequestsPerSecond: input.moduleSafety?.maxRequestsPerSecond ?? defaultModuleSafety.maxRequestsPerSecond,
    maxConcurrency: input.moduleSafety?.maxConcurrency ?? defaultModuleSafety.maxConcurrency,
    loadStageDurationSeconds:
      input.moduleSafety?.loadStageDurationSeconds ?? defaultModuleSafety.loadStageDurationSeconds,
    loadErrorRateThreshold: input.moduleSafety?.loadErrorRateThreshold ?? defaultModuleSafety.loadErrorRateThreshold,
    loadP95LatencyMsThreshold:
      input.moduleSafety?.loadP95LatencyMsThreshold ?? defaultModuleSafety.loadP95LatencyMsThreshold,
  };

  boundedNumber(moduleSafety.maxRequestsPerSecond, 'Maximum requests per second', 1, 10);
  boundedNumber(moduleSafety.maxConcurrency, 'Maximum concurrency', 1, 25);
  boundedNumber(moduleSafety.loadStageDurationSeconds, 'Load stage duration', 10, 600);
  boundedNumber(moduleSafety.loadErrorRateThreshold, 'Load error rate threshold', 0.001, 0.5);
  boundedNumber(moduleSafety.loadP95LatencyMsThreshold, 'Load p95 latency threshold', 100, 60_000);

  if (assessmentModules.includes('supply-chain') && input.sourceMode === 'url-only') {
    throw new Error('Supply-chain review requires source-assisted mode');
  }
  if (moduleSafety.allowActiveDast && moduleSafety.targetEnvironment !== 'staging') {
    throw new Error('Active DAST is allowed only against a staging target');
  }
  if (assessmentModules.includes('http-load-capacity')) {
    if (moduleSafety.targetEnvironment !== 'staging') throw new Error('Controlled load testing is staging-only');
    if (!moduleSafety.acknowledgeLoadRisk) {
      throw new Error('Controlled load testing requires explicit acknowledgement of load-test risk');
    }
  }
  return { assessmentModules, moduleSafety };
}

const laneOrder: readonly ExecutionLane[] = ['injection', 'xss', 'auth', 'authz', 'ssrf'];

export function deriveTestCategories(scopes: readonly AssessmentTestScope[]): ExecutionLane[] {
  const selected = new Set(
    assessmentScopeDefinitions.filter(({ id }) => scopes.includes(id)).flatMap(({ agent }) => (agent ? [agent] : [])),
  );
  return laneOrder.filter((lane) => selected.has(lane));
}

export function expandTestCategories(categories: readonly ExecutionLane[]): AssessmentTestScope[] {
  return assessmentScopeDefinitions
    .filter(
      ({ availability, agent }) => availability === 'available' && agent !== undefined && categories.includes(agent),
    )
    .map(({ id }) => id);
}

export interface OwaspCategorySelection {
  readonly checked: boolean;
  readonly indeterminate: boolean;
  readonly selectedCount: number;
  readonly totalCount: number;
}

/** Return the checkbox state for the available checks beneath an OWASP parent. */
export function getOwaspCategorySelection(
  selectedScopes: readonly AssessmentTestScope[],
  owaspId: OwaspCategory,
): OwaspCategorySelection {
  const children = assessmentScopeDefinitions.filter(
    ({ owaspId: parentId, availability, bulkSelectable }) =>
      parentId === owaspId && availability === 'available' && bulkSelectable !== false,
  );
  const selectedCount = children.filter(({ id }) => selectedScopes.includes(id)).length;
  return {
    checked: children.length > 0 && selectedCount === children.length,
    indeterminate: selectedCount > 0 && selectedCount < children.length,
    selectedCount,
    totalCount: children.length,
  };
}

/** Select or clear every available check beneath an OWASP parent. */
export function setOwaspCategorySelected(
  selectedScopes: readonly AssessmentTestScope[],
  owaspId: OwaspCategory,
  selected: boolean,
): AssessmentTestScope[] {
  const categoryScopes = new Set(
    assessmentScopeDefinitions
      .filter(
        ({ owaspId: parentId, availability, bulkSelectable }) =>
          parentId === owaspId && availability === 'available' && bulkSelectable !== false,
      )
      .map(({ id }) => id),
  );
  if (categoryScopes.size === 0) return [...selectedScopes];
  const next = new Set(selectedScopes);
  for (const scope of categoryScopes) {
    if (selected) next.add(scope);
    else next.delete(scope);
  }
  return assessmentScopeDefinitions.filter(({ id }) => next.has(id)).map(({ id }) => id);
}

export interface TestScopeSelection {
  readonly testScopes?: readonly AssessmentTestScope[];
  readonly testSurfaces?: readonly AssessmentTestSurface[];
  readonly testCategories?: readonly ExecutionLane[];
}

export interface NormalizedTestScopeSelection {
  readonly testScopes: AssessmentTestScope[];
  readonly testSurfaces: AssessmentTestSurface[];
  readonly testCategories: ExecutionLane[];
}

function rejectDuplicates(values: readonly string[], field: string): void {
  if (new Set(values).size !== values.length) throw new Error(`${field} contains duplicate values`);
}

function normalizeScopes(values: readonly AssessmentTestScope[]): AssessmentTestScope[] {
  if (values.length === 0) throw new Error('testScopes must include at least one value');
  rejectDuplicates(values, 'testScopes');
  for (const value of values) {
    const definition = assessmentScopeDefinitions.find(({ id }) => id === value);
    if (!definition) throw new Error(`Unknown assessment scope: ${value}`);
    if (definition.availability !== 'available') throw new Error(`Assessment scope is coming soon: ${value}`);
  }
  return assessmentScopeDefinitions.filter(({ id }) => values.includes(id)).map(({ id }) => id);
}

function normalizeSurfaces(values: readonly AssessmentTestSurface[]): AssessmentTestSurface[] {
  if (values.length === 0) throw new Error('testSurfaces must include at least one value');
  rejectDuplicates(values, 'testSurfaces');
  for (const value of values) {
    const definition = testSurfaceDefinitions.find(({ id }) => id === value);
    if (!definition) throw new Error(`Unknown assessment surface: ${value}`);
    if (definition.availability !== 'available') throw new Error(`Assessment surface is coming soon: ${value}`);
  }
  return testSurfaceDefinitions.filter(({ id }) => values.includes(id)).map(({ id }) => id);
}

/** Normalize public granular and legacy selections into one persisted run scope. */
export function normalizeTestScopeSelection(input: TestScopeSelection): NormalizedTestScopeSelection {
  if (input.testCategories) {
    if (input.testCategories.length === 0 && input.testScopes === undefined) {
      throw new Error('testCategories must include at least one value');
    }
    rejectDuplicates(input.testCategories, 'testCategories');
    for (const value of input.testCategories) {
      if (!laneOrder.includes(value)) throw new Error(`Unknown test category: ${value}`);
    }
  }
  const explicitCategories = input.testCategories
    ? laneOrder.filter((lane) => input.testCategories?.includes(lane))
    : undefined;
  const testScopes = input.testScopes
    ? normalizeScopes(input.testScopes)
    : explicitCategories
      ? expandTestCategories(explicitCategories)
      : [...availableTestScopes];
  const testCategories = deriveTestCategories(testScopes);
  if (
    explicitCategories &&
    (explicitCategories.length !== testCategories.length ||
      explicitCategories.some((category) => !testCategories.includes(category)))
  ) {
    throw new Error('Granular testScopes conflict with legacy testCategories');
  }
  return {
    testScopes,
    testSurfaces: input.testSurfaces ? normalizeSurfaces(input.testSurfaces) : [...availableTestSurfaces],
    testCategories,
  };
}
