import { ALL_VULN_CLASSES, type VulnClass } from './config.js';

export type ScopeAvailability = 'available' | 'partial' | 'coming-soon';

export const OWASP_CATEGORY_REGISTRY = [
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

export type OwaspCategoryId = (typeof OWASP_CATEGORY_REGISTRY)[number]['id'];
export type OwaspCategory = `${OwaspCategoryId} — ${(typeof OWASP_CATEGORY_REGISTRY)[number]['title']}`;

export const ASSESSMENT_SCOPE_REGISTRY = [
  {
    id: 'object-access',
    label: 'Object access and IDOR',
    owaspId: 'A01:2025',
    availability: 'available',
    agent: 'authz',
  },
  {
    id: 'privilege-boundaries',
    label: 'Privilege boundaries',
    owaspId: 'A01:2025',
    availability: 'available',
    agent: 'authz',
  },
  { id: 'tenant-isolation', label: 'Tenant isolation', owaspId: 'A01:2025', availability: 'available', agent: 'authz' },
  { id: 'csrf', label: 'Cross-site request forgery', owaspId: 'A01:2025', availability: 'available', agent: 'authz' },
  { id: 'ssrf', label: 'Server-side request forgery', owaspId: 'A01:2025', availability: 'available', agent: 'ssrf' },
  {
    id: 'cors',
    label: 'Cross-origin resource sharing',
    owaspId: 'A02:2025',
    availability: 'available',
    agent: 'authz',
  },
  { id: 'security-headers', label: 'Security headers', owaspId: 'A02:2025', availability: 'available', agent: 'xss' },
  { id: 'open-redirects', label: 'Open redirects', owaspId: 'A02:2025', availability: 'available', agent: 'ssrf' },
  { id: 'dependency-risk', label: 'Dependency risk', owaspId: 'A03:2025', availability: 'coming-soon' },
  { id: 'package-provenance', label: 'Package provenance', owaspId: 'A03:2025', availability: 'coming-soon' },
  {
    id: 'build-pipeline-integrity',
    label: 'Build-pipeline integrity',
    owaspId: 'A03:2025',
    availability: 'coming-soon',
  },
  {
    id: 'sensitive-data-exposure',
    label: 'Sensitive-data exposure',
    owaspId: 'A04:2025',
    availability: 'available',
    agent: 'authz',
  },
  {
    id: 'transport-session-protection',
    label: 'Transport and session protection',
    owaspId: 'A04:2025',
    availability: 'available',
    agent: 'auth',
  },
  {
    id: 'sql-nosql-injection',
    label: 'SQL and NoSQL injection',
    owaspId: 'A05:2025',
    availability: 'available',
    agent: 'injection',
  },
  {
    id: 'command-injection',
    label: 'Command injection',
    owaspId: 'A05:2025',
    availability: 'available',
    agent: 'injection',
  },
  {
    id: 'template-injection',
    label: 'Template injection',
    owaspId: 'A05:2025',
    availability: 'available',
    agent: 'injection',
  },
  { id: 'xxe', label: 'XML external entities', owaspId: 'A05:2025', availability: 'available', agent: 'injection' },
  {
    id: 'path-traversal-file-inclusion',
    label: 'Path traversal and file inclusion',
    owaspId: 'A05:2025',
    availability: 'available',
    agent: 'injection',
  },
  { id: 'reflected-xss', label: 'Reflected XSS', owaspId: 'A05:2025', availability: 'available', agent: 'xss' },
  { id: 'stored-xss', label: 'Stored XSS', owaspId: 'A05:2025', availability: 'available', agent: 'xss' },
  { id: 'dom-xss', label: 'DOM-based XSS', owaspId: 'A05:2025', availability: 'available', agent: 'xss' },
  { id: 'business-logic', label: 'Business logic', owaspId: 'A06:2025', availability: 'available', agent: 'authz' },
  { id: 'workflow-bypass', label: 'Workflow bypass', owaspId: 'A06:2025', availability: 'available', agent: 'authz' },
  {
    id: 'file-upload',
    label: 'File upload handling',
    owaspId: 'A06:2025',
    availability: 'available',
    agent: 'injection',
  },
  { id: 'rate-limiting', label: 'Rate limiting', owaspId: 'A06:2025', availability: 'available', agent: 'auth' },
  {
    id: 'http-load-capacity',
    label: 'HTTP load and capacity',
    owaspId: 'A06:2025',
    availability: 'available',
    executor: 'http-load',
    bulkSelectable: false,
  },
  {
    id: 'account-enumeration',
    label: 'Account enumeration',
    owaspId: 'A07:2025',
    availability: 'available',
    agent: 'auth',
  },
  { id: 'login-controls', label: 'Login controls', owaspId: 'A07:2025', availability: 'available', agent: 'auth' },
  {
    id: 'account-recovery-mfa',
    label: 'Account recovery and MFA',
    owaspId: 'A07:2025',
    availability: 'available',
    agent: 'auth',
  },
  {
    id: 'session-lifecycle',
    label: 'Session lifecycle',
    owaspId: 'A07:2025',
    availability: 'available',
    agent: 'auth',
  },
  {
    id: 'unsafe-deserialization',
    label: 'Unsafe deserialization',
    owaspId: 'A08:2025',
    availability: 'available',
    agent: 'injection',
  },
  {
    id: 'upload-integrity',
    label: 'Upload integrity',
    owaspId: 'A08:2025',
    availability: 'available',
    agent: 'injection',
  },
  { id: 'security-event-logging', label: 'Security-event logging', owaspId: 'A09:2025', availability: 'coming-soon' },
  { id: 'alerting-effectiveness', label: 'Alerting effectiveness', owaspId: 'A09:2025', availability: 'coming-soon' },
  { id: 'audit-trail-integrity', label: 'Audit-trail integrity', owaspId: 'A09:2025', availability: 'coming-soon' },
  { id: 'verbose-errors', label: 'Verbose errors', owaspId: 'A10:2025', availability: 'available', agent: 'injection' },
  { id: 'fail-open', label: 'Fail-open behavior', owaspId: 'A10:2025', availability: 'available', agent: 'authz' },
] as const satisfies readonly {
  id: string;
  label: string;
  owaspId: OwaspCategoryId;
  availability: 'available' | 'coming-soon';
  agent?: VulnClass;
  executor?: 'http-load';
  bulkSelectable?: boolean;
}[];

export type AssessmentScope = (typeof ASSESSMENT_SCOPE_REGISTRY)[number]['id'];

export const ASSESSMENT_SURFACE_REGISTRY = [
  { id: 'browser', label: 'Browser', availability: 'available' },
  { id: 'api-graphql', label: 'API and GraphQL', availability: 'available' },
  { id: 'websockets', label: 'WebSockets', availability: 'coming-soon' },
] as const;

export type AssessmentSurface = (typeof ASSESSMENT_SURFACE_REGISTRY)[number]['id'];

/** Assessment methods run independently from OWASP vulnerability lanes. */
export const ASSESSMENT_MODULE_REGISTRY = [
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

export type AssessmentModule = (typeof ASSESSMENT_MODULE_REGISTRY)[number]['id'];
export type TargetEnvironment = 'production' | 'staging';

export const DEFAULT_ASSESSMENT_MODULES: AssessmentModule[] = ['passive-exposure'];

export interface ModuleSafetyInput {
  readonly targetEnvironment?: TargetEnvironment;
  readonly allowActiveDast?: boolean;
  readonly acknowledgeLoadRisk?: boolean;
  readonly maxRequestsPerSecond?: number;
  readonly maxConcurrency?: number;
  readonly loadStageDurationSeconds?: number;
  readonly loadErrorRateThreshold?: number;
  readonly loadP95LatencyMsThreshold?: number;
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

export interface AssessmentModuleInput {
  readonly assessmentModules?: readonly AssessmentModule[];
  readonly moduleSafety?: ModuleSafetyInput;
  readonly sourceMode?: 'source-assisted' | 'url-only';
}

export interface NormalizedAssessmentModules {
  readonly assessmentModules: AssessmentModule[];
  readonly moduleSafety: ModuleSafetyConfig;
}

const DEFAULT_MODULE_SAFETY: ModuleSafetyConfig = {
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

/** Normalize module selection and fail closed on unsafe active or load-test settings. */
export function normalizeAssessmentModules(input: AssessmentModuleInput): NormalizedAssessmentModules {
  const requested = input.assessmentModules ?? DEFAULT_ASSESSMENT_MODULES;
  rejectDuplicates(requested, 'assessmentModules');
  const known = new Set(ASSESSMENT_MODULE_REGISTRY.map(({ id }) => id));
  for (const value of requested) {
    if (!known.has(value)) throw new Error(`Unknown assessment module: ${value}`);
  }
  const assessmentModules = ASSESSMENT_MODULE_REGISTRY.filter(({ id }) => requested.includes(id)).map(({ id }) => id);
  const moduleSafety: ModuleSafetyConfig = { ...DEFAULT_MODULE_SAFETY, ...input.moduleSafety };

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

export type ModuleExecutionStatus = 'completed' | 'partial' | 'failed' | 'skipped' | 'unavailable';

export interface ModuleExecutionResult {
  readonly id: AssessmentModule;
  readonly status: ModuleExecutionStatus;
  readonly evidencePath?: string;
}

export interface ModuleCoverage {
  readonly id: AssessmentModule;
  readonly title: string;
  readonly status: ModuleExecutionStatus | 'not-run';
  readonly evidence_path?: string;
}

/** Report modules only from their own evidence, never from vulnerability-lane completion. */
export function buildModuleCoverage(
  selectedModules: readonly AssessmentModule[],
  results: readonly ModuleExecutionResult[],
): ModuleCoverage[] {
  return ASSESSMENT_MODULE_REGISTRY.filter(({ id }) => selectedModules.includes(id)).map(({ id, title }) => {
    const result = results.find((entry) => entry.id === id);
    return {
      id,
      title,
      status: result?.status ?? 'not-run',
      ...(result?.evidencePath && { evidence_path: result.evidencePath }),
    };
  });
}

export const DEFAULT_ASSESSMENT_SCOPES: AssessmentScope[] = ASSESSMENT_SCOPE_REGISTRY.filter(
  (definition) =>
    definition.availability === 'available' &&
    (!('bulkSelectable' in definition) || definition.bulkSelectable !== false),
).map(({ id }) => id);

export const DEFAULT_ASSESSMENT_SURFACES: AssessmentSurface[] = ASSESSMENT_SURFACE_REGISTRY.filter(
  ({ availability }) => availability === 'available',
).map(({ id }) => id);

function scopeAgent(definition: (typeof ASSESSMENT_SCOPE_REGISTRY)[number]): VulnClass | undefined {
  return 'agent' in definition ? definition.agent : undefined;
}

export interface AssessmentScopeInput {
  readonly testScopes?: readonly AssessmentScope[];
  readonly testSurfaces?: readonly AssessmentSurface[];
  readonly vulnClasses?: readonly VulnClass[];
}

export interface NormalizedAssessmentScope {
  readonly testScopes: AssessmentScope[];
  readonly testSurfaces: AssessmentSurface[];
  readonly vulnClasses: VulnClass[];
}

export type ScopeCoverageStatus = 'completed' | 'incomplete' | 'not-selected' | 'coming-soon';

export interface ScopeCoverage {
  readonly owasp_id: OwaspCategoryId;
  readonly title: string;
  readonly availability: ScopeAvailability;
  readonly selected_scopes: AssessmentScope[];
  readonly completed_scopes: AssessmentScope[];
  readonly status: ScopeCoverageStatus;
}

function rejectDuplicates(values: readonly string[], field: string): void {
  if (new Set(values).size !== values.length) throw new Error(`${field} contains duplicate values`);
}

function normalizedClasses(values: readonly VulnClass[], allowEmpty: boolean): VulnClass[] {
  if (values.length === 0 && !allowEmpty) throw new Error('vulnClasses must include at least one value');
  rejectDuplicates(values, 'vulnClasses');
  for (const value of values) {
    if (!ALL_VULN_CLASSES.includes(value)) throw new Error(`Unknown vulnerability class: ${value}`);
  }
  return ALL_VULN_CLASSES.filter((value) => values.includes(value));
}

function normalizeScopes(values: readonly AssessmentScope[]): AssessmentScope[] {
  if (values.length === 0) throw new Error('testScopes must include at least one value');
  rejectDuplicates(values, 'testScopes');
  for (const value of values) {
    const definition = ASSESSMENT_SCOPE_REGISTRY.find(({ id }) => id === value);
    if (!definition) throw new Error(`Unknown assessment scope: ${value}`);
    if (definition.availability !== 'available') throw new Error(`Assessment scope is coming soon: ${value}`);
  }
  return ASSESSMENT_SCOPE_REGISTRY.filter(({ id }) => values.includes(id)).map(({ id }) => id);
}

function normalizeSurfaces(values: readonly AssessmentSurface[]): AssessmentSurface[] {
  if (values.length === 0) throw new Error('testSurfaces must include at least one value');
  rejectDuplicates(values, 'testSurfaces');
  for (const value of values) {
    const definition = ASSESSMENT_SURFACE_REGISTRY.find(({ id }) => id === value);
    if (!definition) throw new Error(`Unknown assessment surface: ${value}`);
    if (definition.availability !== 'available') throw new Error(`Assessment surface is coming soon: ${value}`);
  }
  return ASSESSMENT_SURFACE_REGISTRY.filter(({ id }) => values.includes(id)).map(({ id }) => id);
}

export function deriveVulnClasses(testScopes: readonly AssessmentScope[]): VulnClass[] {
  const selected = new Set(
    ASSESSMENT_SCOPE_REGISTRY.filter(({ id }) => testScopes.includes(id)).flatMap((definition) => {
      const agent = scopeAgent(definition);
      return agent ? [agent] : [];
    }),
  );
  return ALL_VULN_CLASSES.filter((value) => selected.has(value));
}

/** Normalize granular and legacy scope inputs into one deterministic workflow contract. */
export function normalizeAssessmentScope(input: AssessmentScopeInput): NormalizedAssessmentScope {
  const explicitClasses = input.vulnClasses
    ? normalizedClasses(input.vulnClasses, input.testScopes !== undefined)
    : undefined;
  const testScopes = input.testScopes
    ? normalizeScopes(input.testScopes)
    : explicitClasses
      ? ASSESSMENT_SCOPE_REGISTRY.filter((definition) => {
          const agent = scopeAgent(definition);
          return definition.availability === 'available' && agent !== undefined && explicitClasses.includes(agent);
        }).map(({ id }) => id)
      : [...DEFAULT_ASSESSMENT_SCOPES];
  const derivedClasses = deriveVulnClasses(testScopes);
  if (
    explicitClasses &&
    (explicitClasses.length !== derivedClasses.length ||
      explicitClasses.some((value) => !derivedClasses.includes(value)))
  ) {
    throw new Error('Granular testScopes conflict with legacy vulnClasses');
  }
  return {
    testScopes,
    testSurfaces: input.testSurfaces ? normalizeSurfaces(input.testSurfaces) : [...DEFAULT_ASSESSMENT_SURFACES],
    vulnClasses: derivedClasses,
  };
}

/** Build report coverage from selected checks and execution lanes that did not complete. */
export function buildScopeCoverage(
  selectedScopes: readonly AssessmentScope[],
  notAssessed: readonly VulnClass[],
  completedActivityScopes: readonly AssessmentScope[] = [],
): ScopeCoverage[] {
  return OWASP_CATEGORY_REGISTRY.map((category) => {
    const definitions = ASSESSMENT_SCOPE_REGISTRY.filter(({ owaspId }) => owaspId === category.id);
    const selected = definitions.filter(({ id }) => selectedScopes.includes(id)).map(({ id }) => id);
    const completed = definitions
      .filter(({ id }) => selectedScopes.includes(id))
      .filter((definition) => {
        const agent = scopeAgent(definition);
        if (agent !== undefined) return !notAssessed.includes(agent);
        return 'executor' in definition && completedActivityScopes.includes(definition.id);
      })
      .map(({ id }) => id);
    const status: ScopeCoverageStatus =
      category.availability === 'coming-soon'
        ? 'coming-soon'
        : selected.length === 0
          ? 'not-selected'
          : completed.length === selected.length
            ? 'completed'
            : 'incomplete';
    return {
      owasp_id: category.id,
      title: category.title,
      availability: category.availability,
      selected_scopes: selected,
      completed_scopes: completed,
      status,
    };
  });
}
