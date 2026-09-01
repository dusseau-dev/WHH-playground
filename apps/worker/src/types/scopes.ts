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
}[];

export type AssessmentScope = (typeof ASSESSMENT_SCOPE_REGISTRY)[number]['id'];

export const ASSESSMENT_SURFACE_REGISTRY = [
  { id: 'browser', label: 'Browser', availability: 'available' },
  { id: 'api-graphql', label: 'API and GraphQL', availability: 'available' },
  { id: 'websockets', label: 'WebSockets', availability: 'coming-soon' },
] as const;

export type AssessmentSurface = (typeof ASSESSMENT_SURFACE_REGISTRY)[number]['id'];

export const DEFAULT_ASSESSMENT_SCOPES: AssessmentScope[] = ASSESSMENT_SCOPE_REGISTRY.filter(
  ({ availability }) => availability === 'available',
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

function normalizedClasses(values: readonly VulnClass[]): VulnClass[] {
  if (values.length === 0) throw new Error('vulnClasses must include at least one value');
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
  const explicitClasses = input.vulnClasses ? normalizedClasses(input.vulnClasses) : undefined;
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
): ScopeCoverage[] {
  return OWASP_CATEGORY_REGISTRY.map((category) => {
    const definitions = ASSESSMENT_SCOPE_REGISTRY.filter(({ owaspId }) => owaspId === category.id);
    const selected = definitions.filter(({ id }) => selectedScopes.includes(id)).map(({ id }) => id);
    const completed = definitions
      .filter(({ id }) => selectedScopes.includes(id))
      .filter((definition) => {
        const agent = scopeAgent(definition);
        return agent !== undefined && !notAssessed.includes(agent);
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
