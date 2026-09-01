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

export const assessmentScopeDefinitions = scopeDefinitions.map(([id, label, owaspId, agent]) => ({
  id,
  label,
  owaspId,
  availability: agent ? ('available' as const) : ('coming-soon' as const),
  ...(agent && { agent }),
}));

export const availableTestScopes: AssessmentTestScope[] = assessmentScopeDefinitions
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
    ({ owaspId: parentId, availability }) => parentId === owaspId && availability === 'available',
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
      .filter(({ owaspId: parentId, availability }) => parentId === owaspId && availability === 'available')
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
    if (input.testCategories.length === 0) throw new Error('testCategories must include at least one value');
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
