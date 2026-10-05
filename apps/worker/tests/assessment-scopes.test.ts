import { describe, expect, it } from 'vitest';
import { normalizeDetectionValidationSettings } from '../src/types/detection-validation.js';
import {
  ASSESSMENT_MODULE_REGISTRY,
  ASSESSMENT_SCOPE_REGISTRY,
  buildModuleCoverage,
  buildScopeCoverage,
  DEFAULT_ASSESSMENT_MODULES,
  DEFAULT_ASSESSMENT_SCOPES,
  DEFAULT_ASSESSMENT_SURFACES,
  normalizeAssessmentModules,
  normalizeAssessmentScope,
  OWASP_CATEGORY_REGISTRY,
} from '../src/types/scopes.js';

describe('assessment scope registry', () => {
  it('keeps OWASP 2025 categories in canonical order with planned coverage visible', () => {
    expect(OWASP_CATEGORY_REGISTRY.map(({ id }) => id)).toEqual([
      'A01:2025',
      'A02:2025',
      'A03:2025',
      'A04:2025',
      'A05:2025',
      'A06:2025',
      'A07:2025',
      'A08:2025',
      'A09:2025',
      'A10:2025',
    ]);
    expect(OWASP_CATEGORY_REGISTRY.find(({ id }) => id === 'A03:2025')?.availability).toBe('coming-soon');
    expect(OWASP_CATEGORY_REGISTRY.find(({ id }) => id === 'A09:2025')?.availability).toBe('partial');
  });

  it('maps every standard check to one durable execution lane', () => {
    const standard = ASSESSMENT_SCOPE_REGISTRY.filter(
      (definition) => definition.availability === 'available' && 'agent' in definition,
    );
    expect(standard).toHaveLength(DEFAULT_ASSESSMENT_SCOPES.length);
    expect(standard.every(({ agent }) => agent !== undefined)).toBe(true);
    expect(standard.find(({ id }) => id === 'csrf')).toMatchObject({ owaspId: 'A01:2025', agent: 'authz' });
    expect(standard.find(({ id }) => id === 'xxe')).toMatchObject({ owaspId: 'A05:2025', agent: 'injection' });
    expect(standard.find(({ id }) => id === 'rate-limiting')).toMatchObject({
      owaspId: 'A06:2025',
      agent: 'auth',
    });
  });

  it('exposes HTTP load and capacity as an explicit activity-backed check', () => {
    const loadTest = ASSESSMENT_SCOPE_REGISTRY.find(({ id }) => id === 'http-load-capacity');

    expect(loadTest).toEqual({
      id: 'http-load-capacity',
      label: 'HTTP load and capacity',
      owaspId: 'A06:2025',
      availability: 'available',
      executor: 'http-load',
      bulkSelectable: false,
    });
    expect(DEFAULT_ASSESSMENT_SCOPES).not.toContain('http-load-capacity');
    expect(normalizeAssessmentScope({ testScopes: ['http-load-capacity'] })).toEqual({
      testScopes: ['http-load-capacity'],
      testSurfaces: DEFAULT_ASSESSMENT_SURFACES,
      vulnClasses: [],
    });
  });

  it('exposes alerting effectiveness as an opt-in activity-backed check', () => {
    expect(ASSESSMENT_SCOPE_REGISTRY.find(({ id }) => id === 'alerting-effectiveness')).toEqual({
      id: 'alerting-effectiveness',
      label: 'Alerting effectiveness',
      owaspId: 'A09:2025',
      availability: 'available',
      executor: 'detection-validation',
      bulkSelectable: false,
    });
    expect(DEFAULT_ASSESSMENT_SCOPES).not.toContain('alerting-effectiveness');
    expect(normalizeAssessmentScope({ testScopes: ['alerting-effectiveness'] })).toEqual({
      testScopes: ['alerting-effectiveness'],
      testSurfaces: DEFAULT_ASSESSMENT_SURFACES,
      vulnClasses: [],
    });
  });
});

describe('detection validation settings', () => {
  const splunk = {
    managementUrl: 'https://splunk.example.test:8089',
    telemetryIndex: 'waf_events',
    alertIndex: 'security_alerts',
    alertSourcetype: 'notable',
  };

  it('normalizes the staging-only executor contract', () => {
    expect(normalizeDetectionValidationSettings(['alerting-effectiveness'], { splunk }, 'staging')).toEqual({
      canaryPath: '/__shannon__/detection-simulation',
      minimumDetectionRate: 1,
      maxWaitSeconds: 180,
      splunk,
    });
  });

  it('rejects unsafe boundaries and invalid numeric settings', () => {
    expect(() =>
      normalizeDetectionValidationSettings(
        ['alerting-effectiveness'],
        { minimumDetectionRate: 1.1, splunk },
        'staging',
      ),
    ).toThrow(/rate/i);
    expect(() =>
      normalizeDetectionValidationSettings(['alerting-effectiveness'], { maxWaitSeconds: 29, splunk }, 'staging'),
    ).toThrow(/wait/i);
    expect(() =>
      normalizeDetectionValidationSettings(
        ['alerting-effectiveness'],
        { canaryPath: '/safe?query=1', splunk },
        'staging',
      ),
    ).toThrow(/query|fragment/i);
  });
});

describe('assessment scope normalization', () => {
  it('defaults to every available check and surface', () => {
    expect(normalizeAssessmentScope({})).toEqual({
      testScopes: DEFAULT_ASSESSMENT_SCOPES,
      testSurfaces: DEFAULT_ASSESSMENT_SURFACES,
      vulnClasses: ['injection', 'xss', 'auth', 'authz', 'ssrf'],
    });
  });

  it('expands legacy vulnerability classes and derives classes from granular checks', () => {
    const legacy = normalizeAssessmentScope({ vulnClasses: ['authz'] });
    expect(legacy.testScopes).toEqual(
      ASSESSMENT_SCOPE_REGISTRY.filter(
        ({ availability, agent }) => availability === 'available' && agent === 'authz',
      ).map(({ id }) => id),
    );
    expect(legacy.vulnClasses).toEqual(['authz']);

    expect(
      normalizeAssessmentScope({
        testScopes: ['csrf', 'reflected-xss'],
        testSurfaces: ['api-graphql'],
      }),
    ).toEqual({
      testScopes: ['csrf', 'reflected-xss'],
      testSurfaces: ['api-graphql'],
      vulnClasses: ['xss', 'authz'],
    });
  });

  it('accepts equivalent legacy and granular selections', () => {
    expect(
      normalizeAssessmentScope({
        vulnClasses: ['authz'],
        testScopes: ['object-access', 'csrf'],
      }).vulnClasses,
    ).toEqual(['authz']);
  });

  it('rejects conflicts, duplicates, empty selections, and coming-soon values', () => {
    expect(() => normalizeAssessmentScope({ vulnClasses: ['auth'], testScopes: ['csrf'] })).toThrow(/conflict/i);
    expect(() => normalizeAssessmentScope({ testScopes: ['csrf', 'csrf'] })).toThrow(/duplicate/i);
    expect(() => normalizeAssessmentScope({ testScopes: [] })).toThrow(/at least one/i);
    expect(() => normalizeAssessmentScope({ testSurfaces: [] })).toThrow(/at least one/i);
    expect(() => normalizeAssessmentScope({ testSurfaces: ['websockets'] })).toThrow(/coming soon/i);
    expect(() => normalizeAssessmentScope({ testScopes: ['dependency-risk'] })).toThrow(/coming soon/i);
    expect(() => normalizeAssessmentScope({ testScopes: ['unknown-scope' as never] })).toThrow(/unknown/i);
    expect(() => normalizeAssessmentScope({ vulnClasses: ['unknown-lane' as never] })).toThrow(/unknown/i);
  });

  it('builds deterministic OWASP coverage without treating completion as a clean result', () => {
    const coverage = buildScopeCoverage(['csrf', 'xxe'], ['injection']);
    expect(coverage.map(({ owasp_id }) => owasp_id)).toEqual(OWASP_CATEGORY_REGISTRY.map(({ id }) => id));
    expect(coverage.find(({ owasp_id }) => owasp_id === 'A01:2025')).toMatchObject({
      status: 'completed',
      selected_scopes: ['csrf'],
      completed_scopes: ['csrf'],
    });
    expect(coverage.find(({ owasp_id }) => owasp_id === 'A05:2025')).toMatchObject({
      status: 'incomplete',
      selected_scopes: ['xxe'],
      completed_scopes: [],
    });
    expect(coverage.find(({ owasp_id }) => owasp_id === 'A03:2025')).toMatchObject({ status: 'coming-soon' });
    expect(coverage.find(({ owasp_id }) => owasp_id === 'A07:2025')).toMatchObject({ status: 'not-selected' });
  });

  it('marks activity-backed checks complete only when their activity produced completed evidence', () => {
    const incomplete = buildScopeCoverage(['http-load-capacity'], [], []);
    const completed = buildScopeCoverage(['http-load-capacity'], [], ['http-load-capacity']);

    expect(incomplete.find(({ owasp_id }) => owasp_id === 'A06:2025')).toMatchObject({
      status: 'incomplete',
      selected_scopes: ['http-load-capacity'],
      completed_scopes: [],
    });
    expect(completed.find(({ owasp_id }) => owasp_id === 'A06:2025')).toMatchObject({
      status: 'completed',
      selected_scopes: ['http-load-capacity'],
      completed_scopes: ['http-load-capacity'],
    });
  });
});

describe('assessment module registry', () => {
  it('keeps execution methods separate from OWASP checks', () => {
    expect(ASSESSMENT_MODULE_REGISTRY.map(({ id }) => id)).toEqual([
      'passive-exposure',
      'automated-dast',
      'supply-chain',
      'http-load-capacity',
    ]);
    expect(DEFAULT_ASSESSMENT_MODULES).toEqual(['passive-exposure']);
    expect(ASSESSMENT_MODULE_REGISTRY.find(({ id }) => id === 'automated-dast')).toMatchObject({
      tools: ['owasp-zap', 'nuclei'],
    });
    expect(ASSESSMENT_MODULE_REGISTRY.find(({ id }) => id === 'http-load-capacity')).toMatchObject({
      stagingOnly: true,
    });
  });

  it('normalizes safe production defaults', () => {
    expect(normalizeAssessmentModules({ sourceMode: 'url-only' })).toEqual({
      assessmentModules: ['passive-exposure'],
      moduleSafety: {
        targetEnvironment: 'production',
        allowActiveDast: false,
        acknowledgeLoadRisk: false,
        maxRequestsPerSecond: 2,
        maxConcurrency: 2,
        loadStageDurationSeconds: 60,
        loadErrorRateThreshold: 0.05,
        loadP95LatencyMsThreshold: 2000,
      },
    });
  });

  it('requires source access for supply-chain review and explicit staging gates for disruptive modules', () => {
    expect(() => normalizeAssessmentModules({ sourceMode: 'url-only', assessmentModules: ['supply-chain'] })).toThrow(
      /source-assisted/i,
    );
    expect(() =>
      normalizeAssessmentModules({
        sourceMode: 'url-only',
        assessmentModules: ['automated-dast'],
        moduleSafety: { targetEnvironment: 'production', allowActiveDast: true },
      }),
    ).toThrow(/active.*staging/i);
    expect(() =>
      normalizeAssessmentModules({
        sourceMode: 'url-only',
        assessmentModules: ['http-load-capacity'],
        moduleSafety: { targetEnvironment: 'staging' },
      }),
    ).toThrow(/acknowledge/i);
    expect(
      normalizeAssessmentModules({
        sourceMode: 'url-only',
        assessmentModules: ['http-load-capacity'],
        moduleSafety: { targetEnvironment: 'staging', acknowledgeLoadRisk: true },
      }).assessmentModules,
    ).toEqual(['http-load-capacity']);
  });

  it('rejects duplicate modules and unsafe execution bounds', () => {
    expect(() => normalizeAssessmentModules({ assessmentModules: ['passive-exposure', 'passive-exposure'] })).toThrow(
      /duplicate/i,
    );
    expect(() => normalizeAssessmentModules({ moduleSafety: { maxRequestsPerSecond: 0 } })).toThrow(/requests/i);
    expect(() => normalizeAssessmentModules({ moduleSafety: { maxConcurrency: 26 } })).toThrow(/concurrency/i);
    expect(() => normalizeAssessmentModules({ moduleSafety: { loadErrorRateThreshold: 1 } })).toThrow(/error rate/i);
  });

  it('builds evidence-based module coverage instead of inheriting lane completion', () => {
    expect(
      buildModuleCoverage(
        ['passive-exposure', 'automated-dast'],
        [
          {
            id: 'passive-exposure',
            status: 'completed',
            evidencePath: '.shannon/deliverables/modules/passive-exposure.json',
          },
        ],
      ),
    ).toEqual([
      {
        id: 'passive-exposure',
        title: 'Passive exposure review',
        status: 'completed',
        evidence_path: '.shannon/deliverables/modules/passive-exposure.json',
      },
      { id: 'automated-dast', title: 'Automated vulnerability scan', status: 'not-run' },
    ]);
  });
});
