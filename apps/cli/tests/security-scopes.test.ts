import { describe, expect, it } from 'vitest';
import { normalizeDetectionValidationSettings } from '../src/detection-validation.js';
import {
  assessmentModuleDefinitions,
  assessmentScopeCatalog,
  assessmentScopeDefinitions,
  availableTestScopes,
  availableTestSurfaces,
  defaultAssessmentModules,
  deriveTestCategories,
  expandTestCategories,
  getOwaspCategorySelection,
  normalizeAssessmentModules,
  normalizeTestScopeSelection,
  setOwaspCategorySelected,
} from '../src/security-scopes.js';

describe('CLI security scope catalog', () => {
  it('exposes all OWASP Top 10:2025 parents in order', () => {
    expect(assessmentScopeCatalog.map(({ id }) => id)).toEqual([
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
    expect(
      assessmentScopeCatalog.filter(({ availability }) => availability === 'coming-soon').map(({ id }) => id),
    ).toEqual(['A03:2025']);
  });

  it('defaults to available checks and surfaces only', () => {
    expect(availableTestScopes).toContain('csrf');
    expect(availableTestScopes).not.toContain('dependency-risk');
    expect(availableTestSurfaces).toEqual(['browser', 'api-graphql']);
  });

  it('keeps HTTP load and capacity explicitly selectable but outside bulk defaults', () => {
    expect(assessmentScopeDefinitions.find(({ id }) => id === 'http-load-capacity')).toEqual({
      id: 'http-load-capacity',
      label: 'HTTP load and capacity',
      owaspId: 'A06:2025',
      availability: 'available',
      executor: 'http-load',
      bulkSelectable: false,
    });
    expect(availableTestScopes).not.toContain('http-load-capacity');
  });

  it('exposes alerting effectiveness as an opt-in activity-backed check', () => {
    expect(assessmentScopeDefinitions.find(({ id }) => id === 'alerting-effectiveness')).toEqual({
      id: 'alerting-effectiveness',
      label: 'Alerting effectiveness',
      owaspId: 'A09:2025',
      availability: 'available',
      executor: 'detection-validation',
      bulkSelectable: false,
    });
    expect(availableTestScopes).not.toContain('alerting-effectiveness');
    expect(normalizeTestScopeSelection({ testScopes: ['alerting-effectiveness'] })).toMatchObject({
      testScopes: ['alerting-effectiveness'],
      testCategories: [],
    });
  });

  it('round-trips legacy category expansion through execution-lane derivation', () => {
    const scopes = expandTestCategories(['injection', 'authz']);
    expect(deriveTestCategories(scopes)).toEqual(['injection', 'authz']);
    expect(scopes).toContain('xxe');
    expect(scopes).toContain('csrf');
  });

  it('derives checked, unchecked, and indeterminate OWASP parent states', () => {
    expect(getOwaspCategorySelection([], 'A01:2025')).toEqual({
      checked: false,
      indeterminate: false,
      selectedCount: 0,
      totalCount: 5,
    });
    expect(getOwaspCategorySelection(['csrf'], 'A01:2025')).toEqual({
      checked: false,
      indeterminate: true,
      selectedCount: 1,
      totalCount: 5,
    });
    expect(
      getOwaspCategorySelection(
        ['csrf', 'ssrf', 'object-access', 'tenant-isolation', 'privilege-boundaries'],
        'A01:2025',
      ),
    ).toEqual({
      checked: true,
      indeterminate: false,
      selectedCount: 5,
      totalCount: 5,
    });
  });

  it('selects and clears all available children for an OWASP parent in registry order', () => {
    const selected = setOwaspCategorySelected(['verbose-errors'], 'A01:2025', true);
    expect(selected).toEqual([
      'object-access',
      'privilege-boundaries',
      'tenant-isolation',
      'csrf',
      'ssrf',
      'verbose-errors',
    ]);
    expect(setOwaspCategorySelected(selected, 'A01:2025', false)).toEqual(['verbose-errors']);
    expect(setOwaspCategorySelected(selected, 'A03:2025', true)).toEqual(selected);
  });

  it('rejects unknown granular and legacy identifiers from untyped callers', () => {
    expect(() => normalizeTestScopeSelection({ testScopes: ['unknown-scope' as never] })).toThrow(/unknown/i);
    expect(() => normalizeTestScopeSelection({ testCategories: ['unknown-lane' as never] })).toThrow(/unknown/i);
  });
});

describe('CLI detection validation settings', () => {
  const splunk = {
    managementUrl: 'https://splunk.example.test:8089',
    telemetryIndex: 'waf_events',
    alertIndex: 'security_alerts',
    telemetrySourcetype: 'aws:waf',
  };

  it('normalizes safe defaults only for the selected staging scope', () => {
    expect(normalizeDetectionValidationSettings(['alerting-effectiveness'], { splunk }, 'staging')).toEqual({
      canaryPath: '/__shannon__/detection-simulation',
      minimumDetectionRate: 1,
      maxWaitSeconds: 180,
      splunk,
    });
    expect(normalizeDetectionValidationSettings(['csrf'], undefined, 'production')).toBeUndefined();
  });

  it('fails closed on missing, production, or unsafe settings', () => {
    expect(() => normalizeDetectionValidationSettings(['alerting-effectiveness'], undefined, 'staging')).toThrow(
      /requires detection validation configuration/i,
    );
    expect(() => normalizeDetectionValidationSettings(['alerting-effectiveness'], { splunk }, 'production')).toThrow(
      /staging/i,
    );
    expect(() =>
      normalizeDetectionValidationSettings(
        ['alerting-effectiveness'],
        { canaryPath: 'https://evil.test/path', splunk },
        'staging',
      ),
    ).toThrow(/relative/i);
    expect(() =>
      normalizeDetectionValidationSettings(
        ['alerting-effectiveness'],
        { canaryPath: '/safe/%252e%252e/admin', splunk },
        'staging',
      ),
    ).toThrow(/traversal/i);
    expect(() =>
      normalizeDetectionValidationSettings(
        ['alerting-effectiveness'],
        { canaryPath: '/safe/%5cadmin', splunk },
        'staging',
      ),
    ).toThrow(/separator/i);
    expect(() =>
      normalizeDetectionValidationSettings(
        ['alerting-effectiveness'],
        { splunk: { ...splunk, managementUrl: 'http://splunk.example.test:8089' } },
        'staging',
      ),
    ).toThrow(/https/i);
    expect(() =>
      normalizeDetectionValidationSettings(
        ['alerting-effectiveness'],
        { splunk: { ...splunk, alertIndex: 'alerts | delete' } },
        'staging',
      ),
    ).toThrow(/index/i);
    expect(() => normalizeDetectionValidationSettings(['csrf'], { splunk }, 'staging')).toThrow(/requires.*scope/i);
  });
});

describe('CLI assessment module catalog', () => {
  it('exposes separate assessment methods with passive review enabled by default', () => {
    expect(assessmentModuleDefinitions.map(({ id }) => id)).toEqual([
      'passive-exposure',
      'automated-dast',
      'supply-chain',
      'http-load-capacity',
    ]);
    expect(defaultAssessmentModules).toEqual(['passive-exposure']);
  });

  it('enforces production-safe defaults and staging-only active testing', () => {
    expect(normalizeAssessmentModules({ sourceMode: 'url-only' })).toMatchObject({
      assessmentModules: ['passive-exposure'],
      moduleSafety: { targetEnvironment: 'production', allowActiveDast: false },
    });
    expect(() =>
      normalizeAssessmentModules({
        sourceMode: 'url-only',
        assessmentModules: ['automated-dast'],
        moduleSafety: { targetEnvironment: 'production', allowActiveDast: true },
      }),
    ).toThrow(/active.*staging/i);
  });
});
