import { describe, expect, it } from 'vitest';
import {
  ASSESSMENT_SCOPE_REGISTRY,
  buildScopeCoverage,
  DEFAULT_ASSESSMENT_SCOPES,
  DEFAULT_ASSESSMENT_SURFACES,
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
    expect(OWASP_CATEGORY_REGISTRY.find(({ id }) => id === 'A09:2025')?.availability).toBe('coming-soon');
  });

  it('maps every available check to one durable execution lane', () => {
    const available = ASSESSMENT_SCOPE_REGISTRY.filter(({ availability }) => availability === 'available');
    expect(available).toHaveLength(DEFAULT_ASSESSMENT_SCOPES.length);
    expect(available.every(({ agent }) => agent !== undefined)).toBe(true);
    expect(available.find(({ id }) => id === 'csrf')).toMatchObject({ owaspId: 'A01:2025', agent: 'authz' });
    expect(available.find(({ id }) => id === 'xxe')).toMatchObject({ owaspId: 'A05:2025', agent: 'injection' });
    expect(available.find(({ id }) => id === 'rate-limiting')).toMatchObject({
      owaspId: 'A06:2025',
      agent: 'auth',
    });
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
});
