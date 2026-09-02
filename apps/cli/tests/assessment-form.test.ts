import { describe, expect, it } from 'vitest';
import {
  type AssessmentFormValues,
  assessmentDefaults,
  assessmentFormSchema,
} from '../web/src/components/AssessmentConfigFields.js';

function values(overrides: Partial<AssessmentFormValues> = {}): AssessmentFormValues {
  return { ...structuredClone(assessmentDefaults), targetUrl: 'https://authorized.example.test', ...overrides };
}

describe('assessment form scope validation', () => {
  it('defaults every available check and surface on', () => {
    const parsed = assessmentFormSchema.parse(values());
    expect(Object.values(parsed.testScopes).filter(Boolean)).toHaveLength(30);
    expect(
      Object.entries(parsed.testSurfaces)
        .filter(([, enabled]) => enabled)
        .map(([id]) => id),
    ).toEqual(['browser', 'api-graphql']);
    expect(
      Object.entries(parsed.assessmentModules)
        .filter(([, enabled]) => enabled)
        .map(([id]) => id),
    ).toEqual(['passive-exposure']);
    expect(parsed.targetEnvironment).toBe('production');
  });

  it('requires at least one available check and surface', () => {
    const noScopes = assessmentFormSchema.safeParse(
      values({ testScopes: Object.fromEntries(Object.keys(assessmentDefaults.testScopes).map((id) => [id, false])) }),
    );
    expect(noScopes.error?.issues).toContainEqual(
      expect.objectContaining({ path: ['testScopes'], message: 'Select at least one available check' }),
    );

    const noSurfaces = assessmentFormSchema.safeParse(
      values({
        testSurfaces: Object.fromEntries(Object.keys(assessmentDefaults.testSurfaces).map((id) => [id, false])),
      }),
    );
    expect(noSurfaces.error?.issues).toContainEqual(
      expect.objectContaining({ path: ['testSurfaces'], message: 'Select at least one available surface' }),
    );
  });

  it('requires explicit staging acknowledgement for load testing', () => {
    const loadSelected = structuredClone(assessmentDefaults.assessmentModules);
    loadSelected['http-load-capacity'] = true;
    const parsed = assessmentFormSchema.safeParse(
      values({ assessmentModules: loadSelected, targetEnvironment: 'staging', acknowledgeLoadRisk: false }),
    );
    expect(parsed.error?.issues).toContainEqual(
      expect.objectContaining({ path: ['acknowledgeLoadRisk'], message: expect.stringMatching(/acknowledge/i) }),
    );
  });

  it('rejects selecting both independent load executors', () => {
    const scopes = structuredClone(assessmentDefaults.testScopes);
    scopes['http-load-capacity'] = true;
    const modules = structuredClone(assessmentDefaults.assessmentModules);
    modules['http-load-capacity'] = true;

    const parsed = assessmentFormSchema.safeParse(
      values({
        testScopes: scopes,
        assessmentModules: modules,
        targetEnvironment: 'staging',
        acknowledgeLoadRisk: true,
      }),
    );
    expect(parsed.error?.issues).toContainEqual(
      expect.objectContaining({ path: ['assessmentModules'], message: expect.stringMatching(/either|not both/i) }),
    );
  });

  it('accepts manual HTTP load values and requires confirmation above elevated thresholds', () => {
    const loadOnly = Object.fromEntries(Object.keys(assessmentDefaults.testScopes).map((id) => [id, false]));
    loadOnly['http-load-capacity'] = true;

    expect(
      assessmentFormSchema.parse(
        values({
          testScopes: loadOnly,
          httpLoadConcurrency: 5,
          httpLoadRequestsPerSecond: 10,
          httpLoadDurationSeconds: 15,
        }),
      ),
    ).toMatchObject({ httpLoadConcurrency: 5, httpLoadRequestsPerSecond: 10, httpLoadDurationSeconds: 15 });

    const elevated = assessmentFormSchema.safeParse(
      values({ testScopes: loadOnly, httpLoadConcurrency: 21, elevatedLoadConfirmed: false }),
    );
    expect(elevated.error?.issues).toContainEqual(
      expect.objectContaining({ path: ['elevatedLoadConfirmed'], message: expect.stringMatching(/elevated/i) }),
    );
  });
});
