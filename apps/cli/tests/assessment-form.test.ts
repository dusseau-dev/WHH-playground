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
});
