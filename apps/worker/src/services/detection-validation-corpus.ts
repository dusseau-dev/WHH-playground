export type DetectionValidationCohort = 'ai' | 'human';

export interface DetectionValidationFixture {
  readonly id: string;
  readonly pairId: string;
  readonly cohort: DetectionValidationCohort;
  readonly technique: string;
  readonly body: Readonly<Record<string, unknown>>;
}

export const DETECTION_CORPUS_VERSION = '1';

export const DETECTION_VALIDATION_CORPUS: readonly DetectionValidationFixture[] = [
  {
    id: 'human-credential-submission',
    pairId: 'credential-submission',
    cohort: 'human',
    technique: 'Synthetic credential submission',
    body: {
      simulation: 'shannon-inert',
      event: 'credential-submission',
      username: 'alex.lee@northbridge.invalid',
      password: 'SHANNON_FAKE_PASSWORD_DO_NOT_USE',
      note: 'Human-authored defensive fixture using fictional data.',
    },
  },
  {
    id: 'ai-credential-submission',
    pairId: 'credential-submission',
    cohort: 'ai',
    technique: 'Synthetic credential submission',
    body: {
      simulation: 'shannon-inert',
      event: 'credential-submission',
      username: 'casey.morgan@civic-lab.invalid',
      password: 'SHANNON_FAKE_AI_PASSWORD_DO_NOT_USE',
      note: 'Fixed AI-authored defensive fixture using fictional data.',
    },
  },
  {
    id: 'human-browser-store-indicator',
    pairId: 'browser-store-indicator',
    cohort: 'human',
    technique: 'Synthetic browser-store access indicator',
    body: {
      simulation: 'shannon-inert',
      event: 'browser-store-indicator',
      profile: 'fictional-browser-profile.invalid',
      record_count: 3,
      note: 'No browser data was accessed.',
    },
  },
  {
    id: 'ai-browser-store-indicator',
    pairId: 'browser-store-indicator',
    cohort: 'ai',
    technique: 'Synthetic browser-store access indicator',
    body: {
      simulation: 'shannon-inert',
      event: 'browser-store-indicator',
      profile: 'synthetic-managed-profile.invalid',
      record_count: 3,
      note: 'SHANNON_FAKE indicator only; no browser data was accessed.',
    },
  },
  {
    id: 'human-privileged-account-inventory',
    pairId: 'privileged-account-inventory',
    cohort: 'human',
    technique: 'Synthetic privileged-account inventory',
    body: {
      simulation: 'shannon-inert',
      event: 'privileged-account-inventory',
      accounts: ['admin.one@northbridge.invalid', 'admin.two@northbridge.invalid'],
      note: 'Fictional account names for alert validation.',
    },
  },
  {
    id: 'ai-privileged-account-inventory',
    pairId: 'privileged-account-inventory',
    cohort: 'ai',
    technique: 'Synthetic privileged-account inventory',
    body: {
      simulation: 'shannon-inert',
      event: 'privileged-account-inventory',
      accounts: ['operator.alpha@civic-lab.invalid', 'operator.beta@civic-lab.invalid'],
      note: 'Fixed AI-authored SHANNON_FAKE account inventory.',
    },
  },
  {
    id: 'human-session-token-collection',
    pairId: 'session-token-collection',
    cohort: 'human',
    technique: 'Synthetic session-token collection',
    body: {
      simulation: 'shannon-inert',
      event: 'session-token-collection',
      tokens: ['SHANNON_FAKE_SESSION_A', 'SHANNON_FAKE_SESSION_B'],
      note: 'Synthetic values that cannot authenticate anywhere.',
    },
  },
  {
    id: 'ai-session-token-collection',
    pairId: 'session-token-collection',
    cohort: 'ai',
    technique: 'Synthetic session-token collection',
    body: {
      simulation: 'shannon-inert',
      event: 'session-token-collection',
      tokens: ['SHANNON_FAKE_AI_SESSION_A', 'SHANNON_FAKE_AI_SESSION_B'],
      note: 'Fixed AI-authored synthetic values with no authentication capability.',
    },
  },
  {
    id: 'human-data-staging-indicator',
    pairId: 'data-staging-indicator',
    cohort: 'human',
    technique: 'Synthetic data-staging indicator',
    body: {
      simulation: 'shannon-inert',
      event: 'data-staging-indicator',
      files: ['fictional-budget.txt.invalid', 'fictional-directory.csv.invalid'],
      note: 'Names only; no files or data are transmitted.',
    },
  },
  {
    id: 'ai-data-staging-indicator',
    pairId: 'data-staging-indicator',
    cohort: 'ai',
    technique: 'Synthetic data-staging indicator',
    body: {
      simulation: 'shannon-inert',
      event: 'data-staging-indicator',
      files: ['SHANNON_FAKE_RESEARCH.txt.invalid', 'SHANNON_FAKE_CONTACTS.csv.invalid'],
      note: 'Fixed AI-authored names only; no files or data are transmitted.',
    },
  },
] as const;
