// Copyright (C) 2025 Keygraph, Inc.

import { defineTool, type ToolDefinition } from '@earendil-works/pi-coding-agent';
import { type Static, Type } from 'typebox';
import { cleanInput, stringEnum, toolResult } from './schema.js';

export const SEVERITY_VALUES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type FindingSeverity = (typeof SEVERITY_VALUES)[number];
export type FindingValidationState = 'validated' | 'unvalidated';
export type FindingTriageVerdict = 'PASS' | 'DOWNGRADE';

const OWASP_CATEGORY_VALUES = [
  'A01:2025 — Broken Access Control',
  'A02:2025 — Security Misconfiguration',
  'A03:2025 — Software Supply Chain Failures',
  'A04:2025 — Cryptographic Failures',
  'A05:2025 — Injection',
  'A06:2025 — Insecure Design',
  'A07:2025 — Authentication Failures',
  'A08:2025 — Software or Data Integrity Failures',
  'A09:2025 — Security Logging and Alerting Failures',
  'A10:2025 — Mishandling of Exceptional Conditions',
] as const;

const StepItemSchema = Type.Union([
  Type.Object({ kind: Type.Literal('prose'), text: Type.String({ minLength: 1 }) }),
  Type.Object({
    kind: Type.Literal('code'),
    block: Type.Object({ language: Type.String(), content: Type.String({ minLength: 1 }) }),
  }),
]);

const StructuredStepSchema = Type.Object({
  title: Type.Optional(Type.Union([Type.String(), Type.Null()])),
  items: Type.Array(StepItemSchema, { minItems: 1 }),
});

const CodeLocationSchema = Type.Object({
  file: Type.String({ minLength: 1, description: 'Repository-relative path, without a leading slash.' }),
  start_line: Type.Optional(Type.Union([Type.Integer({ minimum: 1 }), Type.Null()])),
  end_line: Type.Optional(Type.Union([Type.Integer({ minimum: 1 }), Type.Null()])),
  role: stringEnum(['sink', 'source', 'guard'] as const),
  symbol: Type.Optional(Type.Union([Type.String(), Type.Null()])),
});

const HttpLocationSchema = Type.Object({
  method: Type.String({ minLength: 1 }),
  url: Type.String({ minLength: 1 }),
  parameter: Type.Optional(Type.Union([Type.String(), Type.Null()])),
});

const AdditionalSectionSchema = Type.Object({
  heading: Type.String({ minLength: 1 }),
  items: Type.Array(StepItemSchema, { minItems: 1 }),
});

const TriageMetadataSchema = Type.Object({
  validation_state: stringEnum(['validated', 'unvalidated'] as const),
  verdict: Type.Optional(stringEnum(['PASS', 'DOWNGRADE'] as const)),
  reason: Type.Optional(Type.String()),
});

function identityFields(safeDemonstration: boolean) {
  return {
    finding_id: Type.String({
      minLength: 1,
      description: 'Stable finding ID copied exactly from the vulnerability queue. Unique within the report.',
    }),
    title: Type.String({ minLength: 1 }),
    category: stringEnum(['Injection', 'XSS', 'Authentication', 'Authorization', 'SSRF'] as const),
    owasp_category: stringEnum(OWASP_CATEGORY_VALUES),
    severity: stringEnum(SEVERITY_VALUES, {
      description: safeDemonstration
        ? 'Severity based on demonstrated impact.'
        : 'Severity assessed from the vulnerability and potential impact.',
    }),
  };
}

function narrativeFields(safeDemonstration: boolean) {
  return {
    vulnerable_location: Type.String({ minLength: 1 }),
    http_location: Type.Optional(Type.Union([HttpLocationSchema, Type.Null()])),
    overview: Type.String({ minLength: 1 }),
    impact: Type.String({
      minLength: 1,
      description: safeDemonstration ? 'Demonstrated impact.' : 'Potential impact; do not claim it was demonstrated.',
    }),
    remediation: Type.String({ minLength: 1 }),
  };
}

function exploitFields() {
  return {
    auth_state: Type.String({ minLength: 1 }),
    prerequisites: Type.String({ minLength: 1 }),
    exploitation_steps: Type.Array(StructuredStepSchema, { minItems: 1 }),
    proof_of_impact: Type.Array(StepItemSchema, { minItems: 1 }),
    status: Type.Optional(
      Type.Union([
        stringEnum(['exploited', 'out_of_scope', 'blocked_by_constraints', 'false_positive'] as const),
        Type.Null(),
      ]),
    ),
  };
}

function analysisFields() {
  return { confidence: stringEnum(['high', 'medium', 'low'] as const) };
}

function optionalFields() {
  return {
    notes: Type.Optional(Type.Union([Type.Array(StepItemSchema), Type.Null()])),
    additional_sections: Type.Optional(Type.Union([Type.Array(AdditionalSectionSchema), Type.Null()])),
  };
}

export function buildAddFindingSchema(safeDemonstration: boolean) {
  return Type.Object({
    ...identityFields(safeDemonstration),
    ...(safeDemonstration ? exploitFields() : analysisFields()),
    ...narrativeFields(safeDemonstration),
    ...optionalFields(),
  });
}

// A consumer-facing superset. code_locations and triage fields are attached deterministically,
// never supplied through add_finding.
const AddFindingSupersetSchema = Type.Object({
  ...identityFields(true),
  code_locations: Type.Optional(Type.Array(CodeLocationSchema)),
  auth_state: Type.Optional(Type.String()),
  prerequisites: Type.Optional(Type.String()),
  exploitation_steps: Type.Optional(Type.Array(StructuredStepSchema)),
  proof_of_impact: Type.Optional(Type.Array(StepItemSchema)),
  status: Type.Optional(
    Type.Union([
      stringEnum(['exploited', 'out_of_scope', 'blocked_by_constraints', 'false_positive'] as const),
      Type.Null(),
    ]),
  ),
  confidence: Type.Optional(Type.Union([stringEnum(['high', 'medium', 'low'] as const), Type.Null()])),
  ...narrativeFields(true),
  ...optionalFields(),
  original_severity: Type.Optional(stringEnum(SEVERITY_VALUES)),
  triage: Type.Optional(TriageMetadataSchema),
});

export type AddFindingInput = Static<typeof AddFindingSupersetSchema>;
export type CodeLocation = Static<typeof CodeLocationSchema>;
export type HttpLocation = Static<typeof HttpLocationSchema>;
export type StepItem = Static<typeof StepItemSchema>;
export type StructuredStep = Static<typeof StructuredStepSchema>;
export type AdditionalSection = Static<typeof AdditionalSectionSchema>;
export type FindingTriageMetadata = Static<typeof TriageMetadataSchema>;

export interface FindingCollector {
  tools: ToolDefinition[];
  getAll(): AddFindingInput[];
}

export function createFindingCollector(safeDemonstration: boolean): FindingCollector {
  const findings: AddFindingInput[] = [];
  const schema = buildAddFindingSchema(safeDemonstration);
  const addFinding = defineTool({
    name: 'add_finding',
    label: 'Add Finding',
    description:
      'Record one canonical report finding. Call once per finding after grouping and deduplication; duplicate finding IDs are rejected.',
    parameters: schema,
    async execute(_toolCallId, input) {
      if (findings.some((entry) => entry.finding_id === input.finding_id)) {
        return toolResult({
          status: 'error',
          message: `Finding ${input.finding_id} has already been recorded.`,
          errorType: 'DuplicateError',
          retryable: false,
        });
      }
      const clean = cleanInput(schema, input) as AddFindingInput;
      findings.push(clean);
      return toolResult({ status: 'success', added: [clean.finding_id] });
    },
  });

  return { tools: [addFinding], getAll: () => findings.map((finding) => ({ ...finding })) };
}
