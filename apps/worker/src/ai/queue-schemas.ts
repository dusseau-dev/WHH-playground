// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * TypeBox schemas and captured submit tools for vulnerability queues.
 *
 * Pi captures structured output through `submit_exploitation_queue`. The
 * caller writes the captured payload to the existing per-class queue file.
 */

import { defineTool } from '@earendil-works/pi-coding-agent';
import { type Static, type TObject, Type } from 'typebox';
import type { AgentName } from '../types/agents.js';
import type { CapturedSubmitTool } from './submit-tool.js';

const ANALYSIS_NOTES_DESCRIPTION = 'Plain context for defenders (caveats, scope, what is at risk). Not attack steps.';

function optStr(description?: string) {
  return Type.Optional(Type.String(description === undefined ? {} : { description }));
}

function baseFields(safeDemonstration: boolean) {
  return {
    ID: Type.String(),
    vulnerability_type: Type.String(),
    externally_exploitable: Type.Boolean(),
    confidence: Type.String(),
    code_locations: Type.Optional(
      Type.Array(
        Type.Object({
          file: Type.String({ description: 'Repository-relative path, no leading slash.' }),
          start_line: Type.Optional(Type.Integer({ minimum: 1 })),
          end_line: Type.Optional(Type.Integer({ minimum: 1, description: 'Set when the flaw spans a range.' })),
          role: Type.Union([Type.Literal('sink'), Type.Literal('source'), Type.Literal('guard')]),
          symbol: Type.Optional(Type.String({ description: 'Enclosing function or method.' })),
        }),
        { description: 'Every code site this finding touches, sink first.' },
      ),
    ),
    notes: safeDemonstration ? optStr() : optStr(ANALYSIS_NOTES_DESCRIPTION),
  };
}

const injectionFields = {
  source: optStr(),
  combined_sources: optStr(),
  path: optStr(),
  sink_call: optStr(),
  slot_type: optStr(),
  sanitization_observed: optStr(),
  concat_occurrences: optStr(),
  verdict: optStr(),
  mismatch_reason: optStr(),
  witness_payload: optStr(),
};

const xssFields = {
  source: optStr(),
  source_detail: optStr(),
  path: optStr(),
  sink_function: optStr(),
  render_context: optStr(),
  encoding_observed: optStr(),
  verdict: optStr(),
  mismatch_reason: optStr(),
  witness_payload: optStr(),
};

const authFields = {
  source_endpoint: optStr(),
  vulnerable_code_location: optStr(),
  missing_defense: optStr(),
  exploitation_hypothesis: optStr(),
  suggested_exploit_technique: optStr(),
};

const ssrfFields = {
  source_endpoint: optStr(),
  vulnerable_parameter: optStr(),
  vulnerable_code_location: optStr(),
  missing_defense: optStr(),
  exploitation_hypothesis: optStr(),
  suggested_exploit_technique: optStr(),
};

const authzFields = {
  endpoint: optStr(),
  vulnerable_code_location: optStr(),
  role_context: optStr(),
  guard_evidence: optStr(),
  side_effect: optStr(),
  reason: optStr(),
  minimal_witness: optStr(),
};

const injectionEntry = () => Type.Object({ ...baseFields(true), ...injectionFields });
const xssEntry = () => Type.Object({ ...baseFields(true), ...xssFields });
const authEntry = () => Type.Object({ ...baseFields(true), ...authFields });
const ssrfEntry = () => Type.Object({ ...baseFields(true), ...ssrfFields });
const authzEntry = () => Type.Object({ ...baseFields(true), ...authzFields });

export type QueueCodeLocation = NonNullable<Static<ReturnType<typeof injectionEntry>>['code_locations']>[number];
export type InjectionFinding = Static<ReturnType<typeof injectionEntry>>;
export type XssFinding = Static<ReturnType<typeof xssEntry>>;
export type AuthFinding = Static<ReturnType<typeof authEntry>>;
export type SsrfFinding = Static<ReturnType<typeof ssrfEntry>>;
export type AuthzFinding = Static<ReturnType<typeof authzEntry>>;

const PER_TYPE_FIELDS: Partial<Record<AgentName, Record<string, ReturnType<typeof optStr>>>> = {
  'injection-vuln': injectionFields,
  'xss-vuln': xssFields,
  'auth-vuln': authFields,
  'ssrf-vuln': ssrfFields,
  'authz-vuln': authzFields,
};

const VULN_AGENT_QUEUE_FILENAMES: Partial<Record<AgentName, string>> = {
  'injection-vuln': 'injection_exploitation_queue.json',
  'xss-vuln': 'xss_exploitation_queue.json',
  'auth-vuln': 'auth_exploitation_queue.json',
  'ssrf-vuln': 'ssrf_exploitation_queue.json',
  'authz-vuln': 'authz_exploitation_queue.json',
};

function queueSchema(agentName: AgentName, safeDemonstration: boolean): TObject | undefined {
  const extra = PER_TYPE_FIELDS[agentName];
  if (!extra) return undefined;
  return Type.Object({ vulnerabilities: Type.Array(Type.Object({ ...baseFields(safeDemonstration), ...extra })) });
}

export function getQueueFilename(agentName: AgentName): string | undefined {
  return VULN_AGENT_QUEUE_FILENAMES[agentName];
}

export function createQueueSubmitTool(agentName: AgentName, safeDemonstration = true): CapturedSubmitTool | undefined {
  const schema = queueSchema(agentName, safeDemonstration);
  if (!schema) return undefined;

  let captured: unknown | undefined;
  return {
    tool: defineTool({
      name: 'submit_exploitation_queue',
      label: 'Submit Exploitation Queue',
      description:
        'Submit the final structured list of analyzed vulnerabilities for this class. Call exactly once when analysis is complete.',
      promptSnippet: 'submit_exploitation_queue: record the final structured findings list (call once)',
      promptGuidelines: [
        'You MUST call submit_exploitation_queue exactly once as your final action.',
        'Include every analyzed finding in the vulnerabilities array.',
      ],
      parameters: schema,
      async execute(_toolCallId, params) {
        captured = params;
        const count = Array.isArray((params as { vulnerabilities?: unknown }).vulnerabilities)
          ? (params as { vulnerabilities: unknown[] }).vulnerabilities.length
          : 0;
        return {
          content: [{ type: 'text' as const, text: `Recorded ${count} findings.` }],
          details: params,
          terminate: true,
        };
      },
    }),
    getCaptured: () => captured,
    directive:
      '\n\nYou MUST call the submit_exploitation_queue tool exactly once as your final action ' +
      'to deliver your structured exploitation queue. Do not output JSON as text. Fill every required parameter.',
  };
}
