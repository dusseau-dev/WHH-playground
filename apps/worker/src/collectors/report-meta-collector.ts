// Copyright (C) 2025 Keygraph, Inc.

import { defineTool, type ToolDefinition } from '@earendil-works/pi-coding-agent';
import { type Static, Type } from 'typebox';
import { cleanInput, toolResult } from './schema.js';

const ReportMetaInputSchema = Type.Object({
  target: Type.String({ minLength: 1, description: 'The authorized target URL copied exactly from the prompt.' }),
  assessment_date: Type.String({ minLength: 1, description: 'Assessment date in YYYY-MM-DD format.' }),
  scope: Type.String({ minLength: 1, description: 'Concise description of the vulnerability classes assessed.' }),
  executive_summary: Type.String({ minLength: 1, description: 'Evidence-grounded executive summary.' }),
});

export type ReportMetaInput = Static<typeof ReportMetaInputSchema>;

export interface ReportMetaCollector {
  readonly tools: ToolDefinition[];
  get(): ReportMetaInput | undefined;
}

/** Capture the agent-authored report narrative without allowing direct file edits. */
export function createReportMetaCollector(): ReportMetaCollector {
  let metadata: ReportMetaInput | undefined;
  const setReportMeta = defineTool({
    name: 'set_report_meta',
    label: 'Set Report Metadata',
    description: 'Record the report target, date, scope, and executive summary. Call exactly once.',
    parameters: ReportMetaInputSchema,
    async execute(_toolCallId, input) {
      if (metadata) {
        return toolResult({
          status: 'error',
          message: 'Report metadata has already been recorded.',
          errorType: 'DuplicateError',
          retryable: false,
        });
      }
      metadata = cleanInput(ReportMetaInputSchema, input);
      return toolResult({ status: 'success' });
    },
  });

  return { tools: [setReportMeta], get: () => (metadata ? { ...metadata } : undefined) };
}
