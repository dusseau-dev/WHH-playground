/**
 * ReportOutputProvider — injectable interface for emitting secondary artifacts
 * from the canonical structured report.
 *
 * Runs after the report agent has finalized the canonical JSON and Markdown.
 * Consumers can override the built-in PDF/SARIF provider.
 */

import type { ActivityInput } from '../temporal/activities.js';
import type { ActivityLogger } from '../types/activity-logger.js';

export interface ReportOutputProvider {
  generate(input: ActivityInput, logger: ActivityLogger): Promise<ReportOutputResult>;
}

export type ReportArtifactKind = 'pdf' | 'sarif';

export interface ReportOutputArtifact {
  readonly kind: ReportArtifactKind;
  readonly outputPath: string;
}

export interface ReportOutputResult {
  /** Compatibility alias for older consumers expecting one secondary output. */
  readonly outputPath?: string;
  readonly artifacts?: readonly ReportOutputArtifact[];
}

/** Default no-op implementation — no additional output produced. */
export class NoOpReportOutputProvider implements ReportOutputProvider {
  async generate(): Promise<ReportOutputResult> {
    return {};
  }
}
