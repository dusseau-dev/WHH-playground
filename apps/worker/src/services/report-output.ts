// Copyright (C) 2025 Keygraph, Inc.

/** Built-in PDF and opt-in SARIF generation from canonical report.json. */

import { rm } from 'node:fs/promises';
import path from 'node:path';
import type {
  ReportOutputArtifact,
  ReportOutputProvider,
  ReportOutputResult,
} from '../interfaces/report-output-provider.js';
import { deliverablesDir } from '../paths.js';
import type { ActivityInput } from '../temporal/activities.js';
import type { ActivityLogger } from '../types/activity-logger.js';
import { atomicWrite, fileExists, readJson } from '../utils/file-io.js';
import { ConfigLoaderService } from './config-loader.js';
import { type RenderReportPdfOptions, renderReportPdf } from './pdf-renderer.js';
import type { ReportData } from './report-renderer.js';
import { renderSarif } from './sarif-renderer.js';
import { isReportData, REPORT_DATA_FILENAME } from './structured-report.js';

export const REPORT_PDF_FILENAME = 'Security-Assessment-Report.pdf';
export const REPORT_SARIF_FILENAME = 'report.sarif';

type PdfRenderer = (options: RenderReportPdfOptions) => Promise<void>;
type SarifRenderer = (data: ReportData, options: { readonly workspaceName: string }) => string;

export interface DefaultReportOutputDependencies {
  readonly pdfRenderer?: PdfRenderer;
  readonly sarifRenderer?: SarifRenderer;
  readonly templatePath?: string;
}

async function sarifRequested(input: ActivityInput, logger: ActivityLogger): Promise<boolean> {
  const result = await new ConfigLoaderService().loadOptional(
    input.configPath,
    input.configData,
    input.configYAML,
    input.sourceMode,
  );
  if (!result.ok) {
    logger.warn(`SARIF configuration could not be resolved; skipping SARIF: ${result.error.message}`);
    return false;
  }
  return result.value?.report.sarif === true;
}

/** Fail-closed gate for machine-readable findings. */
export function isSarifEligible(data: ReportData, requested: boolean): boolean {
  if (!requested || !data.report_meta.safe_demonstration) return false;
  if (data.triage_status !== 'validated' || data.report_meta.validation_state !== 'validated') return false;
  if ((data.validation_issues?.length ?? 0) > 0) return false;
  return data.findings.every(
    (finding) =>
      finding.triage?.validation_state === 'validated' &&
      (finding.triage.verdict === 'PASS' || finding.triage.verdict === 'DOWNGRADE'),
  );
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function removeStale(filePath: string, logger: ActivityLogger): Promise<void> {
  try {
    await rm(filePath, { force: true });
  } catch (error) {
    logger.warn(`Could not remove stale report artifact ${path.basename(filePath)}: ${message(error)}`);
  }
}

/** Default OSS implementation. Secondary output failures never fail the assessment run. */
export class DefaultReportOutputProvider implements ReportOutputProvider {
  private readonly pdfRenderer: PdfRenderer;
  private readonly sarifRenderer: SarifRenderer;
  private readonly templatePath: string | undefined;

  constructor(dependencies: DefaultReportOutputDependencies = {}) {
    this.pdfRenderer = dependencies.pdfRenderer ?? renderReportPdf;
    this.sarifRenderer = dependencies.sarifRenderer ?? renderSarif;
    this.templatePath = dependencies.templatePath;
  }

  async generate(input: ActivityInput, logger: ActivityLogger): Promise<ReportOutputResult> {
    const deliverablesPath = deliverablesDir(input.workingDirectory, input.deliverablesSubdir);
    const reportJsonPath = path.join(deliverablesPath, REPORT_DATA_FILENAME);
    const pdfPath = path.join(deliverablesPath, REPORT_PDF_FILENAME);
    const sarifPath = path.join(deliverablesPath, REPORT_SARIF_FILENAME);
    const artifacts: ReportOutputArtifact[] = [];

    // Removing first guarantees a retry or resume never exposes an artifact from older report data.
    await removeStale(pdfPath, logger);
    await removeStale(sarifPath, logger);

    if (!(await fileExists(reportJsonPath))) {
      logger.warn('Canonical report.json is unavailable; PDF and SARIF generation skipped');
      return { artifacts };
    }

    let reportData: ReportData;
    try {
      const raw = await readJson(reportJsonPath);
      if (!isReportData(raw)) throw new Error('report.json does not match the canonical report contract');
      reportData = raw;
    } catch (error) {
      logger.warn(`Canonical report.json is invalid; PDF and SARIF generation skipped: ${message(error)}`);
      return { artifacts };
    }

    try {
      await this.pdfRenderer({
        reportData,
        outputPath: pdfPath,
        ...(this.templatePath !== undefined && { templatePath: this.templatePath }),
      });
      artifacts.push({ kind: 'pdf', outputPath: pdfPath });
    } catch (error) {
      await removeStale(pdfPath, logger);
      logger.warn(`PDF report generation failed; Markdown remains available: ${message(error)}`);
    }

    const requested = await sarifRequested(input, logger);
    if (!isSarifEligible(reportData, requested)) {
      const reason = !requested
        ? 'report.sarif is disabled'
        : !reportData.report_meta.safe_demonstration
          ? 'the run was analysis-only'
          : 'triage or confirmed findings were not fully validated';
      logger.info(`SARIF report skipped: ${reason}`);
    } else {
      try {
        await atomicWrite(sarifPath, this.sarifRenderer(reportData, { workspaceName: input.sessionId }));
        artifacts.push({ kind: 'sarif', outputPath: sarifPath });
      } catch (error) {
        await removeStale(sarifPath, logger);
        logger.warn(`SARIF report generation failed; human-readable reports remain available: ${message(error)}`);
      }
    }

    return {
      artifacts,
      ...(artifacts[0] && { outputPath: artifacts[0].outputPath }),
    };
  }
}
