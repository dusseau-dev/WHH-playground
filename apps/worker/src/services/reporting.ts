// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { fs, path } from 'zx';
import { deliverablesDir, resolveSessionJsonPath } from '../paths.js';
import type { ActivityLogger } from '../types/activity-logger.js';
import type { SourceMode } from '../types/config.js';
import { ErrorCode } from '../types/errors.js';
import { PentestError } from './error-handling.js';
import {
  isReportData,
  REPORT_DATA_FILENAME,
  REPORT_MARKDOWN_FILENAME,
  writeReportMarkdownFiles,
  writeStructuredReportFiles,
} from './structured-report.js';
import { loadVerdicts, renderVerdictSections } from './triage-report.js';

interface DeliverableFile {
  name: string;
  /** Candidate filenames in priority order. First one that exists wins. */
  paths: readonly string[];
  required: boolean;
}

export const URL_ONLY_COVERAGE_NOTICE = [
  '> [!IMPORTANT]',
  '> **Assessment mode: URL-only dynamic testing.** No source repository was provided. The assessment',
  '> covers behavior observable through the authorized live target; source-code paths, internal-only',
  '> attack surfaces, and code-location attribution were not evaluated.',
].join('\n');

function modeLabel(sourceMode: SourceMode): 'Source-Assisted' | 'URL-Only' {
  return sourceMode === 'url-only' ? 'URL-Only' : 'Source-Assisted';
}

export function renderAssessmentModeSection(sourceMode: SourceMode): string {
  const coverage =
    sourceMode === 'url-only'
      ? 'This assessment used browser and API observations against the authorized live target. Code-level coverage and source-location attribution were unavailable in URL-only mode.'
      : 'This assessment used the provided repository and live target evidence where available. Findings and remediation are limited to evidence collected during this run and do not assert complete source coverage.';

  return ['## Mode', '', modeLabel(sourceMode), '', '## Coverage', '', coverage].join('\n');
}

function stripExistingAssessmentModeSections(report: string): string {
  let cleaned = report.replace(URL_ONLY_COVERAGE_NOTICE, '');
  for (const sourceMode of ['source-assisted', 'url-only'] as const) {
    cleaned = cleaned.replace(renderAssessmentModeSection(sourceMode), '');
  }
  return cleaned.replace(/\n{3,}/g, '\n\n').trim();
}

/** Add deterministic assessment mode and coverage sections exactly once. */
export function renderAssessmentModeSections(report: string, sourceMode: SourceMode): string {
  const cleaned = stripExistingAssessmentModeSections(report);
  const sections = renderAssessmentModeSection(sourceMode);
  const headingMatch = cleaned.match(/^# .+$/m);

  if (!headingMatch || headingMatch.index === undefined) {
    return `${sections}\n\n${cleaned}`;
  }
  const insertionPoint = headingMatch.index + headingMatch[0].length;
  const before = cleaned.slice(0, insertionPoint);
  const after = cleaned.slice(insertionPoint).trimStart();
  return `${before}\n\n${sections}${after ? `\n\n${after}` : ''}`;
}

export async function injectAssessmentModeSections(
  workingDirectory: string,
  deliverablesSubdir: string | undefined,
  sourceMode: SourceMode,
  logger: ActivityLogger,
): Promise<void> {
  const deliverablesPath = deliverablesDir(workingDirectory, deliverablesSubdir);
  if (await fs.pathExists(path.join(deliverablesPath, REPORT_DATA_FILENAME))) {
    logger.info('Canonical report.json already renders assessment mode and coverage; skipping legacy injection');
    return;
  }
  const reportPath = path.join(deliverablesPath, REPORT_MARKDOWN_FILENAME);
  if (!(await fs.pathExists(reportPath))) {
    logger.warn('Final report not found, skipping assessment mode sections');
    return;
  }
  const report = await fs.readFile(reportPath, 'utf8');
  const updated = renderAssessmentModeSections(report, sourceMode);
  await writeReportMarkdownFiles(deliverablesPath, updated);
  if (updated !== report) {
    logger.info('Injected assessment mode and coverage sections');
  } else {
    logger.info('Refreshed assessment mode and coverage sections');
  }
}

// Pure function: Assemble final report from specialist deliverables.
// Per class, prefer the exploit-agent's evidence file; fall back to renderer-produced findings.
// Both never coexist for a workspace because scope (safeDemonstration) is locked.
export async function assembleFinalReport(
  sourceDir: string,
  deliverablesSubdir: string | undefined,
  logger: ActivityLogger,
  triageRan: boolean,
): Promise<string> {
  const deliverableFiles: readonly DeliverableFile[] = [
    { name: 'Injection', paths: ['injection_exploitation_evidence.md', 'injection_findings.md'], required: false },
    { name: 'XSS', paths: ['xss_exploitation_evidence.md', 'xss_findings.md'], required: false },
    { name: 'Authentication', paths: ['auth_exploitation_evidence.md', 'auth_findings.md'], required: false },
    { name: 'SSRF', paths: ['ssrf_exploitation_evidence.md', 'ssrf_findings.md'], required: false },
    { name: 'Authorization', paths: ['authz_exploitation_evidence.md', 'authz_findings.md'], required: false },
  ];

  const dir = deliverablesDir(sourceDir, deliverablesSubdir);
  const sections: string[] = [];

  for (const file of deliverableFiles) {
    let added = false;
    for (const candidate of file.paths) {
      const filePath = path.join(dir, candidate);
      try {
        if (await fs.pathExists(filePath)) {
          const content = await fs.readFile(filePath, 'utf8');
          sections.push(content);
          logger.info(`Added ${file.name} section from ${candidate}`);
          added = true;
          break;
        }
      } catch (error) {
        const err = error as Error;
        logger.warn(`Could not read ${candidate}: ${err.message}`);
      }
    }
    if (!added) {
      if (file.required) {
        throw new PentestError(
          `Required deliverable file not found: ${file.paths.join(' or ')}`,
          'filesystem',
          false,
          { deliverableFile: file.paths, sourceDir },
          ErrorCode.DELIVERABLE_NOT_FOUND,
        );
      }
      logger.info(`No ${file.name} deliverable found`);
    }
  }

  // Prepend the deterministic triage sections (Confirmed / Ruled-out tables, or the
  // UNVALIDATED banner if verdicts are missing/invalid — fail-open).
  const verdicts = await loadVerdicts(sourceDir, deliverablesSubdir, logger);
  const verdictMarkdown = renderVerdictSections(verdicts, triageRan);
  const finalContent = [verdictMarkdown, ...sections].join('\n\n');
  const finalReportPath = path.join(dir, REPORT_MARKDOWN_FILENAME);

  try {
    await writeReportMarkdownFiles(dir, finalContent);
    logger.info(`Final report assembled at ${finalReportPath}`);
  } catch (error) {
    const err = error as Error;
    throw new PentestError(`Failed to write final report: ${err.message}`, 'filesystem', false, {
      finalReportPath,
      originalError: err.message,
    });
  }

  return finalContent;
}

/**
 * Inject model information into the final security report.
 * Reads session.json to get the model(s) used, then injects a "Model:" line
 * into the Executive Summary section of the report.
 */
export async function injectModelIntoReport(
  workingDirectory: string,
  deliverablesSubdir: string | undefined,
  outputPath: string,
  logger: ActivityLogger,
): Promise<void> {
  // 1. Read session.json to get model information
  const sessionJsonPath = resolveSessionJsonPath(outputPath);

  if (!(await fs.pathExists(sessionJsonPath))) {
    logger.warn('session.json not found, skipping model injection');
    return;
  }

  interface SessionData {
    metrics: {
      agents: Record<string, { model?: string }>;
    };
  }

  const sessionData: SessionData = await fs.readJson(sessionJsonPath);

  // 2. Extract unique models from all agents
  const models = new Set<string>();
  for (const agent of Object.values(sessionData.metrics.agents)) {
    if (agent.model) {
      models.add(agent.model);
    }
  }

  if (models.size === 0) {
    logger.warn('No model information found in session.json');
    return;
  }

  const modelStr = Array.from(models).sort().join(', ');
  logger.info(`Injecting model info into report: ${modelStr}`);

  const deliverablesPath = deliverablesDir(workingDirectory, deliverablesSubdir);
  const reportDataPath = path.join(deliverablesPath, REPORT_DATA_FILENAME);
  if (await fs.pathExists(reportDataPath)) {
    const raw = (await fs.readJson(reportDataPath)) as unknown;
    if (!isReportData(raw)) {
      throw new PentestError('Cannot inject model metadata into invalid report.json', 'validation', false, {
        reportDataPath,
      });
    }
    const updated = {
      ...raw,
      report_meta: { ...raw.report_meta, model: modelStr },
    };
    await writeStructuredReportFiles(deliverablesPath, updated);
    logger.info('Updated model metadata in report.json and rerendered Markdown');
    return;
  }

  // 3. Read the final report
  const reportPath = path.join(deliverablesPath, REPORT_MARKDOWN_FILENAME);

  if (!(await fs.pathExists(reportPath))) {
    logger.warn('Final report not found, skipping model injection');
    return;
  }

  let reportContent = await fs.readFile(reportPath, 'utf8');

  // 4. Find and inject model line after "Assessment Date" in Executive Summary
  // Pattern: "- Assessment Date: <date>" followed by a newline
  const assessmentDatePattern = /^(- Assessment Date: .+)$/m;
  const match = reportContent.match(assessmentDatePattern);

  if (match) {
    // Inject model line after Assessment Date
    const modelLine = `- Model: ${modelStr}`;
    reportContent = reportContent.replace(assessmentDatePattern, `$1\n${modelLine}`);
    logger.info('Model info injected into Executive Summary');
  } else {
    // If no Assessment Date line found, try to add after Executive Summary header
    const execSummaryPattern = /^## Executive Summary$/m;
    if (reportContent.match(execSummaryPattern)) {
      // Add model as first item in Executive Summary
      reportContent = reportContent.replace(execSummaryPattern, `## Executive Summary\n- Model: ${modelStr}`);
      logger.info('Model info added to Executive Summary header');
    } else {
      logger.warn('Could not find Executive Summary section');
      return;
    }
  }

  // 5. Keep the public and legacy Markdown artifacts byte-for-byte identical.
  await writeReportMarkdownFiles(deliverablesPath, reportContent);
}
