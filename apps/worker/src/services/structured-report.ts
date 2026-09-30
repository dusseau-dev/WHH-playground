// Copyright (C) 2025 Keygraph, Inc.

import type { ToolDefinition } from '@earendil-works/pi-coding-agent';
import { fs, path } from 'zx';
import { type AddFindingInput, createFindingCollector } from '../collectors/finding-collector.js';
import { createReportMetaCollector, type ReportMetaInput } from '../collectors/report-meta-collector.js';
import { toolResult } from '../collectors/schema.js';
import type { ActivityLogger } from '../types/activity-logger.js';
import { ALL_VULN_CLASSES, type SourceMode, type VulnClass } from '../types/config.js';
import { HTTP_LOAD_SCOPE, type HttpLoadResult, parseHttpLoadResult } from '../types/http-load.js';
import {
  type AssessmentModule,
  type AssessmentScope,
  buildModuleCoverage,
  buildScopeCoverage,
  type ModuleExecutionResult,
  normalizeAssessmentScope,
} from '../types/scopes.js';
import { atomicWrite, ensureDirectory } from '../utils/file-io.js';
import { redactSecrets } from '../utils/redactSecrets.js';
import { loadAssessmentModuleResults } from './assessment-module-runner.js';
import { attachQueueCodeLocations } from './code-location-join.js';
import { reconcileReportFindings } from './report-reconciliation.js';
import { type ReportData, renderReport } from './report-renderer.js';

export const REPORT_DATA_FILENAME = 'report.json';
/** Legacy workspace filename retained for resume and direct-consumer compatibility. */
export const REPORT_MARKDOWN_FILENAME = 'comprehensive_security_assessment_report.md';
/** Stable user-facing Markdown report filename. */
export const PUBLIC_REPORT_MARKDOWN_FILENAME = 'Security-Assessment-Report.md';

const REPORT_MARKDOWN_FILENAMES = [REPORT_MARKDOWN_FILENAME, PUBLIC_REPORT_MARKDOWN_FILENAME] as const;

interface QueueInventory {
  readonly knownFindingIds: readonly string[];
  readonly notAssessed: readonly VulnClass[];
}

export interface StructuredReportSessionOptions {
  readonly deliverablesPath: string;
  readonly webUrl: string;
  readonly sourceMode: SourceMode;
  readonly safeDemonstration: boolean;
  readonly triageRan: boolean;
  readonly selectedVulnClasses: readonly VulnClass[];
  readonly selectedTestScopes?: readonly AssessmentScope[];
  readonly selectedAssessmentModules?: readonly AssessmentModule[];
  readonly httpLoadResult?: HttpLoadResult;
}

export interface StructuredReportSession {
  readonly tools: ToolDefinition[];
  getFindings(): AddFindingInput[];
  finalize(logger: ActivityLogger): Promise<ReportData>;
}

function selectedClasses(values: readonly VulnClass[]): VulnClass[] {
  const selected = new Set(values);
  return ALL_VULN_CLASSES.filter((value) => selected.has(value));
}

async function loadQueueInventory(
  deliverablesPath: string,
  selectedVulnClasses: readonly VulnClass[],
): Promise<QueueInventory> {
  const knownFindingIds: string[] = [];
  const notAssessed: VulnClass[] = [];

  for (const vulnClass of selectedClasses(selectedVulnClasses)) {
    const queuePath = path.join(deliverablesPath, `${vulnClass}_exploitation_queue.json`);
    if (!(await fs.pathExists(queuePath))) {
      notAssessed.push(vulnClass);
      continue;
    }
    try {
      const raw = (await fs.readJson(queuePath)) as { vulnerabilities?: unknown };
      if (!Array.isArray(raw.vulnerabilities)) continue;
      for (const candidate of raw.vulnerabilities) {
        if (typeof candidate !== 'object' || candidate === null) continue;
        const id = (candidate as { ID?: unknown }).ID;
        if (typeof id === 'string' && id.length > 0) knownFindingIds.push(id);
      }
    } catch {
      // A present-but-invalid queue is not described as absent. Its IDs simply cannot be joined.
    }
  }

  return { knownFindingIds, notAssessed };
}

async function loadRawTriage(deliverablesPath: string, logger: ActivityLogger): Promise<unknown | null> {
  const triagePath = path.join(deliverablesPath, 'triage_verdicts.json');
  if (!(await fs.pathExists(triagePath))) return null;
  try {
    return await fs.readJson(triagePath);
  } catch (error) {
    logger.warn(`Could not parse triage_verdicts.json: ${error instanceof Error ? error.message : String(error)}`);
    return { invalid_triage_json: true };
  }
}

function exactFindingTool(baseTool: ToolDefinition, knownFindingIds: readonly string[]): ToolDefinition {
  const known = new Set(knownFindingIds);
  return {
    ...baseTool,
    description:
      `${baseTool.description ?? ''} The finding_id must be copied exactly (case and whitespace included) ` +
      'from a vulnerability queue; unknown IDs are rejected.',
    async execute(toolCallId, input, onUpdate, context, signal) {
      const id = (input as { finding_id?: unknown }).finding_id;
      if (typeof id !== 'string' || !known.has(id)) {
        return toolResult({
          status: 'error',
          message: `Finding ID ${String(id)} is not an exact ID from the selected vulnerability queues.`,
          errorType: 'UnknownFindingId',
          retryable: false,
        });
      }
      return baseTool.execute(toolCallId, input, onUpdate, context, signal);
    },
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Runtime guard used by the report agent validator and metadata updater. */
export function isReportData(value: unknown): value is ReportData {
  if (!isRecord(value)) return false;
  const meta = value.report_meta;
  if (!isRecord(meta)) return false;
  if (
    typeof meta.target !== 'string' ||
    typeof meta.assessment_date !== 'string' ||
    typeof meta.scope !== 'string' ||
    typeof meta.executive_summary !== 'string' ||
    typeof meta.safe_demonstration !== 'boolean' ||
    (meta.source_mode !== 'source-assisted' && meta.source_mode !== 'url-only') ||
    (meta.validation_state !== 'validated' && meta.validation_state !== 'unvalidated') ||
    (meta.model !== undefined && typeof meta.model !== 'string')
  ) {
    return false;
  }
  if (value.triage_status !== 'validated' && value.triage_status !== 'unvalidated') return false;
  if (meta.validation_state !== value.triage_status) return false;
  if (!Array.isArray(value.findings) || !Array.isArray(value.ruled_out) || !Array.isArray(value.not_assessed)) {
    return false;
  }
  if (!value.not_assessed.every((entry) => ALL_VULN_CLASSES.includes(entry as VulnClass))) return false;
  if (value.scope_coverage !== undefined && !Array.isArray(value.scope_coverage)) return false;
  if (value.module_coverage !== undefined && !Array.isArray(value.module_coverage)) return false;
  if (value.validation_issues !== undefined && !Array.isArray(value.validation_issues)) return false;
  if (value.http_load_capacity !== undefined) {
    try {
      parseHttpLoadResult(value.http_load_capacity);
    } catch {
      return false;
    }
  }
  return value.findings.every(
    (finding) =>
      isRecord(finding) &&
      typeof finding.finding_id === 'string' &&
      typeof finding.title === 'string' &&
      typeof finding.category === 'string' &&
      typeof finding.owasp_category === 'string' &&
      typeof finding.severity === 'string' &&
      typeof finding.vulnerable_location === 'string' &&
      typeof finding.overview === 'string' &&
      typeof finding.impact === 'string' &&
      typeof finding.remediation === 'string',
  );
}

export async function writeReportMarkdownFiles(deliverablesPath: string, markdown: string): Promise<void> {
  await ensureDirectory(deliverablesPath);
  const redactedMarkdown = redactSecrets(markdown);
  await Promise.all(
    REPORT_MARKDOWN_FILENAMES.map((filename) => atomicWrite(path.join(deliverablesPath, filename), redactedMarkdown)),
  );
}

export async function writeStructuredReportFiles(deliverablesPath: string, data: ReportData): Promise<void> {
  await ensureDirectory(deliverablesPath);
  const redactedData = redactSecrets(data);
  await atomicWrite(path.join(deliverablesPath, REPORT_DATA_FILENAME), redactedData);
  await writeReportMarkdownFiles(deliverablesPath, renderReport(redactedData));
}

/** Reconcile a resumed HTTP load artifact into an already-generated canonical report. */
export async function synchronizeHttpLoadReportFiles(
  deliverablesPath: string,
  selectedTestScopes: readonly AssessmentScope[],
  result: HttpLoadResult,
): Promise<boolean> {
  const reportPath = path.join(deliverablesPath, REPORT_DATA_FILENAME);
  if (!(await fs.pathExists(reportPath))) return false;

  const raw = (await fs.readJson(reportPath)) as unknown;
  if (!isReportData(raw)) throw new Error('Cannot synchronize HTTP load evidence into invalid report.json');
  const parsedResult = parseHttpLoadResult(result);
  const updated: ReportData = {
    ...raw,
    scope_coverage: buildScopeCoverage(
      selectedTestScopes,
      raw.not_assessed,
      parsedResult.status === 'completed' ? [HTTP_LOAD_SCOPE] : [],
    ),
    http_load_capacity: parsedResult,
  };
  await writeStructuredReportFiles(deliverablesPath, updated);
  return true;
}

/** Validate canonical JSON and both deterministic Markdown renderings. */
export async function validateStructuredReportFiles(
  deliverablesPath: string,
  logger: ActivityLogger,
): Promise<boolean> {
  const jsonPath = path.join(deliverablesPath, REPORT_DATA_FILENAME);
  const markdownPaths = REPORT_MARKDOWN_FILENAMES.map((filename) => path.join(deliverablesPath, filename));
  if (
    !(await fs.pathExists(jsonPath)) ||
    !(await Promise.all(markdownPaths.map((file) => fs.pathExists(file)))).every(Boolean)
  ) {
    logger.error('Missing required structured report.json or rendered Markdown report');
    return false;
  }
  try {
    const raw = (await fs.readJson(jsonPath)) as unknown;
    if (!isReportData(raw)) {
      logger.error('Invalid report.json');
      return false;
    }
    const expectedMarkdown = renderReport(raw);
    for (const markdownPath of markdownPaths) {
      const markdown = await fs.readFile(markdownPath, 'utf8');
      if (markdown !== expectedMarkdown) {
        logger.error(`${path.basename(markdownPath)} does not match the canonical report.json rendering`);
        return false;
      }
    }
    return true;
  } catch (error) {
    logger.error(`Could not validate structured report: ${error instanceof Error ? error.message : String(error)}`);
    return false;
  }
}

function composeReportData(
  metadata: ReportMetaInput,
  options: StructuredReportSessionOptions,
  reconciliation: ReturnType<typeof reconcileReportFindings>,
  notAssessed: readonly VulnClass[],
  moduleResults: readonly ModuleExecutionResult[],
): ReportData {
  const scope = normalizeAssessmentScope({
    ...(options.selectedTestScopes && { testScopes: options.selectedTestScopes }),
    vulnClasses: options.selectedVulnClasses,
  });
  return {
    report_meta: {
      ...metadata,
      target: options.webUrl,
      safe_demonstration: options.safeDemonstration,
      source_mode: options.sourceMode,
      validation_state: reconciliation.triage_status,
    },
    findings: reconciliation.findings,
    ruled_out: reconciliation.ruled_out,
    not_assessed: notAssessed,
    scope_coverage: buildScopeCoverage(
      scope.testScopes,
      notAssessed,
      options.httpLoadResult?.status === 'completed' ? [HTTP_LOAD_SCOPE] : [],
    ),
    ...(options.httpLoadResult && { http_load_capacity: options.httpLoadResult }),
    ...(options.selectedAssessmentModules && {
      module_coverage: buildModuleCoverage(options.selectedAssessmentModules, moduleResults),
    }),
    triage_status: reconciliation.triage_status,
    ...(reconciliation.validation_issues.length > 0 && {
      validation_issues: reconciliation.validation_issues,
    }),
  };
}

/**
 * Create the two report-agent tools and their post-execution finalizer. Queue inventory is read
 * before execution so add_finding can reject invented, normalized, or otherwise unstable IDs.
 */
export async function createStructuredReportSession(
  options: StructuredReportSessionOptions,
): Promise<StructuredReportSession> {
  const inventory = await loadQueueInventory(options.deliverablesPath, options.selectedVulnClasses);
  const moduleResults = await loadAssessmentModuleResults(options.deliverablesPath);
  const metadataCollector = createReportMetaCollector();
  const findingCollector = createFindingCollector(options.safeDemonstration);
  const findingTool = findingCollector.tools[0];
  if (!findingTool) throw new Error('add_finding tool was not created');
  const tools = [...metadataCollector.tools, exactFindingTool(findingTool, inventory.knownFindingIds)];

  return {
    tools,
    getFindings: findingCollector.getAll,
    async finalize(logger) {
      const metadata = metadataCollector.get();
      if (!metadata) throw new Error('Report agent did not call set_report_meta');
      const collected = findingCollector.getAll();
      const joined = await attachQueueCodeLocations(collected, options.deliverablesPath, logger, options.sourceMode);
      const rawTriage = await loadRawTriage(options.deliverablesPath, logger);
      const reconciliation = reconcileReportFindings(joined, rawTriage, {
        triageRan: options.triageRan,
        knownFindingIds: inventory.knownFindingIds,
      });
      const data = composeReportData(metadata, options, reconciliation, inventory.notAssessed, moduleResults);
      await writeStructuredReportFiles(options.deliverablesPath, data);
      return data;
    },
  };
}
