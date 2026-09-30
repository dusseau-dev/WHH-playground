// Copyright (C) 2025 Keygraph, Inc.

/** Compile canonical report data to PDF with the bundled Typst template. */

import { execFile } from 'node:child_process';
import { copyFile, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { ReportData } from './report-renderer.js';

const DATA_FILENAME = 'report.json';
const TEMPLATE_FILENAME = 'report.typ';
const TEMP_PDF_FILENAME = 'report.pdf';

export const DEFAULT_REPORT_TEMPLATE_PATH = path.resolve(import.meta.dirname, '../../templates/typst/report.typ');

export type PdfCommandRunner = (executable: string, args: readonly string[]) => Promise<void>;

const runCommand: PdfCommandRunner = (executable, args) =>
  new Promise<void>((resolve, reject) => {
    // Arguments are passed directly to execFile. A shell is never involved.
    execFile(executable, [...args], (error) => (error ? reject(error) : resolve()));
  });

export interface RenderReportPdfOptions {
  readonly reportData: ReportData;
  readonly outputPath: string;
  readonly templatePath?: string;
  readonly typstExecutable?: string;
  /** Test/embedding seam; production always uses execFile. */
  readonly commandRunner?: PdfCommandRunner;
}

/**
 * Compile in an isolated directory and only copy a completed PDF to the deliverables directory.
 * The temporary directory is removed on success, compiler error, and copy error.
 */
export async function renderReportPdf(options: RenderReportPdfOptions): Promise<void> {
  const templatePath = options.templatePath ?? DEFAULT_REPORT_TEMPLATE_PATH;
  const commandRunner = options.commandRunner ?? runCommand;
  const workDir = await mkdtemp(path.join(tmpdir(), 'shannon-typst-'));

  try {
    const templateCopy = path.join(workDir, TEMPLATE_FILENAME);
    const dataPath = path.join(workDir, DATA_FILENAME);
    const temporaryPdf = path.join(workDir, TEMP_PDF_FILENAME);
    await copyFile(templatePath, templateCopy);
    await writeFile(dataPath, `${JSON.stringify(options.reportData, null, 2)}\n`, 'utf8');

    await commandRunner(options.typstExecutable ?? 'typst', [
      'compile',
      '--root',
      workDir,
      '--input',
      `data=/${DATA_FILENAME}`,
      templateCopy,
      temporaryPdf,
    ]);

    await mkdir(path.dirname(options.outputPath), { recursive: true });
    await copyFile(temporaryPdf, options.outputPath);
  } finally {
    await rm(workDir, { recursive: true, force: true });
  }
}
