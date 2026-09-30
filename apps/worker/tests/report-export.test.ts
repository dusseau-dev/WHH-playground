import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { REPORT_PDF_FILENAME, REPORT_SARIF_FILENAME } from '../src/services/report-output.js';
import {
  PUBLIC_REPORT_MARKDOWN_FILENAME,
  REPORT_DATA_FILENAME,
  REPORT_MARKDOWN_FILENAME,
} from '../src/services/structured-report.js';
import { copyDeliverables } from '../src/temporal/worker.js';

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => fs.rm(root, { recursive: true, force: true })));
});

describe('public deliverable export', () => {
  it('copies public reports and evidence without canonical JSON or workspace internals', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'shannon-report-export-'));
    roots.push(root);
    const deliverables = path.join(root, '.shannon', 'deliverables');
    const output = path.join(root, 'output');
    await fs.mkdir(path.join(deliverables, 'internal'), { recursive: true });
    await fs.mkdir(path.join(deliverables, 'modules', 'automated-dast'), { recursive: true });

    const publicFiles = [
      PUBLIC_REPORT_MARKDOWN_FILENAME,
      REPORT_PDF_FILENAME,
      REPORT_SARIF_FILENAME,
      'injection_exploitation_evidence.md',
      'xss_exploitation_evidence.md',
    ];
    const internalFiles = [
      REPORT_DATA_FILENAME,
      REPORT_MARKDOWN_FILENAME,
      'triage_verdicts.json',
      'injection_exploitation_queue.json',
      'injection_analysis_deliverable.md',
      'error.log',
      `${PUBLIC_REPORT_MARKDOWN_FILENAME}.tmp`,
    ];

    await Promise.all(
      [...publicFiles, ...internalFiles].map((filename) =>
        fs.writeFile(path.join(deliverables, filename), filename, 'utf8'),
      ),
    );
    await fs.writeFile(path.join(deliverables, 'internal', 'nested.txt'), 'internal', 'utf8');
    await fs.writeFile(path.join(deliverables, 'modules', 'manifest.json'), '{"results":[]}', 'utf8');
    await fs.writeFile(path.join(deliverables, 'modules', 'passive-exposure.json'), '{"status":"completed"}', 'utf8');
    await fs.writeFile(
      path.join(deliverables, 'modules', 'automated-dast', 'zap-passive.json'),
      '{"raw":true}',
      'utf8',
    );

    const outside = path.join(root, 'outside.md');
    await fs.writeFile(outside, 'outside', 'utf8');
    await fs.symlink(outside, path.join(deliverables, 'auth_exploitation_evidence.md'));

    copyDeliverables(root, output);

    expect((await fs.readdir(output)).sort()).toEqual([...publicFiles, 'modules'].sort());
    expect((await fs.readdir(path.join(output, 'modules'))).sort()).toEqual(['manifest.json', 'passive-exposure.json']);
    await expect(fs.readFile(path.join(output, PUBLIC_REPORT_MARKDOWN_FILENAME), 'utf8')).resolves.toBe(
      PUBLIC_REPORT_MARKDOWN_FILENAME,
    );
  });
});
