#!/usr/bin/env node

// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Ephemeral Temporal worker for one controller-owned assessment workflow.
 *
 * The host-side ScanController creates the workflow and persists its identity
 * before this process starts. This process only polls the assigned task queue,
 * waits for that workflow to finish, and exits with the worker container.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client, Connection, type WorkflowHandle } from '@temporalio/client';
import { bundleWorkflowCode, NativeConnection, Worker } from '@temporalio/worker';
import dotenv from 'dotenv';
import { deliverablesDir } from '../paths.js';
import { REPORT_PDF_FILENAME, REPORT_SARIF_FILENAME } from '../services/report-output.js';
import { PUBLIC_REPORT_MARKDOWN_FILENAME } from '../services/structured-report.js';
import { DELIVERABLE_FILENAMES, DeliverableType } from '../types/deliverables.js';
import * as activities from './activities.js';
import type { PipelineInput, PipelineProgress, PipelineState } from './shared.js';

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROGRESS_QUERY = 'getProgress';

interface WorkerArgs {
  taskQueue: string;
  workflowId: string;
  workingDirectory: string;
  outputPath?: string;
}

function showUsage(): void {
  console.log('\nShannon Worker');
  console.log('Polls one controller-owned assessment workflow.\n');
  console.log('Usage:');
  console.log(
    '  node dist/temporal/worker.js --task-queue <name> --workflow-id <id> --working-directory <path> [--output <path>]',
  );
}

function optionValue(argv: string[], index: number, option: string): string {
  const value = argv[index + 1];
  if (!value || value.startsWith('-')) throw new Error(`${option} requires a value`);
  return value;
}

export function parseWorkerArgs(argv: string[]): WorkerArgs {
  if (argv.includes('--help') || argv.includes('-h')) {
    showUsage();
    process.exit(0);
  }

  let taskQueue: string | undefined;
  let workflowId: string | undefined;
  let workingDirectory: string | undefined;
  let outputPath: string | undefined;

  for (let index = 0; index < argv.length; index++) {
    const argument = argv[index];
    if (argument === '--task-queue') {
      taskQueue = optionValue(argv, index, argument);
      index++;
    } else if (argument === '--workflow-id') {
      workflowId = optionValue(argv, index, argument);
      index++;
    } else if (argument === '--working-directory' || argument === '--workdir') {
      workingDirectory = optionValue(argv, index, argument);
      index++;
    } else if (argument === '--output') {
      outputPath = optionValue(argv, index, argument);
      index++;
    } else {
      throw new Error(`Unknown worker argument: ${argument ?? ''}`);
    }
  }

  const missing = [
    !taskQueue && '--task-queue',
    !workflowId && '--workflow-id',
    !workingDirectory && '--working-directory',
  ].filter((value): value is string => Boolean(value));
  if (missing.length > 0) throw new Error(`Missing required worker options: ${missing.join(', ')}`);

  return {
    taskQueue: taskQueue as string,
    workflowId: workflowId as string,
    workingDirectory: workingDirectory as string,
    ...(outputPath && { outputPath }),
  };
}

async function waitForWorkflowResult(
  handle: WorkflowHandle<(input: PipelineInput) => Promise<PipelineState>>,
  workerDone: Promise<void>,
): Promise<PipelineState> {
  const progressInterval = setInterval(async () => {
    try {
      const progress = await handle.query<PipelineProgress>(PROGRESS_QUERY);
      const elapsed = Math.floor(progress.elapsedMs / 1000);
      console.log(
        `[${elapsed}s] Phase: ${progress.currentPhase || 'unknown'} | Agent: ${progress.currentAgent || 'none'} | Completed: ${progress.completedAgents.length}/${progress.expectedAgents.length}`,
      );
    } catch {
      // Queries can race workflow startup or completion.
    }
  }, 30_000);

  try {
    return await Promise.race([
      handle.result(),
      workerDone.then(() => {
        throw new Error('Temporal worker stopped before the assessment workflow completed');
      }),
    ]);
  } finally {
    clearInterval(progressInterval);
  }
}

const PUBLIC_DELIVERABLE_FILENAMES = new Set([
  PUBLIC_REPORT_MARKDOWN_FILENAME,
  REPORT_PDF_FILENAME,
  REPORT_SARIF_FILENAME,
  DELIVERABLE_FILENAMES[DeliverableType.INJECTION_EVIDENCE],
  DELIVERABLE_FILENAMES[DeliverableType.XSS_EVIDENCE],
  DELIVERABLE_FILENAMES[DeliverableType.AUTH_EVIDENCE],
  DELIVERABLE_FILENAMES[DeliverableType.AUTHZ_EVIDENCE],
  DELIVERABLE_FILENAMES[DeliverableType.SSRF_EVIDENCE],
]);

/** Copy only stable user-facing reports and evidence; workspace state remains internal. */
export function copyDeliverables(workingDirectory: string, outputPath: string): void {
  const source = deliverablesDir(workingDirectory);
  if (!fs.existsSync(source)) return;

  fs.mkdirSync(outputPath, { recursive: true });
  for (const entry of fs.readdirSync(source, { withFileTypes: true })) {
    if (!entry.isFile() || !PUBLIC_DELIVERABLE_FILENAMES.has(entry.name)) continue;
    fs.copyFileSync(path.join(source, entry.name), path.join(outputPath, entry.name));
  }
}

async function run(): Promise<void> {
  const args = parseWorkerArgs(process.argv.slice(2));
  const address = process.env.TEMPORAL_ADDRESS ?? 'localhost:7233';
  const workerConnection = await NativeConnection.connect({ address });
  let clientConnection: Connection | undefined;
  let worker: Worker | undefined;
  let workerDone: Promise<void> | undefined;

  try {
    clientConnection = await Connection.connect({ address });
    const workflowBundle = await bundleWorkflowCode({ workflowsPath: path.join(__dirname, 'workflows.js') });
    worker = await Worker.create({
      connection: workerConnection,
      namespace: 'default',
      workflowBundle,
      activities,
      taskQueue: args.taskQueue,
      maxConcurrentActivityTaskExecutions: 25,
    });
    workerDone = worker.run();

    const client = new Client({ connection: clientConnection });
    const handle = client.workflow.getHandle<(input: PipelineInput) => Promise<PipelineState>>(args.workflowId);
    const result = await waitForWorkflowResult(handle, workerDone);

    if (args.outputPath) copyDeliverables(args.workingDirectory, args.outputPath);
    console.log(`Workflow ${args.workflowId} finished with status ${result.status}`);
  } finally {
    worker?.shutdown();
    await workerDone?.catch(() => undefined);
    await workerConnection.close();
    await clientConnection?.close();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  run().catch((error) => {
    console.error('Worker failed:', error);
    process.exitCode = 1;
  });
}
