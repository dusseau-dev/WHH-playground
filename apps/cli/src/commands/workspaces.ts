/** List managed runs and read-only legacy workspaces through the shared controller. */

import type { RunListItem } from '../contracts.js';
import { ScanController } from '../scan-controller.js';

function truncate(value: string, width: number): string {
  return value.length <= width ? value : `${value.slice(0, Math.max(0, width - 3))}...`;
}

function target(run: RunListItem): string {
  return run.kind === 'managed' ? run.snapshot.targetUrl : (run.targetUrl ?? '(legacy report)');
}

function mode(run: RunListItem): string {
  if (run.kind === 'managed') return run.snapshot.sourceMode;
  return run.sourceMode ?? 'legacy';
}

export async function workspaces(version: string): Promise<void> {
  const controller = new ScanController({ version });
  const runs = await controller.initialize();
  if (runs.length === 0) {
    console.log('No workspaces found.');
    return;
  }

  const columns = { run: 32, status: 12, mode: 18, target: 48 };
  console.log(
    [
      'RUN'.padEnd(columns.run),
      'STATUS'.padEnd(columns.status),
      'MODE'.padEnd(columns.mode),
      'TARGET'.padEnd(columns.target),
    ].join(' '),
  );
  for (const run of runs) {
    console.log(
      [
        truncate(run.runId, columns.run).padEnd(columns.run),
        run.status.padEnd(columns.status),
        mode(run).padEnd(columns.mode),
        truncate(target(run), columns.target).padEnd(columns.target),
      ].join(' '),
    );
  }
}
