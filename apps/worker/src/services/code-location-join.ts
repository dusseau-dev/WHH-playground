// Copyright (C) 2025 Keygraph, Inc.

import { fs, path } from 'zx';
import type { QueueCodeLocation } from '../ai/queue-schemas.js';
import type { AddFindingInput } from '../collectors/finding-collector.js';
import type { ActivityLogger } from '../types/activity-logger.js';
import { ALL_VULN_CLASSES, type SourceMode } from '../types/config.js';

interface QueueEntry {
  ID?: unknown;
  code_locations?: unknown;
}

function isQueueLocation(value: unknown): value is QueueCodeLocation {
  if (typeof value !== 'object' || value === null) return false;
  const item = value as Record<string, unknown>;
  return (
    typeof item.file === 'string' &&
    item.file.length > 0 &&
    (item.role === 'sink' || item.role === 'source' || item.role === 'guard') &&
    (item.start_line === undefined || (Number.isInteger(item.start_line) && (item.start_line as number) >= 1)) &&
    (item.end_line === undefined || (Number.isInteger(item.end_line) && (item.end_line as number) >= 1))
  );
}

async function loadQueueLocations(
  deliverablesPath: string,
  logger: ActivityLogger,
): Promise<Map<string, QueueCodeLocation[]>> {
  const byId = new Map<string, QueueCodeLocation[]>();
  const ambiguous = new Set<string>();

  for (const vulnClass of ALL_VULN_CLASSES) {
    const queuePath = path.join(deliverablesPath, `${vulnClass}_exploitation_queue.json`);
    if (!(await fs.pathExists(queuePath))) continue;
    try {
      const document = (await fs.readJson(queuePath)) as { vulnerabilities?: unknown };
      if (!Array.isArray(document.vulnerabilities)) continue;
      for (const raw of document.vulnerabilities) {
        if (typeof raw !== 'object' || raw === null) continue;
        const entry = raw as QueueEntry;
        if (typeof entry.ID !== 'string' || !Array.isArray(entry.code_locations)) continue;
        const locations = entry.code_locations.filter(isQueueLocation);
        if (locations.length === 0) continue;
        if (byId.has(entry.ID)) {
          ambiguous.add(entry.ID);
          byId.delete(entry.ID);
          continue;
        }
        if (!ambiguous.has(entry.ID)) byId.set(entry.ID, locations);
      }
    } catch (error) {
      logger.warn(`Could not read ${vulnClass} queue for code locations: ${(error as Error).message}`);
    }
  }

  if (ambiguous.size > 0) {
    logger.warn(`Skipped ambiguous duplicate queue location IDs: ${[...ambiguous].sort().join(', ')}`);
  }
  return byId;
}

/**
 * Attach source-assisted queue locations using a case-sensitive, whitespace-sensitive ID join.
 * URL-only findings retain their HTTP location and cannot acquire code locations.
 */
export async function attachQueueCodeLocations(
  findings: readonly AddFindingInput[],
  deliverablesPath: string,
  logger: ActivityLogger,
  sourceMode: SourceMode = 'source-assisted',
): Promise<AddFindingInput[]> {
  if (sourceMode === 'url-only') {
    return findings.map(({ code_locations: _ignored, ...finding }) => finding as AddFindingInput);
  }

  const byId = await loadQueueLocations(deliverablesPath, logger);
  let attached = 0;
  const joined = findings.map((finding) => {
    const locations = byId.get(finding.finding_id);
    if (!locations) return { ...finding };
    attached += 1;
    return { ...finding, code_locations: locations.map((location) => ({ ...location })) };
  });
  logger.info(`Attached code locations to ${attached}/${findings.length} finding(s) from exact queue IDs`);
  return joined;
}
