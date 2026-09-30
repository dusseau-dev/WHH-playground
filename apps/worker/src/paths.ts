/** Centralized path constants for the worker package */

import fs from 'node:fs';
import path from 'node:path';

/** Worker package root (apps/worker/) resolved from compiled dist/ files */
const WORKER_ROOT = path.resolve(import.meta.dirname, '..');

export const PROMPTS_DIR = path.join(WORKER_ROOT, 'prompts');
export const CONFIGS_DIR = path.join(WORKER_ROOT, 'configs');

/** Default deliverables subdirectory relative to the run's working directory */
export const DEFAULT_DELIVERABLES_SUBDIR = '.shannon/deliverables';

/** Default audit log directory */
export const DEFAULT_AUDIT_DIR = './workspaces';

/** Hidden internal state directory inside each assessment workspace. */
export const INTERNAL_DIR = '.shannon';

/** Resolve current session state while retaining read compatibility with legacy workspaces. */
export function resolveSessionJsonPath(runDirectory: string): string {
  const current = path.join(runDirectory, INTERNAL_DIR, 'session.json');
  if (fs.existsSync(current)) return current;
  const legacy = path.join(runDirectory, 'session.json');
  return fs.existsSync(legacy) ? legacy : current;
}

/**
 * Resolve the deliverables directory for a working root and optional subdir override.
 * @param workingDirectory - Absolute writable root for the run
 * @param subdir - Subdirectory relative to workingDirectory (default: '.shannon/deliverables')
 */
export function deliverablesDir(workingDirectory: string, subdir: string = DEFAULT_DELIVERABLES_SUBDIR): string {
  return path.join(workingDirectory, ...subdir.split('/'));
}

/**
 * Repository root — walk up from WORKER_ROOT looking for pnpm-workspace.yaml.
 * Falls back to two levels up (apps/worker/ → repo root) if not found.
 */
function findRepoRoot(): string {
  let dir = WORKER_ROOT;
  for (let i = 0; i < 5; i++) {
    if (fs.existsSync(path.join(dir, 'pnpm-workspace.yaml'))) {
      return dir;
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return path.resolve(WORKER_ROOT, '..', '..');
}

const REPO_ROOT = findRepoRoot();
export const WORKSPACES_DIR = path.join(REPO_ROOT, 'workspaces');
