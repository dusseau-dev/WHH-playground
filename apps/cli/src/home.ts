/**
 * Dora state directory management.
 *
 * Local mode (cloned repo): uses ./workspaces/, ./credentials/
 * NPX mode: uses ~/.dora/workspaces/, ~/.dora/
 *
 * Renamed from Shannon. Installs that predate the rename still have their
 * configuration and workspaces under ~/.shannon/, so that directory remains a
 * read fallback until the user has migrated.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { getMode } from './mode.js';

const DORA_HOME = path.join(os.homedir(), '.dora');
const LEGACY_HOME = path.join(os.homedir(), '.shannon');

function isDirectory(candidate: string): boolean {
  try {
    return fs.statSync(candidate).isDirectory();
  } catch {
    return false;
  }
}

/** True when the directory exists but holds no entries (ignoring dotfiles). */
function isEmptyDirectory(candidate: string): boolean {
  try {
    return fs.readdirSync(candidate).filter((entry) => !entry.startsWith('.')).length === 0;
  } catch {
    return true;
  }
}

/**
 * The state directory in use.
 *
 * ~/.dora wins when it is populated. A pre-rename install may still have its
 * configuration and workspaces under ~/.shannon/, so that directory is used
 * when ~/.dora is missing or empty. This keeps existing installs visible
 * instead of silently starting from a blank state.
 */
export function getHomeDir(): string {
  if (isDirectory(DORA_HOME) && !isEmptyDirectory(DORA_HOME)) return DORA_HOME;
  if (isDirectory(LEGACY_HOME) && !isEmptyDirectory(LEGACY_HOME)) return LEGACY_HOME;
  return DORA_HOME;
}

/** True when state is still being read from the pre-rename directory. */
export function isUsingLegacyHome(): boolean {
  return getHomeDir() === LEGACY_HOME;
}

export function getConfigFile(): string {
  return path.join(getHomeDir(), 'config.toml');
}

export function getWorkspacesDir(): string {
  return getMode() === 'local' ? path.resolve('workspaces') : path.join(getHomeDir(), 'workspaces');
}

/**
 * Initialize state directories.
 * Local mode: creates ./workspaces/
 * NPX mode: creates <home>/workspaces/
 */
export function initHome(): void {
  if (getMode() === 'local') {
    fs.mkdirSync(path.resolve('workspaces'), { recursive: true });
  } else {
    fs.mkdirSync(path.join(getHomeDir(), 'workspaces'), { recursive: true });
  }
}