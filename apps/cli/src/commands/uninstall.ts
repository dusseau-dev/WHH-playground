/**
 * `shn uninstall` command — remove ~/.dora/ after confirmation (npx only).
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as p from '@clack/prompts';
import { stopInfra, stopWorkers } from '../docker.js';

const DORA_HOME = path.join(os.homedir(), '.dora');

export async function uninstall(): Promise<void> {
  p.intro('Dora Uninstall');

  if (!fs.existsSync(DORA_HOME)) {
    p.log.info('Nothing to remove. Dora is not configured on this machine.');
    p.outro('Done.');
    return;
  }

  const confirmed = await p.confirm({
    message: 'This will permanently remove all past scan data, saved configurations, and API keys. Continue?',
  });
  if (p.isCancel(confirmed) || !confirmed) {
    p.cancel('Aborted.');
    process.exit(0);
  }

  // Stop any running containers first
  stopWorkers();
  stopInfra(false);

  fs.rmSync(DORA_HOME, { recursive: true, force: true });
  p.log.success('All Dora data has been removed.');
  p.outro('Dora has been uninstalled. Run `npx @keygraph/dora setup` to start fresh.');
}
