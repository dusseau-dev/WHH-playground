import fs from 'node:fs/promises';
import path from 'node:path';
import { parseAssessmentConfigYaml } from '../assessment-config.js';
import { ScanController } from '../scan-controller.js';

export async function resume(workspace: string, version: string, configPath?: string): Promise<void> {
  const secrets = configPath
    ? parseAssessmentConfigYaml(await fs.readFile(path.resolve(configPath), 'utf8')).secrets
    : {};
  const controller = new ScanController({ version });
  await controller.initialize();
  const run = await controller.resumeRun(workspace, secrets);
  console.log(`${workspace}: ${run.status} (attempt ${run.attempts.length})`);
}
