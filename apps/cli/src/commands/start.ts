/** Launch a source-assisted or URL-only assessment through the shared controller. */

import fs from 'node:fs/promises';
import path from 'node:path';
import { parseAssessmentConfigYaml } from '../assessment-config.js';
import { AssessmentConfigSchema } from '../contracts.js';
import { getWorkspacesDir } from '../home.js';
import { isLocal } from '../mode.js';
import { ScanController } from '../scan-controller.js';
import { displaySplash } from '../splash.js';

export interface StartArgs {
  url: string;
  repo?: string;
  config?: string;
  workspace?: string;
  output?: string;
  pipelineTesting: boolean;
  debug: boolean;
  version: string;
}

export async function start(args: StartArgs): Promise<void> {
  const parsedConfig = args.config
    ? parseAssessmentConfigYaml(await fs.readFile(path.resolve(args.config), 'utf8'))
    : { config: AssessmentConfigSchema.parse({}), secrets: {} };
  const controller = new ScanController({ version: args.version });
  await controller.initialize();

  displaySplash(isLocal() ? undefined : args.version);
  const run = await controller.startRun({
    targetUrl: args.url,
    sourceMode: args.repo ? 'source-assisted' : 'url-only',
    ...(args.repo && { repoPath: args.repo }),
    config: parsedConfig.config,
    secrets: parsedConfig.secrets,
    ...(args.workspace && { workspace: args.workspace }),
    ...(args.output && { outputPath: args.output }),
    ...(args.pipelineTesting && { pipelineTesting: true }),
    ...(args.debug && { debug: true }),
  });

  const prefix = isLocal() ? './shannon' : 'npx @keygraph/shannon';
  console.log(`  Target:     ${run.snapshot.targetUrl}`);
  console.log(`  Mode:       ${run.snapshot.sourceMode === 'url-only' ? 'URL-only dynamic' : 'Source-assisted'}`);
  if (run.snapshot.repoPath) console.log(`  Repository: ${run.snapshot.repoPath}`);
  console.log(`  Workspace:  ${run.runId}`);
  console.log(`  Status:     ${run.status}`);
  console.log('');
  console.log(`  Open UI:    ${prefix} ui`);
  console.log(`  Logs:       ${prefix} logs ${run.runId}`);
  console.log(`  Reports:    ${path.join(getWorkspacesDir(), run.runId)}/`);
  console.log('');
}
