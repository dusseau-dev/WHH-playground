import { ScanController } from '../scan-controller.js';

export async function cancel(workspace: string, version: string): Promise<void> {
  const controller = new ScanController({ version });
  await controller.initialize();
  const run = await controller.cancelRun(workspace);
  console.log(`${workspace}: ${run.status}`);
}
