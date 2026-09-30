import { startUiServer } from '../ui/server.js';

export async function ui(version: string, port?: number, open = true): Promise<void> {
  const server = await startUiServer({ version, ...(port !== undefined && { port }), open });
  console.log(`Shannon UI: ${server.url}`);

  const shutdown = async (): Promise<void> => {
    await server.close();
    process.exit(0);
  };
  process.once('SIGINT', shutdown);
  process.once('SIGTERM', shutdown);
}
