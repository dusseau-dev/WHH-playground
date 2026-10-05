import fs from 'node:fs/promises';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

describe('Docker pipeline smoke harness', () => {
  it('reads the managed workspace schema', async () => {
    const scriptPath = path.resolve(import.meta.dirname, '../../../scripts/docker-pipeline-smoke.sh');
    const script = await fs.readFile(scriptPath, 'utf8');

    expect(script).toContain(`workspaces/\${workspace}/.shannon/session.json`);
    expect(script).toContain(`workspaces/\${url_workspace}/.shannon/run.json`);
    expect(script).toContain(`workspaces/\${source_workspace}/.shannon/run.json`);
    expect(script).toContain('r.snapshot.sourceMode');
    expect(script).not.toContain('r.spec');
  });
});
