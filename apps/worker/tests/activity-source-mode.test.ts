import { mkdtemp, rm, stat } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  type ActivityInput,
  prepareWorkingDirectory,
  rethrowActivityCancellation,
} from '../src/temporal/activities.js';

const tempRoots: string[] = [];

function baseInput(workingDirectory: string): ActivityInput {
  return {
    webUrl: 'https://example.test',
    workingDirectory,
    sourceMode: 'url-only',
    workflowId: 'workflow-test',
    sessionId: 'session-test',
  };
}

async function makeTempRoot(): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'shannon-worker-'));
  tempRoots.push(root);
  return root;
}

afterEach(async () => {
  await Promise.all(tempRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
});

describe('prepareWorkingDirectory', () => {
  it('creates a missing URL-only working directory', async () => {
    const root = await makeTempRoot();
    const workingDirectory = path.join(root, 'target');

    await prepareWorkingDirectory(baseInput(workingDirectory));

    const stats = await stat(workingDirectory);
    expect(stats.isDirectory()).toBe(true);
  });

  it('does not create missing source-assisted repositories', async () => {
    const root = await makeTempRoot();
    const workingDirectory = path.join(root, 'missing-repo');

    await prepareWorkingDirectory({
      ...baseInput(workingDirectory),
      sourceMode: 'source-assisted',
      repoPath: workingDirectory,
    });

    await expect(stat(workingDirectory)).rejects.toThrow();
  });
});

describe('activity cancellation', () => {
  it('rethrows the Temporal abort reason before ordinary error classification', () => {
    const controller = new AbortController();
    const reason = new Error('cancelled by Temporal');
    controller.abort(reason);
    expect(() => rethrowActivityCancellation(controller.signal)).toThrow(reason);
  });
});
