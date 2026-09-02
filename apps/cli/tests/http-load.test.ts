import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { AssessmentConfigSchema, RunLaunchSpecSchema } from '../src/contracts.js';
import { HTTP_LOAD_DEFAULTS } from '../src/http-load.js';
import { testController } from './helpers.js';

const temporaryDirectories: string[] = [];

async function temporaryDirectory(): Promise<string> {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'shannon-http-load-'));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) => fs.rm(directory, { recursive: true, force: true })),
  );
});

describe('HTTP load CLI contracts', () => {
  it('normalizes safe defaults for an explicitly selected load-only scope', () => {
    const config = AssessmentConfigSchema.parse({ testScopes: ['http-load-capacity'] });

    expect(config).toMatchObject({
      testCategories: [],
      testScopes: ['http-load-capacity'],
      httpLoad: HTTP_LOAD_DEFAULTS,
    });
  });

  it('requires ownership confirmation and a second acknowledgement for elevated settings', () => {
    const config = AssessmentConfigSchema.parse({
      testScopes: ['http-load-capacity'],
      httpLoad: { concurrency: 21, requestsPerSecond: 10, durationSeconds: 15 },
    });
    const launch = {
      targetUrl: 'https://authorized.test',
      sourceMode: 'url-only' as const,
      config,
    };

    expect(() => RunLaunchSpecSchema.parse(launch)).toThrow(/ownership|authorization/i);
    expect(() => RunLaunchSpecSchema.parse({ ...launch, authorizationConfirmed: true })).toThrow(/elevated/i);
    expect(
      RunLaunchSpecSchema.parse({
        ...launch,
        authorizationConfirmed: true,
        elevatedLoadConfirmed: true,
      }),
    ).toMatchObject({ authorizationConfirmed: true, elevatedLoadConfirmed: true });
  });

  it('rejects selecting both load execution implementations', () => {
    expect(() =>
      AssessmentConfigSchema.parse({
        testScopes: ['http-load-capacity'],
        assessmentModules: ['http-load-capacity'],
        moduleSafety: { targetEnvironment: 'staging', acknowledgeLoadRisk: true },
      }),
    ).toThrow(/both.*load|load.*both/i);
  });

  it('keeps acknowledgements out of snapshots while forwarding them to Temporal', async () => {
    const workspacesDir = await temporaryDirectory();
    const { controller, temporal } = testController(workspacesDir);
    const run = await controller.startRun({
      targetUrl: 'https://authorized.test',
      sourceMode: 'url-only',
      workspace: 'authorized-load',
      config: {
        testCategories: [],
        testScopes: ['http-load-capacity'],
        testSurfaces: ['browser', 'api-graphql'],
        httpLoad: HTTP_LOAD_DEFAULTS,
      },
      authorizationConfirmed: true,
    });

    expect(run.snapshot.config.httpLoad).toEqual(HTTP_LOAD_DEFAULTS);
    expect(run.snapshot).not.toHaveProperty('authorizationConfirmed');
    expect(run.snapshot).not.toHaveProperty('elevatedLoadConfirmed');
    expect(temporal.starts[0]?.input).toMatchObject({
      httpLoad: HTTP_LOAD_DEFAULTS,
      httpLoadAuthorizationConfirmed: true,
      elevatedLoadConfirmed: false,
    });
  });
});
