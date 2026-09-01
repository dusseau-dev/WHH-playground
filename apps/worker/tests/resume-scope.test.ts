import { access, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { removeContainer } from '../src/services/container.js';
import { type ActivityInput, loadResumeState, persistOrValidateRunScope } from '../src/temporal/activities.js';

vi.mock('../src/temporal/activity-logger.js', () => ({
  createActivityLogger: () => ({
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  }),
}));

const tempRoots: string[] = [];
const workflowIds: string[] = [];

async function makeTempRoot(): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'shannon-scope-'));
  tempRoots.push(root);
  return root;
}

function inputFor(outputPath: string, overrides: Partial<ActivityInput> = {}): ActivityInput {
  const workflowId = overrides.workflowId ?? `workflow-${workflowIds.length + 1}`;
  workflowIds.push(workflowId);
  return {
    webUrl: 'https://example.test',
    workingDirectory: '/app/target',
    sourceMode: 'url-only',
    workflowId,
    sessionId: 'workspace-a',
    outputPath,
    configYAML: 'description: first config',
    ...overrides,
  };
}

async function readSession(outputPath: string): Promise<{
  session: {
    scope?: {
      sourceMode?: string;
      configHash?: string;
      vulnClasses: string[];
      safeDemonstration?: boolean;
      exploit?: boolean;
    };
  };
}> {
  return JSON.parse(await readFile(path.join(outputPath, 'workspace-a', '.shannon', 'session.json'), 'utf8')) as {
    session: {
      scope?: {
        sourceMode?: string;
        configHash?: string;
        vulnClasses: string[];
        safeDemonstration?: boolean;
        exploit?: boolean;
      };
    };
  };
}

afterEach(async () => {
  for (const workflowId of workflowIds.splice(0)) {
    removeContainer(workflowId);
  }
  await Promise.all(tempRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
});

describe('persistOrValidateRunScope', () => {
  it('preserves legacy resume checkpoints before initializing current session state', async () => {
    const outputPath = await makeTempRoot();
    const workspacePath = path.join(outputPath, 'workspace-a');
    const legacySessionPath = path.join(workspacePath, 'session.json');
    const currentSessionPath = path.join(workspacePath, '.shannon', 'session.json');
    const workingDirectory = path.join(outputPath, 'target');
    const deliverablesPath = path.join(workingDirectory, '.shannon', 'deliverables');
    await mkdir(workspacePath, { recursive: true });
    await mkdir(deliverablesPath, { recursive: true });
    await writeFile(path.join(deliverablesPath, 'pre_recon_deliverable.md'), '# Existing pre-recon');
    await writeFile(
      legacySessionPath,
      JSON.stringify({
        session: {
          id: 'workspace-a',
          webUrl: 'https://example.test',
          status: 'in-progress',
          createdAt: '2026-01-01T00:00:00.000Z',
          originalWorkflowId: 'workflow-original',
          resumeAttempts: [],
        },
        metrics: {
          total_duration_ms: 42,
          total_cost_usd: 0.01,
          phases: {},
          agents: {
            'pre-recon': {
              status: 'success',
              checkpoint: 'legacy-checkpoint',
            },
          },
        },
      }),
    );

    await persistOrValidateRunScope(inputFor(outputPath, { workflowId: 'workflow-resume' }), ['xss'], true);

    const migrated = JSON.parse(await readFile(currentSessionPath, 'utf8')) as {
      session: { originalWorkflowId?: string; scope?: { vulnClasses: string[] } };
      metrics: { agents: Record<string, { checkpoint?: string }> };
    };
    expect(migrated.session.originalWorkflowId).toBe('workflow-original');
    expect(migrated.session.scope?.vulnClasses).toEqual(['xss']);
    expect(migrated.metrics.agents['pre-recon']?.checkpoint).toBe('legacy-checkpoint');
    await expect(access(legacySessionPath)).rejects.toMatchObject({ code: 'ENOENT' });

    const workspaceName = path.relative(path.resolve('workspaces'), workspacePath);
    const resumeState = await loadResumeState(workspaceName, 'https://example.test', workingDirectory, 'url-only');
    expect(resumeState).toMatchObject({
      completedAgents: ['pre-recon'],
      checkpointHash: 'legacy-checkpoint',
      originalWorkflowId: 'workflow-original',
    });
  });

  it('stores source mode and a normalized config hash, then accepts the same scope', async () => {
    const outputPath = await makeTempRoot();

    await persistOrValidateRunScope(inputFor(outputPath, { workflowId: 'workflow-first' }), ['xss'], true);
    const firstSession = await readSession(outputPath);

    expect(firstSession.session.scope).toMatchObject({
      sourceMode: 'url-only',
      vulnClasses: ['xss'],
      safeDemonstration: true,
    });
    expect(firstSession.session.scope?.configHash).toMatch(/^[a-f0-9]{64}$/);

    await expect(
      persistOrValidateRunScope(inputFor(outputPath, { workflowId: 'workflow-second' }), ['xss'], true),
    ).resolves.toBeUndefined();
  });

  it('backfills legacy scope.exploit on resume', async () => {
    const outputPath = await makeTempRoot();
    await persistOrValidateRunScope(inputFor(outputPath, { workflowId: 'workflow-original' }), ['xss'], true);

    const sessionPath = path.join(outputPath, 'workspace-a', '.shannon', 'session.json');
    const session = await readSession(outputPath);
    if (!session.session.scope) throw new Error('Missing scope');
    const { safeDemonstration: _safeDemonstration, ...legacyScope } = session.session.scope;
    session.session.scope = { ...legacyScope, exploit: true };
    await writeFile(sessionPath, JSON.stringify(session, null, 2));

    await expect(
      persistOrValidateRunScope(inputFor(outputPath, { workflowId: 'workflow-resume' }), ['xss'], true),
    ).resolves.toBeUndefined();
    const backfilled = await readSession(outputPath);
    expect(backfilled.session.scope?.safeDemonstration).toBe(true);
    expect(backfilled.session.scope?.exploit).toBeUndefined();
  });

  it('allows secret rotation without treating it as non-secret configuration drift', async () => {
    const outputPath = await makeTempRoot();
    const configYAML = (password: string) => `
authentication:
  login_type: form
  login_url: https://example.test/login
  credentials:
    username: operator
    password: ${password}
  success_condition:
    type: url_contains
    value: /home
`;
    await persistOrValidateRunScope(
      inputFor(outputPath, { workflowId: 'workflow-secret-first', configYAML: configYAML('first-password') }),
      ['xss'],
      true,
    );

    await expect(
      persistOrValidateRunScope(
        inputFor(outputPath, { workflowId: 'workflow-secret-second', configYAML: configYAML('rotated-password') }),
        ['xss'],
        true,
      ),
    ).resolves.toBeUndefined();
  });

  it('rejects changed URL, source mode, classes, demonstration flag, repository, and config hash', async () => {
    const outputPath = await makeTempRoot();
    await persistOrValidateRunScope(
      inputFor(outputPath, {
        workflowId: 'workflow-original',
        sourceMode: 'source-assisted',
        repoPath: '/repos/app',
        workingDirectory: '/repos/app',
      }),
      ['xss'],
      true,
    );

    await expect(
      persistOrValidateRunScope(
        inputFor(outputPath, {
          workflowId: 'workflow-url-change',
          sourceMode: 'source-assisted',
          repoPath: '/repos/app',
          workingDirectory: '/repos/app',
          webUrl: 'https://other.example.test',
        }),
        ['xss'],
        true,
      ),
    ).rejects.toThrow(/URL mismatch/);

    await expect(
      persistOrValidateRunScope(inputFor(outputPath, { workflowId: 'workflow-mode-change' }), ['xss'], true),
    ).rejects.toThrow(/source_mode/);

    await expect(
      persistOrValidateRunScope(
        inputFor(outputPath, {
          workflowId: 'workflow-repo-change',
          sourceMode: 'source-assisted',
          repoPath: '/repos/other',
          workingDirectory: '/repos/other',
        }),
        ['xss'],
        true,
      ),
    ).rejects.toThrow(/Repository mismatch/);

    await expect(
      persistOrValidateRunScope(
        inputFor(outputPath, {
          workflowId: 'workflow-class-change',
          sourceMode: 'source-assisted',
          repoPath: '/repos/app',
          workingDirectory: '/repos/app',
        }),
        ['auth'],
        true,
      ),
    ).rejects.toThrow(/Resume scope mismatch/);

    await expect(
      persistOrValidateRunScope(
        inputFor(outputPath, {
          workflowId: 'workflow-demonstration-change',
          sourceMode: 'source-assisted',
          repoPath: '/repos/app',
          workingDirectory: '/repos/app',
        }),
        ['xss'],
        false,
      ),
    ).rejects.toThrow(/Resume scope mismatch/);

    await expect(
      persistOrValidateRunScope(
        inputFor(outputPath, {
          workflowId: 'workflow-config-change',
          sourceMode: 'source-assisted',
          repoPath: '/repos/app',
          workingDirectory: '/repos/app',
          configYAML: 'description: changed config',
        }),
        ['xss'],
        true,
      ),
    ).rejects.toThrow(/config_hash/);
  });
});
