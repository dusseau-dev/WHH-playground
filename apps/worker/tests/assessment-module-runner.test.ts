import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import yaml from 'js-yaml';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  buildK6Stages,
  buildModuleCommandEnvironment,
  buildNucleiArgs,
  type ModuleCommandRunner,
  runAssessmentModules,
} from '../src/services/assessment-module-runner.js';

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => fs.rm(root, { recursive: true, force: true })));
});

async function workspace(): Promise<{ root: string; deliverables: string }> {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'shannon-module-runner-'));
  roots.push(root);
  const deliverables = path.join(root, '.shannon', 'deliverables');
  await fs.mkdir(deliverables, { recursive: true });
  return { root, deliverables };
}

const safety = {
  targetEnvironment: 'staging' as const,
  allowActiveDast: true,
  acknowledgeLoadRisk: true,
  maxRequestsPerSecond: 3,
  maxConcurrency: 10,
  loadStageDurationSeconds: 30,
  loadErrorRateThreshold: 0.05,
  loadP95LatencyMsThreshold: 2_000,
};

describe('assessment module command safety', () => {
  it('does not pass ambient worker credentials to scanner subprocesses', () => {
    const previous = process.env.OPENAI_API_KEY;
    process.env.OPENAI_API_KEY = 'worker-secret';
    try {
      const env = buildModuleCommandEnvironment({ SHANNON_AUTH_COOKIE: 'session=target-secret' });
      expect(env.OPENAI_API_KEY).toBeUndefined();
      expect(env.SHANNON_AUTH_COOKIE).toBe('session=target-secret');
      expect(env.PATH).toBe(process.env.PATH);
    } finally {
      if (previous === undefined) delete process.env.OPENAI_API_KEY;
      else process.env.OPENAI_API_KEY = previous;
    }
  });

  it('uses an explicit curated Nuclei template set and bounded traffic', () => {
    const args = buildNucleiArgs('/tmp/nuclei-targets.txt', safety, '/tmp/nuclei.jsonl');
    expect(args.slice(0, 2)).toEqual(['-list', '/tmp/nuclei-targets.txt']);
    expect(args).toContain('-rl');
    expect(args).toContain('3');
    expect(args).toContain('-c');
    expect(args).toContain('10');
    expect(args).toContain('-exclude-tags');
    expect(args.join(' ')).toMatch(/dos/);
    expect(args.filter((value) => value === '-t').length).toBeGreaterThan(1);
    expect(args).not.toContain('-ut');
  });

  it('builds the requested gradual ramp and caps it at the authorized concurrency', () => {
    expect(buildK6Stages(25, 60).map(({ target }) => target)).toEqual([1, 5, 10, 25]);
    expect(buildK6Stages(7, 30).map(({ target }) => target)).toEqual([1, 5, 7]);
    expect(buildK6Stages(1, 30).map(({ target }) => target)).toEqual([1]);
  });
});

describe('assessment module execution evidence', () => {
  it('does not follow passive-review redirects outside the authorized target', async () => {
    const { root, deliverables } = await workspace();
    const fetchMock = vi.fn(
      async () => new Response('<html></html>', { status: 302, headers: { location: 'https://outside.test' } }),
    );

    await runAssessmentModules(
      {
        webUrl: 'http://127.0.0.1/',
        workingDirectory: root,
        deliverablesPath: deliverables,
        sourceMode: 'url-only',
        assessmentModules: ['passive-exposure'],
        moduleSafety: {
          ...safety,
          targetEnvironment: 'production',
          allowActiveDast: false,
          acknowledgeLoadRisk: false,
        },
      },
      { fetch: fetchMock as unknown as typeof fetch },
    );

    expect(fetchMock).toHaveBeenCalled();
    for (const [, init] of fetchMock.mock.calls) expect(init).toMatchObject({ redirect: 'manual' });
  });

  it('runs ZAP passive first, curated Nuclei second, and active ZAP only after the staging gate', async () => {
    const { root, deliverables } = await workspace();
    const commands: string[] = [];
    const commandRunner: ModuleCommandRunner = vi.fn(async (spec) => {
      commands.push(`${spec.command} ${spec.args.join(' ')}`);
      if (spec.command === 'zap.sh') {
        const planPath = spec.args.at(-1);
        if (!planPath) throw new Error('Expected ZAP automation plan');
        const planText = await fs.readFile(planPath, 'utf8');
        expect(planText).not.toContain('session=secret');
        const plan = yaml.load(planText) as { jobs: Array<{ type: string; parameters?: Record<string, unknown> }> };
        expect(plan.jobs.map(({ type }) => type)).toContain('replacer');
        expect(plan.jobs.map(({ type }) => type)).toContain('spider');
        const active = plan.jobs.find(({ type }) => type === 'activeScan');
        if (active) {
          expect(active.parameters).toMatchObject({ threadPerHost: 10, delayInMs: 3_334 });
        }
      }
      if (spec.command === 'nuclei') {
        const configIndex = spec.args.indexOf('-config');
        const configPath = spec.args[configIndex + 1];
        if (!configPath) throw new Error('Expected authenticated Nuclei config');
        expect(await fs.readFile(configPath, 'utf8')).toContain('session=secret');
        expect(spec.args.join(' ')).not.toContain('session=secret');
      }
      return { exitCode: 0, stdout: '{"ok":true}', stderr: '' };
    });

    const results = await runAssessmentModules(
      {
        webUrl: 'https://target.test/?access_token=url-secret',
        workingDirectory: root,
        deliverablesPath: deliverables,
        sourceMode: 'source-assisted',
        assessmentModules: ['automated-dast'],
        moduleSafety: safety,
        authenticationCookie: 'session=secret',
      },
      { commandRunner },
    );

    expect(commands[0]).toMatch(/^zap\.sh -cmd -autorun /);
    expect(commands[1]).toMatch(/^nuclei /);
    expect(commands[1]).not.toContain('url-secret');
    expect(commands[2]).toMatch(/^zap\.sh -cmd -autorun /);
    expect(results).toEqual([
      expect.objectContaining({
        id: 'automated-dast',
        status: 'completed',
        evidencePath: 'modules/automated-dast.json',
      }),
    ]);
    const evidence = JSON.parse(await fs.readFile(path.join(deliverables, 'modules', 'automated-dast.json'), 'utf8'));
    expect(evidence.checks.map((check: { id: string }) => check.id)).toEqual([
      'zap-passive',
      'nuclei-curated',
      'zap-active',
    ]);
    await expect(fs.access(path.join(deliverables, 'modules', '.nuclei-auth.yaml'))).rejects.toThrow();
    await expect(fs.access(path.join(deliverables, 'modules', '.nuclei-targets.txt'))).rejects.toThrow();
  });

  it('records missing scanners as unavailable instead of claiming completion', async () => {
    const { root, deliverables } = await workspace();
    const commandRunner: ModuleCommandRunner = vi.fn(async () => ({
      exitCode: null,
      stdout: '',
      stderr: '',
      unavailable: true,
    }));

    const [result] = await runAssessmentModules(
      {
        webUrl: 'https://target.test',
        workingDirectory: root,
        deliverablesPath: deliverables,
        sourceMode: 'url-only',
        assessmentModules: ['automated-dast'],
        moduleSafety: { ...safety, allowActiveDast: false },
      },
      { commandRunner },
    );

    expect(result?.status).toBe('unavailable');
  });

  it('passes load authentication through the child environment and emits automatic-stop thresholds', async () => {
    const { root, deliverables } = await workspace();
    const commandRunner: ModuleCommandRunner = vi.fn(async (spec) => {
      expect(spec.command).toBe('k6');
      expect(spec.env?.SHANNON_AUTH_COOKIE).toBe('session=secret');
      expect(spec.args.join(' ')).not.toContain('session=secret');
      expect(spec.env?.SHANNON_K6_THRESHOLDS).toContain('abortOnFail');
      return { exitCode: 0, stdout: 'load complete', stderr: '' };
    });

    const [result] = await runAssessmentModules(
      {
        webUrl: 'https://target.test',
        workingDirectory: root,
        deliverablesPath: deliverables,
        sourceMode: 'url-only',
        assessmentModules: ['http-load-capacity'],
        moduleSafety: safety,
        authenticationCookie: 'session=secret',
      },
      { commandRunner },
    );

    expect(result?.status).toBe('completed');
  });
});
