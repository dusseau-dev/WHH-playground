import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { Hono } from 'hono';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ProfileStore } from '../src/profiles.js';
import { MemorySecretStore } from '../src/secret-store.js';
import { createApp } from '../src/ui/server.js';
import { type FakeTemporal, testController } from './helpers.js';

const HOST = '127.0.0.1:8787';
const ORIGIN = `http://${HOST}`;
const CSRF = 'csrf-for-tests';
const SESSION = 'session-for-tests';

interface Harness {
  root: string;
  workspacesDir: string;
  profilesDir: string;
  app: Hono;
  cookie: string;
  controller: ReturnType<typeof testController>['controller'];
  temporal: FakeTemporal;
  profiles: ProfileStore;
}

let harness: Harness;
const temporaryDirectories: string[] = [];

async function request(app: Hono, route: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  headers.set('Host', headers.get('Host') ?? HOST);
  return app.request(`${ORIGIN}${route}`, { ...init, headers });
}

async function bootstrap(app: Hono): Promise<string> {
  const response = await request(app, '/api/v1/bootstrap');
  expect(response.status).toBe(200);
  expect((await response.clone().json()).data.csrfToken).toBe(CSRF);
  const setCookie = response.headers.get('set-cookie') ?? '';
  expect(setCookie).toContain('HttpOnly');
  expect(setCookie).toContain('SameSite=Strict');
  return setCookie.split(';')[0] ?? '';
}

function authenticatedHeaders(cookie = harness.cookie): Headers {
  return new Headers({ Cookie: cookie });
}

function mutationHeaders(cookie = harness.cookie): Headers {
  return new Headers({
    Cookie: cookie,
    Origin: ORIGIN,
    'X-Shannon-CSRF': CSRF,
    'Content-Type': 'application/json',
  });
}

async function createHarness(secretStore = new MemorySecretStore()): Promise<Harness> {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'shannon-api-'));
  temporaryDirectories.push(root);
  const workspacesDir = path.join(root, 'workspaces');
  const profilesDir = path.join(root, 'profiles');
  const assetsDir = path.join(root, 'ui');
  await Promise.all([
    fs.mkdir(workspacesDir, { recursive: true }),
    fs.mkdir(profilesDir, { recursive: true }),
    fs.mkdir(assetsDir, { recursive: true }),
  ]);
  await fs.writeFile(path.join(assetsDir, 'index.html'), '<!doctype html><title>Shannon</title>');
  const profiles = new ProfileStore({ profilesDir, secretStore, idGenerator: () => 'profile-api' });
  await profiles.initialize();
  const { controller, temporal } = testController(workspacesDir, {
    secretResolver: (references) => profiles.resolveSecretReferences(references),
  });
  const app = createApp({
    controller,
    profiles,
    version: 'test',
    assetsDir,
    sessionToken: SESSION,
    csrfToken: CSRF,
    eventIntervalMs: 1,
  });
  const cookie = await bootstrap(app);
  return { root, workspacesDir, profilesDir, app, cookie, controller, temporal, profiles };
}

beforeEach(async () => {
  harness = await createHarness();
});

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) => fs.rm(directory, { recursive: true, force: true })),
  );
});

describe('local API security', () => {
  it('rejects non-loopback hosts and unauthenticated API requests without enabling CORS', async () => {
    const invalidHost = await request(harness.app, '/api/v1/health', { headers: { Host: 'attacker.example' } });
    expect(invalidHost.status).toBe(403);
    const unauthenticated = await request(harness.app, '/api/v1/runs');
    expect(unauthenticated.status).toBe(401);
    expect(unauthenticated.headers.get('access-control-allow-origin')).toBeNull();
  });

  it('requires same-origin and CSRF proof for every mutation', async () => {
    const body = JSON.stringify({
      name: 'Target',
      targetUrl: 'https://target.test',
      sourceMode: 'url-only',
      config: {},
    });
    const noOrigin = await request(harness.app, '/api/v1/profiles', {
      method: 'POST',
      headers: authenticatedHeaders(),
      body,
    });
    expect(noOrigin.status).toBe(403);
    const wrongOrigin = await request(harness.app, '/api/v1/profiles', {
      method: 'POST',
      headers: { ...Object.fromEntries(mutationHeaders()), Origin: 'http://localhost:8787' },
      body,
    });
    expect(wrongOrigin.status).toBe(403);
    const noCsrf = await request(harness.app, '/api/v1/profiles', {
      method: 'POST',
      headers: { Cookie: harness.cookie, Origin: ORIGIN, 'Content-Type': 'application/json' },
      body,
    });
    expect(noCsrf.status).toBe(403);
  });

  it('serves the SPA with restrictive browser headers', async () => {
    const response = await request(harness.app, '/runs/example');
    expect(response.status).toBe(200);
    expect(await response.text()).toContain('<title>Shannon</title>');
    expect(response.headers.get('content-security-policy')).toContain("default-src 'self'");
    expect(response.headers.get('x-frame-options')).toBe('DENY');
  });
});

describe('profiles and run lifecycle', () => {
  it('returns a client error for malformed profile YAML', async () => {
    const response = await request(harness.app, '/api/v1/profiles/import', {
      method: 'POST',
      headers: mutationHeaders(),
      body: JSON.stringify({ yaml: 'name: [unterminated' }),
    });
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({ error: { code: 'invalid_profile_yaml' } });
  });

  it('starts, cancels, and resumes a URL-only run with secret re-entry', async () => {
    const start = await request(harness.app, '/api/v1/runs', {
      method: 'POST',
      headers: mutationHeaders(),
      body: JSON.stringify({
        targetUrl: 'https://target.test',
        sourceMode: 'url-only',
        workspace: 'api-run',
        config: {
          authentication: {
            loginType: 'form',
            loginUrl: 'https://target.test/login',
            username: 'operator',
            successCondition: { type: 'url_contains', value: '/home' },
          },
        },
        secrets: { password: 'session-password' },
        authorizationConfirmed: true,
      }),
    });
    expect(start.status).toBe(202);
    expect((await start.json()).data.snapshot).not.toHaveProperty('repoPath');

    const cancel = await request(harness.app, '/api/v1/runs/api-run/cancel', {
      method: 'POST',
      headers: mutationHeaders(),
    });
    expect(cancel.status).toBe(200);
    expect((await cancel.json()).data.status).toBe('cancelled');

    const missing = await request(harness.app, '/api/v1/runs/api-run/resume', {
      method: 'POST',
      headers: mutationHeaders(),
      body: '{}',
    });
    expect(missing.status).toBe(409);
    await expect(missing.json()).resolves.toMatchObject({ error: { code: 'missing_secrets' } });

    const resumed = await request(harness.app, '/api/v1/runs/api-run/resume', {
      method: 'POST',
      headers: mutationHeaders(),
      body: JSON.stringify({ secrets: { password: 'new-session-password' } }),
    });
    expect(resumed.status).toBe(202);
    expect((await resumed.json()).data.attempts).toHaveLength(2);
  });

  it('detects profile references whose session-only secret has been lost', async () => {
    await harness.profiles.create({
      name: 'Lost secret',
      targetUrl: 'https://target.test',
      sourceMode: 'url-only',
      config: {},
      secrets: { password: 'temporary-secret' },
    });
    const restartedProfiles = new ProfileStore({
      profilesDir: harness.profilesDir,
      secretStore: new MemorySecretStore(),
    });
    const restartedApp = createApp({
      controller: harness.controller,
      profiles: restartedProfiles,
      sessionToken: SESSION,
      csrfToken: CSRF,
      assetsDir: path.join(harness.root, 'ui'),
    });
    const cookie = await bootstrap(restartedApp);
    const response = await request(restartedApp, '/api/v1/runs', {
      method: 'POST',
      headers: mutationHeaders(cookie),
      body: JSON.stringify({ profileId: 'profile-api', authorizationConfirmed: true }),
    });
    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toMatchObject({ error: { code: 'missing_secrets' } });
  });

  it('resumes a profile run from its snapshot after the profile configuration changes', async () => {
    const originalAuthentication = {
      loginType: 'form' as const,
      loginUrl: 'https://target.test/login',
      username: 'operator',
      successCondition: { type: 'url_contains' as const, value: '/home' },
    };
    await harness.profiles.create({
      name: 'Original profile',
      targetUrl: 'https://target.test',
      sourceMode: 'url-only',
      config: { testCategories: ['xss'], authentication: originalAuthentication },
      secrets: { password: 'profile-secret' },
    });
    const started = await request(harness.app, '/api/v1/runs', {
      method: 'POST',
      headers: mutationHeaders(),
      body: JSON.stringify({ profileId: 'profile-api', workspace: 'profile-run', authorizationConfirmed: true }),
    });
    expect(started.status).toBe(202);
    await request(harness.app, '/api/v1/runs/profile-run/cancel', {
      method: 'POST',
      headers: mutationHeaders(),
    });

    await harness.profiles.update('profile-api', {
      name: 'Changed profile',
      targetUrl: 'https://changed.test',
      sourceMode: 'url-only',
      config: { testCategories: ['ssrf'] },
      secrets: { password: 'changed-secret' },
    });
    const resumed = await request(harness.app, '/api/v1/runs/profile-run/resume', {
      method: 'POST',
      headers: mutationHeaders(),
      body: '{}',
    });

    expect(resumed.status).toBe(202);
    expect(harness.temporal.starts[1]?.input).toMatchObject({
      webUrl: 'https://target.test',
      vulnClasses: ['xss'],
    });
  });
});

describe('reports, evidence, and event streams', () => {
  async function createArtifactRun(): Promise<string> {
    await harness.controller.startRun({
      targetUrl: 'https://target.test',
      sourceMode: 'url-only',
      workspace: 'artifact-api-run',
      config: {},
    });
    const deliverables = path.join(harness.workspacesDir, 'artifact-api-run', '.shannon', 'deliverables');
    await fs.writeFile(
      path.join(deliverables, 'triage_verdicts.json'),
      JSON.stringify({
        version: 1,
        verdicts: [
          {
            id: 'xss-1',
            vulnType: 'xss',
            title: 'Reflected marker execution',
            verdict: 'PASS',
            severity: 'medium',
            reason: 'Controlled browser marker executed',
            evidenceFile: 'xss_evidence.txt',
          },
        ],
      }),
    );
    await fs.writeFile(path.join(deliverables, 'xss_evidence.txt'), 'sanitized evidence');
    await fs.writeFile(
      path.join(deliverables, 'comprehensive_security_assessment_report.md'),
      [
        '# Report',
        '<iframe>x</iframe>',
        'Contact: analyst@example.com',
        'Authorization: Bearer abcdefghijklmnopqrstuvwxyz',
        'OpenRouter key: sk-or-v1-abcdefghijklmnopqrstuvwxyz1234567890',
      ].join('\n'),
    );
    return deliverables;
  }

  it('sanitizes reports and limits downloads to triage-referenced contained files', async () => {
    const deliverables = await createArtifactRun();
    const report = await request(harness.app, '/api/v1/runs/artifact-api-run/report', {
      headers: authenticatedHeaders(),
    });
    expect(report.status).toBe(200);
    const markdown = (await report.json()).data.markdown as string;
    expect(markdown).toContain('## Mode\n\nURL-Only\n\n## Coverage');
    expect(markdown).not.toContain('<iframe>');
    expect(markdown).not.toContain('analyst@example.com');
    expect(markdown).not.toContain('abcdefghijklmnopqrstuvwxyz');
    expect(markdown).not.toContain('sk-or-v1');

    const evidence = await request(harness.app, '/api/v1/runs/artifact-api-run/artifacts/xss_evidence.txt', {
      headers: authenticatedHeaders(),
    });
    expect(evidence.status).toBe(200);
    expect(await evidence.text()).toBe('sanitized evidence');

    const unreferenced = await request(harness.app, '/api/v1/runs/artifact-api-run/artifacts/unreferenced.txt', {
      headers: authenticatedHeaders(),
    });
    expect(unreferenced.status).toBeGreaterThanOrEqual(400);

    const outside = path.join(harness.root, 'outside.txt');
    await fs.writeFile(outside, 'outside');
    await fs.rm(path.join(deliverables, 'xss_evidence.txt'));
    await fs.symlink(outside, path.join(deliverables, 'xss_evidence.txt'));
    const symlink = await request(harness.app, '/api/v1/runs/artifact-api-run/artifacts/xss_evidence.txt', {
      headers: authenticatedHeaders(),
    });
    expect(symlink.status).toBeGreaterThanOrEqual(400);
  });

  it('downloads only fixed report artifact kinds with exact media types', async () => {
    const deliverables = await createArtifactRun();
    await fs.writeFile(path.join(deliverables, 'comprehensive_security_assessment_report.pdf'), '%PDF-1.7');
    await fs.writeFile(path.join(deliverables, 'report.sarif'), '{"version":"2.1.0"}');
    await fs.writeFile(path.join(deliverables, 'report.json'), '{"internal":true}');

    const detailResponse = await request(harness.app, '/api/v1/runs/artifact-api-run', {
      headers: authenticatedHeaders(),
    });
    const detail = (await detailResponse.json()).data;
    expect(detail.reportAvailable).toBe(true);
    expect(detail.reportArtifacts.map((artifact: { kind: string }) => artifact.kind)).toEqual([
      'markdown',
      'pdf',
      'sarif',
    ]);

    for (const [kind, contentType] of [
      ['markdown', 'text/markdown; charset=utf-8'],
      ['pdf', 'application/pdf'],
      ['sarif', 'application/sarif+json; charset=utf-8'],
    ] as const) {
      const response = await request(harness.app, `/api/v1/runs/artifact-api-run/reports/${kind}`, {
        headers: authenticatedHeaders(),
      });
      expect(response.status).toBe(200);
      expect(response.headers.get('content-type')).toBe(contentType);
      expect(response.headers.get('content-disposition')).toMatch(/^attachment; filename="[^"]+"$/);
      if (kind === 'markdown') {
        const markdown = await response.text();
        expect(markdown).toContain('## Mode\n\nURL-Only\n\n## Coverage');
        expect(markdown).not.toContain('<iframe>');
        expect(markdown).not.toContain('analyst@example.com');
        expect(markdown).not.toContain('abcdefghijklmnopqrstuvwxyz');
        expect(markdown).not.toContain('sk-or-v1');
      }
    }

    for (const kind of ['report.json', '..%2Freport.json', 'markdown%2F..%2Freport.json']) {
      const response = await request(harness.app, `/api/v1/runs/artifact-api-run/reports/${kind}`, {
        headers: authenticatedHeaders(),
      });
      expect(response.status).toBeGreaterThanOrEqual(400);
    }

    for (const filename of ['report.json', 'report.sarif', 'comprehensive_security_assessment_report.pdf']) {
      const response = await request(
        harness.app,
        `/api/v1/runs/artifact-api-run/artifacts/${encodeURIComponent(filename)}`,
        { headers: authenticatedHeaders() },
      );
      expect(response.status).toBeGreaterThanOrEqual(400);
    }
  });

  it('uses Last-Event-ID as the activity cursor and closes terminal streams', async () => {
    await createArtifactRun();
    await fs.writeFile(
      path.join(harness.workspacesDir, 'artifact-api-run', '.shannon', 'workflow.log'),
      '[time] completed safely\n',
    );
    await harness.controller.cancelRun('artifact-api-run');
    const response = await request(harness.app, '/api/v1/runs/artifact-api-run/events', {
      headers: { Cookie: harness.cookie, 'Last-Event-ID': '2' },
    });
    expect(response.status).toBe(200);
    const stream = await response.text();
    expect(stream).toContain('event: snapshot');
    expect(stream).toContain('event: activity');
    expect(stream).toContain('id: 2');
  });
});
