import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { parseAssessmentConfigYaml } from '../src/assessment-config.js';
import { ProfileStore } from '../src/profiles.js';
import { createSecretStore, MemorySecretStore } from '../src/secret-store.js';

const temporaryDirectories: string[] = [];

async function temporaryDirectory(): Promise<string> {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'shannon-profiles-'));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) => fs.rm(directory, { recursive: true, force: true })),
  );
});

describe('CLI assessment YAML', () => {
  it.each([
    ['true', true],
    ['false', false],
    ['"true"', true],
    ['"false"', false],
  ])('normalizes report.sarif from YAML (%s)', (value, expected) => {
    const parsed = parseAssessmentConfigYaml(`report:\n  sarif: ${value}\n`);
    expect(parsed.config.report?.sarif).toBe(expected);
  });

  it('accepts public names and extracts embedded target credentials', () => {
    const parsed = parseAssessmentConfigYaml(`
test_categories: [injection, authz]
safe_demonstration: false
pipeline:
  max_concurrent_pipelines: 2
authentication:
  login_type: form
  login_url: https://target.test/login
  credentials:
    username: operator
    password: target-password
    totp_secret: JBSWY3DPEHPK3PXP
  success_condition:
    type: url_contains
    value: /dashboard
`);
    expect(parsed.config.testCategories).toEqual(['injection', 'authz']);
    expect(parsed.config.safeDemonstration).toBe(false);
    expect(parsed.config.pipeline?.maxConcurrentPipelines).toBe(2);
    expect(parsed.secrets).toEqual({ password: 'target-password', totpSecret: 'JBSWY3DPEHPK3PXP' });
    expect(parsed.config.authentication).not.toHaveProperty('credentials');
  });

  it.each([
    ['exploit: false', false],
    ['exploit: "false"', false],
    ['exploit: true', true],
    ['exploit: "true"', true],
  ])('retains legacy %s', (yaml, expected) => {
    expect(parseAssessmentConfigYaml(yaml).config.safeDemonstration).toBe(expected);
  });

  it('rejects conflicting demonstration aliases', () => {
    expect(() => parseAssessmentConfigYaml('safe_demonstration: true\nexploit: false')).toThrow(/conflicts/);
  });
});

describe('profiles and secret stores', () => {
  it('round-trips SARIF report configuration through profile YAML', async () => {
    const profilesDir = await temporaryDirectory();
    const store = new ProfileStore({
      profilesDir,
      secretStore: new MemorySecretStore(),
      idGenerator: () => 'profile-sarif',
    });
    await store.create({
      name: 'SARIF target',
      targetUrl: 'https://target.test',
      sourceMode: 'url-only',
      config: { report: { sarif: true } },
    });
    const exported = await store.exportYaml('profile-sarif');
    expect(exported).toContain('sarif: true');

    const importedStore = new ProfileStore({
      profilesDir: await temporaryDirectory(),
      secretStore: new MemorySecretStore(),
      idGenerator: () => 'profile-sarif-imported',
    });
    await importedStore.importYaml(exported);
    await expect(importedStore.resolve('profile-sarif-imported')).resolves.toMatchObject({
      profile: { config: { report: { sarif: true } } },
    });
  });

  it('stores only secret references in versioned profile YAML', async () => {
    const profilesDir = await temporaryDirectory();
    const store = new ProfileStore({
      profilesDir,
      secretStore: new MemorySecretStore(),
      idGenerator: () => 'profile-test',
      now: () => new Date('2026-07-18T12:00:00.000Z'),
    });
    const response = await store.create({
      name: 'Authenticated target',
      targetUrl: 'https://target.test',
      sourceMode: 'url-only',
      config: {},
      secrets: { password: 'do-not-persist' },
    });

    const yaml = await fs.readFile(path.join(profilesDir, 'profile-test.yaml'), 'utf8');
    expect(yaml).not.toContain('do-not-persist');
    expect(yaml).toContain('memory:profile-test:password');
    expect(response.hasSecret.password).toBe(true);
    await expect(store.resolve('profile-test')).resolves.toMatchObject({ secrets: { password: 'do-not-persist' } });
  });

  it('imports legacy YAML and moves its password out of the file', async () => {
    const profilesDir = await temporaryDirectory();
    const store = new ProfileStore({
      profilesDir,
      secretStore: new MemorySecretStore(),
      idGenerator: () => 'profile-imported',
    });
    await store.importYaml(`
name: Imported
target_url: https://target.test
source_mode: url-only
exploit: false
authentication:
  login_type: form
  login_url: https://target.test/login
  credentials:
    username: operator
    password: imported-password
  success_condition:
    type: url_contains
    value: /home
`);
    expect(await fs.readFile(path.join(profilesDir, 'profile-imported.yaml'), 'utf8')).not.toContain(
      'imported-password',
    );
    await expect(store.resolve('profile-imported')).resolves.toMatchObject({
      profile: { config: { safeDemonstration: false } },
      secrets: { password: 'imported-password' },
    });
  });

  it('falls back to session memory when keychain is unavailable or unsupported', async () => {
    const unavailable = await createSecretStore({
      platform: 'darwin',
      importer: async () => {
        throw new Error('native module unavailable');
      },
    });
    const unsupported = await createSecretStore({ platform: 'linux' });
    expect(unavailable.persistence).toBe('memory');
    expect(unsupported.persistence).toBe('memory');
  });
});
