import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  clearPipelineCredentials,
  type ProtectedPipelineInput,
  protectPipelineInput,
  resolvePipelineCredentials,
} from '../src/temporal/pipeline-secrets.js';

const tempRoots: string[] = [];

afterEach(async () => {
  await Promise.all(tempRoots.splice(0).map((root) => fs.rm(root, { force: true, recursive: true })));
});

describe('pipeline secret references', () => {
  it('protects backward-compatible PipelineInput fields before Temporal submission', async () => {
    const outputPath = await fs.mkdtemp(path.join(os.tmpdir(), 'shannon-protected-input-'));
    tempRoots.push(outputPath);
    const providerSecret = 'provider-api-secret';
    const targetPassword = 'target-auth-password';
    const protectedInput = (await protectPipelineInput({
      webUrl: 'https://example.test',
      sourceMode: 'url-only',
      workingDirectory: '/app/target',
      sessionId: 'workspace-a',
      outputPath,
      providerConfig: { providerType: 'generic', apiKey: providerSecret },
      configYAML: `authentication:\n  credentials:\n    password: ${targetPassword}\n`,
    })) as ProtectedPipelineInput;

    expect(JSON.stringify(protectedInput)).not.toContain(providerSecret);
    expect(JSON.stringify(protectedInput)).not.toContain(targetPassword);
    expect(protectedInput).toMatchObject({
      secretRef: expect.stringMatching(/^ps_[a-f0-9]{32}$/),
      providerConfig: { providerType: 'generic' },
    });

    const secretPath = path.join(
      outputPath,
      'workspace-a',
      '.shannon',
      'runtime',
      'workflow-secrets',
      `${protectedInput.secretRef}.json`,
    );
    if (process.platform !== 'win32') {
      expect((await fs.stat(secretPath)).mode & 0o777).toBe(0o600);
      expect((await fs.stat(path.dirname(secretPath))).mode & 0o777).toBe(0o700);
    }
    await expect(resolvePipelineCredentials(protectedInput)).resolves.toMatchObject({
      providerConfig: { providerType: 'generic', apiKey: providerSecret },
      configYAML: expect.stringContaining(targetPassword),
    });
    await expect(fs.access(secretPath)).rejects.toMatchObject({ code: 'ENOENT' });
    clearPipelineCredentials(protectedInput);
  });

  it('loads and deletes staged credentials while merging non-secret provider settings', async () => {
    const outputPath = await fs.mkdtemp(path.join(os.tmpdir(), 'shannon-pipeline-secrets-'));
    tempRoots.push(outputPath);
    const secretRef = 'ps_0123456789abcdef0123456789abcdef';
    const secretDirectory = path.join(outputPath, 'workspace-a', '.shannon', 'runtime', 'workflow-secrets');
    const secretPath = path.join(secretDirectory, `${secretRef}.json`);
    await fs.mkdir(secretDirectory, { recursive: true, mode: 0o700 });
    await fs.writeFile(
      secretPath,
      JSON.stringify({
        version: 1,
        apiKey: 'legacy-api-key',
        providerConfig: { authToken: 'provider-auth-token' },
        configYAML: 'authentication:\n  credentials:\n    password: target-auth-password\n',
      }),
      { mode: 0o600 },
    );
    const input = {
      sessionId: 'workspace-a',
      webUrl: 'https://example.test',
      outputPath,
      secretRef,
      providerConfig: { providerType: 'generic', baseUrl: 'https://gateway.test/v1' },
    } as const;

    await expect(resolvePipelineCredentials(input)).resolves.toEqual({
      apiKey: 'legacy-api-key',
      providerConfig: {
        providerType: 'generic',
        baseUrl: 'https://gateway.test/v1',
        authToken: 'provider-auth-token',
      },
      configYAML: 'authentication:\n  credentials:\n    password: target-auth-password\n',
    });
    await expect(fs.access(secretPath)).rejects.toMatchObject({ code: 'ENOENT' });

    // Later activities in the same run reuse only the in-memory value.
    await expect(resolvePipelineCredentials(input)).resolves.toMatchObject({ apiKey: 'legacy-api-key' });
    clearPipelineCredentials(input);
    await expect(resolvePipelineCredentials(input)).rejects.toThrow('Pipeline credentials are unavailable');
  });

  it('rejects path-like references before touching the filesystem', async () => {
    await expect(
      resolvePipelineCredentials({
        sessionId: 'workspace-a',
        webUrl: 'https://example.test',
        secretRef: '../provider-secret',
      }),
    ).rejects.toThrow('Invalid pipeline secret reference');
  });
});
