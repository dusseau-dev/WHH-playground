import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';

const temporaryDirectories: string[] = [];

async function temporaryDirectory(prefix: string): Promise<string> {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  temporaryDirectories.push(directory);
  return directory;
}

async function command(commandName: string, args: string[], cwd: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(commandName, args, { cwd, env: process.env, stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    child.stdout.on('data', (chunk) => {
      output += String(chunk);
    });
    child.stderr.on('data', (chunk) => {
      output += String(chunk);
    });
    child.once('error', reject);
    child.once('exit', (code) => {
      if (code === 0) resolve(output.trim());
      else reject(new Error(`${commandName} ${args.join(' ')} failed (${code}): ${output}`));
    });
  });
}

async function availablePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        reject(new Error('Could not allocate an integration-test port'));
        return;
      }
      server.close(() => resolve(address.port));
    });
  });
}

async function waitForHealth(url: string, output: () => string): Promise<Response> {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${url}/api/v1/health`);
      if (response.ok) return response;
    } catch {
      // The process may still be loading its bundled modules.
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Packaged UI did not become healthy:\n${output()}`);
}

afterAll(async () => {
  await Promise.all(temporaryDirectories.map((directory) => fs.rm(directory, { recursive: true, force: true })));
});

describe('published CLI package', () => {
  it('installs in an unrelated project and serves the bundled UI cwd-independently', async () => {
    const packageRoot = path.resolve(import.meta.dirname, '../..');
    const packDirectory = await temporaryDirectory('shannon-pack-');
    const projectDirectory = await temporaryDirectory('shannon-install-');
    const homeDirectory = await temporaryDirectory('shannon-home-');
    const packOutput = await command('pnpm', ['pack', '--pack-destination', packDirectory], packageRoot);
    const tarballName = packOutput
      .split('\n')
      .map((line) => line.trim())
      .findLast((line) => line.endsWith('.tgz'));
    if (!tarballName) throw new Error(`pnpm pack did not report a tarball: ${packOutput}`);
    const tarball = path.isAbsolute(tarballName) ? tarballName : path.join(packDirectory, tarballName);

    const listing = await command('tar', ['-tzf', tarball], projectDirectory);
    expect(listing).toContain('package/dist/index.mjs');
    expect(listing).toContain('package/dist/ui/index.html');
    expect(listing).toContain('package/infra/compose.yml');

    await fs.writeFile(path.join(projectDirectory, 'package.json'), '{"private":true,"type":"module"}\n');
    await command('npm', ['install', '--ignore-scripts', tarball], projectDirectory);
    const executable = path.join(projectDirectory, 'node_modules', '.bin', 'shannon');
    const help = await command(executable, ['help'], projectDirectory);
    expect(help).toContain('start --url <url> [--repo <path>]');
    expect(help).toContain('ui [--port <number>] [--no-open]');

    const port = await availablePort();
    const child = spawn(executable, ['ui', '--port', String(port), '--no-open'], {
      cwd: projectDirectory,
      env: { ...process.env, HOME: homeDirectory },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let output = '';
    child.stdout.on('data', (chunk) => {
      output += String(chunk);
    });
    child.stderr.on('data', (chunk) => {
      output += String(chunk);
    });
    try {
      const url = `http://127.0.0.1:${port}`;
      const health = await waitForHealth(url, () => output);
      await expect(health.json()).resolves.toMatchObject({ data: { status: 'ok', bind: '127.0.0.1' } });
      const index = await fetch(url);
      expect(index.status).toBe(200);
      expect(await index.text()).toContain('<div id="root"></div>');
      const bootstrap = await fetch(`${url}/api/v1/bootstrap`);
      expect(bootstrap.headers.get('set-cookie')).toContain('HttpOnly');
      await expect(bootstrap.json()).resolves.toMatchObject({
        data: { apiVersion: 1, version: '0.0.0', secretStore: { persistence: expect.any(String) } },
      });
    } finally {
      child.kill('SIGTERM');
      await new Promise<void>((resolve) => {
        child.once('exit', () => resolve());
        setTimeout(() => {
          child.kill('SIGKILL');
          resolve();
        }, 5_000).unref();
      });
    }
  }, 60_000);
});
