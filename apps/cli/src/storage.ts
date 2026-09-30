import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

export async function ensureDirectory(directory: string, mode = 0o700): Promise<void> {
  await fs.mkdir(directory, { recursive: true, mode });
  if (process.platform !== 'win32') await fs.chmod(directory, mode);
}

export async function atomicWriteFile(filePath: string, content: string | Uint8Array, mode = 0o600): Promise<void> {
  const directory = path.dirname(filePath);
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  const temporaryPath = path.join(
    directory,
    `.${path.basename(filePath)}.${crypto.randomBytes(6).toString('hex')}.tmp`,
  );

  try {
    await fs.writeFile(temporaryPath, content, { mode, flag: 'wx' });
    if (process.platform !== 'win32') await fs.chmod(temporaryPath, mode);
    await fs.rename(temporaryPath, filePath);
    if (process.platform !== 'win32') await fs.chmod(filePath, mode);
  } catch (error) {
    await fs.rm(temporaryPath, { force: true }).catch(() => undefined);
    throw error;
  }
}

export async function atomicWriteJson(filePath: string, value: unknown, mode = 0o600): Promise<void> {
  await atomicWriteFile(filePath, `${JSON.stringify(value, null, 2)}\n`, mode);
}

export async function readJsonFile(filePath: string): Promise<unknown> {
  return JSON.parse(await fs.readFile(filePath, 'utf8')) as unknown;
}

export async function readJsonIfExists(filePath: string): Promise<unknown | null> {
  try {
    return await readJsonFile(filePath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw error;
  }
}

export function assertSafeIdentifier(value: string, kind: string): void {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$/.test(value)) {
    throw new Error(`Invalid ${kind}`);
  }
}

export async function resolveExistingContainedPath(root: string, relativePath: string): Promise<string> {
  if (!relativePath || path.isAbsolute(relativePath) || relativePath.includes('\0')) {
    throw new Error('Invalid artifact path');
  }

  const rootRealPath = await fs.realpath(root);
  const candidate = path.resolve(rootRealPath, relativePath);
  const candidateRealPath = await fs.realpath(candidate);
  const relative = path.relative(rootRealPath, candidateRealPath);

  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error('Artifact path escapes the workspace');
  }

  const stat = await fs.stat(candidateRealPath);
  if (!stat.isFile()) throw new Error('Artifact is not a file');
  return candidateRealPath;
}

export async function readFileChunk(
  filePath: string,
  offset: number,
  maxBytes = 64 * 1024,
): Promise<{
  offset: number;
  text: string;
}> {
  let handle: fs.FileHandle | undefined;
  try {
    handle = await fs.open(filePath, 'r');
    const stat = await handle.stat();
    const safeOffset = Math.max(0, Math.min(offset, stat.size));
    const length = Math.min(maxBytes, stat.size - safeOffset);
    if (length === 0) return { offset: safeOffset, text: '' };

    const buffer = Buffer.alloc(length);
    const result = await handle.read(buffer, 0, length, safeOffset);
    return { offset: safeOffset + result.bytesRead, text: buffer.subarray(0, result.bytesRead).toString('utf8') };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { offset, text: '' };
    throw error;
  } finally {
    await handle?.close();
  }
}

export async function pathExists(filePath: string): Promise<boolean> {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}
