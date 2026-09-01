import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { getAgentDir } from '@earendil-works/pi-coding-agent';
import type { DistributedConfig } from '../../types/config.js';

const PERMISSION_EXTENSION_ID = 'pi-permission-system';

export function toPathPatterns(value: string): string[] {
  const base = value.replace(/^(?:\.{0,2}\/)+/, '').replace(/\/+$/, '');
  if (!base) return [];
  if (base.includes('*') || base.includes('?')) {
    const flat = base.replace(/\*\*\//g, '*/').replace(/\*\*/g, '*');
    const tail = flat.replace(/^(?:\*\/)+/, '');
    const patterns = [flat, `*/${tail}`];
    if (!tail.includes('/')) patterns.push(tail.startsWith('*') ? tail : `*${tail}`);
    if (flat.endsWith('/*')) {
      const folder = flat.slice(0, -2);
      if (folder && !folder.includes('*')) patterns.push(folder, `*/${folder}`);
    }
    return [...new Set(patterns)];
  }
  return [base, `${base}/*`, `*/${base}`, `*/${base}/*`];
}

interface PermissionSystemConfig {
  permission: {
    '*': 'allow';
    path: Record<string, 'allow' | 'deny'>;
    external_directory: 'allow';
  };
}

export function buildPermissionConfig(patterns: readonly string[]): PermissionSystemConfig {
  const pathRules: Record<string, 'allow' | 'deny'> = { '*': 'allow' };
  for (const pattern of patterns) {
    for (const expanded of toPathPatterns(pattern)) pathRules[expanded] = 'deny';
  }
  return { permission: { '*': 'allow', path: pathRules, external_directory: 'allow' } };
}

export function permissionSystemConfigPath(agentDir: string): string {
  return path.join(agentDir, 'extensions', PERMISSION_EXTENSION_ID, 'config.json');
}

export function permissionSystemConfigExists(agentDir: string): boolean {
  return fs.existsSync(permissionSystemConfigPath(agentDir));
}

/** Writes only non-secret path policy; credentials remain exclusively in memory. */
export function syncPermissionSystemConfig(config: DistributedConfig | null): void {
  const configPath = permissionSystemConfigPath(getAgentDir());
  const avoidRules = (config?.avoid ?? []).filter((rule) => rule.type === 'code_path');
  if (avoidRules.length === 0) {
    fs.rmSync(configPath, { force: true });
    return;
  }
  fs.mkdirSync(path.dirname(configPath), { recursive: true });
  fs.writeFileSync(configPath, JSON.stringify(buildPermissionConfig(avoidRules.map((rule) => rule.value)), null, 2));
}

export function permissionSystemPackageDir(): string {
  const servicePath = createRequire(import.meta.url).resolve('@gotgenes/pi-permission-system');
  return path.resolve(path.dirname(servicePath), '..');
}
