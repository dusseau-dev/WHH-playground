/**
 * Backwards-compatible environment variable aliases.
 *
 * The project was renamed from Shannon to Dora. Existing installations still
 * export SHANNON_* variables from their .env files and shell profiles, so we
 * copy any SHANNON_* value onto its DORA_* counterpart when the new name is
 * unset. DORA_* always wins, so the migration is silent and one-directional.
 *
 * This must run AFTER environment sources are loaded (dotenv / shell), not at
 * module import time, otherwise the alias is computed against an empty env.
 */

const LEGACY_PREFIX = 'SHANNON_';
const PREFIX = 'DORA_';

/** Copy SHANNON_X -> DORA_X for every legacy variable that is still in use. */
export function applyLegacyEnvAliases(env: NodeJS.ProcessEnv = process.env): string[] {
  const aliased: string[] = [];
  for (const key of Object.keys(env)) {
    if (!key.startsWith(LEGACY_PREFIX)) continue;
    const modern = `${PREFIX}${key.slice(LEGACY_PREFIX.length)}`;
    if (env[modern] !== undefined && env[modern] !== '') continue;
    const value = env[key];
    if (value === undefined) continue;
    env[modern] = value;
    aliased.push(`${key} -> ${modern}`);
  }
  return aliased;
}