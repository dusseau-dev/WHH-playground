/** TOML config writer for ~/.dora/config.toml. */

import fs from 'node:fs';
import path from 'node:path';
import { stringify } from 'smol-toml';
import { getConfigFile } from '../home.js';

// === Types ===

export interface DoraConfig {
  core?: { model?: string; base_url?: string };
  anthropic?: { api_key?: string; oauth_token?: string };
  openai?: { api_key?: string; format?: 'chat-completions' | 'responses' };
  xai?: { api_key?: string };
  bedrock?: { region?: string; token?: string };
  provider?: { api_key?: string };
}

// === File Operations ===

/** Write the config to ~/.dora/config.toml with 0o600 permissions. */
export function saveConfig(config: DoraConfig): void {
  const configPath = getConfigFile();
  const dir = path.dirname(configPath);
  fs.mkdirSync(dir, { recursive: true });

  const content = stringify(config);
  fs.writeFileSync(configPath, content, { mode: 0o600 });
  fs.chmodSync(configPath, 0o600);
}
