import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { dump as dumpYaml, load as loadYaml } from 'js-yaml';
import { normalizeAssessmentConfigObject } from './assessment-config.js';
import {
  type AssessmentConfig,
  type ProfileDraft,
  ProfileDraftSchema,
  type ProfileFile,
  ProfileFileSchema,
  type ProfileResponse,
  SECRET_FIELDS,
  type SecretField,
  type SecretReferences,
  type TargetSecrets,
  TargetSecretsSchema,
} from './contracts.js';
import type { SecretStore } from './secret-store.js';
import { assertSafeIdentifier, atomicWriteFile, ensureDirectory, pathExists } from './storage.js';

export interface ResolvedProfile {
  profile: ProfileResponse;
  secrets: TargetSecrets;
  secretRefs: SecretReferences;
  missingSecretFields: SecretField[];
}

export interface ProfileStoreOptions {
  profilesDir?: string;
  secretStore: SecretStore;
  now?: () => Date;
  idGenerator?: () => string;
}

function yamlForProfile(profile: ProfileFile): string {
  return dumpYaml(profile, { noRefs: true, lineWidth: 120, sortKeys: false });
}

function cloneYamlObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error('Profile YAML must contain an object');
  return JSON.parse(JSON.stringify(value)) as Record<string, unknown>;
}

function takeString(target: Record<string, unknown>, key: string): string | undefined {
  const value = target[key];
  delete target[key];
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
}

function extractEmbeddedSecrets(raw: Record<string, unknown>): TargetSecrets {
  const extracted: TargetSecrets = {};
  const supplied = record(raw.secrets);
  if (supplied) {
    Object.assign(extracted, TargetSecretsSchema.partial().parse(supplied));
    delete raw.secrets;
  }

  const config = record(raw.config) ?? raw;
  const authentication = record(config.authentication);
  const credentials = record(authentication?.credentials);
  if (!credentials) return extracted;

  extracted.password ??= takeString(credentials, 'password');
  extracted.totpSecret ??= takeString(credentials, 'totp_secret') ?? takeString(credentials, 'totpSecret');
  const emailLogin = record(credentials.email_login) ?? record(credentials.emailLogin);
  if (emailLogin) {
    extracted.emailPassword ??= takeString(emailLogin, 'password');
    extracted.emailTotpSecret ??= takeString(emailLogin, 'totp_secret') ?? takeString(emailLogin, 'totpSecret');
  }
  return extracted;
}

function normalizeImportedConfig(raw: Record<string, unknown>): AssessmentConfig {
  const config = record(raw.config) ?? raw;
  return normalizeAssessmentConfigObject(config);
}

function importDraft(rawValue: unknown): {
  draft: ProfileDraft;
  secrets: TargetSecrets;
  importedRefs: SecretReferences;
} {
  const raw = cloneYamlObject(rawValue);
  const secrets = extractEmbeddedSecrets(raw);
  const importedRefs = record(raw.secretRefs) as SecretReferences | undefined;
  const config = normalizeImportedConfig(raw);

  const draft = ProfileDraftSchema.parse({
    name: raw.name,
    targetUrl: raw.targetUrl ?? raw.target_url,
    sourceMode: raw.sourceMode ?? raw.source_mode ?? (raw.repoPath || raw.repo_path ? 'source-assisted' : 'url-only'),
    repoPath: raw.repoPath ?? raw.repo_path,
    config,
    secrets,
  });
  return { draft, secrets, importedRefs: importedRefs ?? {} };
}

export class ProfileStore {
  readonly profilesDir: string;
  private readonly secretStore: SecretStore;
  private readonly now: () => Date;
  private readonly idGenerator: () => string;

  constructor(options: ProfileStoreOptions) {
    this.profilesDir = options.profilesDir ?? path.join(os.homedir(), '.shannon', 'profiles');
    this.secretStore = options.secretStore;
    this.now = options.now ?? (() => new Date());
    this.idGenerator = options.idGenerator ?? (() => `profile-${crypto.randomUUID()}`);
  }

  get secretPersistence(): SecretStore['persistence'] {
    return this.secretStore.persistence;
  }

  async initialize(): Promise<void> {
    await ensureDirectory(this.profilesDir, 0o700);
  }

  async list(): Promise<ProfileResponse[]> {
    await this.initialize();
    const entries = await fs.readdir(this.profilesDir, { withFileTypes: true });
    const profiles: ProfileResponse[] = [];
    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.endsWith('.yaml')) continue;
      try {
        profiles.push(await this.toResponse(await this.readPath(path.join(this.profilesDir, entry.name))));
      } catch {
        // A corrupt profile is isolated instead of making every profile unusable.
      }
    }
    return profiles.sort((left, right) => right.updatedAt.localeCompare(left.updatedAt));
  }

  async get(id: string): Promise<ProfileResponse> {
    return this.toResponse(await this.read(id));
  }

  async create(value: ProfileDraft): Promise<ProfileResponse> {
    const draft = ProfileDraftSchema.parse(value);
    const id = this.idGenerator();
    assertSafeIdentifier(id, 'profile ID');
    if (await pathExists(this.profilePath(id))) throw new Error('Profile already exists');

    const timestamp = this.now().toISOString();
    const secretRefs = await this.storeSecrets(id, {}, draft.secrets ?? {}, draft.clearSecrets ?? []);
    const profile = ProfileFileSchema.parse({
      version: 1,
      id,
      name: draft.name,
      targetUrl: draft.targetUrl,
      sourceMode: draft.sourceMode,
      ...(draft.repoPath && { repoPath: draft.repoPath }),
      config: draft.config ?? {},
      secretRefs,
      createdAt: timestamp,
      updatedAt: timestamp,
    });
    await this.write(profile);
    return this.toResponse(profile);
  }

  async update(id: string, value: ProfileDraft): Promise<ProfileResponse> {
    const current = await this.read(id);
    const draft = ProfileDraftSchema.parse(value);
    const secretRefs = await this.storeSecrets(id, current.secretRefs, draft.secrets ?? {}, draft.clearSecrets ?? []);
    const updated = ProfileFileSchema.parse({
      ...current,
      name: draft.name,
      targetUrl: draft.targetUrl,
      sourceMode: draft.sourceMode,
      repoPath: draft.repoPath,
      config: draft.config ?? {},
      secretRefs,
      updatedAt: this.now().toISOString(),
    });
    await this.write(updated);
    return this.toResponse(updated);
  }

  async delete(id: string): Promise<void> {
    const profile = await this.read(id);
    await Promise.all(
      Object.values(profile.secretRefs)
        .filter((reference): reference is string => Boolean(reference))
        .map((reference) => this.secretStore.delete(reference)),
    );
    await fs.rm(this.profilePath(id), { force: true });
  }

  async importYaml(yaml: string): Promise<ProfileResponse> {
    const imported = importDraft(loadYaml(yaml));
    for (const field of SECRET_FIELDS) {
      if (imported.secrets[field] || !imported.importedRefs[field]) continue;
      const value = await this.secretStore.get(imported.importedRefs[field]);
      if (value) imported.secrets[field] = value;
    }
    return this.create({ ...imported.draft, secrets: imported.secrets });
  }

  async exportYaml(id: string): Promise<string> {
    return yamlForProfile(await this.read(id));
  }

  async resolve(id: string): Promise<ResolvedProfile> {
    const stored = await this.read(id);
    const secrets: TargetSecrets = {};
    const missingSecretFields: SecretField[] = [];
    for (const field of SECRET_FIELDS) {
      const reference = stored.secretRefs[field];
      if (!reference) continue;
      const value = await this.secretStore.get(reference);
      if (value) secrets[field] = value;
      else missingSecretFields.push(field);
    }
    return { profile: await this.toResponse(stored), secrets, secretRefs: stored.secretRefs, missingSecretFields };
  }

  async resolveSecretReferences(references: SecretReferences): Promise<TargetSecrets> {
    const secrets: TargetSecrets = {};
    for (const field of SECRET_FIELDS) {
      const reference = references[field];
      if (!reference) continue;
      const value = await this.secretStore.get(reference);
      if (value) secrets[field] = value;
    }
    return secrets;
  }

  private profilePath(id: string): string {
    assertSafeIdentifier(id, 'profile ID');
    return path.join(this.profilesDir, `${id}.yaml`);
  }

  private async read(id: string): Promise<ProfileFile> {
    return this.readPath(this.profilePath(id));
  }

  private async readPath(filePath: string): Promise<ProfileFile> {
    try {
      return ProfileFileSchema.parse(loadYaml(await fs.readFile(filePath, 'utf8')));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') throw new Error('Profile not found');
      throw error;
    }
  }

  private async write(profile: ProfileFile): Promise<void> {
    await this.initialize();
    await atomicWriteFile(this.profilePath(profile.id), yamlForProfile(profile), 0o600);
  }

  private async toResponse(profile: ProfileFile): Promise<ProfileResponse> {
    const hasSecret: Partial<Record<SecretField, boolean>> = {};
    for (const field of SECRET_FIELDS) {
      const reference = profile.secretRefs[field];
      if (reference) hasSecret[field] = await this.secretStore.has(reference);
    }
    const { secretRefs: _secretRefs, ...safeProfile } = profile;
    return { ...safeProfile, hasSecret };
  }

  private async storeSecrets(
    profileId: string,
    existing: SecretReferences,
    values: TargetSecrets,
    clear: SecretField[],
  ): Promise<SecretReferences> {
    const next: SecretReferences = { ...existing };
    for (const field of clear) {
      const previous = next[field];
      if (previous) await this.secretStore.delete(previous);
      delete next[field];
    }
    for (const field of SECRET_FIELDS) {
      const value = values[field];
      if (!value) continue;
      const previous = next[field];
      next[field] = await this.secretStore.put(profileId, field, value);
      if (previous && previous !== next[field]) await this.secretStore.delete(previous);
    }
    return next;
  }
}
