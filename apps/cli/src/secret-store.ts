import type { SecretField } from './contracts.js';

const KEYCHAIN_SERVICE = 'com.keygraph.shannon.target';

export interface SecretStore {
  readonly persistence: 'keychain' | 'memory';
  put(profileId: string, field: SecretField, value: string): Promise<string>;
  get(reference: string): Promise<string | null>;
  has(reference: string): Promise<boolean>;
  delete(reference: string): Promise<void>;
}

interface KeyringEntry {
  setPassword(value: string): Promise<void> | void;
  getPassword(): Promise<string | null> | string | null;
  deletePassword(): Promise<boolean | undefined> | boolean | undefined;
}

interface KeyringModule {
  Entry?: new (service: string, account: string) => KeyringEntry;
  default?: { Entry?: new (service: string, account: string) => KeyringEntry };
}

type DynamicImporter = (specifier: string) => Promise<unknown>;

function accountFor(profileId: string, field: SecretField): string {
  return `${profileId}:${field}`;
}

function parseReference(reference: string): { storage: 'keychain' | 'memory'; account: string } | null {
  const separator = reference.indexOf(':');
  if (separator < 1) return null;
  const storage = reference.slice(0, separator);
  if (storage !== 'keychain' && storage !== 'memory') return null;
  const account = reference.slice(separator + 1);
  return account ? { storage, account } : null;
}

export class MemorySecretStore implements SecretStore {
  readonly persistence = 'memory' as const;
  private readonly values = new Map<string, string>();

  async put(profileId: string, field: SecretField, value: string): Promise<string> {
    const account = accountFor(profileId, field);
    this.values.set(account, value);
    return `memory:${account}`;
  }

  async get(reference: string): Promise<string | null> {
    const parsed = parseReference(reference);
    if (!parsed || parsed.storage !== 'memory') return null;
    return this.values.get(parsed.account) ?? null;
  }

  async has(reference: string): Promise<boolean> {
    return (await this.get(reference)) !== null;
  }

  async delete(reference: string): Promise<void> {
    const parsed = parseReference(reference);
    if (parsed?.storage === 'memory') this.values.delete(parsed.account);
  }
}

class KeychainSecretStore implements SecretStore {
  readonly persistence = 'keychain' as const;

  constructor(private readonly Entry: NonNullable<KeyringModule['Entry']>) {}

  async put(profileId: string, field: SecretField, value: string): Promise<string> {
    const account = accountFor(profileId, field);
    await this.createEntry(account).setPassword(value);
    return `keychain:${account}`;
  }

  async get(reference: string): Promise<string | null> {
    const parsed = parseReference(reference);
    if (!parsed || parsed.storage !== 'keychain') return null;
    return (await this.createEntry(parsed.account).getPassword()) ?? null;
  }

  async has(reference: string): Promise<boolean> {
    return (await this.get(reference)) !== null;
  }

  async delete(reference: string): Promise<void> {
    const parsed = parseReference(reference);
    if (parsed?.storage === 'keychain') await this.createEntry(parsed.account).deletePassword();
  }

  private createEntry(account: string): KeyringEntry {
    return new this.Entry(KEYCHAIN_SERVICE, account);
  }
}

class RoutedSecretStore implements SecretStore {
  readonly persistence: 'keychain' | 'memory';

  constructor(
    private readonly memory: MemorySecretStore,
    private readonly keychain: KeychainSecretStore | null,
  ) {
    this.persistence = keychain ? 'keychain' : 'memory';
  }

  async put(profileId: string, field: SecretField, value: string): Promise<string> {
    if (this.keychain) {
      try {
        return await this.keychain.put(profileId, field, value);
      } catch {
        // A locked or unavailable keychain degrades to session-only storage.
      }
    }
    return this.memory.put(profileId, field, value);
  }

  async get(reference: string): Promise<string | null> {
    const parsed = parseReference(reference);
    if (parsed?.storage === 'keychain') {
      try {
        return (await this.keychain?.get(reference)) ?? null;
      } catch {
        return null;
      }
    }
    return this.memory.get(reference);
  }

  async has(reference: string): Promise<boolean> {
    return (await this.get(reference)) !== null;
  }

  async delete(reference: string): Promise<void> {
    const parsed = parseReference(reference);
    if (parsed?.storage === 'keychain') {
      try {
        await this.keychain?.delete(reference);
      } catch {
        // Deletion is best-effort when the native keychain is unavailable.
      }
      return;
    }
    await this.memory.delete(reference);
  }
}

export async function createSecretStore(
  options: { platform?: NodeJS.Platform; importer?: DynamicImporter; memory?: MemorySecretStore } = {},
): Promise<SecretStore> {
  const platform = options.platform ?? process.platform;
  const memory = options.memory ?? new MemorySecretStore();
  if (platform !== 'darwin') return new RoutedSecretStore(memory, null);

  const importer = options.importer ?? ((specifier: string) => import(specifier));
  try {
    const loaded = (await importer('@napi-rs/keyring')) as KeyringModule;
    const Entry = loaded.Entry ?? loaded.default?.Entry;
    if (!Entry) return new RoutedSecretStore(memory, null);
    return new RoutedSecretStore(memory, new KeychainSecretStore(Entry));
  } catch {
    return new RoutedSecretStore(memory, null);
  }
}
