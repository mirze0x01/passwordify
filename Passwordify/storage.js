import {
    createEncryptedVault,
    decryptVaultWithKey,
    encryptVaultWithKey,
    normalizeVaultRecord,
    unlockEncryptedVault,
} from './crypto.js';

export const VAULT_SCHEMA_VERSION = 1;
export const MIN_MASTER_PASSWORD_LENGTH = 12;
export const MAX_MASTER_PASSWORD_LENGTH = 256;
export const IDLE_LOCK_TIMEOUT_MS = 5 * 60 * 1000;
export const PENDING_ENTRY_LIFETIME_MS = 10 * 60 * 1000;
export const PENDING_ENTRY_ALARM = 'passwordify-clear-pending-entry';

export const STORAGE_KEYS = Object.freeze({
    vault: 'encryptedVault',
    pendingEntry: 'pendingVaultEntry',
    legacyPasswords: 'savedPasswords',
    legacyMasterPassword: 'masterPassword',
});

export class VaultDataError extends Error {
    constructor(message) {
        super(message);
        this.name = 'VaultDataError';
    }
}

export class ConcurrentVaultUpdateError extends Error {
    constructor() {
        super('The vault changed in another tab. Lock it, unlock it again, and retry your change.');
        this.name = 'ConcurrentVaultUpdateError';
    }
}

function getChrome(chromeApi) {
    if (!chromeApi?.storage?.local || !chromeApi?.storage?.session) {
        throw new VaultDataError('Chrome extension storage is unavailable.');
    }

    return chromeApi;
}

function getAlarms(chromeApi) {
    if (
        !chromeApi?.alarms
        || typeof chromeApi.alarms.create !== 'function'
        || typeof chromeApi.alarms.clear !== 'function'
    ) {
        throw new VaultDataError('Chrome extension alarms are unavailable.');
    }

    return chromeApi.alarms;
}

function getCrypto(cryptoProvider) {
    if (!cryptoProvider || typeof cryptoProvider.getRandomValues !== 'function') {
        throw new VaultDataError('A cryptographically secure random source is unavailable.');
    }

    return cryptoProvider;
}

function nowIso(clock = Date) {
    return new clock().toISOString();
}

function isValidDate(value) {
    return typeof value === 'string' && Number.isFinite(Date.parse(value));
}

function requireString(value, fieldName, maximumLength, { allowEmpty = true } = {}) {
    if (typeof value !== 'string' || value.length > maximumLength || (!allowEmpty && value.length === 0)) {
        throw new VaultDataError(`${fieldName} is invalid.`);
    }

    return value;
}

function makeEntryId(cryptoProvider) {
    const secureCrypto = getCrypto(cryptoProvider);
    if (typeof secureCrypto.randomUUID === 'function') {
        return secureCrypto.randomUUID();
    }

    const bytes = new Uint8Array(16);
    secureCrypto.getRandomValues(bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hexadecimal = [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
    return [
        hexadecimal.slice(0, 8),
        hexadecimal.slice(8, 12),
        hexadecimal.slice(12, 16),
        hexadecimal.slice(16, 20),
        hexadecimal.slice(20),
    ].join('-');
}

export function validateNewMasterPassword(masterPassword) {
    if (typeof masterPassword !== 'string') {
        throw new VaultDataError('Enter a master password.');
    }

    const characterLength = Array.from(masterPassword).length;
    if (characterLength < MIN_MASTER_PASSWORD_LENGTH) {
        throw new VaultDataError(
            `Use at least ${MIN_MASTER_PASSWORD_LENGTH} characters for the master password.`,
        );
    }

    if (characterLength > MAX_MASTER_PASSWORD_LENGTH) {
        throw new VaultDataError(
            `Use no more than ${MAX_MASTER_PASSWORD_LENGTH} characters for the master password.`,
        );
    }

    if (masterPassword.trim().length === 0) {
        throw new VaultDataError('The master password cannot contain only whitespace.');
    }

    return masterPassword;
}

export function createVaultEntry(
    input,
    cryptoProvider = globalThis.crypto,
    timestamp = new Date().toISOString(),
) {
    if (input === null || typeof input !== 'object' || Array.isArray(input)) {
        throw new VaultDataError('The credential is invalid.');
    }

    if (!isValidDate(timestamp)) {
        throw new VaultDataError('The credential timestamp is invalid.');
    }

    const rawName = requireString(input.name ?? '', 'The entry name', 200);
    const name = rawName.trim() || 'Untitled entry';

    return {
        id: makeEntryId(cryptoProvider),
        name,
        username: requireString(input.username ?? '', 'The username', 320),
        url: requireString(input.url ?? '', 'The website', 2048),
        password: requireString(input.password, 'The password', 4096, { allowEmpty: false }),
        notes: requireString(input.notes ?? '', 'The notes', 4000),
        createdAt: timestamp,
        updatedAt: timestamp,
    };
}

function validateVaultEntry(entry) {
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
        throw new VaultDataError('A vault entry is invalid.');
    }

    const id = requireString(entry.id, 'The entry ID', 100, { allowEmpty: false });
    const name = requireString(entry.name, 'The entry name', 200, { allowEmpty: false });
    const createdAt = entry.createdAt;
    const updatedAt = entry.updatedAt;

    if (!isValidDate(createdAt) || !isValidDate(updatedAt)) {
        throw new VaultDataError('A vault entry timestamp is invalid.');
    }

    return {
        id,
        name,
        username: requireString(entry.username ?? '', 'The username', 320),
        url: requireString(entry.url ?? '', 'The website', 2048),
        password: requireString(entry.password, 'The password', 4096, { allowEmpty: false }),
        notes: requireString(entry.notes ?? '', 'The notes', 4000),
        createdAt,
        updatedAt,
    };
}

export function validateVault(vault) {
    if (vault === null || typeof vault !== 'object' || Array.isArray(vault)) {
        throw new VaultDataError('The decrypted vault is invalid.');
    }

    if (vault.schemaVersion !== VAULT_SCHEMA_VERSION) {
        throw new VaultDataError('The decrypted vault schema is unsupported.');
    }

    if (!Number.isSafeInteger(vault.revision) || vault.revision < 0) {
        throw new VaultDataError('The vault revision is invalid.');
    }

    if (!isValidDate(vault.createdAt) || !isValidDate(vault.updatedAt)) {
        throw new VaultDataError('The vault timestamps are invalid.');
    }

    if (!Array.isArray(vault.entries) || vault.entries.length > 10_000) {
        throw new VaultDataError('The vault entry collection is invalid.');
    }

    const entries = vault.entries.map(validateVaultEntry);
    const entryIds = new Set(entries.map((entry) => entry.id));
    if (entryIds.size !== entries.length) {
        throw new VaultDataError('The vault contains duplicate entry IDs.');
    }

    return {
        schemaVersion: VAULT_SCHEMA_VERSION,
        revision: vault.revision,
        createdAt: vault.createdAt,
        updatedAt: vault.updatedAt,
        entries,
    };
}

function legacyEntriesFromValue(value, cryptoProvider, timestamp) {
    if (value === undefined) {
        return { entries: [], invalidEntries: [], recoveryValue: undefined, totalCount: 0 };
    }

    if (!Array.isArray(value)) {
        return { entries: [], invalidEntries: [value], recoveryValue: value, totalCount: 1 };
    }

    const entries = [];
    const invalidEntries = [];

    for (const legacyEntry of value) {
        try {
            entries.push(createVaultEntry({
                name: legacyEntry?.name ?? 'Migrated entry',
                password: legacyEntry?.password,
            }, cryptoProvider, timestamp));
        } catch {
            invalidEntries.push(legacyEntry);
        }
    }

    return {
        entries,
        invalidEntries,
        recoveryValue: invalidEntries,
        totalCount: value.length,
    };
}

async function withNamedLock(name, callback) {
    if (globalThis.navigator?.locks?.request) {
        return globalThis.navigator.locks.request(name, { mode: 'exclusive' }, callback);
    }

    return callback();
}

async function withVaultWriteLock(callback) {
    return withNamedLock('passwordify-vault-write', callback);
}

async function withPendingEntryLock(callback) {
    return withNamedLock('passwordify-pending-entry', callback);
}

export async function hardenStorageAccess(chromeApi = globalThis.chrome) {
    const extensionChrome = getChrome(chromeApi);
    await extensionChrome.storage.local.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });
    await extensionChrome.storage.session.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });
}

export async function getVaultState(chromeApi = globalThis.chrome) {
    const extensionChrome = getChrome(chromeApi);
    const stored = await extensionChrome.storage.local.get([
        STORAGE_KEYS.vault,
        STORAGE_KEYS.legacyPasswords,
        STORAGE_KEYS.legacyMasterPassword,
    ]);
    const legacyPasswordCount = Array.isArray(stored[STORAGE_KEYS.legacyPasswords])
        ? stored[STORAGE_KEYS.legacyPasswords].length
        : (stored[STORAGE_KEYS.legacyPasswords] === undefined ? 0 : 1);

    return {
        hasVault: stored[STORAGE_KEYS.vault] !== undefined,
        legacyPasswordCount,
        hasLegacyMasterPassword: stored[STORAGE_KEYS.legacyMasterPassword] !== undefined,
    };
}

export async function readVaultRecord(chromeApi = globalThis.chrome) {
    const extensionChrome = getChrome(chromeApi);
    const stored = await extensionChrome.storage.local.get(STORAGE_KEYS.vault);
    if (stored[STORAGE_KEYS.vault] === undefined) {
        throw new VaultDataError('No encrypted vault exists yet.');
    }

    return normalizeVaultRecord(stored[STORAGE_KEYS.vault]);
}

export async function setupVault(
    masterPassword,
    {
        chromeApi = globalThis.chrome,
        cryptoProvider = globalThis.crypto,
        clock = Date,
    } = {},
) {
    validateNewMasterPassword(masterPassword);
    const extensionChrome = getChrome(chromeApi);
    const timestamp = nowIso(clock);

    return withVaultWriteLock(async () => {
        const stored = await extensionChrome.storage.local.get([
            STORAGE_KEYS.vault,
            STORAGE_KEYS.legacyPasswords,
        ]);
        if (stored[STORAGE_KEYS.vault] !== undefined) {
            throw new VaultDataError('An encrypted vault already exists. Unlock it instead.');
        }

        const legacy = legacyEntriesFromValue(
            stored[STORAGE_KEYS.legacyPasswords],
            cryptoProvider,
            timestamp,
        );
        const vault = validateVault({
            schemaVersion: VAULT_SCHEMA_VERSION,
            revision: 0,
            createdAt: timestamp,
            updatedAt: timestamp,
            entries: legacy.entries,
        });
        const encrypted = await createEncryptedVault(vault, masterPassword, cryptoProvider);

        await extensionChrome.storage.local.set({ [STORAGE_KEYS.vault]: encrypted.record });
        const verificationRecord = await readVaultRecord(extensionChrome);
        const verification = await unlockEncryptedVault(
            verificationRecord,
            masterPassword,
            cryptoProvider,
        );
        validateVault(verification.vault);

        await extensionChrome.storage.local.remove(STORAGE_KEYS.legacyMasterPassword);
        if (legacy.invalidEntries.length === 0) {
            await extensionChrome.storage.local.remove(STORAGE_KEYS.legacyPasswords);
        } else {
            await extensionChrome.storage.local.set({
                [STORAGE_KEYS.legacyPasswords]: legacy.recoveryValue,
            });
        }

        return {
            vault,
            key: encrypted.key,
            kdf: encrypted.kdf,
            migratedCount: legacy.entries.length,
            invalidLegacyCount: legacy.invalidEntries.length,
        };
    });
}

export async function unlockStoredVault(
    masterPassword,
    {
        chromeApi = globalThis.chrome,
        cryptoProvider = globalThis.crypto,
    } = {},
) {
    const extensionChrome = getChrome(chromeApi);
    const record = await readVaultRecord(extensionChrome);
    const unlocked = await unlockEncryptedVault(record, masterPassword, cryptoProvider);
    const vault = validateVault(unlocked.vault);

    // Remove the obsolete plaintext master password only after authenticated unlock.
    await extensionChrome.storage.local.remove(STORAGE_KEYS.legacyMasterPassword);
    return { vault, key: unlocked.key, kdf: unlocked.kdf };
}

export async function saveVault(
    vault,
    key,
    kdf,
    {
        chromeApi = globalThis.chrome,
        cryptoProvider = globalThis.crypto,
        clock = Date,
    } = {},
) {
    const extensionChrome = getChrome(chromeApi);
    const expectedVault = validateVault(vault);

    return withVaultWriteLock(async () => {
        const currentRecord = await readVaultRecord(extensionChrome);
        const currentVault = validateVault(
            await decryptVaultWithKey(currentRecord, key, cryptoProvider),
        );
        if (currentVault.revision !== expectedVault.revision) {
            throw new ConcurrentVaultUpdateError();
        }

        const nextVault = validateVault({
            ...expectedVault,
            revision: expectedVault.revision + 1,
            updatedAt: nowIso(clock),
        });
        const record = await encryptVaultWithKey(nextVault, key, kdf, cryptoProvider);
        await extensionChrome.storage.local.set({ [STORAGE_KEYS.vault]: record });
        return { vault: nextVault, record };
    });
}

export async function changeMasterPassword(
    vault,
    currentMasterPassword,
    newMasterPassword,
    {
        chromeApi = globalThis.chrome,
        cryptoProvider = globalThis.crypto,
        clock = Date,
    } = {},
) {
    validateNewMasterPassword(newMasterPassword);
    const extensionChrome = getChrome(chromeApi);
    const expectedVault = validateVault(vault);

    return withVaultWriteLock(async () => {
        const currentRecord = await readVaultRecord(extensionChrome);
        const authenticated = await unlockEncryptedVault(
            currentRecord,
            currentMasterPassword,
            cryptoProvider,
        );
        const currentVault = validateVault(authenticated.vault);
        if (currentVault.revision !== expectedVault.revision) {
            throw new ConcurrentVaultUpdateError();
        }

        const nextVault = validateVault({
            ...expectedVault,
            revision: expectedVault.revision + 1,
            updatedAt: nowIso(clock),
        });
        const encrypted = await createEncryptedVault(nextVault, newMasterPassword, cryptoProvider);
        await extensionChrome.storage.local.set({ [STORAGE_KEYS.vault]: encrypted.record });
        return {
            vault: nextVault,
            key: encrypted.key,
            kdf: encrypted.kdf,
            record: encrypted.record,
        };
    });
}

export async function queuePendingEntry(
    input,
    {
        chromeApi = globalThis.chrome,
        clock = Date,
    } = {},
) {
    const extensionChrome = getChrome(chromeApi);
    const alarms = getAlarms(chromeApi);
    const name = requireString(input?.name ?? '', 'The entry name', 200).trim() || 'Generated password';
    const password = requireString(input?.password, 'The password', 4096, { allowEmpty: false });
    const createdAt = new clock().getTime();
    const pendingEntry = {
        name,
        password,
        createdAt,
        expiresAt: createdAt + PENDING_ENTRY_LIFETIME_MS,
    };
    await withPendingEntryLock(async () => {
        const stored = await extensionChrome.storage.session.get(STORAGE_KEYS.pendingEntry);
        const existingPendingEntry = normalizePendingEntry(
            stored[STORAGE_KEYS.pendingEntry],
            createdAt,
        );
        if (existingPendingEntry) {
            throw new VaultDataError(
                'A generated password is already waiting for the vault. Unlock and save it first.',
            );
        }

        await extensionChrome.storage.session.remove(STORAGE_KEYS.pendingEntry);
        await alarms.clear(PENDING_ENTRY_ALARM);
        await extensionChrome.storage.session.set({ [STORAGE_KEYS.pendingEntry]: pendingEntry });
        try {
            await alarms.create(PENDING_ENTRY_ALARM, { when: pendingEntry.expiresAt });
        } catch (error) {
            await extensionChrome.storage.session.remove(STORAGE_KEYS.pendingEntry);
            throw error;
        }
    });
}

function normalizePendingEntry(pendingEntry, currentTime) {
    if (
        pendingEntry === null
        || typeof pendingEntry !== 'object'
        || Array.isArray(pendingEntry)
        || !Number.isFinite(pendingEntry.createdAt)
        || !Number.isFinite(pendingEntry.expiresAt)
        || pendingEntry.expiresAt !== pendingEntry.createdAt + PENDING_ENTRY_LIFETIME_MS
        || currentTime >= pendingEntry.expiresAt
        || pendingEntry.createdAt - currentTime > 60_000
    ) {
        return null;
    }

    try {
        return {
            name: requireString(pendingEntry.name, 'The entry name', 200, { allowEmpty: false }),
            password: requireString(pendingEntry.password, 'The password', 4096, { allowEmpty: false }),
        };
    } catch {
        return null;
    }
}

export async function consumePendingEntry(
    consumer,
    {
        chromeApi = globalThis.chrome,
        clock = Date,
    } = {},
) {
    if (typeof consumer !== 'function') {
        throw new VaultDataError('A pending-entry consumer is required.');
    }

    const extensionChrome = getChrome(chromeApi);
    const alarms = getAlarms(chromeApi);

    return withPendingEntryLock(async () => {
        const stored = await extensionChrome.storage.session.get(STORAGE_KEYS.pendingEntry);
        const currentTime = new clock().getTime();
        const pendingEntry = normalizePendingEntry(
            stored[STORAGE_KEYS.pendingEntry],
            currentTime,
        );

        if (!pendingEntry) {
            await extensionChrome.storage.session.remove(STORAGE_KEYS.pendingEntry);
            await alarms.clear(PENDING_ENTRY_ALARM);
            return null;
        }

        const result = await consumer(pendingEntry);
        await extensionChrome.storage.session.remove(STORAGE_KEYS.pendingEntry);
        await alarms.clear(PENDING_ENTRY_ALARM);
        return result;
    });
}

export async function takePendingEntry(options = {}) {
    return consumePendingEntry(async (pendingEntry) => pendingEntry, options);
}

export async function clearExpiredPendingEntry(
    {
        chromeApi = globalThis.chrome,
        clock = Date,
    } = {},
) {
    const extensionChrome = getChrome(chromeApi);
    const alarms = getAlarms(chromeApi);

    return withPendingEntryLock(async () => {
        const stored = await extensionChrome.storage.session.get(STORAGE_KEYS.pendingEntry);
        const rawPendingEntry = stored[STORAGE_KEYS.pendingEntry];
        const currentTime = new clock().getTime();
        const pendingEntry = normalizePendingEntry(rawPendingEntry, currentTime);

        if (!pendingEntry) {
            await extensionChrome.storage.session.remove(STORAGE_KEYS.pendingEntry);
            await alarms.clear(PENDING_ENTRY_ALARM);
            return true;
        }

        // A previously dispatched alarm may race a newer handoff. Reschedule instead of
        // deleting when the current pending entry has not reached its own expiry time.
        await alarms.create(PENDING_ENTRY_ALARM, { when: rawPendingEntry.expiresAt });
        return false;
    });
}

export async function removeVault(chromeApi = globalThis.chrome) {
    const extensionChrome = getChrome(chromeApi);
    const alarms = getAlarms(chromeApi);
    // Keep the same pending -> vault lock order used by consumePendingEntry().
    await withPendingEntryLock(async () => {
        await withVaultWriteLock(async () => {
            await extensionChrome.storage.local.remove([
                STORAGE_KEYS.vault,
                STORAGE_KEYS.legacyPasswords,
                STORAGE_KEYS.legacyMasterPassword,
            ]);
            await extensionChrome.storage.session.remove(STORAGE_KEYS.pendingEntry);
            await alarms.clear(PENDING_ENTRY_ALARM);
        });
    });
}
