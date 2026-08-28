import assert from 'node:assert/strict';
import test from 'node:test';

import { VaultUnlockError } from '../Passwordify/crypto.js';
import {
    ConcurrentVaultUpdateError,
    PENDING_ENTRY_ALARM,
    STORAGE_KEYS,
    VaultDataError,
    changeMasterPassword,
    clearExpiredPendingEntry,
    createVaultEntry,
    hardenStorageAccess,
    queuePendingEntry,
    removeVault,
    saveVault,
    setupVault,
    takePendingEntry,
    unlockStoredVault,
} from '../Passwordify/storage.js';

class MemoryStorageArea {
    constructor(initialData = {}) {
        this.data = structuredClone(initialData);
        this.accessLevel = null;
    }

    async get(keys) {
        if (keys === null || keys === undefined) {
            return structuredClone(this.data);
        }

        const requestedKeys = typeof keys === 'string' ? [keys] : keys;
        const result = {};
        for (const key of requestedKeys) {
            if (Object.hasOwn(this.data, key)) {
                result[key] = structuredClone(this.data[key]);
            }
        }
        return result;
    }

    async set(items) {
        Object.assign(this.data, structuredClone(items));
    }

    async remove(keys) {
        const requestedKeys = Array.isArray(keys) ? keys : [keys];
        for (const key of requestedKeys) {
            delete this.data[key];
        }
    }

    async setAccessLevel({ accessLevel }) {
        this.accessLevel = accessLevel;
    }
}

class MemoryAlarms {
    constructor() {
        this.data = new Map();
    }

    async create(name, alarmInfo) {
        this.data.set(name, structuredClone(alarmInfo));
    }

    async clear(name) {
        return this.data.delete(name);
    }
}

function createFakeChrome(initialLocalData = {}) {
    return {
        storage: {
            local: new MemoryStorageArea(initialLocalData),
            session: new MemoryStorageArea(),
        },
        alarms: new MemoryAlarms(),
    };
}

test('setup migrates plaintext legacy entries into ciphertext and removes legacy keys', async () => {
    const sentinel = 'MIGRATION-SENTINEL-SECRET!';
    const masterPassword = 'a unique local master passphrase';
    const newMasterPassword = 'a different replacement passphrase';
    const chromeApi = createFakeChrome({
        [STORAGE_KEYS.legacyMasterPassword]: 'old-plaintext-value',
        [STORAGE_KEYS.legacyPasswords]: [{ name: 'Legacy account', password: sentinel }],
    });

    await hardenStorageAccess(chromeApi);
    assert.equal(chromeApi.storage.local.accessLevel, 'TRUSTED_CONTEXTS');
    assert.equal(chromeApi.storage.session.accessLevel, 'TRUSTED_CONTEXTS');

    const firstSession = await setupVault(masterPassword, { chromeApi });
    assert.equal(firstSession.migratedCount, 1);
    const serializedStorage = JSON.stringify(chromeApi.storage.local.data);
    assert.doesNotMatch(serializedStorage, new RegExp(sentinel));
    assert.doesNotMatch(serializedStorage, /old-plaintext-value/);
    assert.equal(chromeApi.storage.local.data[STORAGE_KEYS.legacyPasswords], undefined);
    assert.equal(chromeApi.storage.local.data[STORAGE_KEYS.legacyMasterPassword], undefined);

    const staleSession = await unlockStoredVault(masterPassword, { chromeApi });
    assert.equal(staleSession.vault.entries[0].password, sentinel);

    const addedEntry = createVaultEntry({
        name: 'New account',
        password: 'ANOTHER-SENTINEL-SECRET!',
    });
    const saved = await saveVault({
        ...firstSession.vault,
        entries: [...firstSession.vault.entries, addedEntry],
    }, firstSession.key, firstSession.kdf, { chromeApi });
    assert.equal(saved.vault.revision, 1);
    assert.doesNotMatch(JSON.stringify(chromeApi.storage.local.data), /ANOTHER-SENTINEL-SECRET!/);

    await assert.rejects(
        saveVault(staleSession.vault, staleSession.key, staleSession.kdf, { chromeApi }),
        ConcurrentVaultUpdateError,
    );

    await assert.rejects(
        changeMasterPassword(
            saved.vault,
            'an incorrect current master password',
            newMasterPassword,
            { chromeApi },
        ),
        VaultUnlockError,
    );

    const changed = await changeMasterPassword(
        saved.vault,
        masterPassword,
        newMasterPassword,
        { chromeApi },
    );
    assert.equal(changed.vault.revision, 2);
    await assert.rejects(
        unlockStoredVault(masterPassword, { chromeApi }),
        VaultUnlockError,
    );
    const unlockedWithNewPassword = await unlockStoredVault(newMasterPassword, { chromeApi });
    assert.equal(unlockedWithNewPassword.vault.entries.length, 2);

    await removeVault(chromeApi);
    assert.deepEqual(chromeApi.storage.local.data, {});
});

test('setup preserves malformed legacy storage for explicit manual recovery', async () => {
    const malformedLegacyValue = { unexpected: 'LEGACY-RECOVERY-SENTINEL' };
    const chromeApi = createFakeChrome({
        [STORAGE_KEYS.legacyPasswords]: malformedLegacyValue,
    });

    const session = await setupVault('another unique master passphrase', { chromeApi });
    assert.equal(session.migratedCount, 0);
    assert.equal(session.invalidLegacyCount, 1);
    assert.deepEqual(
        chromeApi.storage.local.data[STORAGE_KEYS.legacyPasswords],
        malformedLegacyValue,
    );
    assert.ok(chromeApi.storage.local.data[STORAGE_KEYS.vault]);
});

test('pending generated entries are session-only, single-use, and time-limited', async () => {
    const chromeApi = createFakeChrome();
    const initialTime = 1_788_000_000_000;
    class InitialClock extends Date {
        constructor() {
            super(initialTime);
        }
    }
    class LaterClock extends Date {
        constructor() {
            super(initialTime + (11 * 60 * 1000));
        }
    }
    class ReplacementClock extends Date {
        constructor() {
            super(initialTime + (10 * 60 * 1000) + 1_000);
        }
    }
    class OldAlarmClock extends Date {
        constructor() {
            super(initialTime + (10 * 60 * 1000) + 2_000);
        }
    }
    class ReplacementExpiryClock extends Date {
        constructor() {
            super(initialTime + (21 * 60 * 1000));
        }
    }

    await queuePendingEntry({ name: 'Example', password: 'SESSION-SECRET' }, {
        chromeApi,
        clock: InitialClock,
    });
    assert.doesNotMatch(JSON.stringify(chromeApi.storage.local.data), /SESSION-SECRET/);
    assert.match(JSON.stringify(chromeApi.storage.session.data), /SESSION-SECRET/);
    assert.equal(chromeApi.alarms.data.has(PENDING_ENTRY_ALARM), true);
    await assert.rejects(
        queuePendingEntry({ name: 'Second', password: 'MUST-NOT-OVERWRITE' }, {
            chromeApi,
            clock: InitialClock,
        }),
        VaultDataError,
    );
    assert.doesNotMatch(JSON.stringify(chromeApi.storage.session.data), /MUST-NOT-OVERWRITE/);

    const pending = await takePendingEntry({ chromeApi, clock: InitialClock });
    assert.deepEqual(pending, { name: 'Example', password: 'SESSION-SECRET' });
    assert.deepEqual(chromeApi.storage.session.data, {});
    assert.equal(chromeApi.alarms.data.has(PENDING_ENTRY_ALARM), false);

    await queuePendingEntry({ name: 'Expired', password: 'OLD-SECRET' }, {
        chromeApi,
        clock: InitialClock,
    });
    assert.equal(await takePendingEntry({ chromeApi, clock: LaterClock }), null);
    assert.deepEqual(chromeApi.storage.session.data, {});

    await queuePendingEntry({ name: 'Original', password: 'ORIGINAL-SECRET' }, {
        chromeApi,
        clock: InitialClock,
    });
    await queuePendingEntry({ name: 'Replacement', password: 'REPLACEMENT-SECRET' }, {
        chromeApi,
        clock: ReplacementClock,
    });
    assert.equal(await clearExpiredPendingEntry({ chromeApi, clock: OldAlarmClock }), false);
    assert.match(JSON.stringify(chromeApi.storage.session.data), /REPLACEMENT-SECRET/);
    assert.equal(
        chromeApi.alarms.data.get(PENDING_ENTRY_ALARM).when,
        initialTime + (20 * 60 * 1000) + 1_000,
    );
    assert.equal(
        await clearExpiredPendingEntry({ chromeApi, clock: ReplacementExpiryClock }),
        true,
    );
    assert.deepEqual(chromeApi.storage.session.data, {});
});
