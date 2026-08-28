import assert from 'node:assert/strict';
import test from 'node:test';

import {
    VaultUnlockError,
    base64ToBytes,
    bytesToBase64,
    createEncryptedVault,
    unlockEncryptedVault,
} from '../Passwordify/crypto.js';

const masterPassword = 'correct horse battery staple';
const sampleVault = {
    schemaVersion: 1,
    revision: 0,
    createdAt: '2026-08-28T00:00:00.000Z',
    updatedAt: '2026-08-28T00:00:00.000Z',
    entries: [{
        id: 'test-entry',
        name: 'Example',
        username: 'person@example.test',
        url: 'https://example.test',
        password: 'SENTINEL-SECRET-123!',
        notes: 'Private note',
        createdAt: '2026-08-28T00:00:00.000Z',
        updatedAt: '2026-08-28T00:00:00.000Z',
    }],
};

test('vault round-trips without putting plaintext in the stored record', async () => {
    const encrypted = await createEncryptedVault(sampleVault, masterPassword);
    const serialized = JSON.stringify(encrypted.record);
    assert.doesNotMatch(serialized, /SENTINEL-SECRET-123!/);
    assert.doesNotMatch(serialized, /correct horse battery staple/);
    assert.equal(encrypted.record.kdf.iterations, 600_000);
    assert.equal(encrypted.record.cipher.name, 'AES-GCM');

    const unlocked = await unlockEncryptedVault(encrypted.record, masterPassword);
    assert.deepEqual(unlocked.vault, sampleVault);
});

test('wrong passwords and ciphertext tampering fail authentication', async () => {
    const encrypted = await createEncryptedVault(sampleVault, masterPassword);
    await assert.rejects(
        unlockEncryptedVault(encrypted.record, 'this is the wrong password'),
        VaultUnlockError,
    );

    const ciphertext = base64ToBytes(encrypted.record.ciphertext);
    ciphertext[0] ^= 0x80;
    const tamperedRecord = {
        ...encrypted.record,
        ciphertext: bytesToBase64(ciphertext),
    };
    await assert.rejects(
        unlockEncryptedVault(tamperedRecord, masterPassword),
        VaultUnlockError,
    );
});

test('each encryption uses fresh salt and IV values', async () => {
    const first = await createEncryptedVault(sampleVault, masterPassword);
    const second = await createEncryptedVault(sampleVault, masterPassword);
    assert.notEqual(first.record.kdf.salt, second.record.kdf.salt);
    assert.notEqual(first.record.cipher.iv, second.record.cipher.iv);
    assert.notEqual(first.record.ciphertext, second.record.ciphertext);
});
