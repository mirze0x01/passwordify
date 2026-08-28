const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8', { fatal: true });

export const VAULT_FORMAT_VERSION = 1;
export const PBKDF2_ITERATIONS = 600_000;
export const MAX_ENCODED_VAULT_BYTES = 5 * 1024 * 1024;

export class VaultFormatError extends Error {
    constructor(message) {
        super(message);
        this.name = 'VaultFormatError';
    }
}

export class VaultUnlockError extends Error {
    constructor(message = 'The master password is incorrect or the vault is damaged.') {
        super(message);
        this.name = 'VaultUnlockError';
    }
}

function getCrypto(cryptoProvider) {
    if (
        !cryptoProvider
        || typeof cryptoProvider.getRandomValues !== 'function'
        || !cryptoProvider.subtle
    ) {
        throw new VaultFormatError('The Web Crypto API is unavailable.');
    }

    return cryptoProvider;
}

function isPlainObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function randomBytes(length, cryptoProvider) {
    const bytes = new Uint8Array(length);
    getCrypto(cryptoProvider).getRandomValues(bytes);
    return bytes;
}

export function bytesToBase64(bytes) {
    if (!(bytes instanceof Uint8Array)) {
        throw new TypeError('Expected a Uint8Array.');
    }

    let binary = '';
    const chunkSize = 0x8000;

    for (let offset = 0; offset < bytes.length; offset += chunkSize) {
        binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
    }

    return btoa(binary);
}

export function base64ToBytes(value, fieldName = 'value') {
    if (
        typeof value !== 'string'
        || value.length === 0
        || value.length > Math.ceil((MAX_ENCODED_VAULT_BYTES * 4) / 3) + 8
        || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
    ) {
        throw new VaultFormatError(`${fieldName} is not valid base64.`);
    }

    try {
        const binary = atob(value);
        return Uint8Array.from(binary, (character) => character.charCodeAt(0));
    } catch {
        throw new VaultFormatError(`${fieldName} is not valid base64.`);
    }
}

function normalizeKdf(kdf) {
    if (!isPlainObject(kdf)) {
        throw new VaultFormatError('The vault key-derivation settings are missing.');
    }

    if (kdf.name !== 'PBKDF2' || kdf.hash !== 'SHA-256') {
        throw new VaultFormatError('The vault uses an unsupported key-derivation algorithm.');
    }

    if (
        !Number.isSafeInteger(kdf.iterations)
        || kdf.iterations < PBKDF2_ITERATIONS
        || kdf.iterations > 10_000_000
    ) {
        throw new VaultFormatError('The vault key-derivation work factor is invalid.');
    }

    const salt = base64ToBytes(kdf.salt, 'The vault salt');
    if (salt.length !== 16) {
        throw new VaultFormatError('The vault salt must be 16 bytes.');
    }

    return {
        name: 'PBKDF2',
        hash: 'SHA-256',
        iterations: kdf.iterations,
        salt: kdf.salt,
    };
}

export function normalizeVaultRecord(record) {
    if (!isPlainObject(record) || record.formatVersion !== VAULT_FORMAT_VERSION) {
        throw new VaultFormatError('The vault format is missing or unsupported.');
    }

    const kdf = normalizeKdf(record.kdf);

    if (!isPlainObject(record.cipher) || record.cipher.name !== 'AES-GCM') {
        throw new VaultFormatError('The vault uses an unsupported cipher.');
    }

    const iv = base64ToBytes(record.cipher.iv, 'The vault IV');
    if (iv.length !== 12) {
        throw new VaultFormatError('The vault IV must be 12 bytes.');
    }

    const ciphertext = base64ToBytes(record.ciphertext, 'The vault ciphertext');
    if (ciphertext.length < 16 || ciphertext.length > MAX_ENCODED_VAULT_BYTES) {
        throw new VaultFormatError('The vault ciphertext size is invalid.');
    }

    return {
        formatVersion: VAULT_FORMAT_VERSION,
        kdf,
        cipher: {
            name: 'AES-GCM',
            iv: record.cipher.iv,
        },
        ciphertext: record.ciphertext,
    };
}

function makeAdditionalData(kdf) {
    return textEncoder.encode(JSON.stringify([
        'passwordify-vault',
        VAULT_FORMAT_VERSION,
        kdf.name,
        kdf.hash,
        kdf.iterations,
        kdf.salt,
        'AES-GCM',
    ]));
}

export function createKdfConfig(cryptoProvider = globalThis.crypto) {
    return {
        name: 'PBKDF2',
        hash: 'SHA-256',
        iterations: PBKDF2_ITERATIONS,
        salt: bytesToBase64(randomBytes(16, cryptoProvider)),
    };
}

export async function deriveVaultKey(masterPassword, kdf, cryptoProvider = globalThis.crypto) {
    if (typeof masterPassword !== 'string' || masterPassword.length === 0) {
        throw new VaultUnlockError();
    }

    const encodedPassword = textEncoder.encode(masterPassword);
    if (encodedPassword.length > 4096) {
        throw new VaultUnlockError('The master password is too long.');
    }

    const normalizedKdf = normalizeKdf(kdf);
    const secureCrypto = getCrypto(cryptoProvider);
    const keyMaterial = await secureCrypto.subtle.importKey(
        'raw',
        encodedPassword,
        'PBKDF2',
        false,
        ['deriveKey'],
    );

    return secureCrypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            hash: normalizedKdf.hash,
            iterations: normalizedKdf.iterations,
            salt: base64ToBytes(normalizedKdf.salt, 'The vault salt'),
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt'],
    );
}

export async function encryptVaultWithKey(
    vault,
    key,
    kdf,
    cryptoProvider = globalThis.crypto,
) {
    const normalizedKdf = normalizeKdf(kdf);
    const plaintext = textEncoder.encode(JSON.stringify(vault));
    if (plaintext.length === 0 || plaintext.length > MAX_ENCODED_VAULT_BYTES - 16) {
        throw new VaultFormatError('The vault is too large to store safely.');
    }

    const secureCrypto = getCrypto(cryptoProvider);
    const iv = randomBytes(12, secureCrypto);
    const ciphertext = await secureCrypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv,
            additionalData: makeAdditionalData(normalizedKdf),
            tagLength: 128,
        },
        key,
        plaintext,
    );

    return {
        formatVersion: VAULT_FORMAT_VERSION,
        kdf: normalizedKdf,
        cipher: {
            name: 'AES-GCM',
            iv: bytesToBase64(iv),
        },
        ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
    };
}

export async function decryptVaultWithKey(record, key, cryptoProvider = globalThis.crypto) {
    const normalizedRecord = normalizeVaultRecord(record);
    const secureCrypto = getCrypto(cryptoProvider);

    try {
        const plaintext = await secureCrypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: base64ToBytes(normalizedRecord.cipher.iv, 'The vault IV'),
                additionalData: makeAdditionalData(normalizedRecord.kdf),
                tagLength: 128,
            },
            key,
            base64ToBytes(normalizedRecord.ciphertext, 'The vault ciphertext'),
        );

        return JSON.parse(textDecoder.decode(plaintext));
    } catch (error) {
        if (error instanceof VaultFormatError) {
            throw error;
        }

        throw new VaultUnlockError();
    }
}

export async function createEncryptedVault(
    vault,
    masterPassword,
    cryptoProvider = globalThis.crypto,
) {
    const kdf = createKdfConfig(cryptoProvider);
    const key = await deriveVaultKey(masterPassword, kdf, cryptoProvider);
    const record = await encryptVaultWithKey(vault, key, kdf, cryptoProvider);
    return { record, key, kdf };
}

export async function unlockEncryptedVault(
    record,
    masterPassword,
    cryptoProvider = globalThis.crypto,
) {
    const normalizedRecord = normalizeVaultRecord(record);
    const key = await deriveVaultKey(masterPassword, normalizedRecord.kdf, cryptoProvider);
    const vault = await decryptVaultWithKey(normalizedRecord, key, cryptoProvider);
    return { vault, key, kdf: normalizedRecord.kdf };
}
