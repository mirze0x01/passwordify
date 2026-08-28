export const MIN_PASSWORD_LENGTH = 12;
export const MAX_PASSWORD_LENGTH = 128;
export const DEFAULT_PASSWORD_LENGTH = 20;
export const MIN_ESTIMATED_ENTROPY_BITS = 64;

export const CHARACTER_POOLS = Object.freeze({
    lowercase: Object.freeze(Array.from('abcdefghijklmnopqrstuvwxyz')),
    uppercase: Object.freeze(Array.from('ABCDEFGHIJKLMNOPQRSTUVWXYZ')),
    numbers: Object.freeze(Array.from('0123456789')),
    symbols: Object.freeze(Array.from('!@#$%^&*()-_=+[]{}|;:,.<>?')),
    emoji: Object.freeze(Array.from('😀😁😂🤣😃😄😅😆😉😊😎😍😘🥰😗😙😚')),
});

export class PasswordGeneratorError extends Error {
    constructor(message) {
        super(message);
        this.name = 'PasswordGeneratorError';
    }
}

function getCrypto(cryptoProvider) {
    if (!cryptoProvider || typeof cryptoProvider.getRandomValues !== 'function') {
        throw new PasswordGeneratorError('A cryptographically secure random source is unavailable.');
    }

    return cryptoProvider;
}

export function secureRandomIndex(maxExclusive, cryptoProvider = globalThis.crypto) {
    if (!Number.isSafeInteger(maxExclusive) || maxExclusive < 1 || maxExclusive > 0x100000000) {
        throw new PasswordGeneratorError('The character pool size is invalid.');
    }

    const secureCrypto = getCrypto(cryptoProvider);
    const range = 0x100000000;
    const unbiasedLimit = Math.floor(range / maxExclusive) * maxExclusive;
    const randomValue = new Uint32Array(1);

    do {
        secureCrypto.getRandomValues(randomValue);
    } while (randomValue[0] >= unbiasedLimit);

    return randomValue[0] % maxExclusive;
}

export function secureShuffle(values, cryptoProvider = globalThis.crypto) {
    const shuffled = [...values];

    for (let index = shuffled.length - 1; index > 0; index -= 1) {
        const swapIndex = secureRandomIndex(index + 1, cryptoProvider);
        [shuffled[index], shuffled[swapIndex]] = [shuffled[swapIndex], shuffled[index]];
    }

    return shuffled;
}

export function estimatePasswordEntropy(selectedPools, length) {
    if (!Array.isArray(selectedPools) || selectedPools.length === 0 || !Number.isSafeInteger(length)) {
        return 0;
    }

    const combinedPoolSize = selectedPools.reduce((total, pool) => total + pool.length, 0);
    const guaranteedCharactersEntropy = selectedPools.reduce(
        (total, pool) => total + Math.log2(pool.length),
        0,
    );
    const remainingCharactersEntropy = Math.max(0, length - selectedPools.length)
        * Math.log2(combinedPoolSize);

    // This deliberately ignores the extra entropy introduced by the secure shuffle.
    return guaranteedCharactersEntropy + remainingCharactersEntropy;
}

export function generatePassword(options, cryptoProvider = globalThis.crypto) {
    const {
        length = DEFAULT_PASSWORD_LENGTH,
        lowercase = true,
        uppercase = true,
        numbers = true,
        symbols = true,
        emoji = false,
    } = options ?? {};

    if (!Number.isSafeInteger(length) || length < MIN_PASSWORD_LENGTH || length > MAX_PASSWORD_LENGTH) {
        throw new PasswordGeneratorError(
            `Password length must be a whole number between ${MIN_PASSWORD_LENGTH} and ${MAX_PASSWORD_LENGTH}.`,
        );
    }

    const selectedPools = [
        lowercase && CHARACTER_POOLS.lowercase,
        uppercase && CHARACTER_POOLS.uppercase,
        numbers && CHARACTER_POOLS.numbers,
        symbols && CHARACTER_POOLS.symbols,
        emoji && CHARACTER_POOLS.emoji,
    ].filter(Boolean);

    if (selectedPools.length === 0) {
        throw new PasswordGeneratorError('Select at least one character type.');
    }

    if (selectedPools.length > length) {
        throw new PasswordGeneratorError('The password is too short for the selected character types.');
    }

    const estimatedEntropy = estimatePasswordEntropy(selectedPools, length);
    if (estimatedEntropy < MIN_ESTIMATED_ENTROPY_BITS) {
        throw new PasswordGeneratorError(
            `These settings provide about ${Math.floor(estimatedEntropy)} bits of entropy. `
            + `Increase the length or add character types to reach at least ${MIN_ESTIMATED_ENTROPY_BITS} bits.`,
        );
    }

    const combinedPool = selectedPools.flat();
    const passwordCharacters = selectedPools.map(
        (pool) => pool[secureRandomIndex(pool.length, cryptoProvider)],
    );

    while (passwordCharacters.length < length) {
        passwordCharacters.push(combinedPool[secureRandomIndex(combinedPool.length, cryptoProvider)]);
    }

    return secureShuffle(passwordCharacters, cryptoProvider).join('');
}
