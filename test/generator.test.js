import assert from 'node:assert/strict';
import test from 'node:test';

import {
    CHARACTER_POOLS,
    PasswordGeneratorError,
    generatePassword,
    secureRandomIndex,
} from '../Passwordify/generator.js';

test('generatePassword returns the requested length and every selected class', () => {
    for (let iteration = 0; iteration < 100; iteration += 1) {
        const password = generatePassword({ length: 32 });
        assert.equal(Array.from(password).length, 32);
        assert.match(password, /[a-z]/);
        assert.match(password, /[A-Z]/);
        assert.match(password, /[0-9]/);
        assert.match(password, /[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]/);
    }
});

test('emoji generation preserves complete Unicode code points', () => {
    const password = generatePassword({
        length: 24,
        lowercase: false,
        uppercase: false,
        numbers: false,
        symbols: false,
        emoji: true,
    });

    const characters = Array.from(password);
    assert.equal(characters.length, 24);
    assert.ok(characters.every((character) => CHARACTER_POOLS.emoji.includes(character)));
    assert.doesNotMatch(password, /\uFFFD/);
});

test('generator rejects unsafe lengths and empty character selections', () => {
    assert.throws(() => generatePassword({ length: 11 }), PasswordGeneratorError);
    assert.throws(() => generatePassword({ length: 129 }), PasswordGeneratorError);
    assert.throws(() => generatePassword({
        length: 20,
        lowercase: false,
        uppercase: false,
        numbers: false,
        symbols: false,
        emoji: false,
    }), PasswordGeneratorError);
});

test('generator rejects low-entropy settings even when length is syntactically valid', () => {
    assert.throws(() => generatePassword({
        length: 12,
        lowercase: false,
        uppercase: false,
        numbers: true,
        symbols: false,
        emoji: false,
    }), /less|entropy|bits/i);

    const numericPassword = generatePassword({
        length: 20,
        lowercase: false,
        uppercase: false,
        numbers: true,
        symbols: false,
        emoji: false,
    });
    assert.match(numericPassword, /^\d{20}$/);
});

test('secureRandomIndex rejects out-of-range samples instead of adding modulo bias', () => {
    const values = [0xffffffff, 7];
    const cryptoProvider = {
        getRandomValues(target) {
            target[0] = values.shift();
            return target;
        },
    };

    assert.equal(secureRandomIndex(10, cryptoProvider), 7);
    assert.equal(values.length, 0);
});
