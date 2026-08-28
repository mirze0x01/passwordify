import {
    generatePassword,
    PasswordGeneratorError,
} from './generator.js';
import {
    hardenStorageAccess,
    queuePendingEntry,
} from './storage.js';

const generatorForm = document.getElementById('generator-form');
const lengthInput = document.getElementById('length');
const passwordOutput = document.getElementById('password-output');
const entryNameInput = document.getElementById('entry-name');
const copyButton = document.getElementById('copy-password');
const saveButton = document.getElementById('save-password');
const viewButton = document.getElementById('view-passwords');
const status = document.getElementById('popup-status');

function setStatus(message, tone = 'neutral') {
    status.textContent = message;
    status.dataset.tone = tone;
}

function selectedGeneratorOptions() {
    return {
        length: lengthInput.valueAsNumber,
        lowercase: document.getElementById('include-lowercase').checked,
        uppercase: document.getElementById('include-uppercase').checked,
        numbers: document.getElementById('include-numbers').checked,
        symbols: document.getElementById('include-special').checked,
        emoji: document.getElementById('include-emoji').checked,
    };
}

function generate() {
    try {
        passwordOutput.value = generatePassword(selectedGeneratorOptions());
        setStatus('A new password was generated with a cryptographic random source.', 'success');
    } catch (error) {
        passwordOutput.value = '';
        setStatus(
            error instanceof PasswordGeneratorError ? error.message : 'Password generation failed.',
            'error',
        );
    }
}

async function openVault() {
    await chrome.tabs.create({ url: chrome.runtime.getURL('passwords.html') });
}

generatorForm.addEventListener('submit', (event) => {
    event.preventDefault();
    generate();
});

copyButton.addEventListener('click', async () => {
    if (!passwordOutput.value) {
        setStatus('Generate a password before copying it.', 'error');
        return;
    }

    try {
        await navigator.clipboard.writeText(passwordOutput.value);
        setStatus('Copied. Your operating system or clipboard manager may retain it.', 'success');
    } catch {
        setStatus('The browser blocked clipboard access. Select and copy the password manually.', 'error');
        passwordOutput.select();
    }
});

saveButton.addEventListener('click', async () => {
    if (!passwordOutput.value) {
        setStatus('Generate a password before saving it.', 'error');
        return;
    }

    saveButton.disabled = true;
    try {
        await queuePendingEntry({
            name: entryNameInput.value,
            password: passwordOutput.value,
        });
        await openVault();
        passwordOutput.value = '';
        entryNameInput.value = '';
        setStatus('The password will be encrypted and saved automatically after you unlock the vault.', 'success');
    } catch {
        setStatus('Could not open the vault. The generated password is still shown above.', 'error');
    } finally {
        saveButton.disabled = false;
    }
});

viewButton.addEventListener('click', async () => {
    viewButton.disabled = true;
    try {
        await openVault();
    } catch {
        setStatus('Could not open the vault tab.', 'error');
    } finally {
        viewButton.disabled = false;
    }
});

async function initialize() {
    try {
        await hardenStorageAccess();
        generate();
    } catch {
        setStatus('Passwordify could not initialize secure local storage.', 'error');
        generatorForm.querySelectorAll('button, input').forEach((element) => {
            element.disabled = true;
        });
        copyButton.disabled = true;
        saveButton.disabled = true;
    }
}

initialize();
