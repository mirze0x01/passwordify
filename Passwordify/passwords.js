import {
    PasswordGeneratorError,
    generatePassword,
} from './generator.js';
import {
    VaultFormatError,
    VaultUnlockError,
} from './crypto.js';
import {
    ConcurrentVaultUpdateError,
    IDLE_LOCK_TIMEOUT_MS,
    VaultDataError,
    changeMasterPassword,
    createVaultEntry,
    getVaultState,
    hardenStorageAccess,
    removeVault,
    saveVault,
    setupVault,
    consumePendingEntry,
    STORAGE_KEYS,
    unlockStoredVault,
} from './storage.js';

const elements = {
    status: document.getElementById('vault-status'),
    loadingPanel: document.getElementById('loading-panel'),
    setupPanel: document.getElementById('setup-panel'),
    setupForm: document.getElementById('setup-form'),
    setupMaster: document.getElementById('setup-master'),
    setupConfirm: document.getElementById('setup-confirm'),
    legacyNotice: document.getElementById('legacy-notice'),
    unlockPanel: document.getElementById('unlock-panel'),
    unlockForm: document.getElementById('unlock-form'),
    unlockMaster: document.getElementById('unlock-master'),
    resetVaultLocked: document.getElementById('reset-vault-locked'),
    vaultPanel: document.getElementById('vault-panel'),
    headerLock: document.getElementById('header-lock'),
    search: document.getElementById('search-entries'),
    addEntry: document.getElementById('add-entry'),
    entryEditor: document.getElementById('entry-editor'),
    editorTitle: document.getElementById('editor-title'),
    entryForm: document.getElementById('entry-form'),
    entryId: document.getElementById('entry-id'),
    entryName: document.getElementById('entry-name'),
    entryUsername: document.getElementById('entry-username'),
    entryUrl: document.getElementById('entry-url'),
    entryPassword: document.getElementById('entry-password'),
    entryNotes: document.getElementById('entry-notes'),
    cancelEntry: document.getElementById('cancel-entry'),
    toggleEntryPassword: document.getElementById('toggle-entry-password'),
    generateEntryPassword: document.getElementById('generate-entry-password'),
    emptyState: document.getElementById('empty-state'),
    entryList: document.getElementById('entry-list'),
    deleteEntryDialog: document.getElementById('delete-entry-dialog'),
    deleteEntryName: document.getElementById('delete-entry-name'),
    cancelDeleteEntry: document.getElementById('cancel-delete-entry'),
    confirmDeleteEntry: document.getElementById('confirm-delete-entry'),
    changeMaster: document.getElementById('change-master'),
    changeMasterDialog: document.getElementById('change-master-dialog'),
    changeMasterForm: document.getElementById('change-master-form'),
    currentMaster: document.getElementById('current-master'),
    newMaster: document.getElementById('new-master'),
    confirmNewMaster: document.getElementById('confirm-new-master'),
    cancelChangeMaster: document.getElementById('cancel-change-master'),
    deleteVault: document.getElementById('delete-vault'),
    deleteVaultDialog: document.getElementById('delete-vault-dialog'),
    deleteVaultForm: document.getElementById('delete-vault-form'),
    deleteVaultConfirmation: document.getElementById('delete-vault-confirmation'),
    cancelDeleteVault: document.getElementById('cancel-delete-vault'),
};

const appState = {
    session: null,
    vaultGeneration: 0,
    idleTimer: null,
    authInputTimer: null,
    deleteEntryId: null,
    revealTimers: new Map(),
};

const pageInstanceId = globalThis.crypto.randomUUID();
const vaultChannel = typeof BroadcastChannel === 'function'
    ? new BroadcastChannel('passwordify-vault-state')
    : null;

function setStatus(message, tone = 'neutral') {
    elements.status.textContent = message;
    elements.status.dataset.tone = tone;
}

function friendlyError(error, fallback = 'The operation failed without changing the vault.') {
    if (error instanceof VaultUnlockError) {
        return error.message;
    }

    if (error instanceof VaultFormatError) {
        return 'The stored vault is damaged or uses an unsupported format.';
    }

    if (
        error instanceof VaultDataError
        || error instanceof ConcurrentVaultUpdateError
        || error instanceof PasswordGeneratorError
    ) {
        return error.message;
    }

    return fallback;
}

function setFormBusy(form, busy) {
    form.querySelectorAll('button[type="submit"]').forEach((button) => {
        button.disabled = busy;
    });
}

function hideAllPanels() {
    elements.loadingPanel.hidden = true;
    elements.setupPanel.hidden = true;
    elements.unlockPanel.hidden = true;
    elements.vaultPanel.hidden = true;
}

function showSetup(vaultState) {
    hideAllPanels();
    elements.setupPanel.hidden = false;
    elements.headerLock.hidden = true;

    if (vaultState.legacyPasswordCount > 0 || vaultState.hasLegacyMasterPassword) {
        const entrySummary = vaultState.legacyPasswordCount === 1
            ? '1 legacy plaintext entry'
            : `${vaultState.legacyPasswordCount} legacy plaintext entries`;
        elements.legacyNotice.textContent =
            `Found ${entrySummary}. Creating the vault will encrypt valid entries and remove the old `
            + 'plaintext master-password value. Invalid legacy records are preserved for manual recovery.';
        elements.legacyNotice.hidden = false;
    } else {
        elements.legacyNotice.hidden = true;
        elements.legacyNotice.textContent = '';
    }

    if (!document.hidden) {
        elements.setupMaster.focus();
    }
}

function showUnlock() {
    hideAllPanels();
    elements.unlockPanel.hidden = false;
    elements.headerLock.hidden = true;
    if (!document.hidden) {
        elements.unlockMaster.focus();
    }
}

function clearRevealTimers() {
    for (const timer of appState.revealTimers.values()) {
        clearTimeout(timer);
    }
    appState.revealTimers.clear();
}

function closeDialog(dialog) {
    if (dialog.open) {
        dialog.close();
    }
}

function clearSensitiveUi() {
    clearTimeout(appState.authInputTimer);
    appState.authInputTimer = null;
    elements.setupForm.reset();
    elements.unlockForm.reset();
    elements.entryForm.reset();
    elements.changeMasterForm.reset();
    elements.entryPassword.type = 'password';
    elements.toggleEntryPassword.textContent = 'Show';
    elements.entryList.replaceChildren();
    elements.entryEditor.hidden = true;
    elements.search.value = '';
    elements.deleteEntryName.textContent = '';
    elements.deleteVaultForm.reset();
    closeDialog(elements.deleteEntryDialog);
    closeDialog(elements.changeMasterDialog);
    closeDialog(elements.deleteVaultDialog);
    clearRevealTimers();
}

function resetAuthInputTimer() {
    clearTimeout(appState.authInputTimer);
    appState.authInputTimer = setTimeout(() => {
        elements.setupForm.reset();
        elements.unlockForm.reset();
        setStatus('Master-password fields were cleared after five minutes of inactivity.', 'neutral');
    }, IDLE_LOCK_TIMEOUT_MS);
}

function clearLockedInputs(message) {
    clearTimeout(appState.authInputTimer);
    appState.authInputTimer = null;
    elements.setupForm.reset();
    elements.unlockForm.reset();
    if (message) {
        setStatus(message, 'neutral');
    }
}

function broadcastVaultChange(reason) {
    vaultChannel?.postMessage({
        type: 'vault-changed',
        source: pageInstanceId,
        reason,
    });
}

function resetIdleTimer() {
    clearTimeout(appState.idleTimer);
    if (!appState.session) {
        appState.idleTimer = null;
        return;
    }

    appState.idleTimer = setTimeout(() => {
        lockVault('Vault locked after five minutes of inactivity.');
    }, IDLE_LOCK_TIMEOUT_MS);
}

function lockVault(message = 'Vault locked.') {
    appState.session = null;
    appState.deleteEntryId = null;
    clearTimeout(appState.idleTimer);
    appState.idleTimer = null;
    clearSensitiveUi();
    showUnlock();
    setStatus(message, 'neutral');
}

function registerActivity() {
    if (appState.session) {
        resetIdleTimer();
    }
}

function createButton(
    label,
    action,
    entryId,
    className = 'text-button',
    accessibleName = label,
) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = className;
    button.textContent = label;
    button.dataset.action = action;
    button.dataset.entryId = entryId;
    button.setAttribute('aria-label', accessibleName);
    return button;
}

function renderEntries() {
    elements.entryList.replaceChildren();
    if (!appState.session) {
        elements.emptyState.hidden = false;
        return;
    }

    const searchText = elements.search.value.trim().toLocaleLowerCase();
    const entries = [...appState.session.vault.entries]
        .filter((entry) => [entry.name, entry.username, entry.url]
            .some((value) => value.toLocaleLowerCase().includes(searchText)))
        .sort((left, right) => left.name.localeCompare(right.name));

    elements.emptyState.textContent = searchText
        ? 'No entries match this search.'
        : 'No entries yet. Add one to begin.';
    elements.emptyState.hidden = entries.length > 0;

    const fragment = document.createDocumentFragment();
    for (const entry of entries) {
        const item = document.createElement('li');
        item.className = 'credential-card';
        item.dataset.entryId = entry.id;

        const headingRow = document.createElement('div');
        headingRow.className = 'credential-heading';
        const titleGroup = document.createElement('div');
        const title = document.createElement('h3');
        title.textContent = entry.name;
        titleGroup.appendChild(title);

        const metadata = [entry.username, entry.url].filter(Boolean);
        if (metadata.length > 0) {
            const summary = document.createElement('p');
            summary.className = 'credential-metadata';
            summary.textContent = metadata.join(' · ');
            titleGroup.appendChild(summary);
        }

        const headingActions = document.createElement('div');
        headingActions.className = 'credential-actions';
        headingActions.append(
            createButton('Edit', 'edit', entry.id, 'text-button', `Edit ${entry.name}`),
            createButton(
                'Delete',
                'delete',
                entry.id,
                'text-button danger-text',
                `Delete ${entry.name}`,
            ),
        );
        headingRow.append(titleGroup, headingActions);

        const passwordRow = document.createElement('div');
        passwordRow.className = 'masked-password-row';
        const passwordDisplay = document.createElement('code');
        passwordDisplay.textContent = '••••••••••••';
        passwordDisplay.dataset.passwordDisplay = 'true';
        const revealButton = createButton(
            'Reveal',
            'reveal',
            entry.id,
            'secondary-button small-button',
            `Reveal password for ${entry.name}`,
        );
        revealButton.setAttribute('aria-pressed', 'false');
        const copyButton = createButton(
            'Copy',
            'copy',
            entry.id,
            'secondary-button small-button',
            `Copy password for ${entry.name}`,
        );
        passwordRow.append(passwordDisplay, revealButton, copyButton);

        item.append(headingRow, passwordRow);
        if (entry.notes) {
            const notes = document.createElement('p');
            notes.className = 'credential-notes';
            notes.textContent = entry.notes;
            item.appendChild(notes);
        }

        fragment.appendChild(item);
    }

    elements.entryList.appendChild(fragment);
}

function findEntry(entryId) {
    return appState.session?.vault.entries.find((entry) => entry.id === entryId) ?? null;
}

function closeEntryEditor() {
    elements.entryForm.reset();
    elements.entryId.value = '';
    elements.entryPassword.type = 'password';
    elements.toggleEntryPassword.textContent = 'Show';
    elements.entryEditor.hidden = true;
}

function openEntryEditor(entry = null) {
    if (!appState.session) {
        return;
    }

    elements.entryForm.reset();
    elements.entryId.value = entry?.id ?? '';
    elements.entryName.value = entry?.name ?? '';
    elements.entryUsername.value = entry?.username ?? '';
    elements.entryUrl.value = entry?.url ?? '';
    elements.entryPassword.value = entry?.password ?? '';
    elements.entryNotes.value = entry?.notes ?? '';
    elements.entryPassword.type = 'password';
    elements.toggleEntryPassword.textContent = 'Show';
    elements.editorTitle.textContent = entry ? 'Edit entry' : 'Add entry';
    elements.entryEditor.hidden = false;
    elements.entryName.focus();
    elements.entryEditor.scrollIntoView({ behavior: 'smooth', block: 'start' });
    resetIdleTimer();
}

async function openVaultSession(session, message) {
    clearTimeout(appState.authInputTimer);
    appState.authInputTimer = null;
    appState.session = session;
    hideAllPanels();
    elements.loadingPanel.querySelector('h2').textContent = 'Opening encrypted vault';
    elements.loadingPanel.querySelector('p').textContent = 'Finishing any secure password handoff.';
    elements.loadingPanel.hidden = false;
    elements.headerLock.hidden = true;
    resetIdleTimer();
    setStatus(message, 'success');

    if (document.hidden) {
        lockVault('Vault locked because the tab is hidden.');
        return;
    }

    try {
        await consumePendingEntry(async (pendingEntry) => {
            if (appState.session !== session) {
                throw new VaultDataError('The vault locked before the pending password could be saved.');
            }

            const entry = createVaultEntry(pendingEntry);
            await persistDraftVault({
                ...session.vault,
                entries: [...session.vault.entries, entry],
            }, 'Generated password saved in the encrypted vault.');
            return entry.id;
        });
    } catch (error) {
        if (error instanceof ConcurrentVaultUpdateError) {
            lockVault(friendlyError(error));
        } else {
            setStatus(
                'Vault unlocked, but the pending password could not be saved. It remains in temporary session storage.',
                'error',
            );
        }
    }

    if (!appState.session) {
        return;
    }

    elements.loadingPanel.hidden = true;
    elements.vaultPanel.hidden = false;
    elements.headerLock.hidden = false;
    renderEntries();
    resetIdleTimer();
}

async function persistDraftVault(draftVault, successMessage) {
    const sessionAtStart = appState.session;
    if (!sessionAtStart) {
        throw new VaultDataError('Unlock the vault before changing it.');
    }

    const saved = await saveVault(draftVault, sessionAtStart.key, sessionAtStart.kdf);
    broadcastVaultChange('updated');
    if (appState.session === sessionAtStart) {
        appState.session.vault = saved.vault;
        renderEntries();
        resetIdleTimer();
        setStatus(successMessage, 'success');
    }
}

elements.setupForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (elements.setupMaster.value !== elements.setupConfirm.value) {
        setStatus('The master-password confirmation does not match.', 'error');
        return;
    }

    setFormBusy(elements.setupForm, true);
    try {
        const session = await setupVault(elements.setupMaster.value);
        const migrationMessage = session.migratedCount > 0
            ? ` ${session.migratedCount} legacy ${session.migratedCount === 1 ? 'entry was' : 'entries were'} migrated.`
            : '';
        const invalidMessage = session.invalidLegacyCount > 0
            ? ` ${session.invalidLegacyCount} invalid legacy ${session.invalidLegacyCount === 1 ? 'record remains' : 'records remain'} in plaintext for manual recovery.`
            : '';
        elements.setupForm.reset();
        await openVaultSession(session, `Encrypted vault created.${migrationMessage}${invalidMessage}`);
    } catch (error) {
        setStatus(friendlyError(error, 'The vault could not be created.'), 'error');
    } finally {
        setFormBusy(elements.setupForm, false);
    }
});

elements.unlockForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    setFormBusy(elements.unlockForm, true);
    const vaultGenerationAtStart = appState.vaultGeneration;
    try {
        const session = await unlockStoredVault(elements.unlockMaster.value);
        if (appState.vaultGeneration !== vaultGenerationAtStart) {
            throw new ConcurrentVaultUpdateError();
        }
        elements.unlockForm.reset();
        await openVaultSession(session, 'Vault unlocked on this device.');
    } catch (error) {
        elements.unlockMaster.value = '';
        setStatus(friendlyError(error, 'The vault could not be unlocked.'), 'error');
    } finally {
        setFormBusy(elements.unlockForm, false);
    }
});

elements.entryForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const sessionAtStart = appState.session;
    if (!sessionAtStart) {
        lockVault();
        return;
    }

    setFormBusy(elements.entryForm, true);
    try {
        const timestamp = new Date().toISOString();
        const candidate = createVaultEntry({
            name: elements.entryName.value,
            username: elements.entryUsername.value,
            url: elements.entryUrl.value,
            password: elements.entryPassword.value,
            notes: elements.entryNotes.value,
        }, globalThis.crypto, timestamp);
        const existingEntry = findEntry(elements.entryId.value);
        const entry = existingEntry
            ? {
                ...candidate,
                id: existingEntry.id,
                createdAt: existingEntry.createdAt,
                updatedAt: timestamp,
            }
            : candidate;
        const entries = existingEntry
            ? sessionAtStart.vault.entries.map((storedEntry) => (
                storedEntry.id === existingEntry.id ? entry : storedEntry
            ))
            : [...sessionAtStart.vault.entries, entry];

        await persistDraftVault(
            { ...sessionAtStart.vault, entries },
            existingEntry ? 'Entry updated and encrypted.' : 'Entry added and encrypted.',
        );
        closeEntryEditor();
    } catch (error) {
        if (error instanceof ConcurrentVaultUpdateError || error instanceof VaultUnlockError) {
            lockVault(friendlyError(error));
        } else {
            setStatus(friendlyError(error, 'The entry could not be saved.'), 'error');
        }
    } finally {
        setFormBusy(elements.entryForm, false);
    }
});

elements.entryList.addEventListener('click', async (event) => {
    const button = event.target.closest('button[data-action]');
    if (!button || !appState.session) {
        return;
    }

    const entry = findEntry(button.dataset.entryId);
    if (!entry) {
        setStatus('That entry no longer exists.', 'error');
        return;
    }

    resetIdleTimer();
    const action = button.dataset.action;
    if (action === 'edit') {
        openEntryEditor(entry);
        return;
    }

    if (action === 'delete') {
        appState.deleteEntryId = entry.id;
        elements.deleteEntryName.textContent = entry.name;
        elements.deleteEntryDialog.showModal();
        return;
    }

    if (action === 'copy') {
        try {
            await navigator.clipboard.writeText(entry.password);
            setStatus('Password copied. Clipboard history may retain it.', 'success');
        } catch {
            setStatus('The browser blocked clipboard access. Use Reveal and copy manually.', 'error');
        }
        return;
    }

    if (action === 'reveal') {
        const card = button.closest('.credential-card');
        const display = card.querySelector('[data-password-display]');
        const isRevealed = button.getAttribute('aria-pressed') === 'true';
        clearTimeout(appState.revealTimers.get(entry.id));
        appState.revealTimers.delete(entry.id);

        if (isRevealed) {
            display.textContent = '••••••••••••';
            button.textContent = 'Reveal';
            button.setAttribute('aria-label', `Reveal password for ${entry.name}`);
            button.setAttribute('aria-pressed', 'false');
            return;
        }

        display.textContent = entry.password;
        button.textContent = 'Hide';
        button.setAttribute('aria-label', `Hide password for ${entry.name}`);
        button.setAttribute('aria-pressed', 'true');
        const timer = setTimeout(() => {
            if (display.isConnected) {
                display.textContent = '••••••••••••';
                button.textContent = 'Reveal';
                button.setAttribute('aria-label', `Reveal password for ${entry.name}`);
                button.setAttribute('aria-pressed', 'false');
            }
            appState.revealTimers.delete(entry.id);
        }, 15_000);
        appState.revealTimers.set(entry.id, timer);
    }
});

elements.confirmDeleteEntry.addEventListener('click', async () => {
    const sessionAtStart = appState.session;
    const entryId = appState.deleteEntryId;
    if (!sessionAtStart || !entryId) {
        closeDialog(elements.deleteEntryDialog);
        return;
    }

    elements.confirmDeleteEntry.disabled = true;
    try {
        const entries = sessionAtStart.vault.entries.filter((entry) => entry.id !== entryId);
        await persistDraftVault({ ...sessionAtStart.vault, entries }, 'Entry permanently deleted.');
        closeDialog(elements.deleteEntryDialog);
        appState.deleteEntryId = null;
        elements.deleteEntryName.textContent = '';
    } catch (error) {
        if (error instanceof ConcurrentVaultUpdateError || error instanceof VaultUnlockError) {
            lockVault(friendlyError(error));
        } else {
            setStatus(friendlyError(error, 'The entry could not be deleted.'), 'error');
        }
    } finally {
        elements.confirmDeleteEntry.disabled = false;
    }
});

elements.changeMasterForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const sessionAtStart = appState.session;
    if (!sessionAtStart) {
        closeDialog(elements.changeMasterDialog);
        lockVault();
        return;
    }

    if (elements.newMaster.value !== elements.confirmNewMaster.value) {
        setStatus('The new master-password confirmation does not match.', 'error');
        return;
    }

    setFormBusy(elements.changeMasterForm, true);
    try {
        const changed = await changeMasterPassword(
            sessionAtStart.vault,
            elements.currentMaster.value,
            elements.newMaster.value,
        );
        broadcastVaultChange('master-password-changed');
        elements.changeMasterForm.reset();
        closeDialog(elements.changeMasterDialog);

        if (appState.session === sessionAtStart) {
            appState.session = changed;
            resetIdleTimer();
            setStatus('Master password changed and the vault was re-encrypted.', 'success');
        }
    } catch (error) {
        if (error instanceof ConcurrentVaultUpdateError) {
            lockVault(friendlyError(error));
        } else {
            setStatus(friendlyError(error, 'The master password could not be changed.'), 'error');
        }
    } finally {
        elements.currentMaster.value = '';
        elements.newMaster.value = '';
        elements.confirmNewMaster.value = '';
        setFormBusy(elements.changeMasterForm, false);
    }
});

elements.deleteVaultForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (elements.deleteVaultConfirmation.value !== 'DELETE') {
        setStatus('Type DELETE exactly to confirm permanent vault deletion.', 'error');
        return;
    }

    setFormBusy(elements.deleteVaultForm, true);
    try {
        await removeVault();
        broadcastVaultChange('deleted');
        appState.session = null;
        clearTimeout(appState.idleTimer);
        appState.idleTimer = null;
        clearSensitiveUi();
        showSetup({
            hasVault: false,
            legacyPasswordCount: 0,
            hasLegacyMasterPassword: false,
        });
        setStatus('The local vault and all Passwordify entries were permanently deleted.', 'success');
    } catch (error) {
        setStatus(friendlyError(error, 'The vault could not be deleted.'), 'error');
    } finally {
        setFormBusy(elements.deleteVaultForm, false);
    }
});

elements.addEntry.addEventListener('click', () => openEntryEditor());
elements.cancelEntry.addEventListener('click', closeEntryEditor);
elements.search.addEventListener('input', renderEntries);
elements.headerLock.addEventListener('click', () => lockVault('Vault locked manually.'));
elements.cancelDeleteEntry.addEventListener('click', () => {
    appState.deleteEntryId = null;
    elements.deleteEntryName.textContent = '';
    closeDialog(elements.deleteEntryDialog);
});
elements.changeMaster.addEventListener('click', () => {
    elements.changeMasterForm.reset();
    elements.changeMasterDialog.showModal();
    elements.currentMaster.focus();
});
elements.cancelChangeMaster.addEventListener('click', () => {
    elements.changeMasterForm.reset();
    closeDialog(elements.changeMasterDialog);
});
elements.deleteVault.addEventListener('click', () => {
    elements.deleteVaultForm.reset();
    elements.deleteVaultDialog.showModal();
    elements.deleteVaultConfirmation.focus();
});
elements.resetVaultLocked.addEventListener('click', () => {
    elements.deleteVaultForm.reset();
    elements.deleteVaultDialog.showModal();
    elements.deleteVaultConfirmation.focus();
});
elements.cancelDeleteVault.addEventListener('click', () => {
    elements.deleteVaultForm.reset();
    closeDialog(elements.deleteVaultDialog);
});
elements.toggleEntryPassword.addEventListener('click', () => {
    const showPassword = elements.entryPassword.type === 'password';
    elements.entryPassword.type = showPassword ? 'text' : 'password';
    elements.toggleEntryPassword.textContent = showPassword ? 'Hide' : 'Show';
    resetIdleTimer();
});
elements.generateEntryPassword.addEventListener('click', () => {
    try {
        elements.entryPassword.value = generatePassword({ length: 20 });
        setStatus('A new 20-character password was generated for this entry.', 'success');
        resetIdleTimer();
    } catch (error) {
        setStatus(friendlyError(error, 'Password generation failed.'), 'error');
    }
});

document.addEventListener('pointerdown', registerActivity, { passive: true });
document.addEventListener('keydown', registerActivity);
elements.setupForm.addEventListener('input', resetAuthInputTimer);
elements.unlockForm.addEventListener('input', resetAuthInputTimer);
elements.deleteEntryDialog.addEventListener('cancel', (event) => {
    event.preventDefault();
    appState.deleteEntryId = null;
    elements.deleteEntryName.textContent = '';
    closeDialog(elements.deleteEntryDialog);
});
elements.changeMasterDialog.addEventListener('cancel', (event) => {
    event.preventDefault();
    elements.changeMasterForm.reset();
    closeDialog(elements.changeMasterDialog);
});
elements.deleteVaultDialog.addEventListener('cancel', (event) => {
    event.preventDefault();
    elements.deleteVaultForm.reset();
    closeDialog(elements.deleteVaultDialog);
});
document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        if (appState.session) {
            lockVault('Vault locked because the tab became hidden.');
        } else {
            clearLockedInputs('Sensitive password fields were cleared because the tab became hidden.');
        }
    }
});

vaultChannel?.addEventListener('message', (event) => {
    if (
        event.data?.type === 'vault-changed'
        && event.data.source !== pageInstanceId
    ) {
        appState.vaultGeneration += 1;
        if (appState.session) {
            lockVault('Vault changed in another Passwordify tab. Unlock again to load the latest data.');
        }
    }
});

chrome.storage.onChanged.addListener((changes, areaName) => {
    const vaultChange = areaName === 'local' ? changes[STORAGE_KEYS.vault] : null;
    if (vaultChange) {
        appState.vaultGeneration += 1;
        if (vaultChange.newValue === undefined && appState.session) {
            lockVault('The encrypted vault was removed from extension storage.');
        }
    }
});

async function initialize() {
    try {
        await hardenStorageAccess();
        const vaultState = await getVaultState();
        if (vaultState.hasVault) {
            showUnlock();
            setStatus('Enter the master password to decrypt the local vault.', 'neutral');
        } else {
            showSetup(vaultState);
            setStatus('Create a master password before saving real credentials.', 'neutral');
        }
    } catch {
        hideAllPanels();
        elements.loadingPanel.hidden = false;
        elements.loadingPanel.querySelector('h2').textContent = 'Passwordify could not start';
        elements.loadingPanel.querySelector('p').textContent =
            'Secure extension storage is unavailable. Reload or reinstall the extension.';
        setStatus('Initialization failed without reading or changing credential data.', 'error');
    }
}

initialize();
