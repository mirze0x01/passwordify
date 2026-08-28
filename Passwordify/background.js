import {
    PENDING_ENTRY_ALARM,
    clearExpiredPendingEntry,
} from './storage.js';

async function hardenStorageAccess() {
    await chrome.storage.local.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });
    await chrome.storage.session.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });
}

chrome.runtime.onInstalled.addListener(() => {
    hardenStorageAccess().catch(() => undefined);
});

chrome.runtime.onStartup.addListener(() => {
    hardenStorageAccess().catch(() => undefined);
});

chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === PENDING_ENTRY_ALARM) {
        clearExpiredPendingEntry().catch(() => undefined);
    }
});
