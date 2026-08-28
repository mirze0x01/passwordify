# Privacy notice

Last updated: 2026-08-28

Passwordify is a local-first, unpacked browser extension. The extension code does not operate a server, create an account, send analytics or telemetry, load remote scripts, call a network API, or declare permission to read websites. Its declared permissions are `storage` for local/session extension data and `alarms` to expire a temporary generated-password handoff.

This notice describes version 2.0.0 as represented by the current source. It matches the summary available from **Privacy** inside the extension.

## Data Passwordify handles

Passwordify can handle:

- vault entry names, usernames/email addresses, website text, passwords, notes, and timestamps that the user enters;
- a vault schema version and revision;
- the encrypted vault's salt, key-derivation parameters, IV, and ciphertext;
- a generated password and optional label waiting to be handed from the popup to the vault page;
- legacy 1.1 `savedPasswords` and `masterPassword` values during migration;
- a master password while the vault page derives an encryption key.

Generator options are read from the popup controls and are not persisted by the extension.

## Where data goes

The encrypted vault is stored in `chrome.storage.local` for the extension in the current browser profile. The complete entry document—including labels, usernames, URLs, passwords, and notes—is inside the AES-GCM ciphertext; key-derivation and cipher parameters remain outside it so the key can be derived and the record decoded.

The master password is not written to 2.0 storage. It is used in the vault page to derive a non-extractable Web Crypto key. That key and the decrypted vault remain in the unlocked page's JavaScript memory and are dropped from the application's state when the page locks. Browser-managed JavaScript memory cannot promise immediate physical zeroization.

Selecting **Save in vault** stores a generated password and label temporarily in access-restricted `chrome.storage.session` and schedules a cleanup alarm for ten minutes later. After the user successfully unlocks, the vault independently enforces the same expiry and automatically writes the handoff as a new encrypted entry. It removes the temporary value and alarm only after that encrypted write succeeds; a failed write leaves it available for retry until expiry. The background worker removes an unread value when the alarm runs. If browser suspension delays that event, the vault still rejects and removes an expired value rather than saving it.

Selecting **Copy** sends a plaintext password to the operating-system clipboard. The operating system, clipboard manager, remote-desktop software, or another local application may retain or read it. Passwordify does not automatically clear clipboard history.

Passwordify itself does not transmit these values to a developer or Passwordify service. The browser, operating system, profile backup, crash reporting, enterprise management, roaming-profile, synchronization, or device-backup features outside the extension may handle browser storage or clipboard data under their own behavior and policies.

## Security measures

- PBKDF2-HMAC-SHA-256 with 600,000 iterations and a fresh 16-byte random salt derives the vault key.
- AES-256-GCM with a fresh 12-byte IV and 128-bit tag encrypts and authenticates the complete vault after every change.
- Vault-format and KDF metadata are authenticated as additional data.
- Local and session extension storage are restricted to trusted extension contexts.
- The extension declares no host permissions, content scripts, remote scripts, externally connectable API, or web-accessible vault page. Its background worker only hardens storage access and handles the handoff-expiry alarm.
- Stored passwords are masked by default, reveals hide after 15 seconds, and the vault locks after five minutes of inactivity or when its tab becomes hidden.

These measures protect a locked vault only within the [documented threat model](README.md#threat-model). They cannot protect data on a compromised device or browser, while a user or malicious tool can observe the unlocked page, after a value reaches the clipboard, or against offline guessing of a weak master password. Version 2.0.0 has not received an independent professional security audit.

## Retention and migration

The encrypted vault remains in the extension's local browser-profile storage until the user deletes it, clears the extension's storage, uninstalls the extension, or the browser/profile removes it.

During first-time migration, valid entries in the legacy 1.1 `savedPasswords` array are encrypted into the new vault. The old plaintext `masterPassword` is removed only after the new vault has been written, read back, decrypted, and validated. Invalid array entries—or a legacy value that is not an array—are retained in plaintext under `savedPasswords` for manual recovery and reported in the interface; they remain there until the user removes all Passwordify data. See [Legacy 1.1 migration](README.md#legacy-11-migration) before migrating irreplaceable data.

## Delete data

In an unlocked vault, use **Delete local data** → **Delete vault**. From the locked screen, use **Reset local vault**. Type `DELETE` and confirm; the master password is not required to discard local data. Passwordify removes:

- the encrypted vault;
- recognized legacy saved-password and master-password keys; and
- the temporary pending-entry value in session storage.

Clear the operating-system clipboard/history separately if a password was copied. Uninstalling Passwordify or clearing its extension storage also removes active extension data according to browser behavior. These actions are logical deletion, not a guaranteed forensic wipe: backups, old profile copies, filesystem snapshots, crash data, swap, clipboard history, or browser storage-engine remnants may survive outside Passwordify's control.

There is no account, password-reset function, recovery service, escrow key, or developer-held copy. Losing the master password or deleting the only usable vault means losing access to its contents.

## Changes and security reports

Material data-handling changes should update this file, the in-extension notice, and [CHANGELOG.md](CHANGELOG.md) together. Report a suspected privacy or security vulnerability privately through the GitHub Security Advisory process described in [SECURITY.md](SECURITY.md); never include real credentials or a real vault in a report.
