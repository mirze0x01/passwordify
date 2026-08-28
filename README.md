# Passwordify

Passwordify is a small, local-first password generator and encrypted credential vault for Chromium browsers. It is implemented as a Manifest V3 extension with native browser APIs and no runtime dependencies, remote scripts, analytics, accounts, or application network service.

> [!WARNING]
> **Maturity:** version 2.0.0 is an unreleased security-hardening rewrite of a personal project. It has automated unit and static checks, but it has not received an independent professional security audit or broad production testing. Do not use this pre-release build as the only copy of important credentials. For high-value secrets, prefer an established, independently reviewed password manager until this project has completed external review, release engineering, and recovery/backup work.

The original 1.1 implementation was not safe for real credentials: it generated passwords with `Math.random()` and stored both saved passwords and a master password as plaintext extension data. The 2.0 rewrite replaces that design rather than presenting the old behavior as acceptable.

## Features

- Generates 12–128-character passwords from selected lowercase, uppercase, number, symbol, and optional emoji pools, rejecting configurations with an estimated entropy below 64 bits.
- Uses Web Crypto randomness with rejection sampling and a cryptographic shuffle; every selected character class is represented.
- Encrypts the complete vault, including entry names, usernames, URLs, passwords, and notes.
- Adds, searches, edits, copies, reveals, and deletes vault entries without granting host permissions.
- Masks stored passwords by default and hides a revealed password again after 15 seconds.
- Locks manually, after five minutes without pointer or keyboard activity, or as soon as the vault tab becomes hidden.
- Requires the current master password before changing it, then re-encrypts the complete vault with a new random salt.
- Detects concurrent vault revisions and uses the Web Locks API where the browser provides it.
- Migrates valid legacy 1.1 entries during first-time vault creation and removes the old plaintext master-password value only after the encrypted vault is verified.
- Uses a minimal background worker only to reapply storage access restrictions at browser lifecycle events and remove an expired popup-to-vault handoff; it has no network role.
- Keeps normal vault data in the current browser profile; there is no Passwordify server, account, sync service, telemetry, or analytics.

## Install the unpacked extension

The extension root is the [`Passwordify`](Passwordify) directory—the directory containing `manifest.json`. Select that directory, not the repository root, when loading it.

### Google Chrome

1. Clone or download this repository.
2. Open `chrome://extensions`.
3. Enable **Developer mode**.
4. Select **Load unpacked**.
5. Choose `<repository>/Passwordify`.
6. Pin Passwordify from the browser's Extensions menu if desired.

The manifest requires Chrome 120 or later. This is a development install: review the checked-out source and rerun the verification commands before loading updates.

### Microsoft Edge

1. Clone or download this repository.
2. Open `edge://extensions`.
3. Enable **Developer mode**.
4. Select **Load unpacked**.
5. Choose `<repository>/Passwordify`.
6. Pin Passwordify from the Extensions menu if desired.

Use a current Chromium-based Edge release. After pulling a code update, return to the extensions page and select **Reload** on the existing Passwordify installation. Loading the extension from a different filesystem path can create a different unpacked-extension identity and therefore a different storage namespace; migration can only see data belonging to the same extension installation and browser profile.

Passwordify requests `storage` for the local/session records and `alarms` to expire the temporary generated-password handoff. It declares no host permissions, content scripts, externally connectable API, or web-accessible vault page. The background worker performs only storage-access hardening and alarm cleanup; it does not make network requests.

## Architecture and data flow

Passwordify has two extension-page entry points:

1. `popup.html` generates a password entirely in the popup with `crypto.getRandomValues()`.
2. Copying places that plaintext in the operating-system clipboard. Passwordify cannot control clipboard history or other software that reads it.
3. **Save in vault** places a one-time handoff value in access-restricted `chrome.storage.session`, schedules a cleanup alarm for ten minutes later, and opens `passwords.html`. It refuses to replace another unexpired handoff, avoiding silent loss of the earlier password.
4. After a successful unlock, the vault page independently validates the expiry and automatically saves the handoff as a new encrypted entry. It removes the session value and clears the alarm only after that encrypted write succeeds, so a failed write can be retried until expiry. The background worker removes an unread value when the expiry alarm runs. If a suspended browser delays the alarm, the vault still rejects and removes the expired value rather than saving it.
5. The master password is passed to PBKDF2 in the vault page. It is not written to storage. The resulting non-extractable `CryptoKey` and decrypted vault object remain in that page's JavaScript memory only while it is unlocked.
6. Every mutation validates the vault, increments its encrypted revision, encrypts the complete JSON document with a fresh IV, and replaces `encryptedVault` in `chrome.storage.local`.
7. Locking drops the in-page session reference, clears sensitive form/list content, and cancels reveal timers. JavaScript and browser memory management cannot guarantee forensic zeroization.

Both local and session storage access levels are set to `TRUSTED_CONTEXTS`. The encrypted local record is still ordinary browser-profile data: a user, browser process, backup tool, or privileged malware may copy, replace, roll back, or delete it.

### Cryptographic parameters

| Purpose | Current format |
| --- | --- |
| Password generation | `crypto.getRandomValues()`; unbiased rejection sampling; Fisher–Yates shuffle |
| Generator safety floor | Conservative estimated entropy of at least 64 bits |
| Key derivation | PBKDF2-HMAC-SHA-256, 600,000 iterations |
| Salt | Fresh 16 random bytes when a vault is created or the master password changes |
| Encryption | AES-256-GCM |
| Nonce/IV | Fresh 12 random bytes for every encryption |
| Authentication tag | 128 bits |
| Authenticated metadata | Format version, KDF name/hash/iterations/salt, and cipher name |
| Master-password policy | 12–256 Unicode characters, not all whitespace |
| Vault limits | Up to 10,000 entries; encoded ciphertext capped at 5 MiB |

AES-GCM authenticates the ciphertext and the listed format metadata. A wrong master password, modified ciphertext, or modified authenticated configuration fails closed with a generic unlock error. PBKDF2 increases the cost of password guessing; it does not make a weak or reused master password safe, and a copied vault can be attacked offline without account lockout.

## Legacy 1.1 migration

Migration runs when the user creates a 2.0 vault in an installation that does not already contain `encryptedVault`:

1. Passwordify reads the legacy `savedPasswords` array from the same extension profile.
2. Entries with a valid, non-empty string password are converted to the new schema. Legacy 1.1 had only a name and password, so it has no username, URL, or notes to migrate.
3. The converted entries are encrypted, written, read back, decrypted, and validated.
4. Only after that verification succeeds is the old `masterPassword` value removed.
5. If every array entry converted, `savedPasswords` is removed. Invalid array entries—or a legacy value that is not an array—remain under that legacy key in plaintext for manual recovery, and the UI reports their count.

Migration recognizes the array shape written by 1.1; it is not a general importer or damaged-data recovery tool. Back up the browser profile before migrating data you cannot replace, confirm every expected entry appears, and then remove any retained invalid legacy data. **Delete vault** removes the encrypted vault and all recognized legacy keys.

If an encrypted vault already exists, unlocking it removes an obsolete legacy plaintext `masterPassword` after authenticated unlock. It does not merge a separate leftover `savedPasswords` collection into that existing vault.

## Threat model

### Intended protection

With a strong, unique master password and a trustworthy browser/device, Passwordify is designed to protect the confidentiality and integrity of a vault copied from a locked browser profile. It also avoids the original generator's predictable randomness and limits accidental on-screen exposure with masking and page locking.

### Explicit limits and non-goals

Passwordify does **not** claim to protect against:

- malware, keyloggers, screen capture, memory inspection, malicious accessibility tools, a compromised browser/OS, or someone controlling the device while the vault is unlocked;
- clipboard readers or clipboard-history retention after a password is copied;
- offline guessing of a weak or reused master password;
- deletion, denial of service, or rollback to an older but valid encrypted vault record;
- data remnants in browser databases, filesystem snapshots, crash dumps, swap, backups, or synchronized browser-profile backups;
- supply-chain risk in extension source or updates that the user has not reviewed;
- loss of the master password, browser profile, or only copy of the encrypted vault;
- phishing or origin confusion: Passwordify does not autofill, bind credentials to page origins, or inspect websites;
- side-channel resistance or guaranteed erasure of JavaScript strings and objects from managed memory.

The current product deliberately has no cloud sync, account recovery, password reset, secure sharing, mobile client, multi-user access control, automatic backup/export, breach lookup, or enterprise policy integration. Local-first describes where the extension code writes data; it is not a guarantee that the surrounding browser, operating system, backup software, or clipboard keeps data local.

See [SECURITY.md](SECURITY.md) for supported versions and private vulnerability reporting. See [PRIVACY.md](PRIVACY.md) for the data-handling notice.

## Development and verification

Development checks require Node.js 22 or later and npm. The extension itself has no npm runtime dependency and is loaded directly from `Passwordify/` as native ES modules.

```powershell
npm test
npm run verify
```

- `npm test` runs Node's built-in test runner over the password generator, vault cryptography, storage behavior, and legacy migration.
- `npm run verify` runs the full local quality gate: manifest/file posture checks, JavaScript syntax checks, bans on `Math.random`, `innerHTML`, `eval`, and inline scripts, followed by the test suite.

Run `npm run verify` before loading or sharing a changed build. The checks are useful regression gates, not a substitute for browser integration testing, code review, cryptographic review, or an independent security assessment.

For a manual smoke test, load `Passwordify/`, create a test vault, add/edit/delete a non-sensitive entry, lock and unlock it, verify hidden-tab and idle locking, change the master password, and test migration only with disposable legacy data. Check the extension's error console after each flow.

## Delete local data

From an unlocked vault, go to **Delete local data** and select **Delete vault**. From the locked screen, select **Reset local vault**. In either flow, type `DELETE` and confirm. This removes Passwordify's `encryptedVault`, `savedPasswords`, and `masterPassword` keys from local extension storage and the pending handoff from session storage; the master password is deliberately not required to discard unrecoverable or damaged local data.

Also clear the operating-system clipboard/history if you copied a password. Uninstalling the extension or clearing its browser storage removes the active extension data according to browser behavior, but neither the UI nor uninstall is a guaranteed forensic wipe of backups, old profile copies, storage-engine remnants, crash data, or snapshots.

There is no recovery service. Forgetting the master password or deleting the only vault copy permanently removes practical access to its contents.

## Project structure

```text
.
├── Passwordify/
│   ├── manifest.json       # Manifest V3 permissions and extension-page policy
│   ├── background.js       # Storage hardening and pending-handoff expiry alarm
│   ├── popup.html/js       # Password generator and vault handoff
│   ├── passwords.html/js   # Unlock flow and vault user interface
│   ├── generator.js        # CSPRNG-based generation and validation
│   ├── crypto.js           # Versioned KDF and authenticated encryption format
│   ├── storage.js          # Schema, migration, persistence, and deletion
│   ├── privacy.html        # Notice shown inside the extension
│   ├── style.css           # Shared popup, vault, dialog, and notice styles
│   └── icon128.png
├── test/                   # Node unit tests
├── scripts/                # Manifest, source, and HTML posture checks
├── .github/workflows/      # Read-only CI job running the verification gate
├── package.json            # Development scripts only
├── README.md
├── SECURITY.md
├── PRIVACY.md
└── CHANGELOG.md
```

## Roadmap

Before calling Passwordify production-ready:

- commission an independent security and cryptographic design review, publish its scope, and resolve findings;
- expand automated browser integration, lifecycle, concurrent-tab, corrupted-storage, and migration testing in CI;
- design and review a versioned encrypted export/import and backup workflow before encouraging real-world use;
- evaluate a memory-hard KDF and a backward-compatible parameter-upgrade strategy;
- add release signing, reproducible packaging, upgrade testing, and supported-version policy;
- complete accessibility and cross-browser behavior reviews;
- document a recovery-safe migration procedure for future vault-format revisions.

Autofill, cloud sync, sharing, recovery, and breach services would substantially expand the threat surface. They are not implied by this roadmap and should not be added without a new security design and privacy review.
