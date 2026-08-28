# Changelog

This file records notable Passwordify changes. Version 2.0.0 is still under development and has not been released.

## [2.0.0] - Unreleased

### Security

- Replaced `Math.random()` password generation with Web Crypto randomness, unbiased rejection sampling, and a cryptographic Fisher–Yates shuffle.
- Guaranteed at least one character from each selected generator pool, bounded generated passwords to 12–128 characters, and rejected configurations with a conservative estimated entropy below 64 bits.
- Replaced normal plaintext credential storage with a versioned, authenticated encrypted vault.
- Added PBKDF2-HMAC-SHA-256 key derivation with 600,000 iterations and a fresh 16-byte random salt.
- Added AES-256-GCM encryption with a fresh 12-byte IV, 128-bit authentication tag, and authenticated vault-format/KDF metadata.
- Stopped storing the master password in the 2.0 data model; the derived non-extractable key and plaintext vault remain only in the unlocked vault page's memory.
- Restricted local and session storage to trusted extension contexts.
- Replaced the background installation prompt with a minimal module service worker that reapplies trusted-context storage access and clears expired generated-password handoffs.
- Removed the public `<all_urls>` web-accessible vault resource.
- Tightened the extension-page Content Security Policy to local scripts and assets, no network connections, no objects, no form submissions, no base-URL rewriting, and no framing.
- Added record-shape, field-length, base64, KDF, IV, ciphertext-size, timestamp, duplicate-ID, entry-count, and schema validation.
- Added exclusive Web Locks writes where available, encrypted revision checks, and fail-closed handling for detected concurrent updates.
- Added five-minute inactivity locking, immediate hidden-tab locking, manual locking, default masking, and automatic re-masking after a 15-second reveal.
- Added explicit clipboard-retention warnings and removed prompt/alert-based credential flows.

### Added

- Local encrypted-vault setup and unlock flows.
- Entry creation, search, editing, deletion, copying, notes, usernames, and website fields.
- Current-password reauthentication followed by master-password change, full-vault re-encryption, and a new salt.
- One-time generated-password handoff through `chrome.storage.session`, accepted for ten minutes, automatically encrypted after unlock, removed only after a successful vault write, protected from accidental overwrite, and backed by an expiry alarm.
- Confirmed whole-vault deletion from either locked or unlocked state, covering encrypted, temporary, and recognized legacy storage keys.
- In-extension privacy/security notice plus root project, security, privacy, and changelog documentation.
- Automated Node tests for generation, cryptography, storage, deletion, and legacy migration.
- Static verification for manifest posture, required files, JavaScript syntax, forbidden insecure APIs, and inline scripts.

### Changed

- Renamed the extension to **Passwordify - Local Password Vault** and moved the manifest version to 2.0.0.
- Reduced the extension manifest to the `storage` and handoff-cleanup `alarms` permissions with no host permissions, content scripts, web-accessible resources, or network integration.
- Rebuilt the popup and vault as native ES modules with DOM-safe rendering through `textContent` and element creation.
- Expanded vault entries from the legacy name/password pair to a validated schema with stable random IDs and creation/update timestamps.
- Re-encrypts the complete vault and increments its encrypted revision after every saved mutation.

### Migration

- Detects the legacy 1.1 `savedPasswords` array when creating the first encrypted vault in the same extension profile.
- Encrypts valid legacy entries and verifies the new stored vault before removing the old plaintext master-password value.
- Removes `savedPasswords` after a complete migration; retains and reports invalid array entries in plaintext for manual recovery.
- Removes an obsolete plaintext master-password value after an existing encrypted vault is authenticated successfully.

### Known limitations

- This pre-release has not received an independent professional security audit and should not be the sole store for important credentials.
- There is no encrypted export/import, automated backup, sync, account recovery, password reset, autofill, origin binding, mobile client, or secure sharing.
- The design does not protect an unlocked vault from a compromised browser/device, malware, keylogging, screen or accessibility capture, memory inspection, or clipboard readers.
- A copied vault remains subject to offline guessing, and storage can be deleted or rolled back to an older valid encrypted record.
- A suspended browser can delay physical alarm cleanup of an unread popup-to-vault handoff, but the vault independently rejects and removes it after the ten-minute acceptance window.

## [1.1] - Historical

### Security warning

- Generated passwords with `Math.random()`.
- Stored saved passwords and the master password as plaintext extension data.
- Exposed `passwords.html` as a web-accessible resource matching all URLs.

Version 1.1 and earlier are unsupported and must not be used for real credentials.
