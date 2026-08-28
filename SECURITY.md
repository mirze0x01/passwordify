# Security policy

Passwordify handles high-value data, so security reports are welcome even while 2.0 remains a pre-release personal project. This policy does not imply that the project has been independently audited, is production-ready, offers a bug bounty, or can meet an enterprise response SLA.

## Supported versions

| Version | Security status |
| --- | --- |
| 2.0.0 | Unreleased development line; reports and fixes are accepted against the latest commit |
| 1.1 and earlier | Unsupported and unsafe for real credentials |

Version 1.1 generated passwords with `Math.random()` and stored saved passwords and the master password as plaintext extension data. Do not report those known design flaws as new 2.0 vulnerabilities, and do not continue using 1.1 for real secrets.

## Report a vulnerability privately

Use this repository's **Security** tab and GitHub's private vulnerability-reporting/GitHub Security Advisory workflow:

1. Open the repository on GitHub.
2. Open **Security and quality** (shown as **Security** in some layouts), then the repository's advisories page.
3. Select **Report a vulnerability** when GitHub presents that option, then create a private report. GitHub documents the current reporter flow in [Privately reporting a security vulnerability](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately).

If **Report a vulnerability** is not available, private vulnerability reporting has not been enabled for the repository. Do not publish exploit details, credential material, vault samples, or other users' data in a public issue. A public issue may contain only a minimal request that the maintainer enable GitHub private vulnerability reporting; keep all sensitive details for the advisory.

Include, where applicable:

- the exact commit hash, extension version, browser/version, and operating system;
- the affected file or flow and the security boundary you expected;
- prerequisites, reproducible steps using test-only credentials, and a minimal proof of concept;
- realistic confidentiality, integrity, or availability impact;
- whether the issue affects a locked vault, unlocked page, migration, generator, clipboard, or update path;
- suggested mitigations or a patch, if available.

Never attach a real vault, master password, generated production password, authentication token, personal data, or secrets belonging to another person. Construct a disposable test case instead.

There is no promised response deadline or reward. Discussion, coordination, and any disclosure timeline should remain in the private GitHub advisory until a fix and safe release plan exist.

## In scope

- password generation, randomness, and character selection;
- key derivation, encryption, authentication, vault-format validation, or downgrade/parameter handling;
- master-password, derived-key, decrypted-vault, reveal, or clipboard lifecycle;
- extension permissions, Content Security Policy, exposed resources, DOM injection, or extension-page boundaries;
- local/session storage access, migration, deletion, concurrent writes, and locked/unlocked state transitions;
- a realistic path by which untrusted website content or a less-trusted extension context can read or change Passwordify data;
- dependency, packaging, or update behavior once those mechanisms are added.

Reports about the browser or operating system are most useful when they identify a concrete way Passwordify unnecessarily increases the impact or can reasonably defend itself.

## Known limits and generally out of scope

The following are documented design limits, not promises of protection:

- a compromised browser or operating system, malware, keylogging, screen capture, accessibility capture, process-memory inspection, or physical control while the vault is unlocked;
- a user choosing a weak or reused master password and an attacker performing offline guesses against a copied vault;
- clipboard history or another local program reading a password after the user explicitly copies it;
- availability attacks, browser-profile deletion, or replacement/rollback with an older valid encrypted record;
- forgotten master passwords, deleted vaults, or requests for password recovery—Passwordify has no recovery secret or service;
- lack of autofill, origin binding, sync, export, sharing, or enterprise management;
- the already documented 1.1 plaintext-storage and `Math.random()` design.

An issue in one of these areas is still worth reporting privately if it demonstrates a surprising extension-specific exploit, crosses a boundary the documentation claims to enforce, or has a practical mitigation.

## Safe research expectations

Test only against a copy you own, with synthetic data. Do not access another person's browser profile, credentials, accounts, or devices; do not persist access, disrupt services, exfiltrate data, or use social engineering. Minimize data collection and delete test artifacts when the report is complete.

Security decisions and fixes should include regression tests when feasible. Passing `npm run verify` is required for local validation, but it does not establish that a change is secure or audited.
