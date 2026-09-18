# Arpie Security Model

Arpie is a **local, single-user desktop** endpoint IDS. Its security measures are
chosen for that context — not copied from a web-app checklist. This document
records the threat model, what is implemented, what is not yet implemented, and
why a couple of common web-security controls are deliberately *not* used.

> Every control below has been checked against the code. Claims are separated into
> **Implemented** and **Not yet implemented** so this file cannot drift into
> asserting protections that do not exist.

## Assets & threat model

| Asset | Where | Threat |
|-------|-------|--------|
| Operator credentials | `operators` table | Offline cracking if the DB is copied; local password guessing |
| API keys (AbuseIPDB, IPinfo) | OS secure store / env | Disclosure if stored in plaintext |
| Alert / session history, emails | SQLite DB | Local disclosure or tampering |
| Firewall control (Seal Mode) | OS firewall | Abuse to disrupt connectivity |

The adversary of interest is someone who obtains the DB file, or who has brief
local access to the login. There is **no network-facing service** — Arpie does
not listen on a socket or expose a remote login.

## Implemented controls

1. **Password hashing — salted scrypt.**
   [`models/base.py`](../arpie/models/base.py) stores passwords as
   `scrypt$N$r$p$salt_b64$key_b64` with per-password random 16-byte salts and
   RFC 7914 interactive parameters (N=2^14, r=8, p=1 — about 16 MB and ~30 ms per
   derivation). Verification is constant-time (`hmac.compare_digest`). Rows written
   by the earlier unsalted SHA-256 scheme still authenticate and are transparently
   re-hashed to scrypt on the next successful login.
   Covered by `tests/test_db.py`: identical passwords must not produce identical
   hashes, no stored hash may be a bare SHA-256 digest, and the legacy upgrade path
   is asserted end to end.
2. **Credential material never enters application state.**
   `authenticate_operator` returns the operator row with `password_hash` and
   `recovery_codes` stripped, so the hash cannot leak into UI structures, session
   snapshots, or exported reports.
3. **Parameterized SQL everywhere.** No query is built by string interpolation, so
   event and config data captured from the network cannot cause SQL injection.
4. **Secrets in the OS secure store.** API keys go to Windows Credential Manager /
   macOS Keychain / Linux Secret Service via `keyring`
   ([`security/secrets_store.py`](../arpie/security/secrets_store.py)), never
   plaintext in the DB. With no keyring backend available the store degrades
   gracefully — every operation returns `None`/`False` rather than raising, and
   never silently falls back to plaintext. Asserted in `tests/test_secrets.py`.
5. **Optional TOTP two-factor authentication.** Any account can enable 2FA
   (Settings → Two-Factor Authentication). Enrollment issues a base32 secret for an
   authenticator app and is confirmed with a live code before it takes effect;
   login then requires the 6-digit code. Implemented on the standard library
   ([`middleware/mfa.py`](../arpie/middleware/mfa.py), RFC 6238, HMAC-SHA1,
   30-second step, 6 digits, ±1 step skew) — no extra dependency. Single-use
   recovery codes are supported.
6. **Credential input validation.** [`forms/auth.py`](../arpie/forms/auth.py)
   enforces a real email format and a password policy (≥ 8 chars, at least one
   letter and one number, not a common password, not equal to the username or
   email local-part) at registration and on password change.
   [`forms/settings.py`](../arpie/forms/settings.py) validates thresholds, export
   paths, and API keys.
7. **Role-based access control.** `middleware/auth.py` defines the two roles and a
   `require_role` decorator; `admin/` centralizes the privileged-operator policy
   checks used by the user-management and settings screens.
8. **Reversible containment.** Seal Mode is user-confirmed, reversible, and
   auto-restores after `auto_restore_seconds` (default 30 minutes) via an
   in-process timer. Every seal and unseal is written to the `actions` table with
   its confirmation flag, so containment is auditable after the fact.
9. **Network privacy on enrichment.** When API keys are configured, only **public**
   IPs are sent to AbuseIPDB and IPinfo; private, loopback, and link-local
   addresses are filtered out in `integrations/threat_intel.py`. Without keys,
   enrichment is skipped and all detection still works.

## Not yet implemented

These are real gaps, listed so the threat model stays honest. They are tracked as
work, not described as protections.

| Gap | Impact | Notes |
|---|---|---|
| **Brute-force lockout** | Unlimited local password guessing against the login screen | No attempt counter or lockout window exists. scrypt raises the per-guess cost to ~30 ms, which slows but does not stop a sustained local attack. |
| **Authentication audit log** | Login successes, failures, and MFA events are not recorded | There is no `auth_events` table. Detection events and containment actions *are* logged; authentication is not. |
| **Restricted DB file permissions** | The SQLite file inherits default umask permissions | No `chmod 0600` is applied on POSIX. Anyone with a local account that can read the file gets the password hashes and TOTP secrets. |
| **Startup cleanup of stranded firewall rules** | A crash mid-seal can leave an OS firewall rule applied | `SealManager` tracks sealed targets in process memory only; the auto-restore timer dies with the process. The `actions` table records the seal, but nothing reconciles it against the firewall on the next launch. |
| **Legacy plaintext API-key migration** | An API key written to the DB before the keyring path existed is not scrubbed | `secrets_store` reads and writes the OS store but does not migrate or erase a pre-existing plaintext value. |

Priority order if this is picked up: DB file permissions (cheapest, largest
payoff), then lockout, then the auth audit log, then seal reconciliation.

## Deliberately not used

- **reCAPTCHA / bot challenges.** These defend *public web forms* against remote
  automated submission. Arpie has no web login and no remote attacker surface, so
  a CAPTCHA would add a third-party dependency and a browser round-trip for zero
  benefit. The right control for local automated guessing is a lockout window —
  see **Not yet implemented** above; a CAPTCHA would not substitute for it.

## Where the TOTP secret lives

The TOTP secret is stored in the `operators` table, in the same SQLite file as the
password hashes. This defends the common case: an attacker who learns or guesses
the password but does not hold the user's authenticator device.

It is **not** a defense against theft of the DB file, which contains both the
secret and the password hash. The control that would narrow that exposure —
owner-only file permissions — is not yet implemented, so treat the database file
as sensitive and rely on the enclosing user profile's protection for now.
