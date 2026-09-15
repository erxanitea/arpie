# Arpie Security Model

Arpie is a **local, single-user desktop** endpoint IDS. Its security measures are
chosen for that context — not copied from a web-app checklist. This document
records the threat model, what is implemented, and why a couple of common
web-security controls are deliberately *not* used.

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

1. **Password hashing — salted scrypt.** [db.py](../arpie/db.py) stores passwords
   as `scrypt$n$r$p$salt$hash` (16 MB work factor), verified in constant time
   (`hmac.compare_digest`). Legacy unsalted SHA-256 rows migrate to scrypt on the
   next successful login.
2. **Brute-force lockout.** After 5 consecutive failed logins an account locks
   for 5 minutes; during lockout the password is not even checked. This is the
   desktop equivalent of a web login's rate-limit/CAPTCHA. The login screen shows
   remaining attempts and lockout time.
3. **Authentication audit log.** Every login success, failure, lockout, and
   blocked-while-locked attempt is recorded in the `auth_events` table.
4. **Secrets in the OS secure store.** API keys go to Windows Credential Manager
   / macOS Keychain / Linux Secret Service via `keyring`, never plaintext in the
   DB. A legacy plaintext key is migrated out and scrubbed once the secure store
   accepts it. With no keyring backend, Arpie uses environment variables and, as
   a last resort, keeps an existing key in the permission-restricted DB rather
   than losing it.
5. **Restricted DB file permissions.** The database is `chmod 0600` (owner-only)
   on POSIX; Windows inherits the user-profile ACL.
6. **Parameterized SQL everywhere.** No query is built by string interpolation, so
   the event/config data captured from the network cannot cause SQL injection.
7. **Optional TOTP two-factor authentication.** Any account can enable 2FA
   (Settings → Two-Factor Authentication). Enrollment issues a base32 secret for
   an authenticator app and is confirmed with a live code before it takes effect;
   login then requires the 6-digit code after the password. Implemented on the
   standard library ([mfa.py](../arpie/mfa.py), RFC 6238, HMAC-SHA1, 30s/6-digit,
   ±1 step skew) — no extra dependency. MFA events are audit-logged.
8. **Credential input validation.** [validation.py](../arpie/validation.py)
   enforces a real email format and a password policy (≥ 8 chars, at least one
   letter and one number, not a common password, not equal to the username/email)
   at registration and on password change.
9. **Least surprise on containment.** Seal Mode is reversible, user-confirmed,
   auto-restores after 30 minutes, and any rule stranded by a crash is cleared on
   next startup.

## Deliberately not used

- **reCAPTCHA / bot challenges.** These defend *public web forms* against remote
  automated submission. Arpie has no web login and no remote attacker surface, so
  a CAPTCHA would add a Google dependency and a browser round-trip for zero
  benefit. The real goal — stopping automated password guessing — is met locally
  by the lockout above.

## Where the TOTP secret lives

The TOTP secret is stored in the `operators` table (the same 0600-restricted DB
as the password hashes). This defends the common case — an attacker who learns
or guesses the password but does not have the user's authenticator device.
It is not a defense against full theft of the DB file (which also contains the
password hash); that is a more severe compromise the file permissions address.

## Note on network privacy

When API keys are configured, Arpie sends observed **public** IPs to AbuseIPDB
and IPinfo for enrichment. Private/LAN addresses are never sent. Without keys,
enrichment is skipped and all detection still works.
