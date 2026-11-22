# Salam ID account service

**Live deployment:** Supabase Free, Singapore, project `lnzisnmpmtqfplncfugn`.

Endpoint: `https://lnzisnmpmtqfplncfugn.supabase.co/functions/v1/salam-id`

The hosted function, private PostgreSQL working state and conditional checkpoint cron are running. GitHub remains the encrypted archive repository. Existing SalamCloud GitHub authorization is held only in function secrets. No paid plan/add-on was enabled, no payment method was added by this task, and no Mac daemon is required. Android login remains optional. Node SQLite is retained as a local development adapter; Cloudflare is not used. Operations are in [部署说明.md](部署说明.md).

## Account flow

- The settings card stays immediately below search: `登录 Salam ID` / `登录 ID 以存储在线音乐数据`.
- `使用订单号登录` checks the existing SalamCloud signed order list. First enrollment asks the user to set a password, creates a random `salam_` username and returns a stable Salam ID. Subsequent login accepts order + password or username + password.
- Username changes require the current password and a unique normalized name. Names support 3–24 letters, Chinese characters, digits or underscores; NFKC and case normalization apply. The account ID never changes with the username.
- Password changes require the current password, generate a new salt and replace every old session with a new session for the requesting device. An existing order alone cannot reset a password. No password-recovery or account-deletion flow is included.
- The ID is the first 128 bits of HMAC-SHA256(AUTH_PEPPER, `Salam-ID/order/v2\n` + normalized order), formatted `SL-` + uppercase hex. The full, separately domain-separated order HMAC is checked to reject a truncated-ID collision. Neither the APK nor the public ID provides a way to calculate candidate order IDs without the server secret.
- Existing order-list PBKDF2 parameters are reused only for eligibility checks. No changes to the Mac SalamCloud interface or its order-management workflow are needed.

## Password format and secrets

The versioned format is **salam-password-v1**, composed of standard password hashing and post-hash peppering:

```
salt = random 32 bytes
D = PBKDF2-HMAC-SHA256(UTF8(password), salt, 600000 iterations, 32 bytes)
tag = HMAC-SHA256(PASSWORD_PEPPER,
      "salam-password-v1\n" + accountID + "\n600000\n" + base64url(salt) + "\n" + base64url(D))
```

The database stores `{scheme, kdf, iterations, salt, tag}`, never the password or D. Passwords are not trimmed or normalized. Verification recomputes the tag and compares it without an early character mismatch exit. Password pepper is a separate server secret, never in SQLite, GitHub or the APK. This is a Salam storage protocol built on standard primitives, not a new cryptographic primitive. The PBKDF2 work factor and post-hash pepper approach follow [OWASP password storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

Three independent 32-byte base64url secrets are required: AUTH_PEPPER (order identity and session hashing), PASSWORD_PEPPER (password tags), ARCHIVE_KEY (AES-256-GCM archives). Back up all three outside the repository. Rotation requires an explicit migration; simply replacing them breaks existing identities, password verification or archive restoration.

## Client and transport

Android persists only its opaque session token, ID, username and endpoint/pin metadata in an AES-GCM vault backed by Android Keystore, under noBackupFilesDir. Raw orders/passwords are excluded by a persistence whitelist; input fields disable state saving, content capture, autofill and personalized IME learning. Credential dialogs use FLAG_SECURE; fields clear on submission/dismissal. No request-body logging is added.

Login/sync use HTTPS, normal platform certificate trust and mandatory **certificate-chain SPKI SHA-256 pins** checked in the TLS handshake before HTTP credentials are transmitted. Redirects and system HTTP proxy routing are disabled for this transport. Up to four pins support deliberate certificate-key rotation. The live configuration includes the verified leaf and Google Trust Services WE1 issuing key, so leaf renewal under that issuer does not require weakening TLS checks. Missing pins fail closed. Current sessions retain their original endpoint; signed configuration may rotate pins for that same endpoint.

Domestic acceleration remains enabled through Android's existing GitHubMirrors for public, signature-verified configuration. The live Singapore backend reads official GitHub directly with a one-hour cache. Android retains domestic acceleration. The backend additionally supports `GITHUB_PUBLIC_MIRRORS=true` for public control.json + control.json.sig via jsdmirror/jsDelivr, verifies the existing ECDSA P-256 signing key and rejects serial rollback, then falls back to the authenticated official GitHub API. These requests contain **no order, password, session token or GitHub token**. GitHub writes and archive recovery use official api.github.com only. A trusted host network route may be needed for those operations; do not send authenticated API traffic through anonymous GitHub mirrors. Mirror signatures authenticate content; mirrors can still lag a new publication.

## Persistence, synchronization and GitHub request reduction

- Private PostgreSQL tables are the hosted durable working store (SQLite for the optional local adapter). GitHub holds encrypted compressed checkpoints in `accounts/v1/` in the existing public repository. Repository write credentials stay in function secrets. The live deployment reuses the existing SalamCloud/gh GitHub authorization through GITHUB_TOKEN; the GitHub App installation-key adapter remains supported. No GitHub credential goes to the APK.
- Ordinary API calls validate the session in the service's own database; there is **no GitHub authentication heartbeat**. Sessions expire after 30 days. The order list is cached for one hour and consulted only during authentication, not playback or sync. Order revocation affects later logins after the cache refresh; it does not forcibly revoke already-issued sessions.
- Android coalesces edits after 15 seconds of quiet with a 60-second maximum wait; foreground entry pulls after five minutes since the last successful sync. Retries back off and stop after five attempts. Sync replies return only records changed since the client cursor, plus submitted keys needed to resolve retry conflicts; an unchanged pull returns no library records. There is no periodic playback poll. Multi-device updates appear on these sync triggers or manual sync, not via realtime push.
- Only online favorites, artists/albums/playlist collections and user playlists/track order are exported. Local music is excluded. Guest data and each account have separate files/preferences; explicit guest merge is offered. Logout restores guest data and retains the old account's unsent journal.
- Immutable batches of up to 500 operations, per-record revisions and device sequence counters make retries idempotent. Independent records merge. A stale conflict on the same record retains the server version and is reported to the user. Durable client journals retain pending and in-flight edits through restarts.
- Dirty accounts are checkpointed after ten minutes, at most 20 accounts and approximately 1.8 MB of account ciphertext per batch, plus the username directory if dirty. Backlogs drain no faster than once a minute. One batch normally needs **five GitHub REST requests**, regardless of the number of edits combined. GitHub App installation tokens are cached. No changes means no checkpoint requests.
- Concurrent repository publications use non-forced branch updates. A failed commit keeps dirty state and retries with backoff; a commit in flight never clears newer account mutations. No Actions workflow is added.

For a concrete 1,000-DAU workload with three separated editing sessions and three foreground pulls per person per day, expect roughly **6,000 account-service sync requests/day**, plus occasional login and profile operations. If edits become 3,000 account checkpoints/day and batches fill with 20 accounts, GitHub checkpoint traffic is roughly **750 REST requests/day**. Small batches, size limits, retries and recovery reads increase that number. The same number of individual song edits can produce very different checkpoint counts depending on timing. This is a workload estimate, not a measured load test or a free-hosting guarantee.

Initial limits: 30 authentication attempts/IP/15 minutes; 12/identifier/15 minutes; 1,200 globally/hour; 100 new enrollments/day. The enrollment rate can be adjusted for launch without changing the 1,000-DAU design. At most 64 active service requests are admitted before backpressure. Each account supports 6,000 records including tombstones, a 750 KB document and 32 device sequences. Old device sequences are not yet pruned.

## Operational handoff

- Production uses Supabase Edge Functions and a PostgreSQL advisory transaction lock, which serializes mutations across separate function instances. A durable lease prevents duplicate concurrent GitHub flushes. The private state schema has RLS enabled and no client policies; Data API was disabled. Source also supports Node SQLite and an optional Cloudflare Durable Object adapter. The exact 600,000-iteration PBKDF2 workload passed both Node tests and live registration/login/password-change calls on Supabase; Cloudflare runtime/CPU compatibility is not validated. Do not lower the work factor automatically to fit a free tier.
- GitHub checkpoints are full compressed encrypted snapshots. Encryption limits Git delta compression; history growth is cumulative. Long-term high-volume usage needs measured retention and/or an incremental archive format. A low request count does not establish low repository storage use.
- GitHub-only recovery loses changes after the latest checkpoint, possibly including a recent password change or username change. Back up the live working database safely, preserve all three secrets, and restore live state preferentially. Archive restoration discards sessions, but a restored older password verifier remains older until recovery reconciles it. Device sequence rollback can require explicit journal reconciliation.
- The public repository exposes opaque ID filenames and commit timing, while account records and password metadata are encrypted. The service manages archive keys; this is server-side archive encryption. Deleting a current file does not erase Git history.
- Live end-to-end checks passed for enrollment, both login forms, wrong-password rejection, simultaneous writes from two independent sessions, delta sync, deletion, playlist editing, rename, password change, old-session revocation, and automatic encrypted GitHub checkpoints. This is functional verification, not a 1,000-user load test. No APK build, device installation or VM interaction was performed.

## Host checks

The current host suite has 16 passing checks. `npm test` exercises order normalization, secret-derived identities, password salt/pepper and work factor, both login modes, immutable enrollment, username uniqueness, password/session rotation, cross-account authorization, no GitHub lookups on normal sync, merges, encrypted checkpoint recovery, archive failures and concurrent writes, SQLite transactions, and public-mirror signature/serial rejection. Tests use memory fixtures and do not contact GitHub or start a network server.
