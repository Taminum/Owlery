# Security and privacy threat model

## Secrets
- TLS required between browser and server and between agents and ingest.
- Encrypt panel API tokens using AES-256-GCM with cryptographically random 96-bit nonce per encryption; AAD binds ciphertext to panel UUID and key version.
- Master key held outside database, e.g. Docker secret/host secret store; never in source, git, frontend, logs, DB dump, or metrics.
- Support versioned key rotation and re-encryption.
- Token display after save: `configured` only; replace/rotate workflow; test connection server-side.
- API tokens least privilege read-only where supported; separate credential per panel.
- Agents use independent revocable enrollment/ingest credentials; do not share panel API tokens.

## SSRF and outbound API probing
- Require `https://` URLs, strict host/port validation; reject URL credentials, fragments, unexpected paths.
- Default deny loopback, link-local, multicast, metadata endpoints and RFC1918/private networks; allow admin-approved internal endpoints via explicit allowlist only.
- Resolve DNS and validate **all** returned A/AAAA addresses; pin validated address during connection, preserve SNI/certificate verification; revalidate on every connection and block redirects.
- Connection tests and sync jobs use the same hardened HTTP client.
- Bound response size, timeouts, concurrency and redirects (disabled).
- Do not offer `skip TLS verification` switch.

## Authentication and authorization
- Password hash Argon2id; secure HttpOnly SameSite cookies; CSRF protection for state-changing requests.
- RBAC scopes per panel: admin, operator, viewer. All SQL queries enforce allowed `panel_id` server-side.
- Rate-limit auth, API tests and ingest.
- No anonymous access to dashboard or raw traffic.
- Audit panel creation, connection tests, token rotation, access changes, exports and deletions without secrets.

## Privacy
- Work traffic metadata is sensitive: domains/IPs, timestamps, account IDs.
- Default raw event retention 30 days configurable per panel; aggregate retention separately.
- Mask client public IP for viewer role; support configurable pseudonymization.
- No external enrichment/AI service by default; opt-in only.
- Export subject to RBAC and audit; deletion job with progress and verification.

## Agent isolation
- Agent read-only log mount where available, unprivileged process, read-only rootfs, minimal capabilities, resource limits.
- Bounded disk spool; explicitly report loss if capacity exhausted.
- Verify event batch schema, max size and authentication; prevent replay with batch/event IDs.
- Never mount Docker socket into public API/web service.
- Do not execute remote commands from agent controller.

## Implemented in M1 (as built)
- Sessions: opaque 256-bit token in an HttpOnly, SameSite=Strict cookie (Secure by default); only its SHA-256 is stored;
  12 h absolute / 2 h idle; ended by password change, reset or disable.
- CSRF: per-session token (HMAC of the session id under a key derived from the master key) in `X-CSRF-Token`, plus a
  same-origin check on `Origin` and `Sec-Fetch-Site`. The token is held in memory by the SPA, never in storage.
- Sign-in answers identically for unknown, wrong, disabled and locked accounts and does equal work for each.
  Lockout: after 5 failures, 30 s doubling to 15 min. The attempted username is never logged.
- SSRF client (`internal/safehttp`): all resolved addresses are checked on every connection and the validated
  address is the one dialled; redirects refused; size and time bounded; ambient proxies ignored; legacy IPv4
  spellings (`127.1`, `0x7f.0.0.1`) rejected because a host name's last label must contain a letter.
- Token encryption, rotation and AAD binding as specified; `api rotate-keys` is compare-and-set and verifies.
- Out-of-scope panels are indistinguishable from missing ones (404 on panel routes, 403 on `panel_ids`).
- Audit holds action, actor, panel, request id and non-secret metadata; tests assert no token or password appears.
- Known gaps: no MFA, no SSO, no e-mail password reset; limits are in-memory per process (fine for one instance).
