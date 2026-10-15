# Operations

## Secrets
Nothing secret lives in environment variables or in git. The API reads files:

| File | Purpose |
|---|---|
| `MASTER_KEY_FILE` | keyring, one `<version>:<base64 32 bytes>` per line; the highest version encrypts |
| `BOOTSTRAP_PASSWORD_FILE` | first owner's password, used once when no account exists |
| `TRUSTED_CA_FILE` | optional admin-managed CA bundle (PEM) for panels that use an internal CA |

Development: `deploy/init-dev-secrets.ps1` (or `.sh`) writes `./secrets/*` once and prints nothing. Open the
files yourself. `./secrets` is git- and docker-ignored.

**Back up the master key separately from the database.** Without it, stored panel tokens cannot be decrypted;
with only the database dump, they are useless to an attacker.

## Keys
```
api gen-key -version 2 >> master_key      # add a new key; keep the old line
# set ACTIVE_KEY_VERSION=2 (or rely on "highest wins"), restart
api rotate-keys                           # re-encrypts every token, verifies, compare-and-set
# once it reports already_current for all panels, the old line can be removed
```
`rotate-keys` fails loudly, changing nothing, if a token needs a key that is no longer in the file.

## Accounts
First owner: `BOOTSTRAP_OWNER` + `BOOTSTRAP_PASSWORD_FILE` (compose does this), or
`api create-owner -username NAME -generate-to /path/file` (writes a random password to a 0600 file).
After that, owners manage accounts in Settings. Lost owner password with no other owner: run `create-owner`
for a new account with the database reachable.

## Production checklist
- `COOKIE_SECURE` unset (defaults to true) and the site served over HTTPS only.
- `SEED_DEMO` unset; no `mockpanel` service; no `ALLOW_PRIVATE_HOSTS` unless a panel really lives on a private
  address, and then only its exact host name.
- `TRUSTED_PROXIES` set to the reverse proxy's address range, and that proxy sets `X-Real-IP`. Without it, rate
  limits and audit see the proxy's IP for everyone.
- The reverse proxy passes `Host` **with the port** (`$http_host` in nginx). The API compares it with the browser's
  `Origin`, and refuses sign-in on a mismatch.
- Postgres is not published; the database user is not a superuser after the first migration (the migrations
  need `CREATE EXTENSION pgcrypto` once).
- `ALLOWED_PORTS` stays `443` unless a panel is deliberately on another port.
- Backups encrypt the database dump; restore needs the master key.

## What is logged
Method, path (never the query string), status and duration, with a request id. Never bodies, tokens, passwords
or attempted usernames. Failed sign-ins record the reason code and, when the account exists, its id.

## Rate limits (per process)
Sign-in 10/min per IP; probe 10/min per account; test 6/min per account and panel; manual sync 3/min per
panel; all other writes 60/min per account.

## Security module
- **Retention.** Security events, snapshots that recorded a change, and certificate observations are kept
  180 days and purged hourly in batches of 5000. The audit log, the alerts table's own 90-day rule and all
  analytics are not touched by it.
- **Alerts.** Three kinds join the existing ones: `sec_agent_silent` (an enrolled agent not heard for 5 minutes),
  `sec_tls` (expired, not valid, or inside 30 days) and `sec_port` (a port that started answering after its
  baseline and is not marked expected, or an expected one that does not answer). Each belongs to the first panel the
  server is linked to; a server linked to none has no panel and its alerts are shown to the owner only, when no
  panel filter is chosen. The alerts page is the only channel; there is no push notification.
- **Backups.** The security tables are in the same database as everything else, so `backup.sh` covers them.
- **Checkers.** A host whose agent runs with `-probe` is asked to make the external checks of the *other*
  servers, so that they are seen from outside. It is a decision per host (see SECURITY_AGENT.md); with none,
  or when none qualifies, the RemnaScope server checks and the result is marked not independent.
- **Discovery.** TLS endpoints are found on their own where a certificate is presented. The port scan is off
  per server until someone turns it on; it tries a fixed list of about sixty ports on registered IP addresses
  once a day.
- **Rollback.** Migrations 0021 to 0028 only add tables and columns (and widen one `CHECK` on
  `security_port_endpoints.source`). An older API ignores them; nothing existing is changed, so going back to a
  previous release needs no database step.
- **More.** [SECURITY_THREAT_MODEL.md](SECURITY_THREAT_MODEL.md) says what the module defends against and what
  it does not; [SECURITY_DNS_REPORT.md](SECURITY_DNS_REPORT.md) is the acceptance report.

## DNS Map
- **Resolvers.** Studies ask 1.1.1.1 and 8.8.8.8 over UDP/TCP port 53, and the zone's authoritative servers when
  their address is public. Outbound port 53 must be open from the API host.
- **Retention.** DNS changes and run records are kept 180 days, separately from Security. Maps and the current
  record sets are not purged; archiving a map keeps its history.
- **Alerts.** `dns_check_failed` and `dns_change` belong to no panel and are shown to the owner under
  "Сетевая разведка". A record set that flips often is marked volatile and raises no alert.
- **Rollback.** Migration 0026 only adds tables; an older API ignores them.
