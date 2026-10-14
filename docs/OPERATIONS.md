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
