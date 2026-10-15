# Installing RemnaScope

Production stack: Caddy (80/443, Let's Encrypt) → nginx (UI, `/api`, `/ingest/`) → API → PostgreSQL.
Only Caddy publishes ports. Memory limits: postgres 512M, api 256M, web 64M, caddy 128M, so a 1 GB VPS is enough.

## Requirements
- A Linux server with Docker and the Compose plugin.
- A DNS name pointing at it. Let's Encrypt fails until it resolves (`nslookup scope.example.com 1.1.1.1`).
- Ports 80 and 443 free.
- A Remnawave panel reachable over HTTPS from the server, and an API token for it (read-only is enough).

## 1. Get the files and create secrets
```bash
git clone https://github.com/Taminum/RemnaScope.git && cd RemnaScope/deploy/prod
sudo ./init-secrets.sh scope.example.com v0.2.0
```
The arguments are your host name and the release tag (see the [releases](../../../releases) page; `latest` also works).
The script creates, once and without printing anything:

| File | Purpose |
|---|---|
| `secrets/master_key` | encrypts the panel tokens stored in the database. **Back it up away from this server.** |
| `secrets/owner_password` | password of the first account, `owner` |
| `secrets/gemini_api_key` | optional, empty; see [AUTOCLASSIFY](AUTOCLASSIFY.md) |
| `.env` | host name, database password, release tag |

Running it again keeps what exists.

## 2. Start
```bash
sudo docker compose -f compose.prod.yml up -d
sudo docker compose -f compose.prod.yml ps
sudo docker compose -f compose.prod.yml logs caddy | tail -5    # certificate obtained?
```
Open `https://scope.example.com`, sign in as `owner` (`sudo cat secrets/owner_password`) and change the password in
Settings. Turn on two-factor authentication there as well.

Images are pulled from `ghcr.io/taminum/remnascope-api` and `-web`. If the packages are private, run
`docker login ghcr.io` with a token that has `read:packages`, or build your own (below).

## 3. Connect a panel and the nodes
1. **Panels → Add panel**: name, HTTPS URL of the panel API, API token. The wizard tests the connection before saving.
2. On the panel's page open **Агенты** (Agents) and create an agent for a node; copy the token (shown once).
3. Install the agent on the node as described in [AGENT](AGENT.md). The binaries are attached to every release.
   The agent URL is `wss://scope.example.com/ingest/v1`.

Optional parts: a router agent (`deploy/router`) for devices behind a shared account, and an AmneziaWG collector
(`deploy/agent/awg`, [AWG_COLLECTOR](AWG_COLLECTOR.md)).

## Updating
```bash
cd RemnaScope/deploy/prod && git pull
sudo sed -i 's/^RELEASE=.*/RELEASE=v0.1.3/' .env      # the new tag
sudo docker compose -f compose.prod.yml pull && sudo docker compose -f compose.prod.yml up -d
```
Database migrations run when the API starts, under an advisory lock. Read the release notes first.

## Rollback
Set `RELEASE` back to the previous tag and run `up -d` again. Migrations only add things, but if a release says
otherwise, restore the database dump taken before the update.

## Backups
`backup.sh` writes a nightly gzip'd `pg_dump` and keeps 14 days. Cron: `17 3 * * * /path/to/deploy/prod/backup.sh`
. Restore: `gunzip -c backups/remnascope-DATE.sql.gz | docker compose
-f compose.prod.yml exec -T postgres psql -U remnascope remnascope`. A restore needs the same `master_key`.

## Building the images yourself
```bash
docker build -f deploy/api.Dockerfile --target api -t remnascope-api:local .
docker build -f deploy/web.Dockerfile -t remnascope-web:local .
```
Then put `API_IMAGE=remnascope-api`, `WEB_IMAGE=remnascope-web` and `RELEASE=local` into `.env`.
`deploy/prod/ship.sh <ssh alias>` does the same and sends the images to a remote server over SSH.

## Behind your own reverse proxy
Remove the `caddy` service, publish `web` on a local port, and make your proxy: terminate TLS, pass `Host` **with the
port**, add `X-Forwarded-For`, and allow WebSocket upgrades on `/ingest/`. Set `TRUSTED_PROXIES` for the API to
your proxy's range. See the production checklist in [OPERATIONS](OPERATIONS.md).

## Hardening notes
- The UI is reachable from the internet behind login, per-IP and per-account rate limits, lockout, CSRF and secure
  cookies. To close it to the public, put an IP allow-list in the Caddyfile for everything except `/ingest/*`.
- Remove everything: `docker compose -f compose.prod.yml down` keeps the data; `down -v` deletes it.
