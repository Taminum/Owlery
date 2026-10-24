# RemnaScope

Self-hosted monitoring for [Remnawave](https://github.com/remnawave) / Xray setups: traffic analytics over several
independent panels and their nodes, the state of the servers they run on, AmneziaWG management, security and
Telegram notifications, with honest attribution of what is measured and what is not.

> The interface is in **Russian** (all strings live in `apps/web/src/i18n`, so adding a language is a matter of
> translating those files). Documentation is in English unless a file says otherwise. A short Russian guide is in
> [README.ru.md](README.ru.md).

## What it does

**Traffic and users**
- **Several panels at once.** Each Remnawave panel keeps its own credentials, nodes, users and retention. Views are
  isolated per panel; panel API tokens are encrypted at rest (AES-256-GCM, versioned keys, rotation).
- **Traffic from the nodes.** A small read-only agent follows the Xray access log of a node and ships it over an
  outbound WebSocket, with a bounded disk spool and exact reporting of anything dropped. The speed each node carries
  right now is read from the panel.
- **Sites, domains and services.** Connections are grouped by site, service and category (rule based, with an
  optional, off-by-default AI assistant that proposes categories for unknown sites).
- **Subscriptions and limits.** When each user's subscription ends and how much of the traffic limit is used, with
  alerts for subscriptions that end within three days and for users past 90% of their limit.
- **Devices behind a router.** A router agent (sing-box Clash API + DHCP leases, e.g. OpenWrt) names the devices
  behind a shared VPN account and counts their bytes.
- **What changed.** A daily page (and message) with the last 24 hours: new sites, new devices, security events.

**Servers**
- **Server resources.** CPU, memory, disks, network, uptime and what each machine is (system, kernel, CPU model);
  history for a week, and which programs, containers and services use the processor and the memory (names only, never
  a command line). Alerts for a nearly full disk and for a processor or memory that stays busy.
- **DDoS detection.** Traffic or packet rate far above what the server usually has, half-open TCP connections, and the
  kernel's own signs (SYN cookies, a full listen queue) raise a "looks like a DDoS" alert. It says what it saw and
  admits that a legitimate surge looks the same.
- **Server security.** A read-only agent reports Fail2ban, listening sockets and firewall rules; the server checks known
  public ports and TLS certificates from outside; a journal, alerts and 180-day retention; the owner can ban or unban one
  address through a narrow helper, with confirmation and an audit trail.
- **DNS Map.** The publicly observable DNS records of a domain, how they link, and what changed: two resolvers must
  agree before a change is recorded, authoritative servers are compared, and DNSSEC is reported as not checked.
- **Payments.** The owner's own list of what is paid for and when (servers, domains), with reminders, a "paid" button
  that moves the date on, and what it all costs a month.

**AmneziaWG**
- Read-only collector (devices, handshakes, totals), optional device management (add, revoke, rename, QR configs,
  per-device limits and expiry) and an optional traffic sensor that adds AmneziaWG traffic to the site and domain lists.
- **Containers from the page.** On a host that opted in, install or remove an AmneziaWG container, take an encrypted
  backup, restore it, or move a container to another host with the same keys, so devices only need the new address.
- Alerts when a container runs without an interface, and when the tools inside it are of another generation than the
  host's kernel module (the case that breaks the interface after a reboot).

**Telegram**
- Alerts as they open and close, a daily summary, and **bot commands** (`/stats`, `/servers`, `/alerts`, `/bans`,
  `/certs`, `/pay`, `/awg`, `/users`, `/dns`, `/mute`). Per channel: which groups of alerts are announced, quiet hours
  (urgent ones still come), reminders for what stays open, mute. See [docs/TELEGRAM.md](docs/TELEGRAM.md).

**Everyday**
- Network intelligence (IP, domain, ASN; geo and ASN data bundled from DB-IP Lite), live view, alerts, endpoint
  probes, activity heat map, per-country view.
- **Kawaii Mode** (off by default): a colour theme and a mascot that comments on alerts. The mascot's pictures are an
  optional add-on pack, not part of this repository; see [docs/KAWAII_MODE.md](docs/KAWAII_MODE.md).
- **Security by default.** Argon2id accounts with roles and optional TOTP, rate limits and lockout, CSRF, strict
  security headers, SSRF-guarded outbound requests, no secrets in environment variables.

What it deliberately does **not** do: invent numbers. Bytes come only from panel counters, the router or the AmneziaWG
sensor, and each figure says where it came from. If a source is not connected, the UI says "no data", not zero.

![Overview with demo data](docs/screenshots/overview.png)

Screenshots come from the dev stack with invented data (`cmd/demodata`).

| | |
|---|---|
| ![Sites](docs/screenshots/sites.png) **Sites** | ![Domains and services](docs/screenshots/domains.png) **Domains and services** |
| ![AmneziaWG](docs/screenshots/awg.png) **AmneziaWG** | ![Network intelligence](docs/screenshots/intel.png) **Network intelligence** |

Also: [nodes](docs/screenshots/nodes.png), [panels](docs/screenshots/panels.png).

## Quick start (production)

You need a Linux server with Docker, a DNS name pointing at it, and ports 80/443 free (Caddy gets the certificate).

```bash
git clone https://github.com/Taminum/RemnaScope.git && cd RemnaScope/deploy/prod
sudo ./init-secrets.sh scope.example.com latest     # host name, release tag (latest or e.g. v0.3.2); creates secrets and .env, prints nothing
sudo docker compose -f compose.prod.yml up -d       # pulls ghcr.io/taminum/remnascope-{api,web}
sudo cat secrets/owner_password                     # sign in at https://scope.example.com as "owner"
```

Then add a panel in the UI, create an agent for a node, and install it as described in
[docs/AGENT.md](docs/AGENT.md). To see the servers' load, security and flood alerts, add each server on the
**Безопасность** page and install the security agent ([docs/SECURITY_AGENT.md](docs/SECURITY_AGENT.md)). For Telegram,
see [docs/TELEGRAM.md](docs/TELEGRAM.md). Full guide, backups, updates and rollback: [docs/INSTALL.md](docs/INSTALL.md).

Back up `secrets/master_key` somewhere other than the server: without it the stored panel tokens cannot be decrypted.

If `docker compose` answers `403 Forbidden` for an image, the image packages are private: see the note in
[docs/INSTALL.md](docs/INSTALL.md).

**The mascot** (Kawaii Mode) is not in the images. If you were given an `ember-pack.tar.gz`, run
`./install-ember.sh ember-pack.tar.gz` in `deploy/prod`; nothing is rebuilt.

## Try it locally (demo data, mock panels)

```bash
./deploy/init-dev-secrets.sh        # or .ps1 on Windows; writes ./secrets once, prints nothing
docker compose up -d --build        # http://localhost:8088, bound to 127.0.0.1 only
```

Sign in as `owner` with the password from `secrets/owner_password`. The dev stack includes two mock Remnawave panels
(`mock-home.demo.test:8443`, `mock-work.demo.test:8444`, tokens in `secrets/mock_*_token`; tick "trust the admin CA")
so you can walk through the connection wizard without a real panel. Mock panels and `SEED_DEMO` are for development
only and are not part of the release images.

## Components

| Part | Where | Notes |
|---|---|---|
| API + workers | `cmd/api`, `internal/` | Go, PostgreSQL, migrations embedded and applied on start; the Telegram bot and the alert evaluator run here |
| Web UI | `apps/web` | React, TypeScript, Tailwind, served by nginx behind Caddy |
| Node agent | `cmd/agent` | read-only; also router and AmneziaWG modes |
| AmneziaWG sensor | `cmd/awgsensor` | optional, passive packet parser, drops privileges |
| Security agent | `cmd/secagent` | read-only: Fail2ban, sockets, firewall, and the host's load; also the Fail2ban helper (`secagent helper`), see [docs/SECURITY_AGENT.md](docs/SECURITY_AGENT.md) |
| Deploy files | `deploy/` | prod compose + Caddy, systemd units, router init script, AWG helpers, the container list unit |

Release binaries (agent, sensor, security agent) and checksums are attached to each [GitHub release](../../releases).

## Development

```bash
go vet ./cmd/... ./internal/... && go test ./cmd/... ./internal/... -p 1   # database tests need TEST_DATABASE_URL (see below)
cd apps/web && npm ci && npm run lint && npm test && npm run build
```

Database tests need an admin connection to any Postgres, e.g. `TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55432/postgres`;
each test gets its own database and they are skipped without it. Run Go tests as `./cmd/... ./internal/...`, not
`./...`, because a local `apps/web/node_modules` can contain stray Go files. `-p 1` runs the packages one at a time,
which is steadier when the packages share one database server.

To fill the analyzer pages with invented traffic (a dev database only, never a real one): `go run ./cmd/demodata -dev-database` with `DATABASE_URL` set; then `node apps/web/scripts/readme-shots.mjs` retakes the screenshots.

Without Docker: a Postgres, `go run ./cmd/api` (needs `DATABASE_URL`, `MASTER_KEY_FILE`) and
`cd apps/web && npm run dev` (http://localhost:5173, `/api` proxied to :8080).

## Documentation

- [INSTALL](docs/INSTALL.md): production install, updates, backups, rollback, the optional mascot pack
- [AGENT](docs/AGENT.md): installing the node agent (what it can and cannot do)
- [OPERATIONS](docs/OPERATIONS.md): secrets, key rotation, accounts, rate limits, production checklist
- [TELEGRAM](docs/TELEGRAM.md): notifications, bot commands and fine tuning
- [SECURITY](docs/SECURITY.md), [ARCHITECTURE](docs/ARCHITECTURE.md), [INGESTION](docs/INGESTION.md),
  [API_SPEC](docs/API_SPEC.md), [DATA_MODEL](docs/DATA_MODEL.md)
- [SECURITY_AGENT](docs/SECURITY_AGENT.md) (also the host's load and the container names), [SECURITY_CHECKS](docs/SECURITY_CHECKS.md),
  [DNS_MAP](docs/DNS_MAP.md)
- [AWG_COLLECTOR](docs/AWG_COLLECTOR.md) (AmneziaWG, Russian), [AUTOCLASSIFY](docs/AUTOCLASSIFY.md) (AI categories, Russian)
- [KAWAII_MODE](docs/KAWAII_MODE.md), [REMNAWAVE_API_RESEARCH](docs/REMNAWAVE_API_RESEARCH.md) (what else the panel's API can tell, Russian)

## License

[AGPL-3.0](LICENSE): free to use, change and share, including commercially; if you modify it or run a modified version as a network service, you must publish your source under the same license. The bundled GeoIP and ASN data are the free DB-IP Lite databases, licensed
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/); attribution: IP geolocation by [DB-IP](https://db-ip.com).
