# Report: Security module and DNS Map (v0.3)

Written against the acceptance list of the specification (§15, items 1 to 14). Everything below was run or
read from the code of `master`; what was not verified is said so.

## What exists

**Security** (`/security`): servers (VPS) linked to panels and nodes, with scoped access; a read-only agent
with an optional Fail2ban helper; Fail2ban state, bans and counts; listening sockets; firewall rules as a
structure and as a comparison between readings; public TCP and TLS checks from the server or from an
independent checker; one journal for all servers; alerts; an overview per server; manual ban and unban with
confirmation, verification and audit; opt-in discovery.

**DNS Map** (a tab of Network intelligence): a domain's observed records as a map and a table, history of
changes confirmed by two resolvers, run records with the authoritative servers, links from addresses to
registered servers.

## Acceptance list

| # | Item | State | Where it is shown |
|---|---|---|---|
| 1 | Create a VPS by hand, link to existing panel/node, no duplication | done | `security_test.go`, UI `Security.tsx` |
| 2 | Agent over an outbound channel, real data, no shell | done on 5 hosts | `docs/SECURITY_AGENT.md`; running on owlery, panel-ru, exit-nl, exit-2, owlnet |
| 3 | Fail2ban jails, bans, history; survives restart | done, with a limit | journal from state comparisons, five-second check for a moved ban set; a ban and unban between two comparisons is counted (`fail2ban.bans_unobserved`), not named |
| 4 | Ban/unban: confirmation, rights, verified result, audit, no double run | done | `security_ban_test.go` (end to end with the real agent and helper) |
| 5 | Local and public ports apart; new ports and bind changes visible; unchecked is not closed | done | Ports tab, `secevents` |
| 6 | Known TCP every 60 min, TLS every 24 h, vantage, SNI and chain, 30/14/7/3 days once | done | `secchecks`, `secevents` tests |
| 7 | Firewall with source and diff; cannot be changed | done | Firewall tab: structure, changes, text; no write path exists |
| 8 | One journal, filters, no duplicate events per poll, wired to alerts | done | `/security` journal, `alerts` |
| 9 | 180-day retention only on security history | done | `TestSecurityRetentionRemovesOnlyOldSecurityHistory` |
| 10 | No false green | done | overview `unknown`/`attention`, stale states, "no agent" |
| 11 | Auth/CSRF/RBAC contracts, no SSRF, no arbitrary shell | done | [SECURITY_THREAT_MODEL.md](SECURITY_THREAT_MODEL.md) |
| 12 | Migrations and tests pass, no regression | done | below |
| 13 | Docs, API schema, connection guide, rollback | done | `docs/SECURITY_AGENT.md`, `SECURITY_CHECKS.md`, `DNS_MAP.md`, `API_SPEC.md`, `OPERATIONS.md` |
| 14 | This report | this file | |

## Architectural decisions

1. **A separate agent.** `cmd/secagent` with its own table, endpoint and capabilities. The Xray/AWG/router
   agents and their protocol did not change.
2. **A helper for the one privileged thing.** Fail2ban's socket belongs to a small service of its own; the
   agent has no access to it and only asks for five fixed operations.
3. **Commands are durable and one-shot.** Intent and outcome are in the audit log; an ID is persisted before it
   runs; a command that is not answered in time is `unknown`, and the next state read settles it.
4. **Vantage on every external result.** The server's own check is never called independent. A security agent
   whose host chose `-probe` can check other servers; it is independent only for a server that is not its own.
5. **Alerts are state, the journal is history.** Open alerts are keyed on `(kind, subject)` and close when the
   condition goes; journal events come from differences between states, with a silent first baseline.
6. **Own DNS client.** `dnsmessage` over UDP and TCP, two public resolvers plus the authoritative servers; a
   change counts only when both resolvers agree; DNSSEC is never claimed validated.
7. **Text first for the firewall.** The agent stores canonical rule text; the screen reads it into tables and
   chains and compares readings line by line. The reader does not interpret what a rule allows.
8. **Discovery is opt-in and bounded.** A fixed port list, registered IPs, once a day, per server, off by
   default; TLS endpoints are found only by a presented certificate on known candidates.

## Changed files

109 files against the starting point of the work (`14a619f`): 90 new, 19 changed, about 18,000 lines including
tests.

- `migrations/0021` to `0028`: VPS and links, agent state and snapshots, events, checks, alerts, commands, DNS
  Map, vantage, discovery. All add tables or columns; none changes an existing one except to extend a
  constraint (`security_port_endpoints.source`).
- `cmd/secagent`, `internal/secagent`, `internal/f2bhelper`, `internal/seccollect`, `internal/secproto`,
  `internal/secingest`, `internal/secops`: the agent, helper, wire format, ingest and command/probe hub.
- `internal/secprobe`, `internal/secchecks`, `internal/secevents`, `internal/secfw`: probes, the worker and
  discovery, state differences, firewall reader and diff.
- `internal/store/security_*.go`, `internal/store/dnsmap.go`: persistence.
- `internal/httpapi/security*.go`, `internal/httpapi/dnsmap.go`: routes.
- `internal/dnsmap`, `internal/dnsworker`: DNS client and scheduler.
- `internal/alerts/security.go`, `internal/alerts/dns.go`: alert conditions.
- `apps/web/src/pages/Security.tsx`, `apps/web/src/pages/DnsMap.tsx`, `apps/web/src/components/Security*.tsx`,
  `DnsGraph.tsx`, `i18n/ru.security.ts`, `i18n/ru.dns.ts`: the screens.
- `deploy/secagent/*`: units and the checker drop-in example.
- `docs/*`: the documents named above.

## How it was tested

```
TEST_DATABASE_URL=postgres://...  go test ./... -count=1 -v
cd apps/web && npx tsc --noEmit -p . && npx eslint src && npx vitest run && npm run build
```

Results on `master` at the time of writing:

- Go: 37 packages `ok`, 484 top-level tests passed, 0 failed, 2 skipped (`TestLiveICMPAndPorts`,
  `TestLiveTrace`: they need raw network access that the test host does not give; both are older than this work).
- Web: 16 files, 134 tests passed; type check, lint and production build clean.
- CI (Go, web, migrations) is green on every merged pull request (#1 to #10).
- End to end with real components: a real agent and helper against the real ingest, for ban/unban, offline and
  reconnect, replay, and probes through the checker path.

Not covered by an automated test, and checked only by hand or not at all:

- The production UI as an owner (the work was done without an owner session on the production host; screens
  were exercised through the test suite and the local stack, and data through the database).
- Fail2ban versions without `fail2ban-client banned`: the five-second check switches itself off by design and is
  covered by a unit test, not by a real old Fail2ban.
- Distributions other than the ones on the five hosts (Debian and Ubuntu with systemd).

## Limits

- Platforms: systemd Linux with Fail2ban, `ss`, and nftables or iptables. No Windows, macOS, or OpenRC.
- Firewall: UFW is read as whatever backend it uses; there is no UFW-specific view.
- Fail2ban history is state-based; the log is not read (a privilege decision for the host's owner).
- Checks see only what a vantage sees; an IPv6-only path, a geo-block or an upstream filter can differ.
- The scan list is about sixty ports. It is a finder of the usual, not an inventory.
- DNS Map does not validate DNSSEC and does not enumerate subdomains it was not told about.
- Alerts appear on the alerts page and the sidebar badge; there is no push channel (not built, by decision).
- A host that enables `-probe` is trusted to say what it saw about *other* servers.

## Manual steps for a new installation

1. Deploy the release; migrations apply on start. Take a database backup first.
2. For each server: add it under Security, link it to its panel, press "Создать агента" and follow the install
   steps in [SECURITY_AGENT.md](SECURITY_AGENT.md#install) with the token (shown once). The helper and unit
   files are in `deploy/secagent/`.
3. To use a checker: on one host that is not a target of the others, add the drop-in
   `deploy/secagent/probe.conf.example`, `systemctl daemon-reload`, restart the agent.
4. To find unlisted ports on a server: open it, "Поиск неизвестных портов", turn it on. Off is the default.

## Rollback

Migrations only add tables and columns (and widen one `CHECK`). A previous release ignores them, so going back is
a deploy of the older image with no database step. A previous API does not know the `probe` message or the
`/overview`, `/firewall/diff`, `/vps-by-address` routes; agents that still announce `probe` simply are not asked.
Stopping the agents loses nothing: they hold no state the server needs apart from the list of command IDs
already run, which should be kept.
