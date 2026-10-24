# RemnaScope REST API v1 (proposed)

All routes `/api/v1`, authenticated except login and health; JSON errors `{code,message,details?,request_id}`.
All list endpoints paginate with `cursor` and `limit` and enforce panel RBAC.

## Panel connections
- `POST /panels/probe` body `{base_url,api_token,requested_capabilities}`; no persistence; returns `{reachable,tls_ok,authenticated,api_version?,capabilities,nodes_preview?,checks:[{name,status,latency_ms,error_code?}]}`; heavily rate limited and SSRF protected.
- `POST /panels` body `{name,base_url,api_token,sync_options,retention_days}`; encrypt token, create panel; returns metadata only.
- `GET /panels`, `GET /panels/{id}`, `PATCH /panels/{id}` (never expose secret).
- `POST /panels/{id}/test` re-probes stored secret server-side.
- `PUT /panels/{id}/token` body `{api_token}`; rotate encrypted secret; audit.
- `POST /panels/{id}/sync` manual sync; rate limited.
- `POST /panels/{id}/disable`; `DELETE /panels/{id}` requires explicit data-retention choice and confirmation.

## Data and analytics
- `GET /overview?panel_ids=...&node_ids=...&from=...&to=...`
- `GET /connections?...&cursor=...`
- `GET /destinations?...&group_by=host|ip|service`
- `GET /traffic/samples?...` returns `source`, `unit`, `granularity`, `coverage`.
- `GET /users?...`, `GET /users/{id}`, `GET /nodes?...`, `GET /nodes/{id}`
- `GET /exports/connections?...` asynchronous for large ranges, audited.

## Agent
- `POST /agents/enroll` admin creates one-time enrollment token bound to panel+node.
- `WSS /ingest/v1` agent authenticates and submits `{agent_id,batch_id,events:[...],sequence_range}`.
- Server returns `{batch_id,ack_sequence,accepted,rejected}` only after durable commit.
- `GET /agents` scoped status, lag, last seen, spool usage and gaps.

## Contract rules
- `panel_ids` must be a subset of actor's authorized panels.
- `GET` endpoints never return panel API token, agent credential or raw auth header.
- All metrics include `metric_kind` (`connection_count` or `bytes`), `source`, and time coverage.
- Use generated OpenAPI spec and typed TS client; do not silently change contracts.
- Remnawave upstream endpoints are adapter implementation details and require verification against installed version.

## As built in M1
Implemented under `/api/v1` (JSON errors `{code,message,request_id,details?}`; every route except health and login needs
a session, every non-GET also `X-CSRF-Token`):
- Auth: `POST /auth/login`, `POST /auth/logout`, `GET /auth/me`, `POST /auth/password`.
- Scope for filters: `GET /scope` (panels and nodes the caller may filter by). Overview: `GET /overview`.
- Panels: `POST /panels/probe`, `POST/GET /panels`, `GET/PATCH/DELETE /panels/{id}`, `POST /panels/{id}/test`,
  `PUT /panels/{id}/token`, `POST /panels/{id}/sync`, `POST /panels/{id}/disable|enable`, `GET /panels/{id}/nodes|users|sync-runs`.
- Accounts (owner): `GET/POST /accounts`, `PATCH /accounts/{id}` (disable, password), `PUT /accounts/{id}/memberships`.
- Audit: `GET /audit?panel_id=&before=`.
Differences from the proposal: `DELETE` takes `{confirm, retention: "purge"|"archive"}`; `POST /panels` re-probes and
answers 422 `probe_failed` or `partial_capabilities` (confirm with `allow_partial`); agents, `/traffic/samples`,
`/destinations`, `/connections` and exports are M2-M3.

## As built: security module (`/api/v1/security`)
Same session, CSRF and error contract. A server is visible to the owner and to anyone with a role on a panel it is
linked to; one outside the caller's scope answers 404 like one that does not exist. Changing a server needs an
administrator role on a linked panel; creating and archiving one is the owner's.
- Servers: `GET/POST /vps`, `GET/PATCH/DELETE /vps/{id}` (DELETE archives and revokes the agent),
  `POST /vps/{id}/links`, `DELETE /vps/{id}/links/{link}`.
- Agent: `GET/POST/DELETE /vps/{id}/agent` (POST returns the secret once). Reports arrive on the WebSocket
  `/ingest/security/v1`, see SECURITY_AGENT.md.
- State read from the agent: `GET /vps/{id}/fail2ban|ports|firewall` (state, observed time, staleness).
- Overview: `GET /vps/{id}/overview` returns `health` (`healthy` | `attention` | `unknown` | `disabled`), the `reasons` for attention, the agent and category states, what the external checks cover and the last event. `unknown` means nothing was read or checked yet; `healthy` is only "nothing alarming among what is read", and the coverage block says what that is.
- `GET /security/vps-by-address?a=<ip>&a=<ip>` (at most 100) answers which of the addresses are registered on a server the caller can see. The DNS Map uses it to link an A or AAAA value to its server; an address that is not registered never links.
- One event: `GET /security/events/{id}` returns it with the server's name and what else was recorded on that server within ten minutes.
- Firewall history and comparison: `GET /vps/{id}/firewall/history?limit=` (stored readings, no rule text) and `GET /vps/{id}/firewall/diff[?from=&to=]` (line difference of two complete readings, by default the two newest; `available:false` with a `reason` otherwise). The `firewall` category also carries `model` (tables, chains, policies, rules) read from the rule text.
- External checks: `GET/POST /vps/{id}/public-ports`, `PATCH /vps/{id}/public-ports/{eid}`,
  `GET/POST /vps/{id}/tls`, `PATCH /vps/{id}/tls/{eid}`, `POST /vps/{id}/checks/{ports|tls}/run` (202, one per 30 s).
  Targets must be registered on the server. See SECURITY_CHECKS.md.
- Ban and unban (owner only): `POST /vps/{id}/fail2ban/{ban|unban}` with `{jail, ip, idempotency_key, acknowledge_risk?}`
  answers 202 with a command, or 409 `risk` (needs `acknowledge_risk`), `agent_offline`, `state_stale`, `no_capability`;
  `GET /commands/{id}`, `GET /vps/{id}/commands`. `GET /vps/{id}/fail2ban` carries `manage: {allowed, ready, reason}`.
- Journal: `GET /vps/{id}/events` and `GET /events` (all visible servers). Filters `vps_id, category, type, severity,
  q, from, to`; paging with `before_ts` + `before_id`; `limit` 1 to 200.
- `GET /settings`: the fixed intervals, retention and the checker's vantage.
- Discovery: `PATCH /vps/{id}` with `discovery_scan: true` opts a server in to the daily bounded scan (off by default; an administrator of a linked panel only). A TLS endpoint can also appear on its own (`source: auto`) when a handshake on a registered domain's 443, or on a known listener at a well-known TLS port, presented a certificate.

Not built: firewall changes (never).

## As built: DNS Map (`/api/v1/intel/dns/maps`, owner only)
- `GET/POST /maps` (create needs `confirm_scope: true`), `GET/PATCH/DELETE /maps/{id}`, `POST /maps/{id}/refresh`
  (202; one per minute per map; 409 `running` while a run is in progress).
- `GET /maps/{id}/records?type=&name=&q=&after_name=&after_type=&limit=`, `GET /maps/{id}/graph?max_nodes=`,
  `GET /maps/{id}/changes?kind=&type=&name=&from=&to=&before_ts=&before_id=&limit=`, `GET /maps/{id}/checks`.
Every answer says how it was obtained: `confirmed` (two resolvers agreed), the views of each resolver, and the
run's coverage. See DNS_MAP.md.

## Digest

`GET /api/v1/analytics/digest?range=24h` (or `from`/`to`, plus `panel_ids`) answers "what changed" in one place: new sites (`new_only` view of Sites, top 10), the five busiest devices behind the router, devices not seen before the period (only for periods up to 14 days), the security journal counted by type for the servers the caller can see, DNS change counts (owner only, `null` otherwise) and the number of open alerts. Empty parts are empty arrays, not missing.

## AmneziaWG containers (owner only)

- `GET /api/v1/awg/hosts`: the AmneziaWG hosts, with `online`, `container_admin` (the host opted in) and the containers each reported.
- `POST /api/v1/awg/hosts/{id}/containers` `{container, port, subnet}`: creates one container in the Amnezia layout. `container` is `amnezia-awg` or `amnezia-awg` plus up to two digits, `port` 1024 to 65535, `subnet` a /24 in 10.0.0.0/8. Answers 409 `container_admin_off` when the host did not opt in.
- `POST /api/v1/awg/instances/{id}/remove` `{confirm}`: removes the container and every device in it. `confirm` must equal the container's name.
- `POST /api/v1/awg/instances/{id}/backup` `{passphrase}`: owner only, the host must have opted in to container operations. Answers with an encrypted file (`RSAWGB1`, argon2id + AES-256-GCM, `Cache-Control: no-store`). The file holds the server key and the preshared keys, so it is shown once and stored nowhere. Passphrase: at least 10 characters.
- `POST /api/v1/awg/hosts/{id}/restore` `{container, passphrase, backup}`: `backup` is the file in base64 (up to 1 MB of body). Creates the container on the host with the same keys and settings; `201 {container, port, server_key_short}`.
- `POST /api/v1/awg/instances/{id}/transfer` `{host_id, container}`: exports the container and restores it on another host in one step; the files pass through the server and are neither stored nor returned.
- `GET /api/v1/subscriptions`: users of the panels in scope with `status`, `expire_at`, `traffic_limit_bytes` and `traffic_used_bytes` (null when the panel did not say), soonest end first. Viewers get masked names.
- `GET /api/v1/pulse/nodes`: what each panel's nodes carry right now (`down_bps`, `up_bps` as the panel reports them, bytes per second), read every 15 seconds and kept in memory only; a reading older than two minutes is not returned.
- `GET /api/v1/hosts`: the monitored servers the viewer may see (the same ones as in the security module) with what the machine is (`os`, `kernel`, `cpu_model`, `cpus`, `mem_total`), the latest reading (`cpu` in percent or null, `load1/5/15`, `mem_used`, `swap_used`, `uptime`, `disks`), and the last hour as `cpu_spark` and `mem_spark`. `procs` are up to 24 groups of processes (program name, unit or `docker:<12 characters>`, count, `cpu` as percent of one core, `rss` bytes): names only, never a command line. A server whose agent has never reported has `has_data: false`; `online` is a reading younger than two minutes.
- `GET /api/v1/hosts/{id}/series?hours=24`: the history of one server (1 to 168 hours, at most 300 points): `cpu`, `load1`, `mem_pct`, `disk_pct` (the root file system) and the network rates `rx_bps` and `tx_bps` in bytes per second, `rx_pps`/`tx_pps` packets per second, and `estab` and `syn_recv` (established and half-open TCP connections). The list also carries the latest `rx_bps`, `tx_bps`, `rx_pps`, `estab` and `syn_recv`. A flood alert (`host_flood`, "Похоже на DDoS") opens when, in at least 3 of the last 12 minutes, incoming traffic or packet rate is above both a floor (30 Mbit/s, 25 thousand packets a second) and four times the 95th percentile of the day before, or half-open connections reach 300, or the kernel sent SYN cookies or dropped connections for a full queue; it says so in its wording, since a legitimate surge looks the same.
- `GET /api/v1/billing`, `POST /api/v1/billing`, `PUT /api/v1/billing/{id}`, `DELETE /api/v1/billing/{id}`, `POST /api/v1/billing/{id}/paid`: the owner's own list of payments (`name`, `provider`, `amount`, `currency`, `period_months`, `next_due`, `note`). Owner only. `paid` records a payment and moves `next_due` one period on from the date that was due. `GET` also returns `monthly`, the cost per month by currency.

## Notifications (owner only)

- `GET /api/v1/notify/channels`, `POST /api/v1/notify/channels` `{name, token, chat_id, on_alerts, digest_hour, digest_tz}`, `PATCH /api/v1/notify/channels/{id}`, `DELETE ...`, `POST .../{id}/test`: Telegram channels. A channel is stored only after a message actually reached the chat; the bot token and chat id are sealed with the master key and are never returned (only a hint of the chat id and the last result).
- `POST /api/v1/notify/telegram/discover` `{token}`: confirms a bot token and lists the chats that wrote to the bot. The token is not kept.
- `PATCH /api/v1/notify/channels/{id}` also takes the fine tuning: `prefs` `{off: [group ids], no_resolved, quiet_on, quiet_from, quiet_to, remind_hours}` (the list also returns `groups` and `critical`), `commands` (the bot answers commands) and `mute_hours` (0 clears). Alert groups: agents, panels, security, resources, flood, awg, dns, users, billing. Critical alerts (flood, a stopped AmneziaWG container, a panel that cannot be synced, a silent agent or probe) are announced in quiet hours and while muted; what is held goes out when the quiet ends, and an alert that closed meanwhile is never announced. `remind_hours` repeats an alert that is still open.
- The bot (long polling, no webhook) answers `/stats /servers /alerts /bans /certs /pay /awg /users /dns /mute /unmute /help`, only from the chat of the channel, only messages not older than two minutes, at most twelve commands a minute; what was written before it started is not answered. The only thing a command changes is the mute. The daily digest is the same summary as `/stats` followed by what happened in the last day.
- What goes out: an alert when it opens and when it closes (what was already open when the channel was added is not announced; more than eight at once become one summary), and a daily digest at the chosen local hour. Failures are stored as fixed words (`network`, `rejected`, `bad_answer`), never as Telegram's text.
