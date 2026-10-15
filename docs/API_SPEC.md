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
Not built: firewall changes (never), a discovery scan of unknown ports.

## As built: DNS Map (`/api/v1/intel/dns/maps`, owner only)
- `GET/POST /maps` (create needs `confirm_scope: true`), `GET/PATCH/DELETE /maps/{id}`, `POST /maps/{id}/refresh`
  (202; one per minute per map; 409 `running` while a run is in progress).
- `GET /maps/{id}/records?type=&name=&q=&after_name=&after_type=&limit=`, `GET /maps/{id}/graph?max_nodes=`,
  `GET /maps/{id}/changes?kind=&type=&name=&from=&to=&before_ts=&before_id=&limit=`, `GET /maps/{id}/checks`.
Every answer says how it was obtained: `confirmed` (two resolvers agreed), the views of each resolver, and the
run's coverage. See DNS_MAP.md.
