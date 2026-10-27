# Architecture

## Logical system
```
Remnawave panel A  ─ HTTPS API ─┐
                                 ├── Go API / sync workers ── PostgreSQL ── React UI
Remnawave panel B  ─ HTTPS API ─┘          ▲
                                             │ authenticated WSS ingest
Node A ─ read-only agent ───────────────┤
Node B ─ read-only agent ───────────────┤
Node C ─ read-only agent ───────────────┤
Panel B nodes (discovered) ─ agents ────────────┘
```

## Services
- `api`: authenticated REST API, query engine, connection wizard, RBAC.
- `sync-worker`: independent jobs per panel, API capability detection, incremental metadata and traffic counter sampling.
- `ingest`: authenticated WSS endpoint, event validation, batch ack, idempotency.
- `agent`: read-only Xray access-log reader, local disk spool, bounded batches.
- `web`: React SPA served by nginx (same-origin `/api` reverse proxy).
- `postgres`: single instance; tenant-aware schema and indexed time-series tables.

## Identity and isolation
`panel_id` is Owlery-generated UUID and primary security boundary.
`node_id` is internal UUID; `(panel_id, remote_node_uuid)` unique.
`user_id` is internal UUID; `(panel_id, remote_user_uuid)` unique.
`agent_id` belongs to exactly one panel/node; separate revocable credential per agent.
Raw Xray `email` is an untrusted identity hint; resolve only through verified mapping, with timestamps and provenance.
If bridge/relay topology duplicates events, don't merge automatically; explicit correlation logic later.

## API adapters
`PanelAdapter` interface: `Probe`, `ListNodes`, `ListUsers`, `GetTrafficCounters`, `GetCapabilities`.
Each adapter records API version/capability flags. Implement official Remnawave endpoints against version-pinned fixtures. Never assume an endpoint works across all versions.
Workers use rate limits, backoff, ETag where supported, bounded concurrency, cursor pagination, and circuit breakers.
No token ever sent to browser after creation.

## Operational boundaries
- Work panel must be reachable from central collector, or use an explicitly configured secure outbound bridge.
- Deploy agents only where log access can be granted safely.
- Current known node has `/var/log/xray/current` inside container with s6-log rotation and no host bind mount. Generic instructions assuming `/var/log/remnanode/access.log` on host WILL NOT WORK there.
- For this node: design a host-side read-only bridge or approved mount/export; prototype against a copied log before any production change. Avoid Docker socket in exposed services.
- Central service should be independently deployable from all Remnawave containers.
- Backups encrypt sensitive DB and config; restore procedure must preserve key material securely.
