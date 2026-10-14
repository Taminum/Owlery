# Agent and event ingestion

## Agent responsibilities
1. Open configured access log read-only; support host-mounted regular file and explicit adapter for s6-log `current` rotation.
2. Detect inode replacement, truncation, restart and rotation; resume from durable checkpoint.
3. Parse accepted TCP/UDP lines; preserve raw destination and distinguish domain, IPv4, bracketed IPv6.
4. Normalize timestamp with timezone; parse Xray email and tags without assuming email is globally unique.
5. Batch by count/bytes/time (default 500 events or 2s); gzip optional; send over WSS.
6. Keep durable local spool and sequence numbers; retry with exponential backoff and jitter.
7. Remove spool data only after server acknowledges durable write; resend safe via idempotency.
8. Report health, parser errors, lag, dropped events and queue size.

## Example observed line
`2026/10/09 12:03:31.803861 from 95.183.45.51:47242 accepted tcp:www.google.com:443 [Steal -> DIRECT] email: 2`

## Known infrastructure detail
Current known `remnanode` uses internal `/var/log/xray/current` and `/command/s6-log ... /var/log/xray` with ~10 MiB rotation. It has no bind mount for logs. Thus an agent configured with host path `/var/log/remnanode/access.log` will not see events. Before deployment choose one:
- Safe MVP: manually export a sample file for parser and dashboard fixtures.
- Production option A: host-side supervised `docker exec` log bridge with robust reconnect/rotation handling, minimal privilege and explicit audit of host Docker access.
- Production option B: approved change to expose a read-only log directory to host/agent; requires careful rollout and may recreate container. **Never do automatically.**
- Do not mount docker.sock into network-exposed agent/API.

## Classification
- Treat `9.9.9.9:443` as IP destination, not definitely DoH; connection counts are not traffic volume.
- TCP/UDP counts by accepted event, not protocol byte distribution.
- Service classification from domain rules or validated IP/ASN metadata; show confidence.
- Internal DNS-generated events may lack `email`; categorize as system events and exclude from user totals when appropriate.

## Data quality
- Coverage/gap timeline; parser version; ingest source; node clock drift warning.
- No exact per-device stats behind a router without router-side telemetry or separate identities.
- No precise per-domain bytes from Xray access logs.

## Node log agent: as built
- Real line shape: `<date> <time.µs> from <client> accepted <tcp|udp>:<dest> [<inbound> <-> | >> <outbound>] [email: <id>]`.
  Tag separator is `->` or `>>` (meaning not assumed, stored as logged); outbounds seen: `DIRECT`, a named one, `BLOCK`;
  `from` is `ip:port`, `tcp:ip:port`, or `DNS` for the node's own resolver (inbound `xray.system.<uuid>`, no email);
  time is UTC with no zone. All of this is in `internal/xraylog` with a sanitised real sample as test data.
- `email` is the Remnawave **numeric user id** (real users have no uuid). Events resolve to a panel user only by
  `(panel_id, id)`; an id that is not a user of that panel stays unresolved and is shown as such, never merged.
- Protocol (`internal/ingestproto`): hello / welcome(ack) / batch / ack / ping; strict contiguous sequence numbers per
  agent epoch; the server acks only after the rows are committed. Replays are skipped by sequence, identical-looking lines
  with different sequence numbers are all kept.
- Agent (`internal/agent`, `cmd/agent`): file source with rotation (s6 `@*.s` archives, head-hash identity) or exec source
  (`tail -F` through `docker exec`); crash-tolerant segmented spool (torn tail trimmed on start), bounded; loss counters and
  gaps persisted until the server confirms them; reconnect with backoff and jitter; `wss://` required.
- Retention: raw events older than the panel's `retention_days` are deleted hourly.
