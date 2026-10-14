# Remnawave API fixtures (v3.4)

**Update 2026-10-13:** the `users_*.json` shape was corrected after the first run against a real 3.4.3 panel: users carry a numeric `id` and no `uuid`. Only field *names* were observed; values here are invented.

**The rest of these files was reconstructed by hand from the Zod schemas published in
`@remnawave/backend-contract` 3.4.15. They were NOT captured from a running panel.**
Values are invented (documentation UUIDs, `example.test` hosts) and some real fields are
deliberately omitted or added to prove the adapter tolerates both.

Before the first production panel is connected, compare them with the panel's own
OpenAPI document (`/docs` on the panel) and replace them with sanitised captures.

| File | Endpoint |
|---|---|
| `nodes.json` | `GET /api/nodes` |
| `users_page1.json`, `users_page2.json` | `GET /api/users/?start=&size=` (offset pagination) |
| `system_stats.json` | `GET /api/system/stats` |
| `bandwidth_nodes.json` | `GET /api/bandwidth-stats/nodes?start=&end=` |
| `metadata.json` | `GET /api/system/metadata` |
| `nodes_unrecognisable.json` | a 2xx whose rows have none of the identity fields we need |
