#!/bin/sh
# Nightly database dump kept for 14 days. Cron: 17 3 * * * /path/to/deploy/prod/backup.sh
# When it is done it tells Owlery how it went (a row in panel_backups), so the page of the panel's health can show it and an
# alert can say when a night went by without one.
set -u
cd "$(dirname "$0")"
mkdir -p backups && chmod 700 backups
out="backups/remnascope-$(date +%Y%m%d).sql.gz"
ok=false
docker compose -f compose.prod.yml exec -T postgres pg_dump -U remnascope remnascope | gzip > "$out"
bytes=$(stat -c %s "$out" 2>/dev/null || echo 0)
# A pipe reports only its last command, so a dump that failed halfway still looks fine to gzip: a real dump is far bigger than this.
if gzip -t "$out" 2>/dev/null && [ "$bytes" -gt 100000 ]; then ok=true; fi
docker compose -f compose.prod.yml exec -T postgres psql -U remnascope remnascope -qc "INSERT INTO panel_backups (bytes, ok) VALUES ($bytes, $ok)" >/dev/null 2>&1 || true
find backups -name 'remnascope-*.sql.gz' -mtime +14 -delete
# Copies taken by hand before a risky migration (pre-*) are kept for a week: each is as big as a nightly one.
find backups -name 'pre-*.sql.gz' -mtime +7 -delete
[ "$ok" = true ]
