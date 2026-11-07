#!/bin/sh
# Nightly database dump kept for 14 days. Cron: 17 3 * * * /path/to/deploy/prod/backup.sh
set -eu
cd "$(dirname "$0")"
mkdir -p backups && chmod 700 backups
docker compose -f compose.prod.yml exec -T postgres pg_dump -U remnascope remnascope | gzip > "backups/remnascope-$(date +%Y%m%d).sql.gz"
find backups -name 'remnascope-*.sql.gz' -mtime +14 -delete
# Copies taken by hand before a risky migration (pre-*) are kept for a week: each is as big as a nightly one.
find backups -name 'pre-*.sql.gz' -mtime +7 -delete
