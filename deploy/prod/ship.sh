#!/bin/bash
# Build the images here, send them to your own server over SSH instead of pulling from ghcr.io, start the stack. Needs Docker and ssh access.
#   deploy/prod/ship.sh <ssh alias> [release tag]
set -euo pipefail
HOST=${1:?usage: ship.sh <ssh alias> [release]}
REL=${2:-$(date +%Y%m%d-%H%M)}
cd "$(dirname "$0")/../.."
docker build -f deploy/api.Dockerfile --target api -t "remnascope-api:$REL" .
docker build -f deploy/web.Dockerfile -t "remnascope-web:$REL" .
docker save "remnascope-api:$REL" "remnascope-web:$REL" | ssh "$HOST" 'docker load'
ssh "$HOST" 'mkdir -p /opt/remnascope/secrets && cd /opt/remnascope/secrets && { [ -e gemini_api_key ] || { umask 077; : > gemini_api_key; chown 65532:65532 gemini_api_key; chmod 400 gemini_api_key; }; }'
scp -q deploy/prod/compose.prod.yml deploy/prod/Caddyfile deploy/prod/init-secrets.sh deploy/prod/backup.sh "$HOST:/opt/remnascope/"
ssh "$HOST" "cd /opt/remnascope && chmod +x init-secrets.sh backup.sh && sed -i 's/^RELEASE=.*/RELEASE=$REL/' .env 2>/dev/null; grep -q '^API_IMAGE=' .env 2>/dev/null || printf 'API_IMAGE=remnascope-api\nWEB_IMAGE=remnascope-web\n' >> .env; echo shipped release $REL"
