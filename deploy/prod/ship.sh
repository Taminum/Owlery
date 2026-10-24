#!/bin/bash
# Build the images here, send them to your own server over SSH instead of pulling from ghcr.io, start the stack. Needs Docker and ssh access.
#   deploy/prod/ship.sh <ssh alias> [release tag]
set -euo pipefail
HOST=${1:?usage: ship.sh <ssh alias> [release]}
REL=${2:-$(date +%Y%m%d-%H%M)}
cd "$(dirname "$0")/../.."
# The mascot artwork lives outside the repository and outside the images: it is packed from the asset package when
# that is here, and sent to the folder that the web container reads (see install-ember.sh).
PACK=""
if [ -d assets/ember/pilot-v2 ]; then
  PACK="$(mktemp -d)"
  python tools/ember-web-pack.py --out "$PACK/pack" --archive "$PACK/ember-pack.tar.gz" || { echo "warning: the mascot could not be packed"; PACK=""; }
else
  echo "note: no assets/ember here; the mascot on the server is left as it is"
fi
docker build -f deploy/api.Dockerfile --target api -t "remnascope-api:$REL" .
docker build -f deploy/web.Dockerfile -t "remnascope-web:$REL" .
docker save "remnascope-api:$REL" "remnascope-web:$REL" | ssh "$HOST" 'docker load'
ssh "$HOST" 'mkdir -p /opt/remnascope/secrets && cd /opt/remnascope/secrets && { [ -e gemini_api_key ] || { umask 077; : > gemini_api_key; chown 65532:65532 gemini_api_key; chmod 400 gemini_api_key; }; }'
scp -q deploy/prod/compose.prod.yml deploy/prod/Caddyfile deploy/prod/init-secrets.sh deploy/prod/backup.sh deploy/prod/install-ember.sh "$HOST:/opt/remnascope/"
if [ -n "$PACK" ]; then
  scp -q "$PACK/ember-pack.tar.gz" "$HOST:/tmp/ember-pack.tar.gz"
  ssh "$HOST" "cd /opt/remnascope && chmod +x install-ember.sh && sh install-ember.sh /tmp/ember-pack.tar.gz && rm -f /tmp/ember-pack.tar.gz"
  rm -rf "$PACK"
fi
ssh "$HOST" "cd /opt/remnascope && chmod +x init-secrets.sh backup.sh && sed -i 's/^RELEASE=.*/RELEASE=$REL/' .env 2>/dev/null; grep -q '^API_IMAGE=' .env 2>/dev/null || printf 'API_IMAGE=remnascope-api\nWEB_IMAGE=remnascope-web\n' >> .env; echo shipped release $REL"
