#!/bin/sh
# Run ON the server in the deployment directory. Creates secrets once, prints nothing.
set -eu
cd "$(dirname "$0")"
umask 077
mkdir -p secrets
tok() { head -c 24 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n'; }
mk() { [ -e "$1" ] && echo "kept    $1" || { printf '%s\n' "$2" > "$1"; echo "created $1"; }; }
mk secrets/master_key     "1:$(head -c 32 /dev/urandom | base64 | tr -d '\n')"
mk secrets/owner_password "$(tok)"
mk secrets/gemini_api_key  ""   # optional: put a Gemini API key here to enable AI categories (docs/AUTOCLASSIFY.md)
if [ ! -e .env ]; then
  printf 'SCOPE_HOST=%s\nPOSTGRES_PASSWORD=%s\nRELEASE=%s\n' "${1:?usage: init-secrets.sh <host name>}" "$(tok)" "${2:-latest}" > .env
  echo "created .env"
else
  echo "kept    .env"
fi
chmod 600 .env
# The API runs as the unprivileged uid 65532 inside its container and must be able to read its secrets;
# nobody else but root can (0400).
chown 65532:65532 secrets/*
chmod 400 secrets/*
echo "Back up secrets/master_key somewhere other than this server: without it stored panel tokens cannot be decrypted."
