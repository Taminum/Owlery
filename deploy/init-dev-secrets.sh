#!/bin/sh
# Creates the local development secrets in ./secrets (git-ignored). Existing files are kept.
# Nothing is printed: open the files yourself when you need a value.
set -eu
dir="$(cd "$(dirname "$0")/.." && pwd)/secrets"
mkdir -p "$dir"
umask 077

token() { head -c 24 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n'; }
write() {
  if [ -e "$dir/$1" ]; then echo "kept    $1"; return; fi
  printf '%s\n' "$2" > "$dir/$1"
  echo "created $1"
}

write master_key      "1:$(head -c 32 /dev/urandom | base64 | tr -d '\n')"
write owner_password  "$(token)"
write mock_home_token "$(token)"
write mock_work_token "$(token)"
echo "Secrets are in $dir. Back up master_key: without it stored panel tokens cannot be decrypted."
