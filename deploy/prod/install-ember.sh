#!/bin/sh
# Installs (or replaces, or with --remove takes away) the Ember pack for Kawaii Mode.
#
#   ./install-ember.sh ember-pack.tar.gz     put the pictures where the site reads them
#   ./install-ember.sh --remove              take the mascot away
#
# The pack is not part of the project: it is a file the owner of the pictures gives you. The site reads it from the
# folder EMBER_DIR (default ./ember next to compose.prod.yml, mounted into the web container); nothing is built and
# nothing is restarted: the mascot is there the next time the page is loaded with Kawaii Mode on.
set -eu
cd "$(dirname "$0")"
DIR="${EMBER_DIR:-./ember}"

if [ "${1:-}" = "--remove" ]; then
  rm -rf "$DIR"
  mkdir -p "$DIR"
  echo "Ember removed from $DIR"
  exit 0
fi

ARC="${1:?usage: install-ember.sh <ember-pack.tar.gz> | --remove}"
[ -f "$ARC" ] || { echo "no such file: $ARC" >&2; exit 1; }

# Look at the archive before opening it: plain files with known names, no paths, no links.
tar -tzvf - < "$ARC" > /tmp/ember-list.$$ || { echo "not a tar.gz archive" >&2; rm -f /tmp/ember-list.$$; exit 1; }
bad=$(awk '{ t = substr($1, 1, 1); if (t != "-") print "not a plain file: " $0 }' /tmp/ember-list.$$ | head -1)
names=$(tar -tzf - < "$ARC")
rm -f /tmp/ember-list.$$
[ -z "$bad" ] || { echo "$bad" >&2; exit 1; }
echo "$names" | grep -qx 'ember.json' || { echo "this is not an Ember pack (no ember.json)" >&2; exit 1; }
if echo "$names" | grep -Evq '^(ember\.json|phrases\.ru\.json|projectile\.png|heart\.png|atlas-[0-9]+\.webp)$'; then
  echo "the pack holds files that Ember does not use; refusing it" >&2
  exit 1
fi

tmp="$(mktemp -d "${DIR%/}.new.XXXXXX")"
tar -xzf - -C "$tmp" --no-same-owner --no-same-permissions < "$ARC"
chmod -R a+rX "$tmp"
rm -rf "$DIR"
mv "$tmp" "$DIR"
echo "Ember installed in $DIR ($(ls "$DIR" | wc -l) files). Turn on Kawaii Mode in Settings -> Appearance."
