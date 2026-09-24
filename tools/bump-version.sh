#!/usr/bin/env bash
# Raises the version, records it in CHANGELOG.md, commits and tags it.
# Usage: tools/bump-version.sh major|minor|patch|build "What changed"
#
# Version format: MAJOR.MINOR.PATCH.BUILD (starts at 1.0.0.0)
#   major  big or incompatible changes (old ciphertext won't decrypt)
#   minor  new features
#   patch  bug fixes
#   build  small tweaks (text, styling, docs)
set -euo pipefail
cd "$(dirname "$0")/.."
PART="${1:?Usage: tools/bump-version.sh major|minor|patch|build \"What changed\"}"
NOTE="${2:?Add a short description of what changed}"

IFS=. read -r MA MI PA BU < VERSION
case "$PART" in
    major) MA=$((MA + 1)); MI=0; PA=0; BU=0 ;;
    minor) MI=$((MI + 1)); PA=0; BU=0 ;;
    patch) PA=$((PA + 1)); BU=0 ;;
    build) BU=$((BU + 1)) ;;
    *) echo "Use major, minor, patch or build." >&2; exit 1 ;;
esac
NEW="$MA.$MI.$PA.$BU"
echo "$NEW" > VERSION

ENTRY="## $NEW ($(date +%Y-%m-%d))"$'\n\n'"- $NOTE"$'\n'
{ head -n 2 CHANGELOG.md; echo "$ENTRY"; tail -n +3 CHANGELOG.md; } > CHANGELOG.md.tmp
mv CHANGELOG.md.tmp CHANGELOG.md

git add -A
git commit -q -m "Release $NEW: $NOTE"
git tag -a "v$NEW" -m "Version $NEW"
echo "Version is now $NEW. Publish it with:"
echo "  git push && git push --tags"
