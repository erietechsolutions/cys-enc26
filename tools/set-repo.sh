#!/usr/bin/env bash
# Points this copy at your GitHub repository.
# Usage: tools/set-repo.sh <github-username> [repository-name]
set -euo pipefail
cd "$(dirname "$0")/.."
USER_NAME="${1:?Usage: tools/set-repo.sh <github-username> [repository-name]}"
REPO_NAME="${2:-cys-enc26}"
REPO="$USER_NAME/$REPO_NAME"

for f in cys26.conf install.sh README.md; do
    sed -i "s#YOUR-GITHUB-USERNAME/cys-enc26#$REPO#g" "$f"
done

if git rev-parse --git-dir >/dev/null 2>&1; then
    if git remote get-url origin >/dev/null 2>&1; then
        git remote set-url origin "https://github.com/$REPO.git"
    else
        git remote add origin "https://github.com/$REPO.git"
    fi
    git add cys26.conf install.sh README.md
    git commit -q -m "Set GitHub repository to $REPO" || true
fi
echo "Repository set to github.com/$REPO"
echo "Next: create an empty public repository named $REPO_NAME on GitHub, then run:"
echo "  git push -u origin main --tags"
