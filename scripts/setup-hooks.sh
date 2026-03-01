#!/bin/sh
# Install git hooks from scripts/ into .git/hooks/.
# Run once after cloning:  ./scripts/setup-hooks.sh

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOOKS_DIR="${REPO_ROOT}/.git/hooks"

for hook in "${REPO_ROOT}"/scripts/pre-push; do
    name="$(basename "$hook")"
    cp "$hook" "${HOOKS_DIR}/${name}"
    chmod +x "${HOOKS_DIR}/${name}"
    echo "installed ${name}"
done
