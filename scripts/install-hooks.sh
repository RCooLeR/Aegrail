#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOOK_DIR="$ROOT/.git/hooks"

if [ ! -d "$ROOT/.git" ]; then
  echo "No .git directory found at $ROOT" >&2
  exit 1
fi

mkdir -p "$HOOK_DIR"
cp "$ROOT/scripts/pre-push" "$HOOK_DIR/pre-push"
chmod +x "$HOOK_DIR/pre-push"

echo "Installed Aegrail pre-push hook."
