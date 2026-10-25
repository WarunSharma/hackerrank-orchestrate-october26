#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ARCHIVE="$ROOT/code.zip"

rm -f "$ARCHIVE"

cd "$ROOT"
zip -q -r "$ARCHIVE" \
  README.md \
  package.json \
  package-lock.json \
  tsconfig.json \
  src \
  code/evaluation \
  scripts/package-code.sh \
  -x \
  "dataset/*" \
  "node_modules/*" \
  "dist/*" \
  ".git/*" \
  ".github/*" \
  "openspec/*" \
  "log.txt" \
  ".env" \
  "*.zip" \
  "*.tar" \
  "*.gz" \
  "*.tgz" \
  "*.7z" \
  "*.rar" \
  "*/__pycache__/*" \
  "*/.venv/*" \
  "*/venv/*" \
  "*/.DS_Store"

printf 'Created %s\n' "$ARCHIVE"
