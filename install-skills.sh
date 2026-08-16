#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEST="$HOME/.claude/skills"

mkdir -p "$DEST/references"

cp "$SCRIPT_DIR/.claude/skills/elevenlabs.md" "$DEST/"
cp "$SCRIPT_DIR/.claude/skills/tts-prosody.md" "$DEST/"
cp "$SCRIPT_DIR/.claude/skills/references/"*.md "$DEST/references/"

echo "Installed skills to $DEST:"
ls -1 "$DEST/"*.md "$DEST/references/"*.md 2>/dev/null
echo ""
echo "Done. Skills are now available globally in Claude Desktop."
