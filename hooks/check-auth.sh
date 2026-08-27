#!/bin/sh
# SessionStart hook: warn early if no Checkmarx One credential is configured.
# Advisory only; never blocks the session.
TIP="Findings-to-Fix is installed. Run /cx-findings-to-fix:fix in the project you want to fix (type /cx-f and press Tab)."
if [ -n "$CX_APIKEY" ]; then
  echo "$TIP"; exit 0
fi
if [ -f "$HOME/.checkmarx/checkmarxcli.yaml" ] && grep -qiE '^\s*(cx_apikey|apikey)\s*:' "$HOME/.checkmarx/checkmarxcli.yaml"; then
  echo "$TIP"; exit 0
fi
FTF="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}/skills/fix-confirmed-findings/ftf.py"
echo "Findings-to-Fix: not authenticated yet. Run this once in a terminal (your API key is prompted for and stored securely): python3 \"$FTF\" auth"
exit 0
