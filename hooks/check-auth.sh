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
echo "Findings-to-Fix: no Checkmarx One API key found. Set CX_APIKEY or run: cx configure set --prop-name cx_apikey --prop-value <key>"
exit 0
