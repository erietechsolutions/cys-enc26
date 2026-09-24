#!/usr/bin/env bash
# Removes CYS-ENC26 for the current user. Your keys and locked files are not touched.
set -eu
read -r -p "Remove CYS-ENC26? [y/N] " answer
case "$answer" in y|Y|yes|YES) ;; *) echo "Nothing was removed."; exit 0 ;; esac
rm -rf "$HOME/.local/share/cys-enc26" "$HOME/.cache/cys-enc26"
rm -f "$HOME/.local/bin/cys26" \
      "$HOME/.local/share/applications/cys-enc26.desktop" \
      "$HOME/.local/share/icons/hicolor/scalable/apps/cys-enc26.svg"
DESKTOP_DIR="$(xdg-user-dir DESKTOP 2>/dev/null || echo "$HOME/Desktop")"
rm -f "$DESKTOP_DIR/cys-enc26.desktop"
echo "CYS-ENC26 was removed."
