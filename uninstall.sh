#!/usr/bin/env bash
# Removes CYS-ENC26 for the current user. Your keys and locked files are not touched.
set -eu
read -r -p "Remove CYS-ENC26? [y/N] " answer
case "$answer" in y|Y|yes|YES) ;; *) echo "Nothing was removed."; exit 0 ;; esac
rm -rf "$HOME/.local/share/cys-enc26" "$HOME/.cache/cys-enc26"
rm -f "$HOME/.local/bin/cys26" \
      "$HOME/.local/share/applications/cys-enc26.desktop" \
      "$HOME/.local/share/applications/cys-enc26-fold.desktop" \
      "$HOME/.local/share/icons/hicolor/scalable/apps/cys-enc26.svg" \
      "$HOME/.local/share/icons/hicolor/scalable/apps/cys-enc26-fold.svg" \
      "$HOME/.local/share/icons/hicolor/scalable/apps/application-x-cys-enc26-folder.svg" \
      "$HOME/.local/share/mime/packages/cys-enc26-fold.xml"
update-mime-database "$HOME/.local/share/mime" >/dev/null 2>&1 || true
update-desktop-database "$HOME/.local/share/applications" >/dev/null 2>&1 || true
DESKTOP_DIR="$(xdg-user-dir DESKTOP 2>/dev/null || echo "$HOME/Desktop")"
rm -f "$DESKTOP_DIR/cys-enc26.desktop"

# FOLD lock records are left in place: locked .f.cys26 files still need them
# (or the password / recovery key) to open. Say where they are.
FOLD_STATE="${XDG_STATE_HOME:-$HOME/.local/state}/cys-enc26/fold"
if [ -d "$FOLD_STATE" ] && [ -n "$(ls -A "$FOLD_STATE" 2>/dev/null)" ]; then
    echo "FOLD lock records were left in $FOLD_STATE"
    echo "Your locked .f.cys26 files need them (or the password) to be opened."
fi
echo "CYS-ENC26 was removed."
