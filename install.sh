#!/usr/bin/env bash
# Installs or updates CYS-ENC26 for the current user.
#
#   From a downloaded copy:  ./install.sh
#   In one line:             curl -fsSL https://raw.githubusercontent.com/YOUR-GITHUB-USERNAME/cys-enc26/main/install.sh | bash
set -euo pipefail

REPO="YOUR-GITHUB-USERNAME/cys-enc26"
BRANCH="main"
QUIET=0
[ "${1:-}" = "--quiet" ] && QUIET=1

APP_DIR="$HOME/.local/share/cys-enc26"
BIN_DIR="$HOME/.local/bin"
APPS_DIR="$HOME/.local/share/applications"
ICON_DIR="$HOME/.local/share/icons/hicolor/scalable/apps"

say() { [ "$QUIET" = 1 ] || echo "$@"; }

# Find the files to install: next to this script, or download them.
SRC=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "$(dirname "${BASH_SOURCE[0]}")/src/cys_enc26.py" ]; then
    SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
    if [[ "$REPO" == YOUR-GITHUB-USERNAME/* ]]; then
        echo "This installer doesn't have a GitHub repository set. Run tools/set-repo.sh first." >&2
        exit 1
    fi
    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' EXIT
    say "Downloading CYS-ENC26 from github.com/$REPO..."
    curl -fsSL "https://github.com/$REPO/archive/refs/heads/$BRANCH.tar.gz" \
        | tar -xz -C "$TMP" --strip-components=1
    SRC="$TMP"
fi

# Dependencies
if ! command -v python3 >/dev/null 2>&1; then
    echo "Python 3 is required. Install it with: sudo dnf install python3" >&2
    exit 1
fi
if ! python3 -c "import tkinter" >/dev/null 2>&1; then
    say "Installing python3-tkinter (needs your password)..."
    if command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y python3-tkinter
    elif command -v apt-get >/dev/null 2>&1; then
        sudo apt-get install -y python3-tk
    else
        echo "Install the Tk package for Python 3, then run this again." >&2
        exit 1
    fi
fi

# Keep an existing repository setting if the new copy doesn't have one.
KEEP_CONF=""
if grep -q "YOUR-GITHUB-USERNAME" "$SRC/cys26.conf" && [ -f "$APP_DIR/cys26.conf" ] \
        && ! grep -q "YOUR-GITHUB-USERNAME" "$APP_DIR/cys26.conf"; then
    KEEP_CONF="$(cat "$APP_DIR/cys26.conf")"
fi

# Install the files
NEW="$APP_DIR.new"
rm -rf "$NEW"
mkdir -p "$NEW"
cp -r "$SRC/src" "$SRC/bin" "$SRC/assets" "$NEW/"
cp "$SRC/VERSION" "$SRC/cys26.conf" "$SRC/uninstall.sh" "$SRC/README.md" "$SRC/CHANGELOG.md" "$NEW/"
[ -n "$KEEP_CONF" ] && printf '%s\n' "$KEEP_CONF" > "$NEW/cys26.conf"
chmod +x "$NEW/bin/cys26" "$NEW/src/cys_enc26.py" "$NEW/uninstall.sh"
rm -rf "$APP_DIR"
mv "$NEW" "$APP_DIR"

mkdir -p "$BIN_DIR" "$APPS_DIR" "$ICON_DIR"
ln -sf "$APP_DIR/bin/cys26" "$BIN_DIR/cys26"
cp "$APP_DIR/assets/cys-enc26.svg" "$ICON_DIR/cys-enc26.svg"

cat > "$APPS_DIR/cys-enc26.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=CYS-ENC26
Comment=Encrypt and decrypt with CYS-ENC26
Exec=$BIN_DIR/cys26 enc
Icon=cys-enc26
Terminal=false
Categories=Utility;Security;
StartupWMClass=Cys-enc26
Actions=encrypt;decrypt;

[Desktop Action encrypt]
Name=Encrypt
Exec=$BIN_DIR/cys26 enc

[Desktop Action decrypt]
Name=Decrypt
Exec=$BIN_DIR/cys26 dec
DESKTOP
update-desktop-database "$APPS_DIR" >/dev/null 2>&1 || true
gtk-update-icon-cache -q "$HOME/.local/share/icons/hicolor" >/dev/null 2>&1 || true

# Replace a desktop shortcut left by an earlier version
DESKTOP_DIR="$(xdg-user-dir DESKTOP 2>/dev/null || echo "$HOME/Desktop")"
if [ -f "$DESKTOP_DIR/cys-enc26.desktop" ]; then
    cp "$APPS_DIR/cys-enc26.desktop" "$DESKTOP_DIR/"
    gio set "$DESKTOP_DIR/cys-enc26.desktop" metadata::trusted true >/dev/null 2>&1 || true
fi

say "CYS-ENC26 $(cat "$APP_DIR/VERSION") is installed."
case ":$PATH:" in
    *":$BIN_DIR:"*) say "Run 'cys26 enc' or 'cys26 dec' to open it." ;;
    *) say "Add ~/.local/bin to your PATH to use the cys26 command:"
       say "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc && source ~/.bashrc" ;;
esac
