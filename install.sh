#!/bin/sh
# Installs chrome-unfreeze for the current user, no sudo needed.
#   ./install.sh            install
#   ./install.sh --remove   uninstall
set -e
cd "$(dirname "$0")"
BIN="$HOME/.local/bin/chrome-unfreeze"
DESKTOP="$HOME/.local/share/applications/io.github.otien.ChromeUnfreeze.desktop"

if [ "$1" = "--remove" ]; then
    rm -f "$BIN" "$DESKTOP"
    echo "chrome-unfreeze removed."
    exit 0
fi

./build.sh >/dev/null
mkdir -p "$(dirname "$BIN")" "$(dirname "$DESKTOP")"
install -m 755 dist/chrome-unfreeze "$BIN"
cat > "$DESKTOP" <<DESK
[Desktop Entry]
Type=Application
Name=Chrome Unfreeze
Comment=Unfreeze a hung Chrome without losing your tabs
Exec=$BIN gui
Icon=web-browser
Terminal=false
Categories=Utility;
Keywords=chrome;chromium;freeze;hang;frozen;process;
StartupNotify=true
DESK
update-desktop-database "$(dirname "$DESKTOP")" 2>/dev/null || true
echo "Installed: $BIN"
echo "Launcher: Chrome Unfreeze, in your applications menu."
case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) echo "Add ~/.local/bin to your PATH to run chrome-unfreeze from a terminal." ;; esac
