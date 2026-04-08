#!/bin/sh
set -e

REPO="leonardomb1/pulse"
BINARY="pulse"

# Detect version (default: latest release).
VERSION="${1:-latest}"

# Detect OS.
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$OS" in
    linux) ;;
    *)
        echo "error: unsupported OS: $OS (pulse requires Linux)"
        exit 1
        ;;
esac

# Detect architecture.
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)   ARCH="amd64" ;;
    aarch64|arm64)   ARCH="arm64" ;;
    *)
        echo "error: unsupported architecture: $ARCH"
        echo "pulse supports: x86_64 (amd64), aarch64 (arm64)"
        exit 1
        ;;
esac

# Resolve latest version if needed.
if [ "$VERSION" = "latest" ]; then
    VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//')"
    if [ -z "$VERSION" ]; then
        echo "error: could not determine latest version"
        exit 1
    fi
fi

URL="https://github.com/$REPO/releases/download/$VERSION/$BINARY-$OS-$ARCH"
INSTALL_DIR="/usr/local/bin"
TMP="$(mktemp)"

echo "pulse installer"
echo "  version:  $VERSION"
echo "  platform: $OS/$ARCH"
echo "  url:      $URL"
echo ""

# Stop pulse if running.
if command -v pulse >/dev/null 2>&1; then
    echo "stopping running pulse daemon..."
    pulse stop 2>/dev/null || true
    sleep 1
fi

# Download.
echo "downloading..."
if ! curl -fsSL -o "$TMP" "$URL"; then
    echo "error: download failed — check that $VERSION exists for $OS-$ARCH"
    rm -f "$TMP"
    exit 1
fi
chmod +x "$TMP"

# Verify it runs.
ACTUAL_VERSION="$("$TMP" version 2>/dev/null || true)"
if [ -z "$ACTUAL_VERSION" ]; then
    echo "error: downloaded binary is not executable"
    rm -f "$TMP"
    exit 1
fi
echo "  binary:   $ACTUAL_VERSION"

# Install.
if [ -w "$INSTALL_DIR" ]; then
    rm -f "$INSTALL_DIR/$BINARY"
    mv "$TMP" "$INSTALL_DIR/$BINARY"
else
    echo ""
    echo "installing to $INSTALL_DIR (requires sudo)..."
    sudo rm -f "$INSTALL_DIR/$BINARY"
    sudo mv "$TMP" "$INSTALL_DIR/$BINARY"
fi

# Set capabilities.
echo "setting capabilities..."
SETCAP="$(command -v setcap 2>/dev/null || echo /sbin/setcap)"
if [ -x "$SETCAP" ]; then
    sudo "$SETCAP" cap_net_admin,cap_net_bind_service=+ep "$INSTALL_DIR/$BINARY" 2>/dev/null || true
else
    echo "  warning: setcap not found — run manually:"
    echo "  sudo setcap cap_net_admin,cap_net_bind_service=+ep $INSTALL_DIR/$BINARY"
fi

echo ""
echo "installed: $(pulse version 2>/dev/null || echo "$INSTALL_DIR/$BINARY")"
echo ""
echo "quickstart:"
echo "  pulse join <relay-addr> --token <token>"
echo "  pulse start --tun --socks --dns <relay-addr>"
