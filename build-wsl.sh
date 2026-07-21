#!/bin/bash
# Build custom Frida server in WSL Ubuntu
#
# Usage from Windows:
#   wsl -d Ubuntu bash /mnt/d/Tools/Reversing/Android/custom-frida-builder/build-wsl.sh
#
# Or from WSL:
#   cd /mnt/d/Tools/Reversing/Android/custom-frida-builder
#   bash build-wsl.sh
#
# Configuration via environment variables:
#   FRIDA_VERSION=17.16.3 (default)
#   CUSTOM_NAME=stealth   (default: ajeossida)
#   CUSTOM_PORT=27142     (default: 27042)
#   BUILD_ARCH=android-arm64  (default: android-arm64)
#   EXTENDED=1            (default: 0)
#   TEMP_FIXES=1          (default: 0)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FRIDA_VERSION="${FRIDA_VERSION:-17.16.3}"
CUSTOM_NAME="${CUSTOM_NAME:-ajeossida}"
CUSTOM_PORT="${CUSTOM_PORT:-}"
BUILD_ARCH="${BUILD_ARCH:-android-arm64}"
EXTENDED="${EXTENDED:-0}"
TEMP_FIXES="${TEMP_FIXES:-0}"

echo "=== Custom Frida Builder (WSL) ==="
echo "  Version: $FRIDA_VERSION"
echo "  Name:    $CUSTOM_NAME"
echo "  Arch:    $BUILD_ARCH"
echo "  Port:    ${CUSTOM_PORT:-27042 (default)}"
echo ""

# Check dependencies
for cmd in git python3 curl unzip make; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: $cmd not found. Install it:"
        echo "  sudo apt update && sudo apt install -y git python3 curl unzip make"
        exit 1
    fi
done

# Build command
build_cmd=(
    python3 "$SCRIPT_DIR/build.py"
    --version "$FRIDA_VERSION"
    --name "$CUSTOM_NAME"
    --arch "$BUILD_ARCH"
    --verify
)

if [ -n "$CUSTOM_PORT" ]; then
    build_cmd+=(--port "$CUSTOM_PORT")
fi

if [ "$EXTENDED" = "1" ]; then
    build_cmd+=(--extended)
fi

if [ "$TEMP_FIXES" = "1" ]; then
    build_cmd+=(--temp-fixes)
fi

printf 'Running:'
printf ' %q' "${build_cmd[@]}"
printf '\n\n'

exec "${build_cmd[@]}"
