#!/usr/bin/env bash
# Build WireVault rpi-core on Linux (Mint/PiOS).
set -euo pipefail
BUILD_DIR="${BUILD_DIR:-build}"

deps_ok=1
if ! pkg-config --exists "sqlite3"; then
  echo "require: libsqlite3-dev (sudo apt install libsqlite3-dev)"
  deps_ok=0
fi
if ! command -v nft >/dev/null 2>&1; then
  echo "[warn] nftables not installed - filter manager needs it at runtime"
fi
if ! command -v wg >/dev/null 2>&1; then
  echo "[warn] wireguard-tools not installed - WG manager needs it at runtime"
fi
if [ "$deps_ok" = "0" ]; then exit 1; fi

cmake -S . -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release
cmake --build "$BUILD_DIR" -j"$(nproc)"

echo
echo "Binaries:"
echo "  $BUILD_DIR/wirevaultd      (sudo ./build/wirevaultd /etc/wirevault/wirevault.json)"
echo "  $BUILD_DIR/wvctl           (control client: ./build/wvctl peer.list)"
echo "  $BUILD_DIR/wirevault-tests (config/json tests)"
echo "  $BUILD_DIR/wirevault-incident-tests (sqlite incident tests)"
