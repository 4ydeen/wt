#!/bin/sh
# Reproducible WatTunnel build: static linux/amd64 and linux/arm64 binaries, and windows/amd64 (wattun-windows-amd64.exe,
# no ICMP), in dist/ with a .sha256 next to each.
# Usage: build.sh [amd64|arm64|windows ...]   (default: all three)
# Go: `go` on PATH (or $GO).
# Prints one line per binary and "BUILD_OK <version>" at the end, or "BUILD_FAIL <step>".
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE"
GO=${GO:-$(command -v go || true)}
[ -n "$GO" ] || { echo "BUILD_FAIL no-go (install Go 1.26+)"; exit 1; }
VER=$(sed -n 's/^const Version = "\([0-9A-Za-z.+-]*\)".*/\1/p' wat/version.go)
[ -n "$VER" ] || { echo "BUILD_FAIL version (wat/version.go)"; exit 1; }
ARCHES=${*:-"amd64 arm64 windows"}
export CGO_ENABLED=0 GOFLAGS=-mod=mod
mkdir -p dist
for a in $ARCHES; do
  case "$a" in
    amd64|arm64) os=linux; arch=$a; out="dist/wattun-linux-$a" ;;
    windows) os=windows; arch=amd64; out="dist/wattun-windows-amd64.exe" ;;
    *) echo "BUILD_FAIL arch $a"; exit 1 ;;
  esac
  GOOS=$os GOARCH=$arch "$GO" build -trimpath -ldflags "-s -w -buildid=" -o "$out" ./cmd/wattun || { echo "BUILD_FAIL build $a"; exit 1; }
  # sha256sum on Linux, shasum on macOS. The file is one standard "<hex>  <name>" line (since 2.0.1), so
  # `sha256sum -c` works next to the binary; readers that take the first field (install.sh, the bot) are unaffected.
  if command -v sha256sum >/dev/null 2>&1; then sum=$(sha256sum "$out" | cut -d' ' -f1); else sum=$(shasum -a 256 "$out" | cut -d' ' -f1); fi
  printf '%s  %s\n' "$sum" "${out##*/}" > "$out.sha256"
  echo "wattun $VER $os/$arch $sum"
done
# The release's signed checksum list: install.sh verifies the RSA signature against the public key baked into it,
# so a download that went through WAT_PROXY (or any tampered copy) cannot pair a swapped binary with its own
# checksum. WAT_SIGN_KEY: path to the private PEM (the release workflow passes it from the WAT_SIGN_KEY secret).
if command -v sha256sum >/dev/null 2>&1; then
  (cd dist && sha256sum wattun-* | grep -v '\.sha256$' > SHA256SUMS)
elif command -v shasum >/dev/null 2>&1; then
  (cd dist && shasum -a 256 wattun-* | grep -v '\.sha256$' > SHA256SUMS)
fi
if [ -f dist/SHA256SUMS ] && [ -n "${WAT_SIGN_KEY:-}" ]; then
  openssl dgst -sha256 -sign "$WAT_SIGN_KEY" -out dist/SHA256SUMS.sig dist/SHA256SUMS || { echo "BUILD_FAIL sign"; exit 1; }
  echo "SHA256SUMS signed"
fi
echo "BUILD_OK $VER"
