#!/bin/sh
# netio.patchman ajan dosyalarını derler.
# Kullanım: scripts/build-agent.sh [sürüm] [çıktı dizini]
# Sürüm verilmezse depodaki VERSION dosyası kullanılır.
# PATCHMAN_SIGNING_KEY bir imzalama anahtarı dosyasını gösteriyorsa dosyalar
# imzalanır (netio-patchman-server agent-key ile oluşturulur; sunucuda tutmayın).
# Çıktı, sunucunun PATCHMAN_AGENT_DIST_DIR dizininde beklediği biçimdedir.
set -eu

OUT="${2:-dist/agent}"
cd "$(dirname "$0")/.."
VERSION="${1:-$(tr -d ' \r\n' < VERSION)}"
mkdir -p "$OUT"

LDFLAGS="-s -w -X netio.patchman/internal/version.Version=${VERSION}"
for arch in amd64 arm64; do
  name="netio-patchman-agent-linux-${arch}"
  echo "Derleniyor: ${name} (${VERSION})"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags "$LDFLAGS" \
    -o "${OUT}/${name}" ./cmd/netio-patchman-agent
  (cd "$OUT" && sha256sum "$name" > "${name}.sha256")
done
name="netio-patchman-agent-windows-amd64.exe"
echo "Derleniyor: ${name} (${VERSION})"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$LDFLAGS" \
  -o "${OUT}/${name}" ./cmd/netio-patchman-agent
(cd "$OUT" && sha256sum "$name" > "${name}.sha256")
echo "$VERSION" > "${OUT}/version"
if [ -n "${PATCHMAN_SIGNING_KEY:-}" ]; then
  go run ./cmd/netio-patchman-server agent-sign -key "$PATCHMAN_SIGNING_KEY" -dir "$OUT"
fi
echo "Ajan dosyaları hazır: ${OUT}"
ls -l "$OUT"
