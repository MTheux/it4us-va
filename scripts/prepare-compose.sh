#!/usr/bin/env bash
# Build the embedded Linux binary required by the runtime-only Dockerfile.
set -euo pipefail
cd "$(cd "$(dirname "$0")/.." && pwd)"

command -v docker >/dev/null 2>&1 || { echo "Docker is required" >&2; exit 1; }
command -v go >/dev/null 2>&1 || { echo "Go 1.26+ is required to build the Docker binary" >&2; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "Node.js/npm is required to build the web UI" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker daemon is unavailable" >&2; exit 1; }

arch="$(docker version --format '{{.Server.Arch}}')"
case "$arch" in
  arm64|aarch64) arch=arm64 ;;
  amd64|x86_64) arch=amd64 ;;
  *) echo "Unsupported Docker server architecture: $arch" >&2; exit 1 ;;
esac

(cd web && npm ci && npm run build:static)
rm -rf server/webui/dist
mkdir -p server/webui/dist "dist/$arch"
cp -R web/out/. server/webui/dist/
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -tags embedui -trimpath -o "dist/$arch/it4us" ./cmd/it4us
echo "Docker binary ready: dist/$arch/it4us"
