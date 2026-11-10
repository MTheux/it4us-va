#!/usr/bin/env bash
# IT4US VA update script: (1) Docker update (pull new image and rebuild)  (2) local build update (rebuild the binary)
# Counterpart of install.sh: install handles the first-time setup, update upgrades to a new version.
# No manual DB migration needed — it4us idempotently re-runs schema.sql on every start (with ADD COLUMN/CREATE
# INDEX IF NOT EXISTS), so "restart equals migrate". Data (pgdata volume, ./data, ./skills) is not affected.
set -euo pipefail
cd "$(cd "$(dirname "$0")" && pwd)"

info(){ printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok(){   printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[!]\033[0m %s\n' "$*"; }
die(){  printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
ask(){  local p="$1" d="${2:-}" a; read -rp "$p${d:+ [$d]}: " a; echo "${a:-$d}"; }

# ── Optional: sync the repo to the latest code (compose/scripts/local build sources all update through it) ───────
sync_repo(){
  [ -d .git ] && command -v git >/dev/null 2>&1 || { warn "not a git working copy, skipping git pull"; return; }
  [ "$(ask 'Pull the latest code (git pull --ff-only)? (y/n)' y)" = y ] || return
  if ! git pull --ff-only; then
    warn "git pull could not fast-forward (local changes or diverged branches) — resolve manually and retry; continuing with the current code"
  fi
}

# ── (1) Docker update ───────────────────────────────
update_docker(){
  command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1 \
    || die "docker / docker compose not detected; install and deploy with ./install.sh first"
  [ -f .env ] || die ".env not found; run ./install.sh first to complete the initial deployment"

  # Optional: upgrade to a specific version tag (empty = keep IT4US_TAG from .env, default latest)
  local tag; tag="$(ask 'Target image tag (press Enter to keep .env / latest)' '')"
  if [ -n "$tag" ]; then
    if grep -q '^IT4US_TAG=' .env; then
      sed -i.bak "s|^IT4US_TAG=.*|IT4US_TAG=${tag}|" .env && rm -f .env.bak
    else
      printf '\nIT4US_TAG=%s\n' "$tag" >> .env
    fi
    ok "IT4US_TAG set to ${tag}"
  fi

  # Touch only it4us: postgres is pinned to 16-alpine and does not need upgrading along
  # (pulling it wastes bandwidth, and a major version bump risks compatibility). it4us
  # declares depends_on postgres, so an up with the service name starts pg if needed and leaves a running one untouched.
  info "Pulling new image (it4us only)…"
  docker compose pull it4us
  info "Rebuilding and starting (schema migrates automatically on it4us restart)…"
  docker compose up -d it4us
  ok "Update complete → http://localhost:8787"
  info "View logs: docker compose logs -f it4us"
  info "Clean up old images (optional): docker image prune -f"
}

# ── (2) Local build update ──────────────────────────────
update_local(){
  command -v go >/dev/null 2>&1 || die "Go (>=1.26) not detected: https://go.dev/dl/"
  [ -f config.json ] || warn "config.json not found — use ./install.sh instead for a first-time deployment"
  ok "Go: $(go version)"

  if command -v npm >/dev/null 2>&1; then
    info "Rebuilding frontend static assets…"
    ( cd web && npm ci && npm run build:static )
    rm -rf server/webui/dist && cp -r web/out server/webui/dist
    info "Recompiling the embedded single binary…"
    CGO_ENABLED=0 go build -tags embedui -trimpath -o it4us ./cmd/it4us
  else
    warn "npm not detected: building a backend **without the embedded frontend** (run the frontend separately with npm run dev)"
    CGO_ENABLED=0 go build -o it4us ./cmd/it4us
  fi
  ok "Build complete → ./it4us"
  warn "Restart the running it4us process to take effect (schema migrates automatically on restart)"
}

echo "=============================="
echo "  IT4US VA Update"
echo "  1) Docker update (pull new image and rebuild)"
echo "  2) Local update (rebuild with go)"
echo "=============================="
case "$(ask 'Choose' 1)" in
  1) sync_repo; update_docker ;;
  2) sync_repo; update_local ;;
  *) die "invalid choice" ;;
esac
