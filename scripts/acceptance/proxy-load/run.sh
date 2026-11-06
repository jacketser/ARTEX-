#!/usr/bin/env bash
# Internal synthetic targets only; never mount production state or publish ports.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
load_root=$(cd ../../.. && pwd)
export ARTEX_LOAD_DIR
ARTEX_LOAD_DIR=$(mktemp -d /tmp/artex-proxy-load-XXXXXXXX)
load_project="artex-load-${ARTEX_LOAD_DIR##*-}"
load_project=${load_project,,}
dc() { docker compose -p "$load_project" -f compose.yml "$@"; }
cleanup() {
  result=$?
  trap - EXIT
  dc exec -T app touch /tmp/proxy-load-monitor.stop >/dev/null 2>&1 || true
  dc cp app:/tmp/proxy-load-resources.jsonl "$ARTEX_LOAD_DIR/resources.jsonl" >/dev/null 2>&1 || true
  dc logs --no-color > "$ARTEX_LOAD_DIR/containers.log" 2>&1 || true
  app_id=$(dc ps -aq app)
  if [[ -n "$app_id" ]]; then
    docker inspect --format '{{json .State}}' "$app_id" > "$ARTEX_LOAD_DIR/app-state.json" || true
    docker inspect --format '{{.Image}}' "$app_id" > "$ARTEX_LOAD_DIR/image-id.txt" || true
  fi
  if [[ -f "$ARTEX_LOAD_DIR/results.json" ]]; then
    python3 summarize.py "$ARTEX_LOAD_DIR" || result=1
  fi
  dc down --volumes --remove-orphans >/dev/null 2>&1 || true
  printf 'Proxy load artifacts: %s\n' "$ARTEX_LOAD_DIR"
  exit "$result"
}
trap cleanup EXIT
if [[ "${ARTEX_LOAD_MODE:-full}" == soak ]]; then
  python3 corpus.py "$load_root" "$ARTEX_LOAD_DIR"
fi
docker run --rm -e GOMAXPROCS=2 -v "$load_root:/src:ro" -w /src \
  -v "$ARTEX_LOAD_DIR:/output" -v artex-dev-gomod:/go/pkg/mod -v artex-dev-gocache:/root/.cache/go-build \
  golang:1.26-bookworm go build -p 1 -o /output/proxy-load ./scripts/acceptance/proxy-load
# Record machine context without environment variables or credentials.
python3 - "$ARTEX_LOAD_DIR" <<'PY'
import json, os, platform, subprocess, sys
from pathlib import Path
p=Path(sys.argv[1])
(p/'host.json').write_text(json.dumps(dict(platform=platform.platform(),cpus=os.cpu_count(),
    memory_total_kib=int(next(x for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemTotal:')).split()[1]),
    source_commit=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()),indent=2))
PY
dc up -d --wait --wait-timeout 150
dc cp app:/app/data/traffic/_ca/mitmproxy-ca-cert.pem "$ARTEX_LOAD_DIR/proxy-ca.pem"
dc exec -d app python3 /acceptance/monitor.py
dc run --rm --no-deps driver | tee "$ARTEX_LOAD_DIR/run.log"
if [[ "${ARTEX_LOAD_MODE:-full}" == soak ]]; then
  dc exec -T app touch /tmp/proxy-load-monitor.stop
  docker inspect --format '{{json .State}}' "$(dc ps -q app)" > "$ARTEX_LOAD_DIR/pre-stop-app-state.json"
  dc stop app
  dc cp app:/app/data/traffic/_index "$ARTEX_LOAD_DIR/index-snapshot"
  docker run --rm --network none --memory 256m -e GOMAXPROCS=2 -v "$ARTEX_LOAD_DIR:/load" \
    --entrypoint /load/proxy-load "${ARTEX_ACCEPTANCE_IMAGE:-jacketser/artex:local}" verify-store
  dc up -d --no-deps --wait --wait-timeout 150 app
  dc run --rm --no-deps driver verify | tee "$ARTEX_LOAD_DIR/restart.log"
fi
