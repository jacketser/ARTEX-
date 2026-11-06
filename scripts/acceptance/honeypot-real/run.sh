#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
repo_root=$(cd ../../.. && pwd)
export ARTEX_HONEY_DIR
ARTEX_HONEY_DIR=$(mktemp -d /tmp/artex-honeypot-real-XXXXXXXX)
project="artex-honey-${ARTEX_HONEY_DIR##*-}"
project=${project,,}
dc() { docker compose -p "$project" -f compose.yml "$@"; }
cleanup() {
  status=$?
  trap - EXIT
  dc logs --no-color > "$ARTEX_HONEY_DIR/containers.log" 2>&1 || true
  dc ps -a --format json > "$ARTEX_HONEY_DIR/containers.json" || true
  dc down --volumes --remove-orphans >/dev/null 2>&1 || true
  printf 'Labeled honeypot evaluation artifacts: %s\n' "$ARTEX_HONEY_DIR"
  exit "$status"
}
trap cleanup EXIT
docker run --rm --network none --entrypoint sh -v "$ARTEX_HONEY_DIR:/output" jacketser/artex:honeypot-eval -c '
  cp -a /sources/opencanary /output/opencanary-source
  /opt/opencanary/bin/pip freeze > /output/opencanary-packages.txt
  /opt/qeeqbox/bin/pip freeze > /output/qeeqbox-packages.txt
  nginx -v 2> /output/nginx-version.txt
  git -C /sources/opencanary rev-parse HEAD > /output/opencanary-commit.txt
  git -C /sources/honeypots rev-parse HEAD > /output/qeeqbox-commit.txt
'
[[ "$(cat "$ARTEX_HONEY_DIR/opencanary-commit.txt")" == a81e3992751548cbf4ae49eda5df78353d4c81ea ]]
[[ "$(cat "$ARTEX_HONEY_DIR/qeeqbox-commit.txt")" == f337a32e3351e2add3a455a3bcaf1f02ded5744b ]]
python3 prepare.py "$ARTEX_HONEY_DIR/opencanary-source" "$ARTEX_HONEY_DIR"
git -C "$repo_root" rev-parse HEAD > "$ARTEX_HONEY_DIR/artex-commit.txt"
python3 - "$repo_root" "$ARTEX_HONEY_DIR" <<'PYHASH'
import hashlib
from pathlib import Path
import sys
repo, out = map(Path, sys.argv[1:])
files = sorted((repo/'scripts/acceptance/honeypot-real').glob('*')) + sorted((repo/'honeydetect').glob('*.go'))
manifest = ''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + str(p.relative_to(repo)) + '\n' for p in files if p.is_file())
(out/'harness-sha256.txt').write_text(manifest)
PYHASH
docker image inspect --format '{{.Id}}' jacketser/artex:honeypot-eval > "$ARTEX_HONEY_DIR/image-id.txt"
docker run --rm -e GOMAXPROCS=2 -v "$repo_root:/src:ro" -w /src -v "$ARTEX_HONEY_DIR:/output" \
  -v artex-dev-gomod:/go/pkg/mod -v artex-dev-gocache:/root/.cache/go-build \
  golang:1.26-bookworm go build -p 1 -o /output/honeypot-eval ./scripts/acceptance/honeypot-real
dc up -d
dc run --rm --no-deps driver | tee "$ARTEX_HONEY_DIR/run.log"
python3 summarize.py "$ARTEX_HONEY_DIR"
