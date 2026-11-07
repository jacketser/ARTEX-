#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
repo_root=$(cd ../../.. && pwd)
corpus=${1:-tuning}
case "$corpus" in
  tuning) compose=compose.yml; image=jacketser/artex:honeypot-eval ;;
  holdout) compose=compose.holdout.yml; image=jacketser/artex:honeypot-holdout ;;
  holdout-20261107) compose=compose.holdout-20261107.yml; image=jacketser/artex:honeypot-holdout-20261107 ;;
  *) exit 2 ;;
esac
export ARTEX_HONEY_DIR
ARTEX_HONEY_DIR=$(mktemp -d /tmp/artex-honeypot-real-XXXXXXXX)
project="artex-honey-${ARTEX_HONEY_DIR##*-}"
project=${project,,}
dc() { docker compose -p "$project" -f "$compose" "$@"; }
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
docker run --rm --network none --entrypoint sh -v "$ARTEX_HONEY_DIR:/output" "$image" -c '
  cp -a /sources/opencanary /output/opencanary-source
  /opt/opencanary/bin/pip freeze > /output/opencanary-packages.txt
  /opt/qeeqbox/bin/pip freeze > /output/qeeqbox-packages.txt
  nginx -v 2> /output/nginx-version.txt
  git -C /sources/opencanary rev-parse HEAD > /output/opencanary-commit.txt
  git -C /sources/honeypots rev-parse HEAD > /output/qeeqbox-commit.txt
'
[[ "$(cat "$ARTEX_HONEY_DIR/opencanary-commit.txt")" == a81e3992751548cbf4ae49eda5df78353d4c81ea ]]
[[ "$(cat "$ARTEX_HONEY_DIR/qeeqbox-commit.txt")" == f337a32e3351e2add3a455a3bcaf1f02ded5744b ]]
if [[ "$corpus" == holdout ]]; then
  docker run --rm --network none --entrypoint sh -v "$ARTEX_HONEY_DIR:/output" "$image" -c '
    /opt/heralding/bin/pip freeze > /output/heralding-packages.txt
    git -C /sources/heralding rev-parse HEAD > /output/heralding-commit.txt
    apache2 -v > /output/apache-version.txt
    python3 --version > /output/python-version.txt
  '
  [[ "$(cat "$ARTEX_HONEY_DIR/heralding-commit.txt")" == ac12724ab38c4e2fe78f07d1bc35e6e586ba69c0 ]]
  docker run --rm --network none --entrypoint /opt/heralding/bin/python -v "$ARTEX_HONEY_DIR:/output" -v "$PWD:/harness:ro" "$image" /harness/prepare-holdout.py /sources/heralding /output
elif [[ "$corpus" == holdout-20261107 ]]; then
  docker run --rm --network none --entrypoint sh -v "$ARTEX_HONEY_DIR:/output" "$image" -c '
    cp /sources/sources-20261107.json /output/sources-20261107.json
    /opt/httpbin/bin/pip freeze > /output/httpbin-packages.txt
    /opt/datasette/bin/pip freeze > /output/datasette-packages.txt
    python3 --version > /output/python-version.txt
  '
  cmp sources-20261107.json "$ARTEX_HONEY_DIR/sources-20261107.json"
  python3 prepare-20261107.py "$ARTEX_HONEY_DIR"
else
  python3 prepare.py "$ARTEX_HONEY_DIR/opencanary-source" "$ARTEX_HONEY_DIR"
fi
git -C "$repo_root" diff b7877ca -- honeydetect server/honeypot_behavior.go > "$ARTEX_HONEY_DIR/detector-diff.txt"
[[ ! -s "$ARTEX_HONEY_DIR/detector-diff.txt" ]]
git -C "$repo_root" rev-parse b7877ca > "$ARTEX_HONEY_DIR/detector-commit.txt"
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
docker image inspect --format '{{.Id}}' "$image" > "$ARTEX_HONEY_DIR/image-id.txt"
docker run --rm --network none -e GOMAXPROCS=2 -v "$repo_root:/src:ro" -w /src -v "$ARTEX_HONEY_DIR:/output" \
  -v artex-dev-gomod:/go/pkg/mod -v artex-dev-gocache:/root/.cache/go-build \
  golang:1.26-bookworm go build -p 1 -o /output/honeypot-eval ./scripts/acceptance/honeypot-real
dc up -d
dc run --rm --no-deps driver | tee "$ARTEX_HONEY_DIR/run.log"
if [[ "$corpus" == holdout-20261107 ]]; then
  for service in log4pot-json log4pot-tomcat; do
    dc cp "$service:/tmp/log4pot.json" "$ARTEX_HONEY_DIR/$service-requests.jsonl"
  done
  python3 check-log4pot-requests.py "$ARTEX_HONEY_DIR"
fi
python3 summarize.py "$ARTEX_HONEY_DIR"
