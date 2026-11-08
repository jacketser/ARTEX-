#!/usr/bin/env bash
set -euo pipefail
# Resolve the optional plan relative to the caller, before changing directory.
plan=""
if [[ -n ${2:-} ]]; then plan=$(realpath "$2"); fi
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
repo_root=$(cd ../../.. && pwd)
corpus=${1:-tuning}
case "$corpus" in
  tuning) compose=compose.yml; image=jacketser/artex:honeypot-eval ;;
  holdout) compose=compose.holdout.yml; image=jacketser/artex:honeypot-holdout ;;
  holdout-20261107) compose=compose.holdout-20261107.yml; image=jacketser/artex:honeypot-holdout-20261107 ;;
  holdout-20261108) compose=compose.holdout-20261108.yml; image=jacketser/artex:honeypot-holdout-20261108 ;;
  *) exit 2 ;;
esac
export ARTEX_HONEY_DIR
ARTEX_HONEY_DIR=$(mktemp -d /tmp/artex-honeypot-real-XXXXXXXX)
project="artex-honey-${ARTEX_HONEY_DIR##*-}"
project=${project,,}
dc() { docker compose -p "$project" -f "$compose" "$@"; }
source_dir=""
cleanup() {
  status=$?
  trap - EXIT
  log_name=containers.log
  if [[ "$corpus" == holdout-20261108 && -f "$ARTEX_HONEY_DIR/request-audit.json" ]]; then
    log_name=containers-final.log # preserve the exact audited access-log snapshot
  fi
  dc logs --no-color > "$ARTEX_HONEY_DIR/$log_name" 2>&1 || true
  dc ps -a --format json > "$ARTEX_HONEY_DIR/containers.json" || true
  if ! dc down --volumes --remove-orphans > "$ARTEX_HONEY_DIR/cleanup.log" 2>&1; then status=1; fi
  if [[ -n "$source_dir" ]]; then rm -rf -- "$source_dir"; fi
  printf 'Labeled honeypot evaluation artifacts: %s\n' "$ARTEX_HONEY_DIR"
  exit "$status"
}
trap cleanup EXIT
detector_ref=b7877ca
if [[ -n "$plan" ]]; then
  cp "$plan" "$ARTEX_HONEY_DIR/evaluation-plan.json"
  detector_ref=$(python3 - "$plan" "$corpus" "$image" <<'PYPLAN'
import json, re, subprocess, sys
p = json.load(open(sys.argv[1]))
assert p['schema'] in (1, 2)
if p['schema'] == 1:
    assert p['evaluation_role'] == 'regression'
else:
    assert sys.argv[2] == 'holdout-20261108' and p['evaluation_role'] in ('new_holdout', 'regression')
    assert re.fullmatch('[0-9a-f]{40}', p['collector_commit'])
assert p['repetitions'] == 3 and re.fullmatch('[0-9a-f]{40}', p['detector_commit'])
actual = subprocess.check_output(['docker', 'image', 'inspect', '--format', '{{.Id}}', sys.argv[3]], text=True).strip()
assert actual == p['image_ids'][sys.argv[2]], 'Fixture image differs from frozen plan'
print(p['detector_commit'])
PYPLAN
)
else
  git -C "$repo_root" diff b7877ca -- honeydetect server/honeypot_behavior.go > "$ARTEX_HONEY_DIR/detector-diff.txt"
  [[ ! -s "$ARTEX_HONEY_DIR/detector-diff.txt" ]]
fi
source_dir=$(mktemp -d /tmp/artex-honey-frozen-source-XXXXXXXX)
git -C "$repo_root" archive "$detector_ref" | tar -x -C "$source_dir"
# Explicit plans freeze the collector independently; schema 1 uses the detector commit.
if [[ -n "$plan" ]]; then
  collector_ref=$(python3 - "$plan" <<'PYCOLLECTOR'
import json, sys
p = json.load(open(sys.argv[1]))
print(p['collector_commit'] if p['schema'] == 2 else p['detector_commit'])
PYCOLLECTOR
)
  git -C "$repo_root" show "$collector_ref:scripts/acceptance/honeypot-real/main.go" > "$source_dir/scripts/acceptance/honeypot-real/main.go"
  printf '%s\n' "$collector_ref" > "$ARTEX_HONEY_DIR/collector-commit.txt"
else
  cp main.go "$source_dir/scripts/acceptance/honeypot-real/main.go"
fi
git -C "$repo_root" rev-parse "$detector_ref" > "$ARTEX_HONEY_DIR/detector-commit.txt"
git -C "$repo_root" rev-parse HEAD > "$ARTEX_HONEY_DIR/artex-commit.txt"
if [[ "$corpus" == holdout-20261108 ]]; then
  [[ -n "$plan" ]]
  docker run --rm --network none --entrypoint sh -v "$ARTEX_HONEY_DIR:/output" "$image" -c '
    cp /sources/sources-20261108.json /output/sources-20261108.json
    /opt/qeeqbox/bin/pip freeze > /output/runtime-packages.txt
    python3 --version > /output/python-version.txt
  '
  cmp sources-20261108.json "$ARTEX_HONEY_DIR/sources-20261108.json"
  python3 prepare-20261108.py "$ARTEX_HONEY_DIR"
  python3 - "$plan" "$ARTEX_HONEY_DIR" <<'PYPREFLIGHT'
import hashlib, json, subprocess, sys
from pathlib import Path
p = json.load(open(sys.argv[1]))
root = Path(sys.argv[2])
assert p['schema'] == 2
assert json.loads((root/'configuration-hashes.json').read_text()) == p['configuration_hashes']
assert hashlib.sha256((root/'sources-20261108.json').read_bytes()).hexdigest() == p['sources_sha256']
actual = subprocess.check_output(['docker','image','inspect','--format','{{.Id}}','jacketser/artex:local'],text=True).strip()
assert actual == p['driver_image_id'], 'Driver image changed'
PYPREFLIGHT
else
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
fi
python3 - "$repo_root" "$ARTEX_HONEY_DIR" "$source_dir" <<'PYHASH'
import hashlib
from pathlib import Path
import sys
repo, out, source = map(Path, sys.argv[1:])
files = sorted((repo/'scripts/acceptance/honeypot-real').glob('*'))
manifest = ''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + str(p.relative_to(repo)) + '\n' for p in files if p.is_file())
(out/'harness-sha256.txt').write_text(manifest)
files = sorted((source/'honeydetect').glob('*.go')) + [source/'scripts/acceptance/honeypot-real/main.go']
(out/'detector-sha256.txt').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + str(p.relative_to(source)) + '\n' for p in files))
PYHASH
docker image inspect --format '{{.Id}}' "$image" > "$ARTEX_HONEY_DIR/image-id.txt"
docker image inspect --format '{{.Id}}' jacketser/artex:local > "$ARTEX_HONEY_DIR/driver-image-id.txt"
docker run --rm --network none -e GOMAXPROCS=2 -v "$source_dir:/src:ro" -w /src -v "$ARTEX_HONEY_DIR:/output" \
  -v artex-dev-gomod:/go/pkg/mod -v artex-dev-gocache:/root/.cache/go-build \
  golang:1.26-bookworm go build -p 1 -o /output/honeypot-eval ./scripts/acceptance/honeypot-real
sha256sum "$ARTEX_HONEY_DIR/honeypot-eval" | cut -d ' ' -f 1 > "$ARTEX_HONEY_DIR/driver-binary-sha256.txt"
dc up -d --pull never
dc run --rm --no-deps --pull never driver | tee "$ARTEX_HONEY_DIR/run.log"
if [[ "$corpus" == holdout-20261107 ]]; then
  for service in log4pot-json log4pot-tomcat; do
    dc cp "$service:/tmp/log4pot.json" "$ARTEX_HONEY_DIR/$service-requests.jsonl"
  done
  python3 check-log4pot-requests.py "$ARTEX_HONEY_DIR"
fi
if [[ "$corpus" == holdout-20261108 ]]; then
  dc logs --no-color > "$ARTEX_HONEY_DIR/containers.log"
  python3 check-requests-20261108.py "$ARTEX_HONEY_DIR"
fi
python3 summarize.py "$ARTEX_HONEY_DIR"
