#!/usr/bin/env bash
set -euo pipefail
repo=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
fixtures=$(realpath "${1:?usage: run.sh FIXTURES OUTPUT}")
mkdir -p "${2:?usage: run.sh FIXTURES OUTPUT}"
output=$(realpath "$2")
rm -f "$output/measurements.json" "$output/measurements.json.tmp" "$output/summary.json"
ref=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["detector_commit"])' "$fixtures/samples.json")
expected=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["detector_commit"])' "$repo/scripts/acceptance/honeypot-content/sources.json")
[[ "$ref" == "$expected" ]] || { echo 'Frozen detector mismatch' >&2; exit 1; }
snapshot=$(mktemp -d /tmp/artex-content-holdout-source-XXXXXXXX)
trap 'rm -rf "$snapshot"' EXIT
git -C "$repo" archive "$ref" | tar -x -C "$snapshot"
cp "$repo/scripts/acceptance/honeypot-content/runner_test.go.txt" "$snapshot/honeydetect/content_holdout_test.go"
docker run --rm --network none -e GOMAXPROCS=2 \
  -v "$snapshot:/src:ro" -v "$fixtures:/fixtures:ro" -v "$output:/output" \
  -v artex-dev-gomod:/go/pkg/mod -v artex-dev-gocache:/root/.cache/go-build \
  -w /src golang:1.26-bookworm \
  go test -p 1 ./honeydetect -run '^TestContentHoldout$' -count=1 -v
python3 "$repo/scripts/acceptance/honeypot-content/summarize.py" "$fixtures/samples.json" "$output/measurements.json" "$output/summary.json"
