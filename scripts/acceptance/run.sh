#!/usr/bin/env bash
# A fresh, internal-only Docker network and disposable DB; no production mounts.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
run_dir=$(mktemp -d /tmp/artex-acceptance-XXXXXXXX)
project="artex-acceptance-${run_dir##*-}"
project="${project,,}"
dc() { docker compose -p "$project" -f compose.yml "$@"; }
cleanup() {
  result=$?
  trap - EXIT
  dc logs --no-color >"$run_dir/containers.log" 2>&1 || true
  for name in settings assets failure; do
    dc cp "app:/tmp/artex-behavior-$name.png" "$run_dir/$name.png" >/dev/null 2>&1 || true
  done
  dc down --volumes --remove-orphans >/dev/null 2>&1 || true
  echo "Acceptance artifacts: $run_dir"
  exit "$result"
}
trap cleanup EXIT
dc up -d --wait --wait-timeout 150
asset_id=$(dc exec -T postgres psql -U verify -d verify -Atq -v ON_ERROR_STOP=1 -c "INSERT INTO assets(type,url,service_name) VALUES('service','http://target:8080','HTTP') RETURNING id")
[[ "$asset_id" =~ ^[0-9]+$ ]]
dc exec -T -e "ASSET_ID=$asset_id" app node /acceptance/behavior-browser.cjs | tee "$run_dir/result.json"
