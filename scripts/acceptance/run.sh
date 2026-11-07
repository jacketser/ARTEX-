#!/usr/bin/env bash
# A fresh, internal-only Docker network and disposable DB; no production mounts.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
run_dir=$(mktemp -d /tmp/artex-acceptance-XXXXXXXX)
project="artex-acceptance-${run_dir##*-}"
project="${project,,}"
profiles=()
if [[ ${ARTEX_ACCEPTANCE_CONTENT:-0} == 1 ]]; then profiles=(--profile content); fi
dc() { docker compose -p "$project" -f compose.yml "${profiles[@]}" "$@"; }
cleanup() {
  result=$?
  trap - EXIT
  dc logs --no-color >"$run_dir/containers.log" 2>&1 || true
  for name in settings assets content legacy failure; do
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
if [[ ${ARTEX_ACCEPTANCE_CONTENT:-0} != 1 ]]; then exit 0; fi
# The preceding budget test intentionally leaves a process-local cooldown.
# Restart only the disposable app; retain its database and stored configuration.
dc restart app >/dev/null
dc up -d --wait --wait-timeout 150
content_id=$(dc exec -T postgres psql -U verify -d verify -Atq -v ON_ERROR_STOP=1 -c "INSERT INTO assets(type,url,service_name) VALUES('service','http://content-target:8080','HTTP') RETURNING id")
[[ "$content_id" =~ ^[0-9]+$ ]]
dc exec -T -e "ASSET_ID=$content_id" app node /acceptance/content-browser.cjs | tee "$run_dir/result-content.json"
# Clone only the synthetic result in this disposable database, preserving the
# matching fingerprint/revision so the algorithm version alone makes it stale.
dc exec -T postgres psql -U verify -d verify -v ON_ERROR_STOP=1 -c "INSERT INTO asset_honeypot_probes(asset_id,origin,source_fingerprint,rule_revision,status,created_at,finished_at,result) SELECT asset_id,origin,source_fingerprint,rule_revision,status,created_at,finished_at,(result - 'content_warnings') || '{\"version\":\"http-behavior-v3\",\"outcome\":\"needs_review\",\"confidence\":\"low\",\"signals\":[\"旧版隐藏注册内容提示（合成历史）\"]}'::jsonb FROM asset_honeypot_probes WHERE asset_id=$content_id" >/dev/null
dc exec -T -e "ASSET_ID=$content_id" -e CONTENT_HISTORY_ONLY=1 app node /acceptance/content-browser.cjs | tee "$run_dir/result-legacy.json"
