#!/usr/bin/env bash
# Only a new, disposable Compose project; no production mounts or host ports.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
run_dir=$(mktemp -d /tmp/artex-export-XXXXXXXX)
project="artex-export-${run_dir##*-}"
project="${project,,}"
dc() { docker compose -p "$project" -f export-compose.yml "$@"; }
cleanup() {
  result=$?
  trap - EXIT
  dc cp app:/tmp/artex-export "$run_dir/downloads" >/dev/null 2>&1 || true
  dc logs --no-color >"$run_dir/containers.log" 2>&1 || true
  if ! dc down --volumes --remove-orphans >"$run_dir/cleanup.log" 2>&1; then
    echo "Cleanup failed: $run_dir/cleanup.log" >&2
    result=1
  fi
  echo "Acceptance artifacts: $run_dir"
  exit "$result"
}
trap cleanup EXIT
dc up -d --wait --wait-timeout 150 --pull never
python3 export-fixture.py seed | dc exec -T postgres psql -U verify -d verify -q -v ON_ERROR_STOP=1
snapshot() {
  dc exec -T postgres psql -U verify -d verify -Atq -v ON_ERROR_STOP=1 -c "SELECT jsonb_build_object('findings',(SELECT jsonb_agg(to_jsonb(f) ORDER BY id) FROM findings f),'reviews',(SELECT jsonb_agg(to_jsonb(r) ORDER BY finding_id) FROM finding_reviews r),'tasks',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM tasks t),'explorations',(SELECT jsonb_agg(to_jsonb(e) ORDER BY id) FROM explorations e),'credential',(SELECT value FROM settings WHERE key='brave_search_api_key'));" | sha256sum | cut -d ' ' -f 1
}
snapshot >"$run_dir/source-before.sha256"
dc exec -T -e "EXPORT_EXPECTED_VERSION=${EXPORT_EXPECTED_VERSION:-dev-806bc74}" app node /acceptance/export-browser.cjs | tee "$run_dir/normal.json"
dc cp app:/tmp/artex-export "$run_dir/checked-downloads" >/dev/null
python3 export-fixture.py verify "$run_dir/checked-downloads" | tee "$run_dir/bytes.json"
# Break only the credential lookup in the disposable database; auth remains usable.
dc exec -T postgres psql -U verify -d verify -q -v ON_ERROR_STOP=1 -c 'ALTER TABLE llm_profiles RENAME TO export_test_profiles_unavailable'
dc exec -T -e EXPORT_FAILURE=1 -e "EXPORT_EXPECTED_VERSION=${EXPORT_EXPECTED_VERSION:-dev-806bc74}" app node /acceptance/export-browser.cjs | tee "$run_dir/failure.json"
dc exec -T postgres psql -U verify -d verify -q -v ON_ERROR_STOP=1 -c 'ALTER TABLE export_test_profiles_unavailable RENAME TO llm_profiles'
snapshot >"$run_dir/source-after.sha256"
cmp "$run_dir/source-before.sha256" "$run_dir/source-after.sha256"
echo 'Synthetic source snapshot unchanged; browser download acceptance passed.'
