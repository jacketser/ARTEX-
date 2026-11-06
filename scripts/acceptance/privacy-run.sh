#!/usr/bin/env bash
# End-to-end CLI lifecycle in disposable stores; no production mounts or ports.
set -euo pipefail
privacy_image=${ARTEX_ACCEPTANCE_IMAGE:-jacketser/artex:local}
privacy_work=$(mktemp -d /tmp/artex-privacy-acceptance-XXXXXXXX)
privacy_project="artex-privacy-${privacy_work##*-}"
privacy_project=${privacy_project,,}
privacy_pg="$privacy_project-pg"
privacy_app="$privacy_project-app"
privacy_dsn="postgres://verify:isolated-cli-only@$privacy_pg:5432/verify?sslmode=disable"
mkdir -p "$privacy_work/data" "$privacy_work/backup"
cleanup() {
  code=$?
  trap - EXIT
  docker logs "$privacy_app" > "$privacy_work/app.log" 2>&1 || true
  docker rm -f "$privacy_app" "$privacy_pg" >/dev/null 2>&1 || true
  docker network rm "$privacy_project" >/dev/null 2>&1 || true
  echo "Privacy acceptance artifacts: $privacy_work"
  exit "$code"
}
trap cleanup EXIT
docker network create --internal "$privacy_project" >/dev/null
docker run -d --name "$privacy_pg" --network "$privacy_project" --tmpfs /var/lib/postgresql/data \
  -e POSTGRES_USER=verify -e POSTGRES_PASSWORD=isolated-cli-only -e POSTGRES_DB=verify postgres:16-alpine >/dev/null
for attempt in {1..60}; do
  if docker exec "$privacy_pg" pg_isready -U verify -d verify >/dev/null 2>&1; then break; fi
  sleep 1
done
docker run -d --name "$privacy_app" --network "$privacy_project" \
  -e "ARTEX_PG_DSN=$privacy_dsn" -e GOMAXPROCS=2 -v "$privacy_work/data:/app/data" \
  --entrypoint /app/artex "$privacy_image" -addr :8787 -proxy 127.0.0.1:8788 >/dev/null
for attempt in {1..60}; do
  if docker exec "$privacy_app" curl --fail --silent http://127.0.0.1:8787/api/health > "$privacy_work/health.json" 2>/dev/null; then break; fi
  sleep 1
done
docker exec "$privacy_app" curl --fail --silent http://127.0.0.1:8787/api/health >/dev/null
if docker exec "$privacy_app" /app/artex history-redact -scope traffic > "$privacy_work/live-rejected.txt" 2>&1; then
  echo 'Live maintenance unexpectedly succeeded' >&2
  exit 1
fi
grep -q '请先停机' "$privacy_work/live-rejected.txt"
docker stop "$privacy_app" >/dev/null
docker run --rm -i -v "$privacy_work/data:/app/data" --entrypoint python3 "$privacy_image" - <<'PY'
import sqlite3, pathlib, hashlib, json
c = sqlite3.connect('/app/data/traffic/_index/index.sqlite')
body = b'{"token":"synthetic-cli-only","number":9007199254740993}'
c.execute("INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path) VALUES('privacy-one',1,'fixture.test','GET','/','http://fixture.test/',200,'application/json',0,?,'')", (len(body),))
c.execute("INSERT INTO exchange_bodies(id,req_head,req_body,resp_head,resp_body) VALUES('privacy-one',?,?,?,?)", ('GET / HTTP/1.1\nAuthorization: Bearer synthetic-cli-only\n', b'', 'HTTP 200\nContent-Type: application/json\n', body))
c.execute("INSERT INTO exchanges SELECT 'privacy-two',ts,host,method,url_template,url,status,content_type,req_len,resp_len,path FROM exchanges WHERE id='privacy-one'")
c.execute("INSERT INTO exchange_bodies SELECT 'privacy-two',req_head,req_body,req_blob,resp_head,resp_body,resp_blob FROM exchange_bodies WHERE id='privacy-one'")
# Original per-directory format, including the old two-level blob layout.
legacy_body=body+b' '*300000
legacy_hash=hashlib.sha256(legacy_body).hexdigest()
legacy_dir=pathlib.Path('/app/data/traffic/fixture.test/GET/privacy-legacy')
legacy_dir.mkdir(parents=True)
blob=pathlib.Path('/app/data/traffic/_blobs/sha256')/legacy_hash[:2]/legacy_hash[2:4]/(legacy_hash+'.bin')
blob.parent.mkdir(parents=True,exist_ok=True)
blob.write_bytes(legacy_body)
(legacy_dir/'request.http').write_bytes(b'GET / HTTP/1.1\nAuthorization: Bearer synthetic-cli-only\n\n')
(legacy_dir/'response.http').write_text('HTTP 200\nContent-Type: application/json\n\n@blob sha256:'+legacy_hash+' (len='+str(len(legacy_body))+')')
(legacy_dir/'meta.json').write_text(json.dumps(dict(id='privacy-legacy',host='fixture.test',method='GET',url='http://fixture.test/',template='/',status=200,content_type='application/json')))
(legacy_dir/'keep.txt').write_text('user-owned file')
c.execute("INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path) VALUES('privacy-legacy',3,'fixture.test','GET','/','http://fixture.test/',200,'application/json',0,?,'fixture.test/GET/privacy-legacy')",(len(legacy_body),))
c.commit()
PY
docker exec "$privacy_pg" pg_dump -U verify -d verify -Fc > "$privacy_work/backup/postgres.dump"
tar -czf "$privacy_work/backup/files.tar.gz" -C "$privacy_work" data
cli() {
  docker run --rm --network "$privacy_project" -e "ARTEX_PG_DSN=$privacy_dsn" \
    -v "$privacy_work/data:/app/data" -v "$privacy_work/backup:/backup:ro" \
    --entrypoint /app/artex "$privacy_image" history-redact "$@"
}
cli -scope traffic -migrate-legacy -batch-size 1 > "$privacy_work/preview.json"
fingerprint=$(python3 - "$privacy_work/preview.json" <<'PY'
import json, sys
r=json.load(open(sys.argv[1]))
assert r['rows']==1 and r['changes']==1 and r['applied'] is False and r['more'] is True
assert 'next_cursor' not in r
print(r['fingerprint'])
PY
)
cli -scope traffic -migrate-legacy -batch-size 1 -apply "$fingerprint" -backup /backup > "$privacy_work/applied.json"
# A new process recovers the successful page's cursor; previews cannot advance it.
cursor=$(python3 - "$privacy_work/applied.json" <<'PYRESUME'
import json,sys
r=json.load(open(sys.argv[1]))
assert r['applied'] is True and r['more'] is True
print(r['next_cursor'])
PYRESUME
)
cli -scope traffic -migrate-legacy -batch-size 1 -cursor "$cursor" > "$privacy_work/preview-two.json"
fingerprint_two=$(python3 - "$privacy_work/preview-two.json" <<'PYPREVIEW'
import json,sys
r=json.load(open(sys.argv[1]))
assert r['rows']==1 and r['changes']==1 and r['more'] is True
print(r['fingerprint'])
PYPREVIEW
)
docker run --rm -i -v "$privacy_work/data:/app/data" --entrypoint python3 "$privacy_image" - <<'PYFAIL'
import sqlite3
c=sqlite3.connect('/app/data/traffic/_index/index.sqlite')
c.execute("CREATE TRIGGER fail_batch BEFORE UPDATE ON exchanges BEGIN SELECT RAISE(ABORT,'synthetic failure'); END")
c.commit()
PYFAIL
if cli -scope traffic -migrate-legacy -batch-size 1 -cursor "$cursor" -apply "$fingerprint_two" -backup /backup > "$privacy_work/failed.txt"; then
 echo 'Injected batch failure unexpectedly succeeded' >&2
 exit 1
fi
docker run --rm -i -v "$privacy_work/data:/app/data" --entrypoint python3 "$privacy_image" - <<'PYRETRY'
import sqlite3
c=sqlite3.connect('/app/data/traffic/_index/index.sqlite')
c.execute('DROP TRIGGER fail_batch')
c.commit()
PYRETRY
cli -scope traffic -migrate-legacy -batch-size 1 -cursor "$cursor" -apply "$fingerprint_two" -backup /backup > "$privacy_work/applied-two.json"
cursor_three=$(python3 - "$privacy_work/applied-two.json" <<'PYTHREE'
import json,sys
r=json.load(open(sys.argv[1]))
assert r['applied'] is True and r['more'] is True
print(r['next_cursor'])
PYTHREE
)
cli -scope traffic -migrate-legacy -batch-size 1 -cursor "$cursor_three" > "$privacy_work/preview-three.json"
fingerprint_three=$(python3 - "$privacy_work/preview-three.json" <<'PYLEGACY'
import json,sys
r=json.load(open(sys.argv[1]))
assert r['rows']==1 and r['legacy_rows']==1 and r['changes']==1 and r['more'] is False
print(r['fingerprint'])
PYLEGACY
)
cli -scope traffic -migrate-legacy -batch-size 1 -cursor "$cursor_three" -apply "$fingerprint_three" -backup /backup > "$privacy_work/applied-three.json"
cli -scope traffic -migrate-legacy > "$privacy_work/after.json"
cli -scope evidence > "$privacy_work/evidence.json"
docker start "$privacy_app" >/dev/null
for attempt in {1..60}; do
  if docker exec "$privacy_app" curl --fail --silent http://127.0.0.1:8787/api/health > "$privacy_work/health-after.json" 2>/dev/null; then break; fi
  sleep 1
done
python3 - "$privacy_work" <<'PY'
import json, pathlib, sqlite3, sys
p=pathlib.Path(sys.argv[1])
assert json.loads((p/'applied.json').read_text())['applied'] is True
assert json.loads((p/'after.json').read_text())['changes']==0
assert json.loads((p/'evidence.json').read_text())['rows']==0
assert json.loads((p/'health-after.json').read_text())['ok'] is True
c=sqlite3.connect((p/'data/traffic/_index/index.sqlite').as_uri()+'?mode=ro',uri=True)
rows=c.execute('SELECT req_head,resp_body FROM exchange_bodies').fetchall()
assert len(rows)==3
for head,body in rows:
 assert 'synthetic-cli-only' not in head and b'synthetic-cli-only' not in body
 assert b'9007199254740993' in body
last=json.loads((p/'applied-three.json').read_text())
assert last['applied'] is True and last['more'] is False and 'next_cursor' not in last
assert last['legacy_rows']==1 and last['migrate_legacy'] is True
assert c.execute("SELECT count(*) FROM exchanges WHERE path<>''").fetchone()[0]==0
legacy=p/'data/traffic/fixture.test/GET/privacy-legacy'
assert all(not (legacy/name).exists() for name in ['request.http','response.http','meta.json'])
assert (legacy/'keep.txt').read_text()=='user-owned file'
assert not list((p/'data/traffic/_blobs/sha256').glob('*/*/*.bin'))
audit=[json.loads(f.read_text()) for f in (p/'data/privacy-audit').glob('*.json')]
assert sorted(a['status'] for a in audit)==['complete','complete','complete','failed_or_partial','started','started','started','started']
assert all('next_cursor' not in a for a in audit if a['status']!='complete')
print(json.dumps({'live_rejected':True,'batches':3,'legacy_migrated':1,'failed_batch_retried':True,'applied':True,'remaining_changes':0,'audit_complete':True,'restart_healthy':True}))
PY

# Cold archive maintenance uses the same stopped-application/backup lifecycle.
docker stop "$privacy_app" >/dev/null
python3 "$(dirname -- "${BASH_SOURCE[0]}")/privacy-archive.py" seed "$privacy_work"
docker exec -i "$privacy_pg" psql -U verify -d verify -v ON_ERROR_STOP=1 < "$privacy_work/archive-seed.sql" > "$privacy_work/archive-seed.log"
docker exec "$privacy_pg" pg_dump -U verify -d verify -Fc > "$privacy_work/backup/postgres.dump"
tar -czf "$privacy_work/backup/files.tar.gz" -C "$privacy_work" data
cli -scope archive-traffic -archive-id 900000001 > "$privacy_work/archive-preview.json"
archive_fp=$(python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); assert r["rows"]==1 and r["changes"]==1 and not r["applied"]; print(r["fingerprint"])' "$privacy_work/archive-preview.json")
cli -scope archive-traffic -archive-id 900000001 -apply "$archive_fp" -backup /backup > "$privacy_work/archive-applied.json"
cli -scope archive-traffic -archive-id 900000001 > "$privacy_work/archive-after.json"
docker exec "$privacy_pg" psql -U verify -d verify -Atc "SELECT json_build_object('path',archive_path,'sha256',sha256,'original_size',original_size,'compressed_size',compressed_size) FROM task_archives WHERE id=900000001" > "$privacy_work/archive-catalog.json"
python3 "$(dirname -- "${BASH_SOURCE[0]}")/privacy-archive.py" verify "$privacy_work"
# Evidence/report maintenance has a separate scope and fingerprint.
python3 "$(dirname -- "${BASH_SOURCE[0]}")/privacy-archive.py" seed-evidence "$privacy_work"
docker exec -i "$privacy_pg" psql -U verify -d verify -v ON_ERROR_STOP=1 < "$privacy_work/archive-evidence-seed.sql" > "$privacy_work/archive-evidence-seed.log"
docker exec "$privacy_pg" pg_dump -U verify -d verify -Fc > "$privacy_work/backup/postgres.dump"
tar -czf "$privacy_work/backup/files.tar.gz" -C "$privacy_work" data
cli -scope archive-evidence -archive-id 900000002 > "$privacy_work/archive-evidence-preview.json"
evidence_fp=$(python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); assert r["rows"]==6 and r["changes"]==6 and not r["applied"]; print(r["fingerprint"])' "$privacy_work/archive-evidence-preview.json")
cli -scope archive-evidence -archive-id 900000002 -apply "$evidence_fp" -backup /backup > "$privacy_work/archive-evidence-applied.json"
cli -scope archive-evidence -archive-id 900000002 > "$privacy_work/archive-evidence-after.json"
docker exec "$privacy_pg" psql -U verify -d verify -Atc "SELECT json_build_object('path',archive_path,'sha256',sha256,'original_size',original_size,'compressed_size',compressed_size) FROM task_archives WHERE id=900000002" > "$privacy_work/archive-evidence-catalog.json"
python3 "$(dirname -- "${BASH_SOURCE[0]}")/privacy-archive.py" verify-evidence "$privacy_work"

docker start "$privacy_app" >/dev/null
for attempt in {1..60}; do
  if docker exec "$privacy_app" curl --fail --silent http://127.0.0.1:8787/api/health > "$privacy_work/archive-health-after.json" 2>/dev/null; then break; fi
  sleep 1
done
docker exec "$privacy_app" curl --fail --silent http://127.0.0.1:8787/api/health >/dev/null

# Test the host wrapper's resume-file gate with a Docker argument spy. It never
# connects to production; the actual binary lifecycle above used real containers.
mkdir -p "$privacy_work/bin"
cat > "$privacy_work/bin/docker" <<'SHSPY'
#!/usr/bin/env bash
if [[ " $* " == *" ps "* ]]; then exit 0; fi
printf '%s\n' "$@" > "$PRIVACY_ARGV"
SHSPY
chmod +x "$privacy_work/bin/docker"
wrapper="$(dirname -- "${BASH_SOURCE[0]}")/../history-redact.sh"
PATH="$privacy_work/bin:$PATH" PRIVACY_ARGV="$privacy_work/wrapper-argv.txt" bash "$wrapper" preview traffic --batch-size 1 --resume "$privacy_work/applied.json"
python3 - "$privacy_work" <<'PYWRAPPER'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1])
a=(p/'wrapper-argv.txt').read_text().splitlines()
r=json.loads((p/'applied.json').read_text())
assert a[a.index('-cursor')+1]==r['next_cursor']
assert a[a.index('-batch-size')+1]=='1'
assert '-migrate-legacy' in a
PYWRAPPER
for invalid in preview.json applied-three.json; do
 if PATH="$privacy_work/bin:$PATH" PRIVACY_ARGV="$privacy_work/wrapper-argv.txt" bash "$wrapper" preview traffic --resume "$privacy_work/$invalid" > "$privacy_work/wrapper-rejected-$invalid.txt" 2>&1; then
  echo 'Wrapper accepted non-resumable result' >&2
  exit 1
 fi
done
echo 'Wrapper resume gate passed (argument spy).'

PATH="$privacy_work/bin:$PATH" PRIVACY_ARGV="$privacy_work/archive-wrapper-argv.txt" bash "$wrapper" preview archive-traffic --archive-id 900000001
python3 - "$privacy_work/archive-wrapper-argv.txt" <<'PYARCHIVEWRAPPER'
import pathlib,sys
a=pathlib.Path(sys.argv[1]).read_text().splitlines()
assert a[a.index('-scope')+1]=='archive-traffic' and a[a.index('-archive-id')+1]=='900000001'
PYARCHIVEWRAPPER

PATH="$privacy_work/bin:$PATH" PRIVACY_ARGV="$privacy_work/evidence-wrapper-argv.txt" bash "$wrapper" preview archive-evidence --archive-id 900000002
python3 - "$privacy_work/evidence-wrapper-argv.txt" <<'PYEVIDENCEWRAPPER'
import pathlib,sys
a=pathlib.Path(sys.argv[1]).read_text().splitlines()
assert a[a.index('-scope')+1]=='archive-evidence' and a[a.index('-archive-id')+1]=='900000002'
PYEVIDENCEWRAPPER
