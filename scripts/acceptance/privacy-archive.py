"""Synthetic cold archive fixture for privacy-run.sh (host Python + libzstd)."""
import base64
import ctypes
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile

work = Path(sys.argv[2])
evidence = sys.argv[1].endswith('-evidence')
archive_id = 900000002 if evidence else 900000001
stem = 'archive-evidence' if evidence else 'archive'
original_name = stem + '-original.tar.zst'
zstd = ctypes.CDLL('libzstd.so.1')
zstd.ZSTD_isError.argtypes = [ctypes.c_size_t]
zstd.ZSTD_isError.restype = ctypes.c_uint
zstd.ZSTD_compressBound.argtypes = [ctypes.c_size_t]
zstd.ZSTD_compressBound.restype = ctypes.c_size_t
zstd.ZSTD_compress.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
zstd.ZSTD_compress.restype = ctypes.c_size_t
zstd.ZSTD_decompress.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t]
zstd.ZSTD_decompress.restype = ctypes.c_size_t


def snapshot_id(snapshot):
    # Field order follows db.TrafficEvidenceSnapshot; identity excludes ID/time.
    fields = ('id', 'source_traffic_id', 'captured_at', 'url', 'method', 'status',
              'content_type', 'req_head', 'resp_head', 'req_hash', 'resp_hash',
              'req_len', 'resp_len', 'created_at')
    identity = {key: snapshot[key] for key in fields}
    identity['id'] = ''
    identity['created_at'] = '0001-01-01T00:00:00Z'
    return hashlib.sha256(json.dumps(identity, separators=(',', ':')).encode()).hexdigest()


def evidence_path(digest):
    return f'evidence/blobs/{digest[:2]}/{digest}.bin'


if sys.argv[1].startswith('seed'):
    body = b'{"token":"synthetic-archive-only","number":9007199254740993}'
    digest = hashlib.sha256(body).hexdigest()
    exchange = dict(id='cold-cli-only', ts=19, host='fixture.test', method='GET',
                    url_template='/', url='http://fixture.test/', status=200,
                    content_type='application/json', req_len=0, resp_len=len(body),
                    req_head='GET / HTTP/1.1\nHost: fixture.test\n',
                    resp_head='HTTP 200\nContent-Type: application/json\n',
                    resp_blob=digest)
    members = {
        'manifest.json': json.dumps(dict(format_version=3, task_id=archive_id,
                                         data_counts={'traffic': 1})).encode(),
        'traffic/traffic.json': json.dumps(dict(version=1, exchanges=[exchange], blobs=[digest])).encode(),
        'traffic/blobs/' + digest + '.bin': body,
        f'files/tasks/{archive_id}/note.txt': b'workspace unchanged',
    }
    if evidence:
        empty_hash = hashlib.sha256(b'').hexdigest()
        snapshot = dict(id='', source_traffic_id='cold-cli-only', captured_at=19,
                        url=exchange['url'], method='GET', status=200, content_type='application/json',
                        req_head=exchange['req_head'], resp_head=exchange['resp_head'],
                        req_hash=empty_hash, resp_hash=digest, req_len=0, resp_len=len(body),
                        created_at='2026-01-01T00:00:00Z')
        snapshot['id'] = snapshot_id(snapshot)
        finding = dict(id=9007199254740993, task_id=archive_id, name='fixture',
                       summary='', evidence=body.decode(), report=body.decode(), status='confirmed',
                       evidence_version=7, report_evidence_version=7)
        binding = dict(id=9007199254740995, finding_id=finding['id'], snapshot_id=snapshot['id'],
                       role='proof', note=body.decode(), position=0, created_at='2026-01-01T00:00:00Z')
        tables = dict(findings=[finding], traffic_evidence_snapshots=[snapshot], finding_traffic_bindings=[binding])
        historical_time = '2026-01-01T00:00:00Z'
        tables['finding_retests'] = [dict(id=9007199254740996, finding_id=finding['id'],
            conversation_id=None, status='completed', verdict='inconclusive', notes=body.decode(),
            snapshot=json.loads(body), summary=body.decode(), evidence=body.decode(), error='',
            created_at=historical_time, started_at=historical_time, finished_at=historical_time)]
        tables['finding_reviews'] = [dict(finding_id=finding['id'], fingerprint='original-fingerprint',
            verdict='inconclusive', sources=body.decode(), reproduction=body.decode(),
            counter_evidence=body.decode(), limitations=body.decode(), updated_at=historical_time)]
        tables['finding_review_history'] = [dict(id=9007199254740997, finding_id=finding['id'],
            kind='automatic', fingerprint='original-fingerprint', result=json.loads(body), created_at=historical_time)]
        members['manifest.json'] = json.dumps(dict(format_version=4, task_id=archive_id, tables=tables,
                                                   data_counts={**{k: len(v) for k, v in tables.items()}, 'traffic': 1})).encode()
        members[evidence_path(empty_hash)] = b''
        members[evidence_path(digest)] = body
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w') as archive:
        for name, value in members.items():
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(value), 0o600
            archive.addfile(info, io.BytesIO(value))
    raw = raw.getvalue()
    out = ctypes.create_string_buffer(zstd.ZSTD_compressBound(len(raw)))
    size = zstd.ZSTD_compress(out, len(out), raw, len(raw), 3)
    assert not zstd.ZSTD_isError(size)
    packed = out.raw[:size]
    target = work / 'data/archives/tasks' / original_name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(packed)
    (work / (stem + '-seed.sql')).write_text(f"""
INSERT INTO explorations(id,goal) VALUES({archive_id},'synthetic archive');
INSERT INTO tasks(id,description,goal,exploration_id,status,archived_at,deleted_at)
 VALUES({archive_id},'synthetic archive','fixture',{archive_id},'done',now(),now());
INSERT INTO task_archives(id,task_id,state,format_version,archive_path,sha256,original_size,compressed_size)
 VALUES({archive_id},{archive_id},'ready',{4 if evidence else 3},'/app/data/archives/tasks/{original_name}',
 '{hashlib.sha256(packed).hexdigest()}',{sum(map(len,members.values()))},{len(packed)});
""")
else:
    catalog = json.loads((work / (stem + '-catalog.json')).read_text())
    packed = (work / 'data' / Path(catalog['path']).relative_to('/app/data')).read_bytes()
    assert hashlib.sha256(packed).hexdigest() == catalog['sha256']
    assert len(packed) == catalog['compressed_size']
    out = ctypes.create_string_buffer(1024 * 1024)
    size = zstd.ZSTD_decompress(out, len(out), packed, len(packed))
    assert not zstd.ZSTD_isError(size)
    with tarfile.open(fileobj=io.BytesIO(out.raw[:size]), mode='r:') as archive:
        assert sum(m.size for m in archive.getmembers()) == catalog['original_size']
        if evidence:
            manifest_raw = archive.extractfile('manifest.json').read()
            assert b'synthetic-archive-only' not in manifest_raw
            manifest = json.loads(manifest_raw)
            assert manifest['format_version'] == 4
            tables = manifest['tables']
            for name in ('finding_retests', 'finding_reviews', 'finding_review_history'):
                assert manifest['data_counts'][name] == 1 and len(tables[name]) == 1
                assert tables[name][0]['finding_id'] == 9007199254740993
            retest = tables['finding_retests'][0]
            assert retest['id'] == 9007199254740996 and retest['status'] == 'completed'
            assert retest['conversation_id'] is None and retest['snapshot']['number'] == 9007199254740993
            assert retest['finished_at'] == '2026-01-01T00:00:00Z'
            assert tables['finding_reviews'][0]['fingerprint'] == 'original-fingerprint'
            history = tables['finding_review_history'][0]
            assert history['id'] == 9007199254740997 and history['fingerprint'] == 'original-fingerprint'
            assert history['result']['number'] == 9007199254740993
            assert history['kind'] == 'automatic' and history['created_at'] == retest['finished_at']
            finding = tables['findings'][0]
            assert finding['id'] == 9007199254740993 and finding['status'] == 'confirmed'
            assert finding['evidence_version'] == 8 and finding['report_evidence_version'] == 7
            snapshot = tables['traffic_evidence_snapshots'][0]
            assert snapshot_id(snapshot) == snapshot['id']
            assert tables['finding_traffic_bindings'][0]['snapshot_id'] == snapshot['id']
            body = archive.extractfile(evidence_path(snapshot['resp_hash'])).read()
            assert hashlib.sha256(body).hexdigest() == snapshot['resp_hash']
            assert len(body) == snapshot['resp_len']
            assert b'synthetic-archive-only' not in body and b'9007199254740993' in body
            # Ordinary traffic remains an independent, explicitly unprocessed copy.
            traffic = json.load(archive.extractfile('traffic/traffic.json'))
            old_body = archive.extractfile('traffic/blobs/' + traffic['blobs'][0] + '.bin').read()
            assert b'synthetic-archive-only' in old_body
            assert evidence_path(traffic['blobs'][0]) not in archive.getnames()
        else:
            assert not any(m.name.startswith('traffic/blobs/') for m in archive.getmembers())
            snapshot = json.load(archive.extractfile('traffic/traffic.json'))
            assert not snapshot['blobs']
            restored = snapshot['exchanges'][0]
            body = base64.b64decode(restored['resp_body'])
            assert b'synthetic-archive-only' not in body and b'9007199254740993' in body
            assert restored['resp_len'] == len(body) and restored['id'] == 'cold-cli-only'
        assert archive.extractfile(f'files/tasks/{archive_id}/note.txt').read() == b'workspace unchanged'
    assert not (work / 'data/archives/tasks' / original_name).exists()
    assert json.loads((work / (stem + '-applied.json')).read_text())['applied'] is True
    assert json.loads((work / (stem + '-after.json')).read_text())['changes'] == 0
    audits = [json.loads(p.read_text()) for p in (work / 'data/privacy-audit').glob('*.json')]
    audits = [a for a in audits if a['scope'] == ('archive-evidence' if evidence else 'archive-traffic')]
    assert sorted(a['status'] for a in audits) == ['complete', 'started']
    assert all(a['archive_id'] == archive_id and a['more'] is False for a in audits)
    print(f'{stem} CLI: package, redaction, retained independent data, audit and idempotence passed.')
