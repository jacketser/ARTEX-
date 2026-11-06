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
zstd = ctypes.CDLL('libzstd.so.1')
zstd.ZSTD_isError.argtypes = [ctypes.c_size_t]
zstd.ZSTD_isError.restype = ctypes.c_uint
zstd.ZSTD_compressBound.argtypes = [ctypes.c_size_t]
zstd.ZSTD_compressBound.restype = ctypes.c_size_t
zstd.ZSTD_compress.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
zstd.ZSTD_compress.restype = ctypes.c_size_t
zstd.ZSTD_decompress.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t]
zstd.ZSTD_decompress.restype = ctypes.c_size_t

if sys.argv[1] == 'seed':
    body = b'{"token":"synthetic-archive-only","number":9007199254740993}'
    digest = hashlib.sha256(body).hexdigest()
    exchange = dict(id='cold-cli-only', ts=19, host='fixture.test', method='GET',
                    url_template='/', url='http://fixture.test/', status=200,
                    content_type='application/json', req_len=0, resp_len=len(body),
                    req_head='GET / HTTP/1.1\nHost: fixture.test\n',
                    resp_head='HTTP 200\nContent-Type: application/json\n',
                    resp_blob=digest)
    members = {
        'manifest.json': json.dumps(dict(format_version=3, task_id=900000001,
                                         data_counts={'traffic': 1})).encode(),
        'traffic/traffic.json': json.dumps(dict(version=1, exchanges=[exchange], blobs=[digest])).encode(),
        'traffic/blobs/' + digest + '.bin': body,
        'files/tasks/900000001/note.txt': b'workspace unchanged',
    }
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
    target = work / 'data/archives/tasks/cli-original.tar.zst'
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(packed)
    (work / 'archive-seed.sql').write_text(f"""
INSERT INTO explorations(id,goal) VALUES(900000001,'synthetic archive');
INSERT INTO tasks(id,description,goal,exploration_id,status,archived_at,deleted_at)
 VALUES(900000001,'synthetic archive','fixture',900000001,'done',now(),now());
INSERT INTO task_archives(id,task_id,state,format_version,archive_path,sha256,original_size,compressed_size)
 VALUES(900000001,900000001,'ready',3,'/app/data/archives/tasks/cli-original.tar.zst',
 '{hashlib.sha256(packed).hexdigest()}',{sum(map(len,members.values()))},{len(packed)});
""")
else:
    catalog = json.loads((work / 'archive-catalog.json').read_text())
    packed = (work / 'data' / Path(catalog['path']).relative_to('/app/data')).read_bytes()
    assert hashlib.sha256(packed).hexdigest() == catalog['sha256']
    assert len(packed) == catalog['compressed_size']
    out = ctypes.create_string_buffer(1024 * 1024)
    size = zstd.ZSTD_decompress(out, len(out), packed, len(packed))
    assert not zstd.ZSTD_isError(size)
    with tarfile.open(fileobj=io.BytesIO(out.raw[:size]), mode='r:') as archive:
        assert sum(m.size for m in archive.getmembers()) == catalog['original_size']
        assert not any(m.name.startswith('traffic/blobs/') for m in archive.getmembers())
        snapshot = json.load(archive.extractfile('traffic/traffic.json'))
        assert not snapshot['blobs']
        restored = snapshot['exchanges'][0]
        body = base64.b64decode(restored['resp_body'])
        assert b'synthetic-archive-only' not in body and b'9007199254740993' in body
        assert restored['resp_len'] == len(body) and restored['id'] == 'cold-cli-only'
        assert archive.extractfile('files/tasks/900000001/note.txt').read() == b'workspace unchanged'
    assert not (work / 'data/archives/tasks/cli-original.tar.zst').exists()
    assert json.loads((work / 'archive-applied.json').read_text())['applied'] is True
    assert json.loads((work / 'archive-after.json').read_text())['changes'] == 0
    audits = [json.loads(p.read_text()) for p in (work / 'data/privacy-audit').glob('*.json')]
    audits = [a for a in audits if a['scope'] == 'archive-traffic']
    assert sorted(a['status'] for a in audits) == ['complete', 'started']
    assert all(a['archive_id'] == 900000001 and a['more'] is False for a in audits)
    print('Cold archive CLI: checksum, retained workspace, redacted traffic, audit and idempotence passed.')
