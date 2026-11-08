"""Fetch locked public sources only; no target probing or upstream setup scripts."""
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import urllib.request

here = Path(__file__).resolve().parent
out = Path(sys.argv[1]).resolve()
out.mkdir(parents=True, exist_ok=True)

cache = Path(sys.argv[2]) if len(sys.argv) > 2 else None

def fetch(url, digest, filename):
    if cache is not None and (cache / filename).is_file():
        body = (cache / filename).read_bytes()
        if hashlib.sha256(body).hexdigest() != digest:
            raise ValueError("Cached source hash mismatch")
        return body
    req = urllib.request.Request(url, headers={'User-Agent': 'ARTEX-source-evaluation'})
    with urllib.request.urlopen(req, timeout=45) as response:
        body = response.read(40 * 1024 * 1024 + 1)
    if len(body) > 40 * 1024 * 1024 or hashlib.sha256(body).hexdigest() != digest:
        raise ValueError('Source archive size/hash mismatch')
    return body

for source in json.loads((here / 'sources-20261108.json').read_text()):
    body = fetch(source['archive_url'], source['archive_sha256'], source['id'] + '.tar.gz')
    dest = out / source['id']
    dest.mkdir()
    links = []
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:gz') as archive:
        for member in archive.getmembers():
            parts = Path(member.name).parts[1:]
            if not parts:
                continue
            if '..' in parts or Path(*parts).is_absolute():
                raise ValueError('Unsafe archive path')
            path = dest.joinpath(*parts)
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(archive.extractfile(member).read())
            elif member.issym():
                links.append((path, member.linkname))
            else:
                raise ValueError('Unsupported archive member')
    for path, target in links:
        resolved = (path.parent / target).resolve()
        if not resolved.is_relative_to(dest) or not resolved.is_file():
            raise ValueError('Unsafe source symlink')
        path.symlink_to(target)
    print(source['id'], source['commit'], source['archive_sha256'])
(out / 'wheels').mkdir()
for wheel in json.loads((here / 'dependencies-20261108.json').read_text()):
    (out / 'wheels' / wheel['filename']).write_bytes(fetch(wheel['url'], wheel['sha256'], wheel['filename']))
for name in ('sources-20261108.json', 'dependencies-20261108.json', 'Dockerfile.holdout-20261108'):
    (out / name).write_bytes((here / name).read_bytes())
