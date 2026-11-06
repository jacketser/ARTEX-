"""Build reproducible text from explicitly selected tracked project docs only."""
import hashlib
import html
import json
from pathlib import Path
import subprocess
import sys

root, output = Path(sys.argv[1]), Path(sys.argv[2])
items, sources = [], []
for index, name in enumerate(('README.md', 'DEPLOYMENT.md')):
    raw = subprocess.check_output(['git', '-C', str(root), 'show', 'HEAD:' + name])
    sources.append(dict(path=name, sha256=hashlib.sha256(raw).hexdigest()))
    paragraphs = raw.decode().splitlines()
    for size in (16384, 65536):
        for kind in ('html', 'json'):
            ident = f'doc{index}-{size}-{kind}'
            marker = f'artexcorpus{index}size{size}{kind}'
            request = json.dumps(dict(document=ident, query=marker, excerpts=paragraphs[:24]), ensure_ascii=False).encode()
            # Preserve complete UTF-8 and valid markup/JSON; sizes are targets,
            # actual byte lengths (including wrappers) are recorded below.
            chosen, chars = [], 0
            for line in paragraphs * 16:
                chosen.append(line)
                chars += len(line.encode())
                if chars >= size:
                    break
            if kind == 'html':
                response = ('<!doctype html><html lang="zh"><head><title>' + marker +
                            '</title></head><body>' + ''.join('<p>' + html.escape(x) + '</p>' for x in chosen) +
                            '</body></html>').encode()
                content_type = 'text/html; charset=utf-8'
            else:
                response = json.dumps(dict(document=ident, marker=marker, paragraphs=chosen), ensure_ascii=False).encode()
                content_type = 'application/json'
            # JSON represents bytes as UTF-8 strings for easy audit in Python/Go.
            items.append(dict(id=ident, marker=marker, content_type=content_type,
                              request=request.decode(), response=response.decode(),
                              request_bytes=len(request), response_bytes=len(response),
                              request_sha256=hashlib.sha256(request).hexdigest(),
                              response_sha256=hashlib.sha256(response).hexdigest()))
manifest = dict(source_commit=subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip(),
                sources=sources, items=items)
(output / 'corpus.json').write_text(json.dumps(manifest, ensure_ascii=False))
print(f'Prepared {len(items)} HTML/JSON corpus pairs from tracked project documentation.')
