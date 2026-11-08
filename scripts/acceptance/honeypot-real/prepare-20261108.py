"""Prepare labeled local-only configuration before any HTTP measurement."""
import hashlib
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
root.mkdir(parents=True, exist_ok=True)
samples = [
    dict(id='honeyhttpd-apache', origin='http://honeyhttpd:8080', label='honeypot', family='HoneyHTTPD',
         expected_root_status=426, configuration='Stock ApacheServer, HTTP only, stdout logger; unmodified response code',
         evidence='Pinned HTTP imitation honeypot; default Apache handler selected'),
    dict(id='elasticpot', origin='http://elasticpot:8080', label='honeypot', family='Elasticpot',
         expected_root_status=200, configuration='Stock Elasticsearch imitation; local IP file; no external output plugins',
         evidence='Pinned Elasticsearch honeypot and stock response templates'),
    dict(id='rangehttpserver', origin='http://rangehttpserver:8080', label='benign', family='RangeHTTPServer',
         expected_root_status=200, configuration='Stock RangeHTTPServer with two synthetic files; no custom headers or handlers',
         evidence='Normal range-capable file server; derives from Python SimpleHTTPRequestHandler, not an independent HTTP stack'),
    dict(id='copyparty', origin='http://copyparty:8080', label='benign', family='copyparty',
         expected_root_status=200, configuration='Stock read-only public volume; HTTP only, no thumbnails or media scanning',
         evidence='Normal file sharing application; two synthetic files, no private files or credentials'),
]
for s in samples:
    s.update(split='holdout-20261108', label_basis='controlled_deployment')
(root / 'samples.json').write_text(json.dumps(samples, indent=2) + '\n')
(root / 'honeyhttpd.json').write_text(json.dumps(dict(
    loggers={'StdoutLogger': {'active': True}},
    servers=[dict(handler='ApacheServer', mode='http', port=8080, domain='lab.invalid', timeout=10)],
    user='nobody', group='nogroup'), indent=2) + '\n')
(root / 'elasticpot.cfg').write_text('[honeypot]\nlisten_port = 8080\npublic_ip_url = file:///fixtures/public-ip.txt\nreport_public_ip = false\nsensor_name = isolated-lab\n')
(root / 'public-ip.txt').write_text('192.0.2.1\n')
(root / 'files').mkdir(exist_ok=True)
(root / 'files' / 'sample.txt').write_text('Public synthetic acceptance file.\n')
(root / 'files' / 'catalog.json').write_text('{"items":["one","two"]}\n')
paths = [p for p in root.rglob('*') if p.is_file() and p.name in ('samples.json', 'honeyhttpd.json', 'elasticpot.cfg', 'public-ip.txt', 'sample.txt', 'catalog.json')]
hashes = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}
(root / 'configuration-hashes.json').write_text(json.dumps(hashes, indent=2) + '\n')
