"""Build deployment labels before evaluation, never from detected markers."""
import hashlib
import html
import json
from pathlib import Path
import sys

source, out = Path(sys.argv[1]), Path(sys.argv[2])
settings = json.loads((source / 'opencanary/data/settings.json').read_text())
for key in settings:
    if key.endswith('.enabled'):
        settings[key] = False
settings.update({'http.enabled': True, 'http.port': 8088, 'device.listen_addr': '0.0.0.0'})
settings['logger']['kwargs']['handlers'] = {'console': {'class': 'logging.StreamHandler', 'stream': 'ext://sys.stdout'}}
for suffix, skin in [('nas', 'nasLogin')]:
    settings['http.skin'] = skin
    (out / f'canary-{suffix}.json').write_text(json.dumps(settings, indent=2))
doc = (source / 'README.md').read_text()
(out / 'docs').mkdir()
(out / 'docs/index.html').write_text('<!doctype html><html><head><title>OpenCanary project documentation</title></head><body><pre>' + html.escape(doc) + '</pre></body></html>')
conf = 'worker_processes 1; pid /tmp/honey-nginx.pid; error_log /dev/stderr; events {worker_connections 128;} http { access_log /dev/stdout; default_type text/html;\n'
for port, root, fallback in [(8080, '/usr/share/nginx/html', False), (8081, '/usr/share/nginx/html', True), (8082, '/srv/honey-docs', False), (8083, '/srv/honey-docs', True)]:
    conf += f'server {{ listen {port}; root {root}; index index.html; location / {{ try_files $uri $uri/ ' + ('/index.html' if fallback else '=404') + '; } }\n'
(out / 'nginx.conf').write_text(conf + '}\n')
samples = [
    dict(id='opencanary-nas', origin='http://canary-nas:8088', label='honeypot', family='OpenCanary', configuration='nasLogin; stock Apache banner', evidence='Pinned OpenCanary source, packaged skin and HTTP-only configuration'),
    dict(id='qeeqbox-http', origin='http://qhttp:8080', label='honeypot', family='QeeqBox', configuration='QHTTPServer defaults; randomly selected server banner', evidence='Pinned upstream QHTTPServer runs without response-code changes'),
    dict(id='qeeqbox-https', origin='https://qhttps:8443', label='honeypot', family='QeeqBox', configuration='QHTTPSServer defaults; generated self-signed certificate', evidence='Pinned upstream QHTTPSServer; default strict TLS validation remains enabled'),
    dict(id='nginx-default', origin='http://normal:8080', label='benign', family='nginx', configuration='packaged welcome page; unknown path 404', evidence='Debian nginx runtime and packaged content; controlled normal deployment'),
    dict(id='nginx-fallback', origin='http://normal:8081', label='benign', family='nginx', configuration='packaged welcome page with ordinary fallback routing', evidence='Known normal configuration control, not an independent website'),
    dict(id='nginx-product-doc', origin='http://normal:8082', label='benign', family='nginx', configuration='upstream OpenCanary README rendered as escaped HTML; unknown path 404', evidence='Product documentation served by nginx; no honeypot runtime'),
    dict(id='nginx-product-doc-fallback', origin='http://normal:8083', label='benign', family='nginx', configuration='same product documentation with fallback routing', evidence='Known normal overlap control: product names plus uniform page, not an independent website'),
]
for item in samples:
    item['label_basis'] = 'controlled_deployment'
    item['expected_root_status'] = 0 if item['id'] == 'qeeqbox-https' else (302 if item['id'] == 'opencanary-nas' else 200)
(out / 'samples.json').write_text(json.dumps(samples, indent=2))
(out / 'configuration-hashes.json').write_text(json.dumps({n: hashlib.sha256((out/n).read_bytes()).hexdigest() for n in ['canary-nas.json', 'nginx.conf', 'docs/index.html', 'samples.json']}, indent=2))
