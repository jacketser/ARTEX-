"""Predeclared holdout labels/configurations; never derives labels from results."""
import hashlib
import html
import json
from pathlib import Path
import sys
import yaml

source, out = map(Path, sys.argv[1:])
config = yaml.safe_load((source / 'heralding/heralding.yml').read_text())
for cap in config['capabilities'].values():
    cap['enabled'] = False
config['capabilities']['http'].update(enabled=True, port=8080)
config['public_ip_as_destination_ip'] = False
config['hash_cracker']['enabled'] = False
for logger in config['activity_logging'].values():
    logger['enabled'] = False
(out / 'heralding.yml').write_text(yaml.safe_dump(config))
(out / 'docs').mkdir()
(out / 'docs/index.html').write_text('<!doctype html><title>Project documentation</title><pre>' + html.escape((source / 'README.rst').read_text()) + '</pre>')
(out / 'plain').mkdir()
(out / 'plain/index.html').write_text('<!doctype html><title>Internal handbook</title><p>Ordinary static documentation.</p>')
# A normal HTTP Basic challenge is not a detection success. This unused dummy
# account is confined to the lab; the driver never submits credentials.
(out / 'apache.conf').write_text('''ServerRoot /etc/apache2
PidFile /tmp/apache-eval.pid
ServerName normal.test
LoadModule mpm_event_module /usr/lib/apache2/modules/mod_mpm_event.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
LoadModule authn_core_module /usr/lib/apache2/modules/mod_authn_core.so
LoadModule authn_file_module /usr/lib/apache2/modules/mod_authn_file.so
LoadModule authz_user_module /usr/lib/apache2/modules/mod_authz_user.so
LoadModule auth_basic_module /usr/lib/apache2/modules/mod_auth_basic.so
LoadModule dir_module /usr/lib/apache2/modules/mod_dir.so
User www-data
Group www-data
ErrorLog /dev/stderr
LogLevel warn
StartServers 1
ThreadsPerChild 4
MaxRequestWorkers 8
Listen 8080
Listen 8081
Listen 8082
<Directory />
Require all granted
</Directory>
DirectoryIndex index.html
<VirtualHost *:8080>
DocumentRoot /var/www/html
</VirtualHost>
<VirtualHost *:8081>
DocumentRoot /srv/honey-docs
FallbackResource /index.html
</VirtualHost>
<VirtualHost *:8082>
DocumentRoot /var/www/html
<Location />
AuthType Basic
AuthName "Restricted handbook"
AuthUserFile /srv/eval-users
Require valid-user
</Location>
</VirtualHost>
''')
(out / 'eval-users').write_text('lab-unused:!\n')
samples = [
    dict(id='heralding-http', origin='http://heralding:8080', label='honeypot', family='Heralding', configuration='stock HTTP capability; unauthenticated request', expected_root_status=401),
    dict(id='apache-default', origin='http://apache:8080', label='benign', family='Apache httpd', configuration='Debian packaged welcome page; unknown path 404', expected_root_status=200),
    dict(id='apache-document-fallback', origin='http://apache:8081', label='benign', family='Apache httpd', configuration='escaped Heralding README.rst and FallbackResource; no honeypot runtime', expected_root_status=200),
    dict(id='apache-auth', origin='http://apache:8082', label='benign', family='Apache httpd', configuration='ordinary HTTP Basic authentication; no credentials submitted', expected_root_status=401),
    dict(id='python-static', origin='http://python:8080', label='benign', family='Python http.server', configuration='stdlib static server; normal handbook; unknown path 404', expected_root_status=200),
]
for s in samples:
    s.update(split='holdout', label_basis='controlled_deployment', evidence='Predeclared runtime and configuration; not inferred from detection')
(out / 'samples.json').write_text(json.dumps(samples, indent=2))
(out / 'configuration-hashes.json').write_text(json.dumps({n: hashlib.sha256((out/n).read_bytes()).hexdigest() for n in ['heralding.yml', 'apache.conf', 'eval-users', 'docs/index.html', 'plain/index.html', 'samples.json']}, indent=2))
