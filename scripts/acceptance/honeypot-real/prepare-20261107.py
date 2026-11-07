"""New application holdout: labels fixed before the detector is run."""
import hashlib
import json
from pathlib import Path
import sqlite3
import sys

out = Path(sys.argv[1])
with sqlite3.connect(out / 'catalog.db') as db:
    db.execute('CREATE TABLE books(id INTEGER PRIMARY KEY, title TEXT, year INTEGER)')
    db.executemany('INSERT INTO books VALUES(?,?,?)', [(1, 'Internal handbook', 2022), (2, 'Operations guide', 2024), (3, 'API reference', 2025)])
samples = [
    dict(id='log4pot-json', origin='http://log4pot-json:8080', label='honeypot', family='Log4Pot', configuration='Original default.json response; stock Server; payloader/cloud logging disabled', evidence='Pinned Log4Pot server and original bundled JSON response; actual HTTP capture honeypot'),
    dict(id='log4pot-tomcat', origin='http://log4pot-tomcat:8080', label='honeypot', family='Log4Pot', configuration='Original bundled tomcat-default.html via upstream --response/--content-type; stock Server', evidence='Same Log4Pot family, different bundled response; not an independent family'),
    dict(id='httpbin', origin='http://httpbin:8080', label='benign', family='httpbin', configuration='Pinned upstream HTTP application with gunicorn, one worker; root Swagger UI', evidence='Real request/response debugging application; no honeypot runtime'),
    dict(id='datasette', origin='http://datasette:8080', label='benign', family='Datasette', configuration='Pinned Datasette 0.65.1; immutable synthetic SQLite catalog, default templates and settings', evidence='Real data browsing application, separate from all previous static web server controls'),
]
for s in samples:
    s.update(split='holdout-20261107', label_basis='controlled_deployment', expected_root_status=200)
(out / 'samples.json').write_text(json.dumps(samples, indent=2))
(out / 'configuration-hashes.json').write_text(json.dumps({n: hashlib.sha256((out/n).read_bytes()).hexdigest() for n in ['catalog.db', 'samples.json']}, indent=2))
