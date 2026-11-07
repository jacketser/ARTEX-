#!/usr/bin/env python3
"""Offline completeness checks. Does not issue HTTP requests."""
import copy
import json
import pathlib
import shutil
import sys
import tempfile
from summarize import summarize

manifest_path, measurements_path = map(pathlib.Path, sys.argv[1:3])
lock_path = sys.argv[3] if len(sys.argv) > 3 else None
manifest = json.loads(manifest_path.read_text())
measurements = json.loads(measurements_path.read_text())
with tempfile.TemporaryDirectory(prefix='artex-content-summary-check-') as directory:
    root = pathlib.Path(directory)
    shutil.copytree(manifest_path.parent / 'bodies', root / 'bodies')
    shutil.copytree(manifest_path.parent / 'sources', root / 'sources')
    output = root / 'summary.json'

    def run(m, data):
        (root / 'samples.json').write_text(json.dumps(m))
        (root / 'measurements.json').write_text(json.dumps(data))
        summarize(root / 'samples.json', root / 'measurements.json', output, lock_path)

    run(manifest, measurements)
    for mode in ('missing', 'duplicate', 'subset-both', 'label', 'version', 'outcome', 'requests', 'observations', 'body-hash', 'status', 'source'):
        m, data = copy.deepcopy(manifest), copy.deepcopy(measurements)
        if mode == 'missing': data.pop()
        elif mode == 'duplicate': data[-1] = data[0]
        elif mode == 'subset-both': m['samples'].pop(); data.pop()
        elif mode == 'label': m['samples'][0]['group'] = 'injection_hidden'
        elif mode == 'version': data[0]['result']['version'] = 'http-behavior-v2'
        elif mode == 'outcome': data[0]['result']['outcome'] = 'safe'
        elif mode == 'requests': data[0]['requests'] = 5
        elif mode == 'observations': data[0]['result']['observations'].pop()
        elif mode == 'body-hash': data[0]['body_sha256'] = '0' * 64
        elif mode == 'status': data[0]['result']['observations'][0]['status'] = 302
        elif mode == 'source': m['sources'][0]['commit'] = '0' * 40
        output.write_text('stale summary')
        try:
            run(m, data)
        except (ValueError, KeyError, IndexError):
            if output.exists(): raise AssertionError('stale summary survived')
        else:
            raise AssertionError('accepted corrupted result: ' + mode)
    print('Valid corpus and 11 corruption cases: PASS')
