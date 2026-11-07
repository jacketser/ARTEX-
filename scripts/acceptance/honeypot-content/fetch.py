#!/usr/bin/env python3
"""Fetch only the predeclared public GitHub source files; never sample URLs."""
import concurrent.futures
import hashlib
import json
import pathlib
import sys
import urllib.request

lock = json.loads(pathlib.Path(__file__).with_name('sources.json').read_text())
root = pathlib.Path(sys.argv[1])
root.mkdir(parents=True, exist_ok=True)


def fetch(item):
    url = 'https://raw.githubusercontent.com/' + item['repository'] + '/' + item['commit'] + '/' + item['path']
    with urllib.request.urlopen(url, timeout=25) as response:
        raw = response.read(item['bytes'] + 1)
    digest = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    if len(raw) != item['bytes'] or digest != item['git_blob_sha1']:
        raise ValueError('source integrity mismatch: ' + item['path'])
    name = item['repository'].replace('/', '_') + '-' + item['path'].replace('/', '_')
    path = root / name
    temp = root / (name + '.tmp')
    temp.write_bytes(raw)
    temp.replace(path)
    return name


with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
    files = list(pool.map(fetch, lock['sources']))
print('Verified source files:', len(files))
