#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
build_dir=$(mktemp -d /tmp/artex-honey-20261107-build-XXXXXXXX)
python3 - "$build_dir" <<'PY'
import hashlib, json, subprocess, sys, tarfile
from pathlib import Path
out = Path(sys.argv[1])
for source in json.loads(Path('sources-20261107.json').read_text()):
    archive = out / (source['name'] + '.tar.gz')
    subprocess.run(['curl', '-fsSL', '--connect-timeout', '10', '--max-time', '120', '--retry', '2',
                    f"https://api.github.com/repos/{source['repository']}/tarball/{source['commit']}", '-o', str(archive)], check=True)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != source['archive_sha256']:
        raise ValueError('Source archive differs: ' + source['name'])
    destination = out / source['name']
    destination.mkdir()
    # Use tar's stripping only after validating every member path and link.
    with tarfile.open(archive) as tar:
        for member in tar.getmembers():
            p = Path(member.name)
            if p.is_absolute() or '..' in p.parts or member.issym() or member.islnk() or member.isdev():
                raise ValueError('Unsafe archive member: ' + member.name)
    subprocess.run(['tar', '-xzf', str(archive), '-C', str(destination), '--strip-components=1'], check=True)
PY
cp sources-20261107.json "$build_dir/"
cp Dockerfile.holdout-20261107 "$build_dir/Dockerfile"
docker build -t jacketser/artex:honeypot-holdout-20261107 "$build_dir"
printf 'Pinned new holdout sources: %s\n' "$build_dir"
