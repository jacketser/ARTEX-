#!/usr/bin/env bash
# Run after editing the fork. Dependencies are built in Docker, not on the host.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
python3 - <<'PY'
from pathlib import Path
import secrets

if not Path('.env').exists():
    with Path('.env').open('x') as f:
        f.write('POSTGRES_PASSWORD=' + secrets.token_hex(24) + '\n'
                'ARTEX_BIND_ADDRESS=127.0.0.1\nARTEX_HTTP_PORT=8787\n')
    Path('.env').chmod(0o600)
if not Path('jwt.key').exists():
    with Path('jwt.key').open('x') as f:
        f.write(secrets.token_urlsafe(48))
    Path('jwt.key').chmod(0o600)
Path('data').mkdir(mode=0o700, exist_ok=True)
PY
ARTEX_BUILD_VERSION="dev-$(git rev-parse --short HEAD)"
if [[ -n "$(git status --porcelain)" ]]; then
  ARTEX_BUILD_VERSION+="-dirty"
fi
export ARTEX_BUILD_VERSION
docker compose -f compose.source.yml config --quiet
docker compose -f compose.source.yml build artex
docker compose -f compose.source.yml up -d --wait --wait-timeout 180
docker compose -f compose.source.yml ps
