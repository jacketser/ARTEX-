#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
[[ "$(docker image inspect --format '{{.Id}}' jacketser/artex:honeypot-eval)" == sha256:dbd70b4d075e906774db6129d5577ec012914c4084c6fbb2cd5eb468a1372043 ]]
context=$(mktemp -d /tmp/artex-honey-holdout-build-XXXXXXXX)
# Only source archives/wheels are downloaded. The Docker build uses no network.
python3 fetch-20261108.py "$context" "${1:-$context}"
docker build --network none --pull=false -f "$context/Dockerfile.holdout-20261108" -t jacketser/artex:honeypot-holdout-20261108 "$context"
printf 'Pinned build sources: %s\n' "$context"
