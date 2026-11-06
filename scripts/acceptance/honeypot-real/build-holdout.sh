#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
build_dir=$(mktemp -d /tmp/artex-honey-holdout-build-XXXXXXXX)
git init -q "$build_dir/heralding"
git -C "$build_dir/heralding" fetch --depth 1 https://github.com/johnnykv/heralding.git ac12724ab38c4e2fe78f07d1bc35e6e586ba69c0
git -C "$build_dir/heralding" checkout -q --detach FETCH_HEAD
[[ "$(git -C "$build_dir/heralding" rev-parse HEAD)" == ac12724ab38c4e2fe78f07d1bc35e6e586ba69c0 ]]
cp Dockerfile.holdout "$build_dir/Dockerfile"
docker build -t jacketser/artex:honeypot-holdout "$build_dir"
printf 'Pinned holdout sources: %s\n' "$build_dir"
