#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
build_dir=$(mktemp -d /tmp/artex-honeypot-build-XXXXXXXX)
for entry in 'opencanary https://github.com/thinkst/opencanary.git a81e3992751548cbf4ae49eda5df78353d4c81ea' 'honeypots https://github.com/qeeqbox/honeypots.git f337a32e3351e2add3a455a3bcaf1f02ded5744b'; do
  read -r name remote revision <<< "$entry"
  git init -q "$build_dir/$name"
  git -C "$build_dir/$name" fetch --depth 1 "$remote" "$revision"
  git -C "$build_dir/$name" checkout -q --detach FETCH_HEAD
  [[ "$(git -C "$build_dir/$name" rev-parse HEAD)" == "$revision" ]]
done
cp Dockerfile "$build_dir/Dockerfile"
docker build -t jacketser/artex:honeypot-eval "$build_dir"
printf 'Pinned build sources: %s\n' "$build_dir"
