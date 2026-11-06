#!/usr/bin/env bash
# Offline maintenance only; never starts/stops production or deletes backups.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
usage() {
  echo 'Usage: bash scripts/history-redact.sh preview traffic|evidence'
  echo '       bash scripts/history-redact.sh apply traffic|evidence FINGERPRINT BACKUP_DIRECTORY'
}
if (( $# < 2 )); then usage; exit 2; fi
action=$1
scope=$2
if [[ "$scope" != traffic && "$scope" != evidence ]]; then usage; exit 2; fi
dc() { docker compose -f compose.source.yml "$@"; }
if [[ -n "$(dc ps -q --status running artex)" ]]; then
  echo '应用仍在运行。请先确认没有进行中的任务、完成备份并停止 artex，再执行预览或清理。' >&2
  exit 1
fi
args=(history-redact -data /app/data -scope "$scope")
mounts=()
case "$action" in
  preview) [[ $# == 2 ]] || { usage; exit 2; } ;;
  apply)
    [[ $# == 4 && "$3" =~ ^[0-9a-f]{64}$ ]] || { usage; exit 2; }
    backup_dir=$(realpath -- "$4")
    [[ -s "$backup_dir/postgres.dump" && -s "$backup_dir/files.tar.gz" ]] || { echo '备份文件不存在或为空' >&2; exit 1; }
    # Validate archive readability before mounting it read-only into maintenance.
    dc exec -T postgres pg_restore --list < "$backup_dir/postgres.dump" >/dev/null
    tar -tzf "$backup_dir/files.tar.gz" >/dev/null
    mounts=(-v "$backup_dir:/privacy-backup:ro")
    args+=(-apply "$3" -backup /privacy-backup)
    ;;
  *) usage; exit 2 ;;
esac
dc run --rm --no-deps -T "${mounts[@]}" --entrypoint /app/artex artex "${args[@]}"
