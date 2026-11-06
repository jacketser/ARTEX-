#!/usr/bin/env bash
# Offline maintenance only; never starts/stops production or deletes backups.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
usage() {
  echo 'Usage: bash scripts/history-redact.sh preview traffic|evidence|archive-traffic|archive-evidence [--archive-id ID] [--migrate-legacy] [--batch-size N] [--cursor TOKEN | --resume RESULT_JSON]'
  echo '       bash scripts/history-redact.sh apply traffic|evidence|archive-traffic|archive-evidence FINGERPRINT BACKUP_DIRECTORY [--archive-id ID] [--migrate-legacy] [--batch-size N] [--cursor TOKEN | --resume RESULT_JSON]'
}
if (( $# < 2 )); then usage; exit 2; fi
action=$1
scope=$2
if [[ "$scope" != traffic && "$scope" != evidence && "$scope" != archive-traffic && "$scope" != archive-evidence ]]; then usage; exit 2; fi
dc() { docker compose -f compose.source.yml "$@"; }
if [[ -n "$(dc ps -q --status running artex)" ]]; then
  echo '应用仍在运行。请先确认没有进行中的任务、完成备份并停止 artex，再执行预览或清理。' >&2
  exit 1
fi
args=(history-redact -data /app/data -scope "$scope")
mounts=()
case "$action" in
  preview) shift 2 ;;
  apply)
    [[ $# -ge 4 && "$3" =~ ^[0-9a-f]{64}$ ]] || { usage; exit 2; }
    backup_dir=$(realpath -- "$4")
    [[ -s "$backup_dir/postgres.dump" && -s "$backup_dir/files.tar.gz" ]] || { echo '备份文件不存在或为空' >&2; exit 1; }
    # Validate archive readability before mounting it read-only into maintenance.
    dc exec -T postgres pg_restore --list < "$backup_dir/postgres.dump" >/dev/null
    tar -tzf "$backup_dir/files.tar.gz" >/dev/null
    mounts=(-v "$backup_dir:/privacy-backup:ro")
    args+=(-apply "$3" -backup /privacy-backup)
    shift 4
    ;;
  *) usage; exit 2 ;;
esac
cursor_set=0
while (( $# )); do
  if [[ "$1" == --migrate-legacy ]]; then args+=(-migrate-legacy); shift; continue; fi
  [[ $# -ge 2 ]] || { usage; exit 2; }
  case "$1" in
    --archive-id)
      [[ "$2" =~ ^[1-9][0-9]{0,17}$ ]] || { usage; exit 2; }
      args+=(-archive-id "$2") ;;
    --batch-size)
      [[ "$2" =~ ^[0-9]{1,5}$ ]] && (( 10#$2 >= 1 && 10#$2 <= 10000 )) || { usage; exit 2; }
      args+=(-batch-size "$((10#$2))") ;;
    --cursor|--resume)
      (( cursor_set == 0 )) || { usage; exit 2; }
      cursor_set=1
      if [[ "$1" == --resume ]]; then
        # Only successful execution output or its complete audit can advance.
        cursor=$(python3 - "$2" "$scope" <<'PYRESUME'
import json, sys
try:
 r=json.load(open(sys.argv[1]))
 if r['scope']!=sys.argv[2] or r['applied'] is not True or r['more'] is not True or r.get('status','complete')!='complete':
  raise ValueError('not resumable')
 c=r['next_cursor']
 if not isinstance(c,str) or not 0<len(c)<=2048:
  raise ValueError('invalid cursor')
 print(c)
 print('true' if r.get('migrate_legacy',False) is True else 'false')
except Exception:
 sys.exit('续跑文件须为同一范围的成功批次结果，且仍有下一批；预览、失败或已完成结果不能续跑')
PYRESUME
)
        if [[ "${cursor##*$'\n'}" == true ]]; then args+=(-migrate-legacy); fi
        cursor=${cursor%$'\n'*}
      else
        cursor=$2
      fi
      args+=(-cursor "$cursor") ;;
    *) usage; exit 2 ;;
  esac
  shift 2
done
dc run --rm --no-deps -T "${mounts[@]}" --entrypoint /app/artex artex "${args[@]}"
