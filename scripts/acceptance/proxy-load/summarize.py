"""Join bounded load results with half-second application resource samples."""
import datetime as dt
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
results = json.loads((root / 'results.json').read_text())
samples = [json.loads(line) for line in (root / 'resources.jsonl').read_text().splitlines()]
assert samples, 'no application resource samples'

def memory_parts(sample):
    values = dict(line.split() for line in sample.get('memory.stat', '').splitlines())
    return {key + '_mib': int(values.get(key, 0)) / 2**20 for key in ('anon', 'file', 'kernel')}

rows = []
for result in results:
    start = dt.datetime.fromisoformat(result['start'].replace('Z', '+00:00')).timestamp()
    end = dt.datetime.fromisoformat(result['end'].replace('Z', '+00:00')).timestamp()
    selected = [s for s in samples if start <= s['time'] <= end]
    result['resource_samples'] = len(selected)
    if selected:
        result['rss_peak_mib'] = max(s['rss_kib'] for s in selected) / 1024
        result['fds_peak'] = max(s['fds'] for s in selected)
        result['threads_peak'] = max(s['threads'] for s in selected)
        result['rss_end_mib'] = selected[-1]['rss_kib'] / 1024
        result['fds_end'] = selected[-1]['fds']
        result['memory_end'] = memory_parts(selected[-1])
        result['cgroup_end_mib'] = int(selected[-1].get('memory.current', 0)) / 2**20
        result['index_end_mib'] = selected[-1].get('index_bytes', 0) / 2**20
        if len(selected) > 1:
            result['cpu_cores_mean'] = (selected[-1]['cpu_seconds'] - selected[0]['cpu_seconds']) / (selected[-1]['time'] - selected[0]['time'])
    before, after = result.get('capture_before', {}), result.get('capture_after', {})
    if after.get('stages'):
        result['capture_ms_per_request'] = {
            k: (v['nanoseconds'] - before.get('stages', {}).get(k, {}).get('nanoseconds', 0)) / 1e6 / max(1, result['requests'])
            for k, v in after['stages'].items()
        }
        commits = after['stages']['commit']['calls'] - before['stages']['commit']['calls']
        result['capture_commits'] = commits
        result['records_per_commit'] = (after['written'] - before['written']) / max(1, commits)
    rows.append(result)
last = samples[-1]
summary = dict(cases=rows, total_requests=sum(r['requests'] for r in rows),
    total_errors=sum(r['errors'] for r in rows), rss_peak_mib=max(s['rss_kib'] for s in samples)/1024,
    rss_end_mib=last['rss_kib']/1024, fds_start=samples[0]['fds'], fds_end=last['fds'],
    fds_peak=max(s['fds'] for s in samples), last_cgroup=last,
    complete=(root/'security-stats.json').exists())
if (root / 'corpus.json').exists():
    summary['complete'] = summary['complete'] and (root / 'restart-check.json').exists()
    for name in ('soak-progress', 'offline-integrity', 'restart-check'):
        if (root / (name + '.json')).exists():
            summary[name.replace('-', '_')] = json.loads((root / (name + '.json')).read_text())
    manifest = json.loads((root / 'corpus.json').read_text())
    summary['corpus'] = {**manifest, 'items': [
        {k: v for k, v in item.items() if k not in ('request', 'response')} for item in manifest['items']]}
(root/'summary.json').write_text(json.dumps(summary, indent=2))
lines = ['| Scenario | Requests | RPS | p50 ms | p95 ms | p99 ms | Errors | RSS peak MiB |',
         '| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |']
for r in rows:
    rss = f"{r['rss_peak_mib']:.1f}" if 'rss_peak_mib' in r else 'unsampled'
    lines.append(f"| {r['scenario']['name']} | {r['requests']} | {r['rps']:.1f} | {r['p50_ms']:.1f} | {r['p95_ms']:.1f} | {r['p99_ms']:.1f} | {r['errors']} | {rss} |")
(root/'summary.md').write_text('\n'.join(lines)+'\n')
print(json.dumps({k:v for k,v in summary.items() if k not in ('cases','last_cgroup','corpus')}))
for name in ('app-state.json', 'pre-stop-app-state.json'):
    if (root/name).exists():
        state=json.loads((root/name).read_text())
        assert not state['OOMKilled'] and state['Running'], 'app died or OOM killed'
        assert state.get('Health',{}).get('Status') == 'healthy', 'app unhealthy'
assert summary['complete'] and not summary['total_errors'], 'incomplete or failed run'
if 'soak_progress' in summary:
    progress = summary['soak_progress']
    assert progress['completed_windows'] == progress['requested_windows'], 'soak ended early'

if 'memory.events' in last:
    events = dict(line.split() for line in last['memory.events'].splitlines())
    assert int(events.get('oom_kill', '0')) == 0, 'cgroup reported an OOM kill'
