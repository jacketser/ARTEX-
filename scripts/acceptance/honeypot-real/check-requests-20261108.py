"""Compare target access logs to planned metadata + Probe requests, offline."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
(root / 'request-audit.json').unlink(missing_ok=True)
rows = json.loads((root / 'measurements.json').read_text())
log = (root / 'containers.log').read_text()
patterns = {
    'honeyhttpd-apache': ('honeyhttpd', r'"([A-Z]+) (\S+) HTTP/1\.[01]" \d+'),
    'elasticpot': ('elasticpot', r'\[INFO\].*?: ([A-Z]+): (\S+)$'),
    'rangehttpserver': ('rangehttpserver', r'"([A-Z]+) (\S+) HTTP/1\.[01]" \d+'),
    'copyparty': ('copyparty', r'LOG: ([A-Z]+) +(\S+) @'),
}
result = {}
for sample, (service, pattern) in patterns.items():
    expected = Counter()
    group = [r for r in rows if r['sample_id'] == sample]
    assert len(group) == 3
    for row in group:
        expected[('GET', '/')] += 1  # metadata collector
        for observation in row['behavior']['observations']:
            assert not observation.get('error')
            expected[(observation['method'], observation['path'])] += 1
    actual = Counter()
    for line in log.splitlines():
        if not re.match(re.escape(service) + r'-1\s+\|', line):
            continue
        match = re.search(pattern, line)
        if match:
            actual[match.groups()] += 1
    if actual != expected:
        raise ValueError('Target request accounting mismatch: ' + sample)
    if any(method not in ('GET', 'HEAD') or (path != '/' and not re.fullmatch('/artex-behavior-check-[0-9a-f]{24}', path)) for method, path in actual):
        raise ValueError('Unplanned method/path')
    result[sample] = dict(requests=sum(actual.values()), root_get=actual[('GET','/')], root_head=actual[('HEAD','/')],
                          random_get=sum(n for (method,path),n in actual.items() if path != '/'), matched=True)
result = dict(targets=result, target_log_sha256=hashlib.sha256((root/'containers.log').read_bytes()).hexdigest(),
              limits='Target access-log accounting, not a full packet capture. No credentials in the frozen collector/Probe requests; logs alone do not prove header absence for every target.')
(root/'request-audit.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result['targets']))
