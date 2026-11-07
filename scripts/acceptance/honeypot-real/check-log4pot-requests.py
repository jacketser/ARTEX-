"""Verify only the planned credential-free GET/HEAD requests reached Log4Pot."""
import collections
import json
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
verified = {}
for name in ('log4pot-json', 'log4pot-tomcat'):
    rows = [json.loads(line) for line in (root / (name + '-requests.jsonl')).read_text().splitlines()]
    assert all(r['type'] in ('start', 'request') for r in rows), 'unexpected event type'
    requests = [r for r in rows if r['type'] == 'request']
    assert len(requests) == 15, 'expected three metadata GETs plus twelve behavior requests'
    counts = collections.Counter()
    for r in requests:
        method, path, protocol = r['request'].split()
        headers = {k.lower(): v for k, v in r['headers'].items()}
        assert not {'authorization', 'cookie', 'proxy-authorization'} & headers.keys(), 'credentials reached target'
        assert method in ('GET', 'HEAD') and protocol == 'HTTP/1.1'
        if path != '/':
            assert method == 'GET' and re.fullmatch('/artex-behavior-check-[a-f0-9]{24}', path)
            path = '/random'
        counts[method + ' ' + path] += 1
    assert counts == {'GET /': 9, 'HEAD /': 3, 'GET /random': 3}, counts
    verified[name] = dict(total_requests=15, methods_and_paths=dict(counts), credentials_seen=False, exploit_events=0)
(root / 'request-audit.json').write_text(json.dumps(verified, indent=2) + '\n')
print('Log4Pot planned requests verified')
