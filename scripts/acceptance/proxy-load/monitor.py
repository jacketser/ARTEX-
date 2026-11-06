"""Read process/cgroup counters only; never inspect environment or request data."""
import json
import os
from pathlib import Path
import time

clock_ticks = os.sysconf('SC_CLK_TCK')
with open('/tmp/proxy-load-resources.jsonl', 'w') as out:
    while True:
        if Path('/tmp/proxy-load-monitor.stop').exists():
            break
        try:
            pid = next(p for p in Path('/proc').iterdir()
                       if p.name.isdigit() and (p / 'comm').read_text().strip() == 'artex')
            status = dict(line.split(':', 1) for line in (pid / 'status').read_text().splitlines())
            stat = (pid / 'stat').read_text().split(') ', 1)[1].split()
            row = dict(time=time.time(), rss_kib=int(status['VmRSS'].split()[0]),
                       threads=int(status['Threads']), fds=len(list((pid / 'fd').iterdir())),
                       cpu_seconds=(int(stat[11]) + int(stat[12])) / clock_ticks)
            for name in ('memory.current', 'memory.peak', 'memory.events', 'memory.stat', 'io.stat'):
                p = Path('/sys/fs/cgroup') / name
                if p.exists():
                    row[name] = p.read_text().strip()
            out.write(json.dumps(row) + '\n')
            out.flush()
        except (OSError, StopIteration, KeyError, ValueError):
            pass
        time.sleep(0.5)
