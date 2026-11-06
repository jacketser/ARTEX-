"""Exercise integrity failures using a completed isolated run (no requests)."""
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

original = Path(sys.argv[1])
script = Path(__file__).with_name('summarize.py')
with tempfile.TemporaryDirectory(prefix='artex-honey-summary-') as tmp:
    target = Path(tmp)
    for p in original.iterdir():
        if p.is_file() and p.suffix in ('.json', '.txt') and p.name != 'summary.json':
            shutil.copy(p, target / p.name)
    rows = json.loads((target / 'measurements.json').read_text())
    complete = json.loads((target / 'evaluation-complete.json').read_text())
    samples = json.loads((target / 'samples.json').read_text())
    for case in ('valid', 'missing-measurement', 'duplicate-repeat', 'missing-target', 'missing-completion', 'wrong-partition', 'unknown-outcome', 'mixed-algorithm'):
        r, c, s = copy.deepcopy(rows), copy.deepcopy(complete), copy.deepcopy(samples)
        if case == 'missing-measurement': r.pop()
        if case == 'duplicate-repeat': r[-1]['repetition'] = 1
        if case == 'missing-target': s.pop()
        if case == 'wrong-partition': s[0]['split'] = 'other'
        if case == 'unknown-outcome': r[0]['behavior']['outcome'] = 'unknown'
        if case == 'mixed-algorithm': r[0]['behavior']['version'] = 'unknown'
        (target / 'measurements.json').write_text(json.dumps(r))
        (target / 'samples.json').write_text(json.dumps(s))
        (target / 'evaluation-complete.json').write_text(json.dumps(c))
        if case == 'missing-completion': (target / 'evaluation-complete.json').unlink()
        (target / 'summary.json').unlink(missing_ok=True)
        proc = subprocess.run([sys.executable, str(script), str(target)], capture_output=True)
        passed = proc.returncode == 0 and (target / 'summary.json').exists()
        assert passed == (case == 'valid'), (case, proc.stdout, proc.stderr)
        if case != 'valid': assert not (target / 'summary.json').exists(), case
        print(case, 'PASS')
