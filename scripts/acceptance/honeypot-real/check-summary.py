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
    plan_path = target / 'evaluation-plan.json'
    plan = json.loads(plan_path.read_text()) if plan_path.exists() else None
    detector_path = target / 'detector-commit.txt'
    detector = detector_path.read_text() if detector_path.exists() else None
    cases = ['valid', 'missing-measurement', 'duplicate-repeat', 'missing-target', 'missing-completion', 'wrong-partition', 'unknown-outcome', 'mixed-algorithm', 'wrong-label', 'missing-observations', 'wrong-request-count', 'uniform-wrong-algorithm']
    if plan is not None:
        cases += ['missing-plan', 'changed-plan-version', 'changed-plan-image', 'changed-detector-commit', 'relabel-as-holdout']
    for case in cases:
        r, c, s = copy.deepcopy(rows), copy.deepcopy(complete), copy.deepcopy(samples)
        if plan is not None:
            p = copy.deepcopy(plan)
            if case == 'changed-plan-version': p['behavior_version'] = 'unknown'
            if case == 'changed-plan-image': p['image_ids'][c['split']] = 'sha256:wrong'
            if case == 'relabel-as-holdout': p['evaluation_role'] = 'new_holdout'
            plan_path.write_text(json.dumps(p))
            detector_path.write_text('bad-ref' if case == 'changed-detector-commit' else detector)
            if case == 'missing-plan': plan_path.unlink()
        if case == 'missing-measurement': r.pop()
        if case == 'duplicate-repeat': r[-1]['repetition'] = 1
        if case == 'missing-target': s.pop()
        if case == 'wrong-partition': s[0]['split'] = 'other'
        if case == 'unknown-outcome': r[0]['behavior']['outcome'] = 'unknown'
        if case == 'mixed-algorithm': r[0]['behavior']['version'] = 'unknown'
        if case == 'wrong-label': s[0]['label'] = 'benign' if s[0]['label'] == 'honeypot' else 'honeypot'
        if case == 'missing-observations': r[0]['behavior']['observations'] = []
        if case == 'wrong-request-count': r[0]['authorized_requests'] += 1
        if case == 'uniform-wrong-algorithm':
            c['behavior_version'] = 'unknown'
            for row in r: row['behavior']['version'] = 'unknown'
        (target / 'measurements.json').write_text(json.dumps(r))
        (target / 'samples.json').write_text(json.dumps(s))
        (target / 'evaluation-complete.json').write_text(json.dumps(c))
        if case == 'missing-completion': (target / 'evaluation-complete.json').unlink()
        (target / 'summary.json').write_text('{}')
        (target / 'summary.md').write_text('old summary')
        proc = subprocess.run([sys.executable, str(script), str(target)], capture_output=True)
        passed = proc.returncode == 0 and (target / 'summary.json').exists()
        assert passed == (case == 'valid'), (case, proc.stdout, proc.stderr)
        if case == 'valid' and plan is not None:
            summary = json.loads((target / 'summary.json').read_text())
            assert summary['evaluation_role'] == 'regression'
            assert summary['evaluation_plan'] == plan
        if case != 'valid':
            assert not (target / 'summary.json').exists(), case
            assert not (target / 'summary.md').exists(), case
        print(case, 'PASS')
