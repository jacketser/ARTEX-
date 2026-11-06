"""Report abstention and review burdens separately; repeats are not samples."""
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
complete = json.loads((root / 'evaluation-complete.json').read_text())
samples = json.loads((root / 'samples.json').read_text())
rows = json.loads((root / 'measurements.json').read_text())
if not (len(samples) == complete['samples'] == 7 and complete['repetitions'] == 3
        and len(rows) == len(samples) * 3 == complete['measurements']
        and len({s['id'] for s in samples}) == len(samples)):
    raise ValueError('Incomplete or duplicate deployment corpus')
by_id = {s['id']: [r for r in rows if r['sample_id'] == s['id']] for s in samples}
for group in by_id.values():
    if sorted(r['repetition'] for r in group) != [1, 2, 3]:
        raise ValueError('Missing or duplicate measurement')

def verdict(r):
    m = r['metadata']
    return (m['evaluated'], m.get('result', {}).get('matched'), m.get('result', {}).get('confidence'), r['behavior']['outcome'])

summary = dict(completion=complete, samples=samples, measurements=rows,
               unstable_samples=[ident for ident, group in by_id.items() if len({verdict(r) for r in group}) != 1],
               counts={}, provenance={})
for label in ('honeypot', 'benign'):
    first = [by_id[s['id']][0] for s in samples if s['label'] == label]
    summary['counts'][label] = dict(
        deployments=len(first),
        behavior_completed_comparison=sum(r['behavior']['outcome'] != 'inconclusive' for r in first),
        metadata_evaluated=sum(r['metadata']['evaluated'] for r in first),
        metadata_any_match=sum(r['metadata'].get('result', {}).get('matched', False) for r in first),
        metadata_medium_or_high=sum(r['metadata'].get('result', {}).get('confidence') in ('medium', 'high') for r in first),
        behavior_suspected=sum(r['behavior']['outcome'] == 'suspected' for r in first),
        behavior_needs_review=sum(r['behavior']['outcome'] == 'needs_review' for r in first),
        behavior_no_signal=sum(r['behavior']['outcome'] == 'no_signal' for r in first),
        behavior_inconclusive=sum(r['behavior']['outcome'] == 'inconclusive' for r in first),
    )
for name in ('artex-commit', 'harness-sha256', 'opencanary-commit', 'qeeqbox-commit', 'nginx-version', 'image-id'):
    summary['provenance'][name] = (root / (name + '.txt')).read_text().strip()
summary['excluded_deployments'] = [dict(id='opencanary-basic', reason='Pinned upstream basicLogin skin lacks redirect.html; GET / returns 500. Excluded before final run, not counted as a detector miss.') ]
summary['runtime_compatibility'] = 'QeeqBox Twisted 24.10.0 with pyOpenSSL 26.4.0 failed TLS Context reuse; isolated QeeqBox environment pinned to pyOpenSSL 24.3.0 / cryptography 44.0.3. Server response code unchanged.'
summary['configuration_hashes'] = json.loads((root / 'configuration-hashes.json').read_text())
summary['dependency_versions'] = {name: (root / (name + '-packages.txt')).read_text().splitlines() for name in ('opencanary', 'qeeqbox')}
summary['rules'] = json.loads((root / 'rules.json').read_text())
summary['limits'] = [
    'Controlled local deployments, not independently labeled Internet observations.',
    'Two honeypot families with related configurations; four nginx controls are not four independent websites.',
    'Normal product-document fallback deliberately tests overlapping signals; its prevalence is unknown.',
    'Three repetitions measure stability only; counts use the first result per deployment.',
    'Inconclusive and no_signal do not establish a benign verdict. No population accuracy or precision estimate.',
    'Default rules frozen; no tuning against this evaluation set. No login attempts, payloads, redirects or TLS bypass.',
    'Metadata extraction is the evaluation collector; behavior calls production Probe directly, not the asset UI.',
]
(root / 'summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
lines = ['| Deployment | Known label | Metadata | Behavior | HTTP observations |',
         '| --- | --- | --- | --- | --- |']
for s in samples:
    r = by_id[s['id']][0]
    lines.append('| ' + ' | '.join([s['id'], s['label'], r['metadata'].get('result', {}).get('confidence', 'not_evaluated'),
                                   r['behavior']['outcome'], ', '.join(str(o['status']) if not o.get('error') else o['error'] for o in r['behavior']['observations'])]) + ' |')
(root / 'summary.md').write_text('\n'.join(lines) + '\n')
print(json.dumps({'counts': summary['counts'], 'unstable_samples': summary['unstable_samples']}))
