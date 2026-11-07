"""Report abstention and review burdens separately; repeats are not samples."""
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
# A rejected rerun must not leave a previous summary looking current.
for name in ('summary.json', 'summary.md'):
    (root / name).unlink(missing_ok=True)
complete = json.loads((root / 'evaluation-complete.json').read_text())
samples = json.loads((root / 'samples.json').read_text())
rows = json.loads((root / 'measurements.json').read_text())
expected = {
    'holdout-20261107': {'log4pot-json', 'log4pot-tomcat', 'httpbin', 'datasette'},
    'tuning': {'opencanary-nas', 'qeeqbox-http', 'qeeqbox-https', 'nginx-default', 'nginx-fallback', 'nginx-product-doc', 'nginx-product-doc-fallback'},
    'holdout': {'heralding-http', 'apache-default', 'apache-document-fallback', 'apache-auth', 'python-static'},
}
split = complete['split']
if split not in expected or {s['id'] for s in samples} != expected[split] or any(s['split'] != split or s['label'] not in ('honeypot', 'benign') for s in samples):
    raise ValueError('Wrong corpus or partition')
if not (len(samples) == complete['samples'] == len(expected[split]) and complete['repetitions'] == 3
        and len(rows) == len(samples) * 3 == complete['measurements']
        and len({s['id'] for s in samples}) == len(samples)):
    raise ValueError('Incomplete or duplicate deployment corpus')
by_id = {s['id']: [r for r in rows if r['sample_id'] == s['id']] for s in samples}
for group in by_id.values():
    if sorted(r['repetition'] for r in group) != [1, 2, 3]:
        raise ValueError('Missing or duplicate measurement')

expected_labels = {
    'opencanary-nas': 'honeypot', 'qeeqbox-http': 'honeypot', 'qeeqbox-https': 'honeypot',
    'heralding-http': 'honeypot', 'log4pot-json': 'honeypot', 'log4pot-tomcat': 'honeypot',
}
if any(s['label'] != expected_labels.get(s['id'], 'benign') for s in samples):
    raise ValueError('Deployment label differs from preregistered label')
for r in rows:
    observations = r['behavior']['observations']
    if not 1 <= len(observations) <= 4 or r['authorized_requests'] != len(observations):
        raise ValueError('Incomplete or invalid request accounting')
    if r['behavior']['outcome'] != 'inconclusive' and (len(observations) != 4 or any(o.get('error') or o['truncated'] for o in observations)):
        raise ValueError('Conclusion without complete usable observations')
    if r['behavior']['outcome'] not in ('suspected', 'needs_review', 'no_signal', 'inconclusive'):
        raise ValueError('Unknown behavior outcome')
    if r['behavior']['version'] != complete['behavior_version']:
        raise ValueError('Mixed behavior algorithm versions')
    if r['metadata']['evaluated']:
        result = r['metadata']['result']
        if result['version'] != complete['metadata_version'] or result['rule_revision'] != complete['rule_revision']:
            raise ValueError('Mixed metadata rules or algorithm versions')

def verdict(r):
    m = r['metadata']
    return (m['evaluated'], m.get('result', {}).get('matched'), m.get('result', {}).get('confidence'), r['behavior']['outcome'])

summary = dict(completion=complete, samples=samples, measurements=rows,
               unstable_samples=[ident for ident, group in by_id.items() if len({verdict(r) for r in group}) != 1],
               counts={}, provenance={}, evaluation_role='new_holdout' if split == 'holdout-20261107' else 'regression')
for label in ('honeypot', 'benign'):
    first = [by_id[s['id']][0] for s in samples if s['label'] == label]
    summary['counts'][label] = dict(
        deployments=len(first),
        behavior_four_requests=sum(len(r['behavior']['observations']) == 4 for r in first),
        behavior_completed_comparison=sum(r['behavior']['outcome'] != 'inconclusive' for r in first),
        metadata_evaluated=sum(r['metadata']['evaluated'] for r in first),
        metadata_any_match=sum(r['metadata'].get('result', {}).get('matched', False) for r in first),
        metadata_medium_or_high=sum(r['metadata'].get('result', {}).get('confidence') in ('medium', 'high') for r in first),
        behavior_suspected=sum(r['behavior']['outcome'] == 'suspected' for r in first),
        behavior_needs_review=sum(r['behavior']['outcome'] == 'needs_review' for r in first),
        behavior_no_signal=sum(r['behavior']['outcome'] == 'no_signal' for r in first),
        behavior_inconclusive=sum(r['behavior']['outcome'] == 'inconclusive' for r in first),
    )
names = ['artex-commit', 'harness-sha256', 'opencanary-commit', 'qeeqbox-commit', 'nginx-version', 'image-id']
if split == 'holdout':
    names += ['heralding-commit', 'apache-version', 'python-version']
if split == 'holdout-20261107':
    names = ['artex-commit', 'harness-sha256', 'image-id', 'python-version']
if (root / 'detector-commit.txt').exists():
    names.append('detector-commit')
for name in names:
    summary['provenance'][name] = (root / (name + '.txt')).read_text().strip()
summary['excluded_deployments'] = [dict(id='opencanary-basic', reason='Pinned upstream basicLogin skin lacks redirect.html; GET / returns 500. Excluded before final run, not counted as a detector miss.') ]
if split != 'tuning':
    summary['excluded_deployments'] = []
summary['runtime_compatibility'] = 'QeeqBox Twisted 24.10.0 with pyOpenSSL 26.4.0 failed TLS Context reuse; isolated QeeqBox environment pinned to pyOpenSSL 24.3.0 / cryptography 44.0.3. Server response code unchanged.'
if split == 'holdout-20261107':
    summary['runtime_compatibility'] = 'Log4Pot uses its documented stdlib-only mode. httpbin and Datasette use separate venvs; no response-code changes.'
    summary['source_archives'] = json.loads((root / 'sources-20261107.json').read_text())
    summary['target_request_audit'] = json.loads((root / 'request-audit.json').read_text())
summary['configuration_hashes'] = json.loads((root / 'configuration-hashes.json').read_text())
summary['dependency_versions'] = {name: (root / (name + '-packages.txt')).read_text().splitlines() for name in (('httpbin', 'datasette') if split == 'holdout-20261107' else (('heralding',) if split == 'holdout' else ('opencanary', 'qeeqbox')))}
summary['rules'] = json.loads((root / 'rules.json').read_text())
summary['limits'] = [
    'Controlled local deployments, not independently labeled Internet observations.',
    'Historical tuning and holdout partitions are now regression sets. New holdout uses two configurations of one Log4Pot family and two normal applications, not a random population sample.',
    'Normal product-document fallback regressions deliberately test overlapping signals; their prevalence is unknown.',
    'Three repetitions measure stability only; counts use the first result per deployment.',
    'Inconclusive and no_signal do not establish a benign verdict. No population accuracy or precision estimate.',
    'Name rules unchanged; behavior v2 tuned only on the earlier baseline, then frozen before holdout measurement. No login attempts, payloads, redirects or TLS bypass.',
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
