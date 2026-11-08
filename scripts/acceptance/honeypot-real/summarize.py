"""Report abstention and review burdens separately; repeats are not samples."""
import hashlib
import json
import re
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
    'holdout-20261108': {'honeyhttpd-apache', 'elasticpot', 'rangehttpserver', 'copyparty'},
    'holdout-20261107': {'log4pot-json', 'log4pot-tomcat', 'httpbin', 'datasette'},
    'tuning': {'opencanary-nas', 'qeeqbox-http', 'qeeqbox-https', 'nginx-default', 'nginx-fallback', 'nginx-product-doc', 'nginx-product-doc-fallback'},
    'holdout': {'heralding-http', 'apache-default', 'apache-document-fallback', 'apache-auth', 'python-static'},
}
split = complete['split']
plan_path = root / 'evaluation-plan.json'
plan = json.loads(plan_path.read_text()) if plan_path.exists() else None
if plan is not None:
    if (plan['schema'] not in (1, 2) or plan['evaluation_role'] not in ('regression', 'new_holdout')
            or plan['repetitions'] != 3 or not re.fullmatch('[0-9a-f]{40}', plan['detector_commit'])
            or any(complete[key] != plan[key] for key in ('behavior_version', 'metadata_version', 'rule_revision', 'repetitions'))
            or (root / 'detector-commit.txt').read_text().strip() != plan['detector_commit']
            or (root / 'image-id.txt').read_text().strip() != plan['image_ids'].get(split)):
        raise ValueError('Measurement differs from frozen regression plan')
    if plan['schema'] == 1 and (plan['evaluation_role'] != 'regression' or split == 'holdout-20261108'):
        raise ValueError('Historical samples cannot be relabeled as new holdout')
    if plan['schema'] == 2:
        if (split != 'holdout-20261108'
                or (root / 'collector-commit.txt').read_text().strip() != plan['collector_commit']
                or not re.fullmatch('[0-9a-f]{40}', plan['collector_commit'])
                or hashlib.sha256((root / 'sources-20261108.json').read_bytes()).hexdigest() != plan['sources_sha256']
                or json.loads((root / 'configuration-hashes.json').read_text()) != plan['configuration_hashes']
                or (root / 'driver-image-id.txt').read_text().strip() != plan['driver_image_id']):
            raise ValueError('New holdout differs from preregistered sources/configuration/collector')
        for name, digest in plan['configuration_hashes'].items():
            path = (root / name).resolve()
            if not path.is_relative_to(root.resolve()) or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise ValueError('Fixture configuration bytes changed')

elif split == 'holdout-20261108' or complete['behavior_version'] != 'http-behavior-v2' or complete['metadata_version'] != 'metadata-v2':
    raise ValueError('Nonlegacy detector requires an explicit frozen plan')
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
    'honeyhttpd-apache': 'honeypot', 'elasticpot': 'honeypot',
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
    return (m['evaluated'], m.get('result', {}).get('matched'), m.get('result', {}).get('confidence'), r['behavior']['outcome'], tuple(r['behavior'].get('content_warnings', [])))

summary = dict(completion=complete, samples=samples, measurements=rows,
               unstable_samples=[ident for ident, group in by_id.items() if len({verdict(r) for r in group}) != 1],
               counts={}, provenance={}, evaluation_role=plan['evaluation_role'] if plan is not None else ('new_holdout' if split == 'holdout-20261107' else 'regression'))
if plan is not None:
    summary['evaluation_plan'] = plan
    summary['evaluation_plan_sha256'] = hashlib.sha256(plan_path.read_bytes()).hexdigest()
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
        content_warning_deployments=sum(bool(r['behavior'].get('content_warnings')) for r in first),
    )
names = ['artex-commit', 'harness-sha256', 'opencanary-commit', 'qeeqbox-commit', 'nginx-version', 'image-id']
if split == 'holdout':
    names += ['heralding-commit', 'apache-version', 'python-version']
if split in ('holdout-20261107', 'holdout-20261108'):
    names = ['artex-commit', 'harness-sha256', 'image-id', 'python-version']
if plan is not None and plan['schema'] == 2:
    names.append('collector-commit')
if (root / 'detector-commit.txt').exists():
    names.append('detector-commit')
if plan is not None:
    names += ['detector-sha256', 'driver-image-id', 'driver-binary-sha256']
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
if split == 'holdout-20261108':
    summary['runtime_compatibility'] = 'Existing Python 3.11.2 / Twisted 24.10.0 environment; only termcolor 2.5.0 added with wheel hash. Upstream response code unchanged. Elasticpot public-IP lookup reads a local synthetic file, no external output plugins.'
    summary['source_archives'] = json.loads((root / 'sources-20261108.json').read_text())
summary['configuration_hashes'] = json.loads((root / 'configuration-hashes.json').read_text())
summary['dependency_versions'] = {name: (root / (name + '-packages.txt')).read_text().splitlines() for name in (('runtime',) if split == 'holdout-20261108' else ('httpbin', 'datasette') if split == 'holdout-20261107' else (('heralding',) if split == 'holdout' else ('opencanary', 'qeeqbox')))}
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
if plan is not None:
    summary['limits'][1] = 'All partitions, including historical holdout-20261107, are previously viewed regression sets. No new independent holdout.'
    summary['limits'][5] = 'Detector and fixture images frozen by explicit plan; no rule tuning in this run. No login attempts, payloads, redirects or TLS bypass.'
if split == 'holdout-20261108' and plan['evaluation_role'] == 'new_holdout':
    summary['limits'][1] = 'First measurement of two new honeypot families and two normal file services; frozen detector. RangeHTTPServer shares Python stdlib implementation ancestry with earlier controls. Once viewed, these samples must become regression material for future tuning.'
if split == 'holdout-20261108':
    if plan['evaluation_role'] == 'regression':
        summary['limits'][1] = 'Previously viewed holdout-20261108 samples replayed as regression. No new independent holdout.'
    summary['limits'][2] = 'Labels come from controlled source/configuration, not independent Internet labels. No signal overlap was injected into target responses.'
(root / 'summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
lines = ['| Deployment | Known label | Metadata | Behavior | HTTP observations |',
         '| --- | --- | --- | --- | --- |']
for s in samples:
    r = by_id[s['id']][0]
    lines.append('| ' + ' | '.join([s['id'], s['label'], r['metadata'].get('result', {}).get('confidence', 'not_evaluated'),
                                   r['behavior']['outcome'], ', '.join(str(o['status']) if not o.get('error') else o['error'] for o in r['behavior']['observations'])]) + ' |')
(root / 'summary.md').write_text('\n'.join(lines) + '\n')
print(json.dumps({'counts': summary['counts'], 'unstable_samples': summary['unstable_samples']}))
