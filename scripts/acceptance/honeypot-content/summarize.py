#!/usr/bin/env python3
"""Reject incomplete/mismatched content runs; outcomes are observations, not assertions."""
import contextlib
import io
import tempfile
from prepare import prepare
import hashlib
import json
import pathlib
import sys


def summarize(manifest_path, measurements_path, output_path):
    output = pathlib.Path(output_path)
    output.unlink(missing_ok=True)
    manifest = json.loads(pathlib.Path(manifest_path).read_text())
    lock = json.loads(pathlib.Path(__file__).with_name("sources.json").read_text())
    if manifest['detector_commit'] != lock['detector_commit'] or manifest['algorithm'] != lock['algorithm']:
        raise ValueError('wrong detector')
    if [{k: s[k] for k in lock['sources'][i]} for i, s in enumerate(manifest['sources'])] != lock['sources']:
        raise ValueError('source lock mismatch')
    # Reconstruct from independently verified source bytes; reject edits to labels,
    # subsets or renderings even when a matching partial result is supplied.
    with tempfile.TemporaryDirectory(prefix='artex-content-manifest-') as temp:
        with contextlib.redirect_stdout(io.StringIO()):
            prepare(pathlib.Path(manifest_path).parent / 'sources', temp)
        if json.loads((pathlib.Path(temp) / 'samples.json').read_text()) != manifest:
            raise ValueError('manifest differs from predeclared corpus')
    measurements = json.loads(pathlib.Path(measurements_path).read_text())
    samples = manifest['samples']
    by_id = {s['id']: s for s in samples}
    if len(by_id) != len(samples) or len(measurements) != len(samples) or not samples:
        raise ValueError('incomplete manifest or run')
    outcomes = ('suspected', 'needs_review', 'no_signal', 'inconclusive')
    groups = {g: dict.fromkeys(outcomes, 0) for g in ('normal_html', 'injection_visible', 'injection_hidden')}
    seen = set()
    for item in measurements:
        s = by_id[item['id']]
        body = (pathlib.Path(manifest_path).parent / s['file']).read_bytes()
        if s['group'] not in groups or item['id'] in seen or item['body_sha256'] != s['body_sha256'] or hashlib.sha256(body).hexdigest() != s['body_sha256']:
            raise ValueError('duplicate, altered or unknown sample')
        seen.add(item['id'])
        result = item['result']
        if result['version'] != manifest['algorithm'] or result['outcome'] not in outcomes:
            raise ValueError('unknown outcome or mixed algorithm')
        obs = result['observations']
        if item['requests'] != 4 or len(obs) != 4 or [o['method'] for o in obs] != ['GET', 'GET', 'HEAD', 'GET']:
            raise ValueError('incomplete HTTP sequence')
        if [o['status'] for o in obs] != [200, 200, 200, 404] or any(o.get('error') or o['truncated'] for o in obs):
            raise ValueError('fixture transport failure')
        if any(o['body_sha256'] != s['body_sha256'] for o in obs[:2]):
            raise ValueError('observed body mismatch')
        groups[s['group']][result['outcome']] += 1
    if not all(sum(g.values()) for g in groups.values()):
        raise ValueError('missing group')
    result = dict(group='source_independent_content_holdout', detector_commit=manifest['detector_commit'],
                  algorithm=manifest['algorithm'], sources=manifest['sources'], counts=groups,
                  samples=samples, measurements=measurements,
                  limitations=['Content replay, not real honeypot deployments or browser/model evaluation.',
                               'Visible/hidden renderings share attack texts; variants are not independent samples.'])
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(groups, ensure_ascii=False))


if __name__ == '__main__':
    summarize(*sys.argv[1:])
