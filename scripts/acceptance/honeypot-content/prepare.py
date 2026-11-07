#!/usr/bin/env python3
"""Build the predeclared content corpus from verified local source downloads."""
import hashlib
import html
import json
import pathlib
import sys


def sha(data):
    return hashlib.sha256(data).hexdigest()


def prepare(source_dir, output_dir):
    lock = json.loads(pathlib.Path(__file__).with_name("sources.json").read_text())
    source_dir, output_dir = pathlib.Path(source_dir), pathlib.Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    # A failed preparation must not leave a previous complete manifest usable.
    manifest = output_dir / "samples.json"
    manifest.unlink(missing_ok=True)
    (output_dir / "bodies").mkdir(exist_ok=True)
    (output_dir / "sources").mkdir(exist_ok=True)
    samples, sources = [], []

    def add(group, key, body, source):
        if not body or len(body) > 64 * 1024:
            raise ValueError("empty or oversized fixture: " + key)
        ident = f"sample-{len(samples):04d}"
        filename = f"bodies/{ident}.html"
        (output_dir / filename).write_bytes(body)
        samples.append(dict(id=ident, group=group, source_key=key, source_sha256=source,
                            file=filename, body_sha256=sha(body), bytes=len(body)))

    for item in lock["sources"]:
        filename = item["repository"].replace("/", "_") + "-" + item["path"].replace("/", "_")
        raw = (source_dir / filename).read_bytes()
        git_hash = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        if git_hash != item["git_blob_sha1"] or len(raw) != item["bytes"]:
            raise ValueError("source does not match lock: " + filename)
        (output_dir / "sources" / filename).write_bytes(raw)
        sources.append(dict(**item, sha256=sha(raw)))
        if item["repository"] == "mdn/learning-area":
            add("normal_html", item["path"], raw, sha(raw))
        elif item["repository"] == "microsoft/BIPIA":
            dataset = json.loads(raw)
            if not isinstance(dataset, dict) or not dataset:
                raise ValueError("unknown dataset structure")
            for category, values in sorted(dataset.items()):
                if not isinstance(values, list) or not values:
                    raise ValueError("unknown category structure")
                for index, value in enumerate(values):
                    if not isinstance(value, str) or not value.strip():
                        raise ValueError("empty or non-string attack")
                    for group, attribute in [("injection_visible", ""), ("injection_hidden", " hidden")]:
                        body = ("<!doctype html><html><body><section" + attribute + ">" +
                                html.escape(value) + "</section></body></html>").encode()
                        add(group, f"{category}/{index}", body, sha(raw))
        else:
            raise ValueError("unexpected source")
    manifest.write_text(json.dumps(dict(detector_commit=lock["detector_commit"],
        algorithm=lock["algorithm"], sources=sources, samples=samples), ensure_ascii=False, indent=2) + "\n")
    print(f"Prepared {len(samples)} fixtures from {len(sources)} verified files")


if __name__ == "__main__":
    prepare(*sys.argv[1:])
