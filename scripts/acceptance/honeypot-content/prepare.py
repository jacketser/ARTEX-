#!/usr/bin/env python3
"""Build the predeclared content corpus from verified local source downloads."""
import ast
import hashlib
import html
import json
import pathlib
import sys


def sha(data):
    return hashlib.sha256(data).hexdigest()


def prepare(source_dir, output_dir, lock_path=None):
    lock = json.loads(pathlib.Path(lock_path or pathlib.Path(__file__).with_name("sources.json")).read_text())
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
        kind = item.get("kind")
        if kind == "normal_document":
            text = raw.decode("utf-8")
            for group, attribute in [("normal_visible", ""), ("normal_hidden", " hidden")]:
                body = ("<!doctype html><html><body><section" + attribute + ">" + html.escape(text) + "</section></body></html>").encode()
                add(group, item["path"], body, sha(raw))
        elif kind == "html_lure_final_variants":
            tree = ast.parse(raw)
            assignments = [n for n in tree.body if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.target.id == "RECIPROCITY_LURE_TEMPLATES"]
            if len(assignments) != 1 or not isinstance(assignments[0].value, ast.Tuple):
                raise ValueError("unknown lure schema")
            selected = []
            for node in assignments[0].value.elts:
                if not isinstance(node, ast.Call):
                    raise ValueError("unknown template schema")
                fields = {k.arg: k.value for k in node.keywords}
                if ast.literal_eval(fields["id"]) == "html_reciprocity_canary":
                    selected.append(ast.literal_eval(fields["final_variants"]))
            if len(selected) != 1 or len(selected[0]) != 3:
                raise ValueError("unexpected final variants")
            for index, text in enumerate(selected[0]):
                if not isinstance(text, str) or not text.strip():
                    raise ValueError("nonliteral or empty variant")
                key = f"html_reciprocity_canary/final/{index}"
                add("lure_native", key, text.encode(), sha(raw))
                add("lure_hidden", key, ("<!doctype html><html><body><section hidden>" + html.escape(text) + "</section></body></html>").encode(), sha(raw))
        elif kind == "development_regression":
            tree = ast.parse(raw)
            matches = [n.value for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "C2_RECRUIT_PROMPT" for t in n.targets)]
            if len(matches) != 1:
                raise ValueError("missing development template")
            text = ast.literal_eval(matches[0])
            if not isinstance(text, str):
                raise ValueError("nonliteral development template")
            add("development_regression", "C2_RECRUIT_PROMPT", text.encode(), sha(raw))
        elif kind is not None:
            raise ValueError("unknown source kind")
        elif item["repository"] == "mdn/learning-area":
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
