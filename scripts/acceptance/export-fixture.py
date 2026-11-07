#!/usr/bin/env python3
"""Synthetic fixtures and independent checks of real browser download bytes."""
import base64
import csv
import hashlib
import io
import json
from pathlib import Path
import sys
from urllib.parse import quote, quote_plus

SECRET = "synthetic-export/key+value?=123456"
VARIANTS = [SECRET, quote_plus(SECRET, safe=""), quote(SECRET, safe="+="),
            base64.b64encode(SECRET.encode()).decode(),
            base64.urlsafe_b64encode(SECRET.encode()).decode().rstrip("="),
            SECRET.encode().hex()]
SUMMARY = 'ordinary-text, "quoted"\n' + " | ".join(VARIANTS)
EVIDENCE = '{"password":"unknown-json-password","count":9007199254740993,"public":"ordinary-json"}'
PEM = "-----BEGIN PRIVATE KEY-----\nc3ludGhldGlj\n-----END PRIVATE KEY-----"
HEADERS = ["ID", "名称", "类别", "严重等级", "状态", "所属任务", "发现时间", "概述",
           "流量证据数量", "流量证据ID", "人工复核", "复核是否过期", "脱敏副本说明"]


def sql(value):
    return "'" + value.replace("'", "''") + "'"


def seed():
    fingerprint = hashlib.sha256(json.dumps(
        [0, "TEST", "low", SUMMARY, EVIDENCE], ensure_ascii=False,
        separators=(",", ":")).encode()).hexdigest()
    print("BEGIN;")
    print("INSERT INTO settings(key,value) VALUES('brave_search_api_key'," + sql(SECRET) + ");")
    print("INSERT INTO explorations(id,goal,status) VALUES(1,'synthetic-only','achieved');")
    print("INSERT INTO tasks(id,description,goal,exploration_id,status) VALUES(1," +
          sql("ordinary-task " + SECRET) + ",'synthetic-only',1,'done');")
    print("INSERT INTO findings(id,task_id,name,vulnclass,severity,summary,evidence,report) VALUES(1,1," +
          ",".join(map(sql, ["EXPORT-ALPHA " + SECRET, "TEST", "low", SUMMARY, EVIDENCE,
                             "ordinary-report " + SECRET + "\n" + PEM])) + ");")
    print("INSERT INTO findings(id,name,vulnclass,severity,summary) VALUES(2,'EXPORT-BETA','TEST','high','ordinary-beta');")
    print("INSERT INTO finding_reviews(finding_id,fingerprint,verdict,sources) VALUES(1," +
          sql(fingerprint) + ",'supported'," + sql("ordinary-review " + SECRET) + ");")
    print("COMMIT;")


def verify(directory):
    results = []
    for scope in ["all", "selected", "filtered"]:
        for fmt in ["md", "csv"]:
            path = directory / (scope + "." + fmt)
            raw = path.read_bytes()
            value = raw.decode("utf-8-sig")
            cells = list(csv.reader(io.StringIO(value))) if fmt == "csv" else None
            searchable = "\n".join(cell for row in cells for cell in row) if cells else value
            for secret in VARIANTS + ["unknown-json-password", "c3ludGhldGlj"]:
                assert secret not in searchable, (scope, fmt, "sensitive value survived")
            assert "非原始证据" in value and "ordinary-text" in value
            assert "EXPORT-ALPHA" in value
            assert ("EXPORT-BETA" in value) == (scope == "all")
            if cells:
                assert raw.startswith(b"\xef\xbb\xbf")
                assert cells[0] == HEADERS
                assert len(cells) == (3 if scope == "all" else 2)
                assert all(len(row) == 13 for row in cells)
                alpha = next(row for row in cells[1:] if row[0] == "1")
                assert 'ordinary-text, "quoted"\n' in alpha[7]
                assert alpha[10:12] == ["现有证据支持结论", "false"], alpha[10:12]
                assert "ordinary-task" in alpha[5]
                assert all("非原始证据" in row[12] for row in cells[1:])
            else:
                assert all(v in value for v in ["9007199254740993", "ordinary-json", "ordinary-report", "ordinary-review", "ordinary-task"])
                assert "BEGIN PRIVATE KEY" not in value
                assert "复核已过期" not in value
            results.append({"file": path.name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    original = json.loads((directory / "original.json").read_text())
    assert SECRET in json.dumps(original, ensure_ascii=False)
    print(json.dumps({"passed": True, "downloads": results, "csv_columns": 13,
                      "known_secret_representations": len(set(VARIANTS)),
                      "json_remains_original": True}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    if sys.argv[1:] == ["seed"]:
        seed()
    elif len(sys.argv) == 3 and sys.argv[1] == "verify":
        verify(Path(sys.argv[2]))
    else:
        raise SystemExit("usage: export-fixture.py seed | verify DOWNLOAD_DIRECTORY")
