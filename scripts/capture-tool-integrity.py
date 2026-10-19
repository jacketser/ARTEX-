"""Capture selected installed files after image construction; performs no downloads."""
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys

files = set()
for name in ("python3", "node", "curl", "nmap", "playwright", "playwright-cli", "playwright-mcp"):
    path = shutil.which(name)
    if not path:
        raise SystemExit(f"Required image tool missing: {name}")
    files.add(str(pathlib.Path(path).resolve()))
root = pathlib.Path(subprocess.check_output(["npm", "root", "-g"], text=True).strip())
for package in ("playwright", "@playwright/cli", "@playwright/mcp"):
    files.add(str(root / package / "package.json"))
records = []
for path in sorted(files):
    with open(path, "rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    records.append({"path": path, "sha256": digest})
pathlib.Path(sys.argv[1]).write_text(json.dumps(records, indent=2) + "\n")
