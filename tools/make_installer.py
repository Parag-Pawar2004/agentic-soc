#!/usr/bin/env python3
"""Pack this whole project into ONE self-extracting file: install_agentic_soc.py

    python3 tools/make_installer.py

Anyone can then run  `python3 install_agentic_soc.py`  on a fresh machine: it unpacks
the project into a folder and runs setup_soc.py, which only asks for passwords/API keys.
"""
from __future__ import annotations

import base64
import io
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git", "node_modules", ".next", ".venv", "__pycache__", ".pytest_cache", "logs", ".terraform", "out"}
SKIP_FILES = {".env", ".env.local", "install_agentic_soc.py"}
SKIP_SUFFIX = {".pyc", ".db", ".npz", ".tfstate"}

TEMPLATE = '''#!/usr/bin/env python3
"""Agentic SOC - single-file installer.

    python3 install_agentic_soc.py          (Windows: py install_agentic_soc.py)

Unpacks the project into ./agentic-soc (or a folder you choose) and starts the guided
setup. It only asks for passwords, API keys and yes/no choices.
Extra arguments are passed to setup_soc.py, e.g.  --no-start
"""
import base64, io, os, subprocess, sys, zipfile
from pathlib import Path

PAYLOAD = "{payload}"


def main():
    if sys.version_info < (3, 10):
        sys.exit("Python 3.10 or newer is required: https://www.python.org/downloads/")
    default = Path.cwd() / "agentic-soc"
    try:
        answer = input(f"Install Agentic SOC into [{{default}}]: ").strip()
    except EOFError:
        answer = ""
    target = Path(answer).expanduser().resolve() if answer else default
    if (target / "setup_soc.py").exists():
        print(f"Found an existing install in {{target}} - keeping your settings and updating files.")
    target.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(base64.b64decode(PAYLOAD))) as zf:
        for member in zf.infolist():
            dest = (target / member.filename).resolve()
            if not str(dest).startswith(str(target)):
                continue  # never write outside the chosen folder
            zf.extract(member, target)
    print(f"Unpacked {{len(zf.infolist())}} files into {{target}}\\n")
    sys.exit(subprocess.call([sys.executable, str(target / "setup_soc.py"), *sys.argv[1:]], cwd=target))


if __name__ == "__main__":
    main()
'''


def build(out: Path | None = None) -> Path:
    buf = io.BytesIO()
    count = 0
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in sorted(ROOT.rglob("*")):
            rel = path.relative_to(ROOT)
            if any(part in SKIP_DIRS for part in rel.parts) or path.is_dir():
                continue
            if path.name in SKIP_FILES or path.suffix in SKIP_SUFFIX:
                continue
            zf.write(path, rel.as_posix())
            count += 1
    out = out or ROOT / "install_agentic_soc.py"
    out.write_text(TEMPLATE.format(payload=base64.b64encode(buf.getvalue()).decode()), encoding="utf-8")
    print(f"Wrote {out} ({count} files, {out.stat().st_size // 1024} KB)")
    return out


if __name__ == "__main__":
    build()
