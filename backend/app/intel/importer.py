"""Import threat-intel files that YOU supply (CSV or JSON) into the RAG store.

Accepted shapes
---------------
CSV with a header row. Recognised columns (case-insensitive, all optional except one
of value/title/text):  value, kind, title, text (or description), tags, source, url

JSON: a list of objects with the same keys, or {"records": [...]}.

`kind` is inferred when missing: ip, cidr, domain, url, cve, hash or note.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
from pathlib import Path

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_HASH = re.compile(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$", re.I)
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.I)


def infer_kind(value: str) -> str:
    v = value.strip()
    if not v:
        return "note"
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if "/" in v:
        try:
            ipaddress.ip_network(v, strict=False)
            return "cidr"
        except ValueError:
            pass
    if v.lower().startswith(("http://", "https://")):
        return "url"
    if _CVE.match(v):
        return "cve"
    if _HASH.match(v):
        return "hash"
    if _DOMAIN.match(v):
        return "domain"
    return "note"


def _normalise(row: dict, default_source: str) -> dict | None:
    row = {str(k).strip().lower(): ("" if v is None else v) for k, v in row.items()}
    value = str(row.get("value", "")).strip()
    title = str(row.get("title", "")).strip()
    text = str(row.get("text") or row.get("description") or "").strip()
    if not (value or title or text):
        return None
    kind = str(row.get("kind", "")).strip().lower() or infer_kind(value)
    tags = row.get("tags", [])
    if isinstance(tags, str):
        tags = [t.strip() for t in re.split(r"[;,|]", tags) if t.strip()]
    source = str(row.get("source", "")).strip() or default_source
    key = value or title or text[:80]
    return {
        "id": f"{source}:{kind}:{key}"[:250],
        "source": source,
        "kind": kind,
        "value": value or key,
        "title": (title or f"{kind.upper()} {value}".strip())[:300],
        "text": (text or title or value)[:2000],
        "tags": list(tags)[:10],
        "url": str(row.get("url", "")).strip() or None,
    }


def parse_intel(content: str, filename: str = "upload.csv", default_source: str = "import") -> list[dict]:
    name = filename.lower()
    rows: list[dict]
    if name.endswith(".json"):
        data = json.loads(content)
        rows = data.get("records", []) if isinstance(data, dict) else data
    else:
        rows = list(csv.DictReader(io.StringIO(content)))
    out = []
    for row in rows:
        if isinstance(row, dict):
            record = _normalise(row, default_source)
            if record:
                out.append(record)
    return out


def load_seed(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return parse_intel(path.read_text(encoding="utf-8"), path.name, default_source="reference")


def files_in(folder: Path) -> list[Path]:
    if not folder.exists():
        return []
    return sorted(p for p in folder.iterdir() if p.suffix.lower() in {".csv", ".json"})
