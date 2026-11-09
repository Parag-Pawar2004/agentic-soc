import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Isolated, offline test environment (no LLM, no Milvus server, no real firewall).
_TMP = tempfile.mkdtemp(prefix="soc-test-")
os.environ.update({
    "DATA_DIR": _TMP,
    "DATABASE_PATH": str(Path(_TMP) / "soc.db"),
    "LLM_PROVIDER": "none",
    "EMBEDDING_BACKEND": "hash",
    "VECTOR_STORE": "builtin",
    "FIREWALL_PROVIDER": "mock",
    "IDENTITY_PROVIDER": "mock",
    "ANALYST_USERNAME": "analyst",
    "ANALYST_PASSWORD": "test-password",
    "SECRET_KEY": "test-secret",
    "INGEST_API_KEY": "ingest-key",
})


@pytest.fixture
def settings(tmp_path):
    from app.config import get_settings

    get_settings.cache_clear()
    os.environ["DATA_DIR"] = str(tmp_path)
    os.environ["DATABASE_PATH"] = str(tmp_path / "soc.db")
    s = get_settings()
    yield s
    get_settings.cache_clear()
    os.environ["DATA_DIR"] = _TMP
    os.environ["DATABASE_PATH"] = str(Path(_TMP) / "soc.db")
