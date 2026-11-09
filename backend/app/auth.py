"""Analyst login with signed, expiring bearer tokens."""
from __future__ import annotations

import hmac
import secrets

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer


class Auth:
    def __init__(self, settings):
        self.settings = settings
        self._secret = settings.secret_key or secrets.token_urlsafe(32)
        self._serializer = URLSafeTimedSerializer(self._secret, salt="soc-analyst")

    @property
    def enabled(self) -> bool:
        return bool(self.settings.analyst_password)

    def login(self, username: str, password: str) -> str | None:
        if not self.enabled:
            return self._serializer.dumps({"u": username or "analyst"})
        ok_user = hmac.compare_digest(username.encode(), self.settings.analyst_username.encode())
        ok_pass = hmac.compare_digest(password.encode(), self.settings.analyst_password.encode())
        return self._serializer.dumps({"u": username}) if ok_user and ok_pass else None

    def verify(self, token: str | None) -> str | None:
        if not self.enabled:
            return "analyst"
        if not token:
            return None
        try:
            data = self._serializer.loads(token, max_age=self.settings.token_ttl_hours * 3600)
        except (BadSignature, SignatureExpired):
            return None
        return data.get("u")

    def check_ingest_key(self, key: str | None) -> bool:
        if not self.settings.ingest_api_key:
            return True
        return bool(key) and hmac.compare_digest(key.encode(), self.settings.ingest_api_key.encode())
