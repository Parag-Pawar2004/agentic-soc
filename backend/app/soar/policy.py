"""Guardrails applied before any response action is proposed or executed."""
from __future__ import annotations

import ipaddress
import re

ACTION_TYPES = {"block_ip", "unblock_ip", "suspend_user", "revoke_sessions", "disable_access_keys"}
_USER = re.compile(r"^[A-Za-z0-9._@+-]{1,128}$")
_DEMO_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def check_target(action_type: str, target: str, allowlist: list[str], simulated: bool = False) -> str | None:
    """Return a rejection reason, or None if the target is acceptable."""
    if action_type not in ACTION_TYPES:
        return f"unknown action type {action_type!r}"
    if action_type in {"block_ip", "unblock_ip"}:
        try:
            ip = ipaddress.ip_address(target)
        except ValueError:
            return f"{target!r} is not a valid IP address"
        if any(ip in _net(n) for n in allowlist):
            return f"{target} is on the allowlist"
        is_demo = any(ip in n for n in _DEMO_NETS)
        if simulated and is_demo:
            return None
        if not ip.is_global:
            return f"{target} is private/reserved and will not be blocked"
        return None
    if not _USER.match(target):
        return f"{target!r} is not a valid username"
    return None


def _net(value: str):
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return ipaddress.ip_network("255.255.255.255/32")
