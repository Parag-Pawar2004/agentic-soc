"""Built-in alert simulator so you can watch the agents work without a SIEM.

Uses documentation-only IP ranges (RFC 5737) so nothing real is ever touched, and
simulated alerts are always routed to the mock firewall.
"""
from __future__ import annotations

import random

SCENARIOS = [
    {
        "category": "authentication", "severity": "high", "source": "sshd",
        "title": "SSH brute force: 214 failed logins from one host",
        "description": "Failed login burst against 37 different usernames on bastion-01 within 4 minutes, "
                       "followed by one successful login for user deploy.",
        "src_ip": "203.0.113.45", "dst_ip": "10.0.4.12", "username": "deploy",
        "raw": {"failed_attempts": 214, "distinct_users": 37, "service": "ssh", "success_after_failures": True},
    },
    {
        "category": "network", "severity": "medium", "source": "zeek",
        "title": "Periodic beacon from workstation to rare external host",
        "description": "Host ws-fin-22 contacted the same external server every 60s (±2s) for 6 hours with "
                       "~400 byte requests. Destination seen by no other host.",
        "src_ip": "10.0.8.22", "dst_ip": "198.51.100.23", "username": None,
        "raw": {"interval_seconds": 60, "jitter": 2, "duration_hours": 6, "bytes_per_request": 410},
    },
    {
        "category": "identity", "severity": "high", "source": "okta",
        "title": "Impossible travel sign-in with MFA push fatigue",
        "description": "User priya.sharma signed in from Pune and, 18 minutes later, from an anonymising network "
                       "abroad after rejecting 9 MFA pushes and approving the 10th.",
        "src_ip": "203.0.113.200", "dst_ip": None, "username": "priya.sharma",
        "raw": {"mfa_pushes": 10, "minutes_between_logins": 18, "geo": ["IN", "unknown"]},
    },
    {
        "category": "web", "severity": "medium", "source": "waf",
        "title": "SQL injection attempts against /api/orders",
        "description": "WAF logged 63 requests with SQL injection payloads in the id parameter; 4 returned HTTP 500.",
        "src_ip": "203.0.113.150", "dst_ip": "10.0.2.5", "username": None,
        "raw": {"requests": 63, "server_errors": 4, "path": "/api/orders"},
    },
    {
        "category": "network", "severity": "low", "source": "firewall",
        "title": "Large outbound transfer from backup server",
        "description": "backup-02 sent 48 GB to the offsite storage provider during the scheduled nightly backup window.",
        "src_ip": "10.0.9.2", "dst_ip": "192.0.2.80", "username": "svc-backup",
        "raw": {"bytes": 48_000_000_000, "window": "scheduled 01:00-03:00"},
    },
    {
        "category": "endpoint", "severity": "critical", "source": "edr",
        "title": "Mass file encryption on file server",
        "description": "Process on fs-01 renamed 12,400 files to .lockd and deleted shadow copies; ransom note "
                       "README_RESTORE.txt created. Process runs as user j.doe.",
        "src_ip": "10.0.3.7", "dst_ip": None, "username": "j.doe",
        "raw": {"files_renamed": 12400, "shadow_copies_deleted": True},
    },
]


def random_alert(index: int | None = None) -> dict:
    scenario = dict(SCENARIOS[index % len(SCENARIOS)] if index is not None else random.choice(SCENARIOS))
    scenario["simulated"] = True
    return scenario
