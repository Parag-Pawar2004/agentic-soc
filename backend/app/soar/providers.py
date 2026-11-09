"""Response-action providers (SOAR). Nothing here runs until an analyst approves.

firewall providers : mock | aws_waf | script
identity providers : mock | okta | aws_iam
"""
from __future__ import annotations

import asyncio
import ipaddress
import shlex
from typing import Any

FIREWALL_ACTIONS = {"block_ip", "unblock_ip"}
IDENTITY_ACTIONS = {"suspend_user", "revoke_sessions", "disable_access_keys"}


class ProviderError(RuntimeError):
    pass


def provider_for(action_type: str, settings, simulated: bool) -> str:
    if simulated:
        return "mock"
    if action_type in FIREWALL_ACTIONS:
        return settings.firewall_provider
    ip = settings.identity_provider
    if action_type == "disable_access_keys":
        return "aws_iam" if ip == "aws_iam" else "mock"
    return "okta" if ip == "okta" else "mock"  # AWS IAM has no session/suspend concept here


async def execute(action: dict, settings, db) -> dict[str, Any]:
    provider, type_, target = action["provider"], action["type"], action["target"]
    if provider == "mock":
        return _mock(type_, target, db, action["id"])
    if provider == "aws_waf":
        return await asyncio.to_thread(_aws_waf, type_, target, settings)
    if provider == "script":
        return await _script(type_, target, settings)
    if provider == "okta":
        return await _okta(type_, target, settings)
    if provider == "aws_iam":
        return await asyncio.to_thread(_aws_iam, type_, target, settings)
    raise ProviderError(f"unknown provider {provider!r}")


# ---------------------------------------------------------------- mock
def _mock(type_: str, target: str, db, action_id: str) -> dict:
    if type_ == "block_ip":
        db.add_block(target, "ip", "mock", action_id)
        return {"message": f"{target} added to the simulated firewall blocklist"}
    if type_ == "unblock_ip":
        db.remove_block(target)
        return {"message": f"{target} removed from the simulated firewall blocklist"}
    db.add_block(target, "user", "mock", action_id) if type_ == "suspend_user" else None
    return {"message": f"simulated {type_.replace('_', ' ')} for {target}"}


# ---------------------------------------------------------------- AWS WAF
def _aws_waf(type_: str, target: str, settings) -> dict:
    import boto3

    if not settings.aws_waf_ipset_name or not settings.aws_waf_ipset_id:
        raise ProviderError("AWS_WAF_IPSET_NAME and AWS_WAF_IPSET_ID must be set")
    ip = ipaddress.ip_address(target)
    cidr = f"{ip}/32" if ip.version == 4 else f"{ip}/128"
    waf = boto3.client("wafv2", region_name=settings.aws_region)
    kwargs = {"Name": settings.aws_waf_ipset_name, "Scope": settings.aws_waf_scope, "Id": settings.aws_waf_ipset_id}
    current = waf.get_ip_set(**kwargs)
    addresses = set(current["IPSet"]["Addresses"])
    if type_ == "block_ip":
        addresses.add(cidr)
    else:
        addresses.discard(cidr)
    waf.update_ip_set(**kwargs, Addresses=sorted(addresses), LockToken=current["LockToken"])
    return {"message": f"WAF IP set {settings.aws_waf_ipset_name} updated ({len(addresses)} entries)"}


# ---------------------------------------------------------------- local script (ufw, iptables, your firewall CLI)
async def _script(type_: str, target: str, settings) -> dict:
    ipaddress.ip_address(target)  # strict validation before it reaches a command line
    template = settings.firewall_block_cmd if type_ == "block_ip" else settings.firewall_unblock_cmd
    if not template:
        raise ProviderError("FIREWALL_BLOCK_CMD / FIREWALL_UNBLOCK_CMD not configured")
    argv = [part.replace("{ip}", target) for part in shlex.split(template)]
    proc = await asyncio.create_subprocess_exec(*argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    out, err = await asyncio.wait_for(proc.communicate(), timeout=30)
    if proc.returncode != 0:
        raise ProviderError(f"command exited {proc.returncode}: {err.decode()[:300]}")
    return {"message": out.decode()[:500] or "command succeeded", "command": argv}


# ---------------------------------------------------------------- Okta
async def _okta(type_: str, target: str, settings) -> dict:
    import httpx

    if not settings.okta_org_url or not settings.okta_api_token:
        raise ProviderError("OKTA_ORG_URL and OKTA_API_TOKEN must be set")
    headers = {"Authorization": f"SSWS {settings.okta_api_token}", "Accept": "application/json"}
    async with httpx.AsyncClient(base_url=settings.okta_org_url, headers=headers, timeout=20) as client:
        user = await client.get(f"/api/v1/users/{target}")
        if user.status_code != 200:
            raise ProviderError(f"Okta user {target} not found ({user.status_code})")
        uid = user.json()["id"]
        if type_ == "suspend_user":
            r = await client.post(f"/api/v1/users/{uid}/lifecycle/suspend")
        elif type_ == "revoke_sessions":
            r = await client.delete(f"/api/v1/users/{uid}/sessions")
        else:
            raise ProviderError(f"Okta does not support {type_}")
        if r.status_code >= 300:
            raise ProviderError(f"Okta returned {r.status_code}: {r.text[:200]}")
    return {"message": f"Okta {type_.replace('_', ' ')} done for {target}"}


# ---------------------------------------------------------------- AWS IAM
def _aws_iam(type_: str, target: str, settings) -> dict:
    import boto3

    if type_ != "disable_access_keys":
        raise ProviderError(f"AWS IAM provider does not support {type_}")
    iam = boto3.client("iam")
    keys = iam.list_access_keys(UserName=target)["AccessKeyMetadata"]
    for key in keys:
        iam.update_access_key(UserName=target, AccessKeyId=key["AccessKeyId"], Status="Inactive")
    return {"message": f"deactivated {len(keys)} access key(s) for IAM user {target}"}
