"""Open-weight LLM access (Llama 3 family).

Providers, in the order `auto` tries them:
  * openrouter    - hosted Llama 3.3 70B, free tier (needs OPENROUTER_API_KEY, no GPU needed)
  * groq          - Groq's hosted open-weight models (Groq retired Llama 3 in Aug 2026;
                    default is openai/gpt-oss-20b)
  * ollama        - Llama 3.2 running locally on your CPU via Ollama (http://localhost:11434)
  * openai_compat - any OpenAI-compatible server (vLLM, LM Studio, Together, ...)
  * none          - no LLM; agents fall back to the deterministic heuristic analyst
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

log = logging.getLogger("soc.llm")


class LLMUnavailable(RuntimeError):
    pass


def resolve_provider(settings) -> str:
    provider = settings.llm_provider
    if provider != "auto":
        return provider
    if settings.openrouter_api_key:
        return "openrouter"
    if settings.groq_api_key:
        return "groq"
    if settings.openai_compat_url and settings.openai_compat_model:
        return "openai_compat"
    return "ollama"  # tried at call time; falls back to heuristics if not running


def describe_provider(settings) -> str:
    provider = resolve_provider(settings)
    return {
        "openrouter": f"OpenRouter · {settings.openrouter_model.split('/')[-1]}",
        "groq": f"Groq · {settings.groq_model}",
        "ollama": f"Ollama · {settings.ollama_model}",
        "openai_compat": f"OpenAI-compatible · {settings.openai_compat_model}",
        "none": "Heuristic analyst (no LLM)",
    }.get(provider, provider)


def extract_json(text: str) -> dict:
    """Pull the first JSON object out of a model response."""
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if fence:
        text = fence.group(1)
    try:
        return json.loads(text)
    except ValueError:
        pass
    start = text.find("{")
    while start != -1:
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start : i + 1])
                    except ValueError:
                        break
        start = text.find("{", start + 1)
    raise ValueError("no JSON object in model output")


async def chat_json(settings, system: str, user: str) -> tuple[dict, str]:
    """Send a chat request and return (parsed_json, provider_label)."""
    import httpx  # local import keeps the module importable without httpx

    provider = resolve_provider(settings)
    if provider == "none":
        raise LLMUnavailable("LLM disabled")
    messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    timeout = httpx.Timeout(settings.llm_timeout, connect=5)

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            if provider == "ollama":
                resp = await client.post(
                    f"{settings.ollama_url}/api/chat",
                    json={"model": settings.ollama_model, "messages": messages, "stream": False,
                          "format": "json", "options": {"temperature": 0.1}},
                )
                resp.raise_for_status()
                content = resp.json()["message"]["content"]
            else:
                if provider == "openrouter":
                    url, key, model = ("https://openrouter.ai/api/v1", settings.openrouter_api_key,
                                       settings.openrouter_model)
                elif provider == "groq":
                    url, key, model = "https://api.groq.com/openai/v1", settings.groq_api_key, settings.groq_model
                else:
                    url, key, model = settings.openai_compat_url, settings.openai_compat_key, settings.openai_compat_model
                headers = {"Authorization": f"Bearer {key}"} if key else {}
                body: dict[str, Any] = {"model": model, "messages": messages, "temperature": 0.1,
                                        "response_format": {"type": "json_object"}}
                resp = await client.post(f"{url}/chat/completions", json=body, headers=headers)
                if resp.status_code in (400, 422) and "response_format" in resp.text.lower():
                    body.pop("response_format")
                    resp = await client.post(f"{url}/chat/completions", json=body, headers=headers)
                resp.raise_for_status()
                content = resp.json()["choices"][0]["message"]["content"]
    except httpx.HTTPError as exc:
        raise LLMUnavailable(f"{provider} request failed: {exc}") from exc

    try:
        return extract_json(content), describe_provider(settings)
    except ValueError as exc:
        raise LLMUnavailable(f"{provider} returned non-JSON output") from exc


async def check_llm(settings) -> dict:
    """Lightweight health check used by the dashboard's status bar."""
    import httpx

    provider = resolve_provider(settings)
    if provider == "none":
        return {"provider": "none", "ok": True, "label": describe_provider(settings)}
    try:
        async with httpx.AsyncClient(timeout=4) as client:
            if provider == "ollama":
                r = await client.get(f"{settings.ollama_url}/api/tags")
                ok = r.status_code == 200
            elif provider == "groq":
                r = await client.get("https://api.groq.com/openai/v1/models",
                                     headers={"Authorization": f"Bearer {settings.groq_api_key}"})
                ok = r.status_code == 200
            elif provider == "openrouter":
                r = await client.get("https://openrouter.ai/api/v1/key",
                                     headers={"Authorization": f"Bearer {settings.openrouter_api_key}"})
                ok = r.status_code == 200
            else:
                ok = True
    except Exception:
        ok = False
    return {"provider": provider, "ok": ok, "label": describe_provider(settings)}
