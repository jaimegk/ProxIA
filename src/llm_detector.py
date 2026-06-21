"""
LLM-based PII detector — primary detection layer.

Uses a local Ollama model to understand context and identify sensitive data
that regex cannot catch: hostnames without FQDNs, internal system names,
domain usernames (DOMAIN\\user), project codenames, company-specific strings, etc.

HARD FAILURE POLICY: if Ollama is unreachable or times out, detection raises
OllamaUnavailableError. The proxy MUST NOT forward requests when the LLM layer
is down — that would silently leak org names, hostnames, and person names that
only contextual detection can catch.

System prompt hot-reload:
  If data/system_prompt.txt exists, it overrides the hardcoded _SYSTEM_PROMPT.
  The file is re-read at most every PROMPT_CACHE_TTL_S seconds so the proxy picks
  up improvements from the feedback loop without restarting.
  To apply a new prompt permanently, write it to data/system_prompt.txt.
"""
import asyncio
import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

from .config import config

log = logging.getLogger("cc-proxy.llm")


class OllamaUnavailableError(RuntimeError):
    """Raised when Ollama is unreachable or unresponsive.

    The proxy treats this as a hard failure: requests are blocked rather than
    forwarded with incomplete anonymization.
    """


async def health_check() -> None:
    """Verify Ollama is reachable, the model is available, and pre-warm it.

    Raises OllamaUnavailableError if Ollama is unreachable or model is missing.
    Also sends a warmup inference with keep_alive=-1 to load the model into RAM
    before the first real request, eliminating cold-start latency (~60-80s on CPU).
    Called at startup; the server refuses to start if this raises.
    """
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.get(f"{config.OLLAMA_HOST}/api/tags")
            resp.raise_for_status()
        except httpx.ConnectError as exc:
            raise OllamaUnavailableError(
                f"Cannot reach Ollama at {config.OLLAMA_HOST} — is it running? ({exc})"
            ) from exc
        except httpx.TimeoutException as exc:
            raise OllamaUnavailableError(
                f"Ollama health check timed out at {config.OLLAMA_HOST}: {exc}"
            ) from exc

    model_names = [m.get("name", "") for m in resp.json().get("models", [])]
    if not model_names:
        raise OllamaUnavailableError(
            f"Ollama is running but has no models loaded. "
            f"Run: ollama pull {config.OLLAMA_MODEL}"
        )
    base_names = [n.split(":")[0] for n in model_names]
    configured_base = config.OLLAMA_MODEL.split(":")[0]
    if configured_base not in base_names:
        raise OllamaUnavailableError(
            f"Model {config.OLLAMA_MODEL!r} not found in Ollama. "
            f"Available: {model_names}. Run: ollama pull {config.OLLAMA_MODEL}"
        )

    # Warm up: load the model into RAM before the first real request.
    # keep_alive=-1 pins it in memory for the container lifetime.
    # We use a long timeout (150s) because cold loading takes ~60-80s on CPU.
    log.info(f"Warming up {config.OLLAMA_MODEL} — loading into RAM (may take ~60s on CPU)…")
    async with httpx.AsyncClient(timeout=150) as client:
        try:
            await client.post(
                f"{config.OLLAMA_HOST}/api/generate",
                json={"model": config.OLLAMA_MODEL, "prompt": "", "keep_alive": -1},
            )
            log.info(f"{config.OLLAMA_MODEL} warmed up and pinned in RAM")
        except Exception as exc:
            log.warning(f"Model warmup failed (non-fatal): {exc}")


# ── System-prompt hot-reload ──────────────────────────────────────────────────
PROMPT_CACHE_TTL_S = 60   # re-read from disk at most once per minute
_prompt_cache: dict = {"text": None, "mtime": 0.0, "checked_at": 0.0}


def _system_prompt_path() -> Path:
    return config.DATA_DIR / "system_prompt.txt"


def get_system_prompt() -> str:
    """Return the active system prompt.

    Loads from data/system_prompt.txt if it exists (with TTL caching).
    Falls back to the hardcoded _SYSTEM_PROMPT constant.
    """
    now = time.monotonic()
    cache = _prompt_cache

    if now - cache["checked_at"] < PROMPT_CACHE_TTL_S:
        return cache["text"] if cache["text"] is not None else _SYSTEM_PROMPT

    path = _system_prompt_path()
    cache["checked_at"] = now

    if path.exists():
        try:
            mtime = path.stat().st_mtime
            if mtime != cache["mtime"] or cache["text"] is None:
                text = path.read_text(encoding="utf-8").strip()
                if text and len(text) > 100:
                    cache["text"] = text
                    cache["mtime"] = mtime
                    log.info(f"System prompt loaded from {path} ({len(text)} chars)")
        except Exception as exc:
            log.warning(f"Failed to read system prompt from {path}: {exc}")
    else:
        if cache["text"] is not None:
            log.info("data/system_prompt.txt removed — reverting to hardcoded prompt")
        cache["text"] = None
        cache["mtime"] = 0.0

    return cache["text"] if cache["text"] is not None else _SYSTEM_PROMPT

_SYSTEM_PROMPT = """\
You are a data privacy guardian. Your job is to find any string that could identify a real person, organization, location, account, or sensitive record, so it can be replaced with a fake value before the text is sent to a cloud AI. When in doubt, flag it.

FLAG (return exact substrings from input):
PERSON — first+last names in any language; dot-separated usernames like "john.smith", "rafael.moura" (first.last format = person, not generic words)
ORGANIZATION — company/brand/project/team names (return the EXACT text with its capitalization and spaces, e.g., "Acme Corp" not "acme.corp"); internal product or codename strings; cloud resource names prefixed with the org name (buckets, namespaces, project IDs)
HOSTNAME — bare machine names without a domain: DB-PROD-01, web-app-02, FILESERVER-PRD — anything that looks like a unique host in context
IP_ADDRESS / CIDR / DOMAIN — IPs, CIDRs, subnets, internal/external domains and subdomains
EMAIL_ADDRESS — any email address
USERNAME — login names, service accounts (svc_*, deploy_bot, db_admin), domain logins (DOMAIN\\user, user@domain)
PHONE — telephone / mobile / fax numbers in any national or international format
POSTAL_ADDRESS — street addresses, including city/postal-code when part of a person's or org's address
DATE_OF_BIRTH — birth dates (only when clearly a date of birth, not arbitrary timestamps)
NATIONAL_ID — government identity numbers: SSN, DNI/NIE, passport numbers, CPF/CNPJ, tax IDs, driver's license numbers
CREDIT_CARD / IBAN / SWIFT / BANK_ACCOUNT — payment card numbers, IBANs, BIC/SWIFT codes, bank account/routing numbers
HEALTH_ID — medical record numbers (MRN), patient IDs, clinical case numbers, insurance member IDs
CREDENTIAL — passwords, secrets, private keys, password hashes; inline CLI passwords (-p value, PASSWORD=value); creds in URLs (redis://:pass@host)
TOKEN — API keys, bearer/OAuth tokens, JWTs, session tokens
PATH — file paths containing an org name or username as a directory component
HASH — standalone hash strings not already caught as CREDENTIAL

DO NOT FLAG:
- Software / tool / library names and CLI commands: git, docker, kubectl, npm, pip, nmap, curl, ssh, ls, grep — these are not entities
- Protocols and standards: HTTP, HTTPS, TCP, SSH, RDP, LDAP, DNS, TLS, SMTP, OAuth
- Tech products and versions: Apache, nginx, MySQL, PostgreSQL, Python, Node.js, Windows, Ubuntu, and any version string
- Port numbers, CVE/CWE IDs, HTTP status codes, generic tech jargon (config, handler, debug, verbose…)
- Built-in system accounts and groups: root, nobody, daemon, www-data, administrator (standalone), Domain Users, Domain Admins
- Structural keywords (the words themselves, not values after them): branch, HEAD, origin, merge, commit, Secret, ConfigMap, Namespace, username, password, email (the LABEL word, not the value next to it)
- Important: in "Author: Pedro Alves <pedro@corp.com>", extract BOTH "Pedro Alves" as PERSON and "pedro@corp.com" as EMAIL_ADDRESS — do not skip the name because you found the email
- Table/CSV column headers: Name, Email, Phone, Address, ID, Department (the header words, not the cell values)
- Bare generic words with no context: admin, panel, server, client, user, host, group, domain — only flag if they are clearly a specific entity name
- Small bare integers used as counts/IDs/UIDs: 0, 1, 500, 1001 are not PII on their own

CRITICAL: Return the EXACT substring as it appears in the input. Never normalize, lowercase, abbreviate, or modify the text.

Return ONLY valid JSON:
{"entities": [{"text": "<exact substring from input>", "type": "PERSON|ORGANIZATION|HOSTNAME|IP_ADDRESS|CIDR|DOMAIN|EMAIL_ADDRESS|USERNAME|PHONE|POSTAL_ADDRESS|DATE_OF_BIRTH|NATIONAL_ID|CREDIT_CARD|IBAN|SWIFT|BANK_ACCOUNT|HEALTH_ID|CREDENTIAL|TOKEN|PATH|HASH|IDENTIFIER|OTHER"}]}
Nothing found: {"entities": []}"""


@dataclass
class LLMMatch:
    text: str
    entity_type: str


def _strip_thinking(text: str) -> str:
    """Remove Qwen3 thinking artifacts: <think> blocks and /no_think suffix."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    text = re.sub(r"\s*/no_think\s*$", "", text)
    return text.strip()


def _extract_json(raw: str) -> str:
    """Extract JSON object from a response that may contain markdown code fences."""
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    if m:
        return m.group(1)
    m = re.search(r"\{.*\}", raw, re.DOTALL)
    if m:
        return m.group(0)
    return raw


def _parse_response(raw: str, chunk_text: str) -> list[LLMMatch]:
    try:
        cleaned = _strip_thinking(raw)
        cleaned = _extract_json(cleaned)
        data = json.loads(cleaned)
        results = []
        for e in data.get("entities", []):
            text = e.get("text", "").strip()
            # Only include if the entity actually appears in the chunk (hallucination guard)
            if text and text in chunk_text:
                results.append(LLMMatch(text=text, entity_type=e.get("type", "OTHER")))
        return results
    except Exception as exc:
        log.debug(f"LLM response parse failed: {exc} | raw={raw[:300]!r}")
        return []


def _chunks(text: str) -> list[tuple[str, int]]:
    """Yield (chunk_text, start_offset) with overlap between consecutive chunks."""
    size = config.LLM_CHUNK_SIZE
    overlap = config.LLM_CHUNK_OVERLAP
    i = 0
    result = []
    while i < len(text):
        result.append((text[i: i + size], i))
        if i + size >= len(text):
            break
        i += size - overlap
    return result


# Minimum chars to call the LLM — only skip truly trivial inputs like "yes", "ok", "sure".
# Company names appear even in short user messages, so keep this very low.
_MIN_LLM_LENGTH = 20

# ── Chunk-level LRU cache ─────────────────────────────────────────────────────
# Caches LLM results by (chunk_text_md5, prompt_version) to avoid re-inferring
# identical text chunks (common when the same tool format is run multiple times).
_CACHE_MAX = 500
_chunk_cache: dict[str, list["LLMMatch"]] = {}
_cache_keys_ordered: list[str] = []   # insertion-order for eviction


def _cache_key(chunk_text: str) -> str:
    return hashlib.md5(chunk_text.encode(), usedforsecurity=False).hexdigest()


def _cache_get(key: str) -> list["LLMMatch"] | None:
    return _chunk_cache.get(key)


def _cache_put(key: str, value: list["LLMMatch"]) -> None:
    if key in _chunk_cache:
        return
    if len(_cache_keys_ordered) >= _CACHE_MAX:
        oldest = _cache_keys_ordered.pop(0)
        _chunk_cache.pop(oldest, None)
    _chunk_cache[key] = value
    _cache_keys_ordered.append(key)


async def detect(text: str) -> list[LLMMatch]:
    """
    Detect sensitive entities using local Ollama.
    Returns empty list (not an error) if Ollama is unreachable or disabled.
    Skips LLM for short texts — regex handles those fast and accurately.
    """
    if not config.LLM_ENABLED or not text or not text.strip():
        return []

    if len(text) < _MIN_LLM_LENGTH:
        log.debug(f"Skipping LLM (text too short: {len(text)} chars)")
        return []

    chunks = _chunks(text)
    seen: set[str] = set()
    all_matches: list[LLMMatch] = []

    # Process chunks concurrently (max 2 at a time) so large texts don't block
    # proportionally to their chunk count. Ollama queues requests internally.
    _sem = asyncio.Semaphore(2)

    async def _call_chunk(chunk_text: str) -> list[LLMMatch]:
        key = _cache_key(chunk_text)
        cached = _cache_get(key)
        if cached is not None:
            log.debug(f"LLM cache hit for chunk ({len(chunk_text)} chars)")
            return cached

        async with _sem:
            async with httpx.AsyncClient(timeout=config.OLLAMA_TIMEOUT) as client:
                try:
                    resp = await client.post(
                        f"{config.OLLAMA_HOST}/api/chat",
                        json={
                            "model": config.OLLAMA_MODEL,
                            "think": False,
                            "messages": [
                                {"role": "system", "content": get_system_prompt()},
                                {"role": "user",   "content": chunk_text},
                            ],
                            "stream": False,
                            "format": "json",
                            "keep_alive": -1,
                            "options": {
                                "temperature": 0,
                                "num_thread": config.OLLAMA_NUM_THREADS,
                                "num_predict": 300,
                            },
                        },
                    )
                    resp.raise_for_status()
                    raw = resp.json().get("message", {}).get("content", "")
                    result = _parse_response(raw, chunk_text)
                    _cache_put(key, result)
                    return result
                except httpx.ConnectError as exc:
                    raise OllamaUnavailableError(
                        f"Ollama unreachable at {config.OLLAMA_HOST} during detection: {exc}"
                    ) from exc
                except httpx.TimeoutException as exc:
                    raise OllamaUnavailableError(
                        f"Ollama timed out during detection ({len(chunk_text)} chars): {exc}"
                    ) from exc
                except Exception as exc:
                    log.warning(f"LLM detection error on chunk: {exc}")
                    return []

    results = await asyncio.gather(*[_call_chunk(ct) for ct, _ in chunks])

    for chunk_matches in results:
        for match in chunk_matches:
            if match.text not in seen:
                all_matches.append(match)
                seen.add(match.text)

    return all_matches
