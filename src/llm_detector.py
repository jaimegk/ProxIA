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
You are a strict data privacy guardian operating under LGPD and GDPR principles.

For each piece of text, ask: "Could this — alone or combined with other data — identify a real company, person, or system?"

If yes: flag it.
When in doubt: flag it. A false positive is always safer than a false negative.

FLAG anything that could identify a target:

PEOPLE — flag any personal identifier:
- Person names (first+last combinations) in any language, inside CSV rows, tables, or prose:
  "Fernanda Oliveira", "Lucas Pereira", "John Smith", "Roberto Alves", "Michael Johnson",
  "Sarah Williams", "Mariana Costa" — always PERSON
- Dot-separated names acting as usernames: "john.smith", "jane.doe", "m.rodriguez",
  "rafael.moura", "carla.nascimento", "diana.costa", "pedro.alves", "ana.lima",
  "rafael.torres" — these are PERSON (first.last format), not generic words
- National IDs: CPF (###.###.###-##), CNPJ (##.###.###/####-##), SSN, passport, RG

ORGANIZATIONS — flag any org/company/project identifier:
- Company names, brand names, project codenames: "Contoso Corporation", "Acme Corp",
  "Acme Corp Ltda", "Omega Producao", "Vortex Corp", "Nexus", "StellarTech" —
  even if embedded in page titles, file paths, or resource names
- WiFi SSID names in airodump-ng/hostapd output — ALL ESSID values are org-specific:
  ESSID column values like "CORPORATE-NET", "CORP_VISITORS", "ACME-WIFI",
  "ENTERPRISE-CORP", "STAFF-WIRELESS" — flag the SSID string itself as ORGANIZATION
  (WiFi network names reveal the organization operating them)
- All-caps NetBIOS/workgroup names that identify a company: NORDVENTO, SOLAR, CONTOSO,
  HELIOS, ACME, QUANTUM, PRATICA, ORION — 4-15 char uppercase words used as
  Windows domain/workgroup names → ORGANIZATION
- Custom PKI / AD CS names: CA names like "FORTUNA-CA", certificate template names like
  "FortunaUserAuth" — org-specific → ORGANIZATION
- GCP/AWS/Azure cloud resource names that embed the org name:
  * GCP project IDs with numeric suffix: "omega-producao-441210", "omega-staging-332109",
    "acme-prod-project-12345" → ORGANIZATION (the project name, not the number)
  * S3/GCS bucket names: "acme-prod-backups", "omega-prod-backups", "stellartech-artifacts"
  * GitHub Actions / CI-CD identifiers: "acme-github-actions", "stellartech-deploy-key"
  * Any resource whose name starts with the company name: "acme-portal", "acme_prod",
    "acme_production", "acme_db_user", "nexus_prod", "stellartech-ci-01",
    "stellartech-app-01", "nuvem_deploy", "nuvem-prod-01", "nuvem-attack-01"
- K8s namespace and secret/configmap names embedding org or product name:
  Namespaces: "producao", "vortex", "staging-vortex" → ORGANIZATION
  Secrets: "vortex-db-credentials", "vortex-api-jwt-secret", "vortex-smtp-config" →
    ORGANIZATION (the secret name reveals what system/product it belongs to)
- HTTP page titles from nmap scripts revealing org: "Vortex Intranet Portal",
  "Acme Internal Wiki", "StellarTech Dashboard" → ORGANIZATION

HOSTS & NETWORK — flag all internal infrastructure:
- IPs, CIDRs, subnets, domains, subdomains, internal zones, NetBIOS names
- Short bare hostnames WITHOUT FQDN — ALWAYS flag these as HOSTNAME:
  * Windows DC/server names: DC01, DC02, WEBSERVER01, FILESERVER-PRD, HELIOS-DC01,
    DELTA-DC01, PRATICA-SQL01, ORION-DC01, ORION-WEB01 — unique machine names
  * Hyphenated server names: stellartech-ci-01, stellartech-app-01, nuvem-prod-01,
    ORION-BACKUP, HELIOS-DC01 — all HOSTNAME regardless of case
  * CA/DC machine names: FORTUNA-CA, DELTA-DC01 — HOSTNAME
  RULE: any short name that is clearly a machine/server identifier in context → HOSTNAME
  even without a domain suffix. "Computer: WEBSERVER01" → flag WEBSERVER01.
- Short all-caps NetBIOS domain names (CONTOSO, NORDVENTO, SOLAR, HELIOS, ORION,
  QUANTUM) that appear WITHOUT a TLD — these are ORGANIZATION (workgroup/domain name)
- HTTP page titles revealing org name → ORGANIZATION (see ORGANIZATIONS section)

CREDENTIALS — flag all secrets and authentication material:
- Passwords, hashes (NTLM/MD5/SHA), API keys, tokens, cookies, JWTs
- Inline credentials in CLI: -p 'password', -p password, PASSWORD=value, SECRET_KEY=value
- Cracked passwords in hashcat/asleap output:
  "$krb5tgs$...: CrackedPassword" → flag the cleartext password as CREDENTIAL
  "password:           Solar@WiFi2024!" (asleap format) → CREDENTIAL
  "PSK: SolarCorpWPA2#Key" → CREDENTIAL
- Jenkins credential store dump: "cred-id : username : Password"
  "stellartech-deploy-key : deploy_bot : StellarDeploy!2024" → flag StellarDeploy!2024
  "stellartech-db-prod : db_admin : ProdDB#Stellar99!" → flag ProdDB#Stellar99!
- Password spray results: when a password is shown next to a username as [HIT],
  "joao.ferreira@domain.com : Nexus@2024" → flag the password Nexus@2024
  Additional passwords found in body of messages: "senha: Nexus@VPN2024#" → CREDENTIAL
- Credentials embedded in service URLs: redis://:password@host, postgres://user:pass@host
- Mimikatz / LSASS dumps: "* Password : value" lines → CREDENTIAL

PATHS & FILES — flag complete paths containing org or user identifiers:
- /home/operator/engagements/contoso/ → flag this entire path as PATH
- /home/operator/sqlmap/solaris_2024/ → PATH
- /tmp/quantum_ldap/ → PATH
- Any path where a directory component is an org name or username

USERNAMES — flag all account names specific to this target:
- Domain usernames with or without prefix: DOMAIN\\user, user@domain, standalone "john.smith"
- Service accounts: svc_mssql, svc_web, svc_backup, svc_gitlab, svc_erp → USERNAME
- Functional/app accounts: ti_helpdesk, deploy_bot, db_admin, devuser → USERNAME
- Org-specific app/deploy accounts: acme_db_user, acme_prod, nexus_prod,
  stellarapp_prod, IT_HELPDESK → USERNAME/ORGANIZATION (whichever fits context)

DO NOT FLAG:
- Security tool names: nmap, burpsuite, metasploit, mimikatz, wireshark, crackmapexec,
  impacket, evil-winrm, bloodhound, hashcat, responder, certipy, rubeus, secretsdump,
  sekurlsa, logonpasswords, hashdump, meterpreter, msf6, kubectl, helm, terraform
- Tool sub-commands or flags: --shares, --no-pass, -sV, -sC, -oN, get, apply, delete
- Protocols and services: HTTP, HTTPS, SMB, SSH, RDP, LDAP, DNS, Kerberos, WinRM,
  NTLM, SMTP, IMAP, POP3, FTP, git, github, gitlab, docker, kubernetes, redis, postgres
- CVE identifiers (CVE-YYYY-NNNNN), port numbers, generic tech terms
- The word "administrator" alone — it is the Windows built-in account name, not org-specific
  (but DO flag "administrator" when it appears as an active credential with a hash or password)

- Technology product names and version strings — CRITICAL for CVE matching, never flag:
  * Web servers: Apache, Apache httpd, nginx, IIS, Tomcat, Jetty, Lighttpd, Caddy
  * Databases: MySQL, PostgreSQL, MariaDB, MSSQL, MongoDB, Oracle, SQLite, Cassandra, Redis
  * Mail / directory: Postfix, Sendmail, Dovecot, OpenLDAP, Samba
  * SSH / VPN / crypto: OpenSSH, OpenSSL, Cisco, FortiGate, Palo Alto (product only, not hostname)
  * Languages / runtimes: PHP, Python, Ruby, Node.js, Java, .NET, Go, Perl
  * OS and distros: Windows, Windows Server, Ubuntu, Debian, CentOS, RHEL, Alpine, Kali
  * Version strings in any format: "2.4.51", "7.4p1", "10.0.17763", "5.7.38-log",
    "1:1.0.2k-fips", "8.0.30", "(Ubuntu)", "(Debian)", build numbers, patch levels
  * Full banner strings from nmap -sV: "Apache httpd 2.4.51 (Ubuntu)",
    "OpenSSH 7.4 (protocol 2.0)", "MySQL 5.7.38-log", "Microsoft IIS 10.0",
    "nginx 1.18.0 (Ubuntu)", "PHP 7.4.33"
  The test is about identifying THE TARGET, not the technology they use. Millions of
  companies run Apache 2.4.51. Flag "dc01.target.local" (unique to target) but never
  "Apache 2.4.51" (common to everyone).

- OS build details tied to technology: "Windows Server 2019 10.0.17763",
  "Ubuntu 22.04 LTS", "Debian GNU/Linux 11 (bullseye)" — these are generic
- Git / dotfile config KEY names (not values): user.name, user.email, core.editor,
  push.default, credential.helper, merge.tool, diff.tool — these are config keys
- Column headers in CSV/tables: Nome, CPF, Email, Telefone, Cargo, Departamento,
  Salario, Nome Completo, Data, ID
- Generic role words: CISO, CTO, CEO, CFO, COO, CIO (only flag if they directly
  reveal a real person's name that identifies the target)
- WiFi protocol terms: WPA2, CCMP, MGT, PSK, BSSID, RADIUS, EAP, TKIP — these are
  wireless standards, not org identifiers
  (but DO flag ESSID/SSID values like "CORPORATE-NET", "CORP_VISITORS", "ACME-WIFI"
  which are the actual WiFi network names and reveal the organization)
- Generic K8s types and verbs: Secret, Opaque, Deployment, Pod, Running, Ready,
  ConfigMap, Service, Namespace — these are K8s API terms
  (but DO flag the NAME of the K8s resource: "vortex-db-credentials", namespace "producao")
- Well-known AD built-in accounts: krbtgt, Guest (these exist in every AD domain)
- Well-known LDAP/AD group names: "Domain Users", "Domain Admins", "Enterprise Admins",
  "Administrators", "Schema Admins", "Backup Operators", "Remote Desktop Users"
- AS-REP/Kerberoasting attack technique names, AD CS attack names (ESC1, PKINIT, etc.)

Return ONLY valid JSON, no explanation, no markdown:
{"entities": [{"text": "<exact substring from input>", "type": "ORGANIZATION|PERSON|IP_ADDRESS|CIDR|HOSTNAME|DOMAIN|USERNAME|EMAIL_ADDRESS|CREDENTIAL|HASH|IDENTIFIER|PATH|TOKEN|OTHER"}]}

Nothing found: {"entities": []}"""


@dataclass
class LLMMatch:
    text: str
    entity_type: str


def _strip_thinking(text: str) -> str:
    """Remove <think>...</think> blocks emitted by Qwen3 in thinking mode."""
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


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
                            "messages": [
                                {"role": "system", "content": get_system_prompt()},
                                {"role": "user",   "content": chunk_text},
                            ],
                            "stream": False,
                            "format": "json",
                            "keep_alive": -1,
                            "options": {
                                "temperature": 0,
                                "think": False,
                                "num_thread": config.OLLAMA_NUM_THREADS,
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
