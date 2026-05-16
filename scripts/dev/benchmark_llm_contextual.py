#!/usr/bin/env python3
"""
Benchmark: LLM contextual detection — entities regex CANNOT catch.

Tests qwen3:1.7b and qwen3:4b against realistic pentest text where
no structured patterns exist (no IPs, hashes, or labeled fields).

Measures:
  - Catch rate per case
  - False positive rate
  - Prefill time (KV cache: 1st call vs subsequent calls)
  - Generate time

Usage:
    python3 scripts/dev/benchmark_llm_contextual.py
    python3 scripts/dev/benchmark_llm_contextual.py --model qwen3:4b --timeout 120
"""
import argparse
import asyncio
import json
import re
import time
from dataclasses import dataclass, field

import httpx

CHUNK_SIZE    = 800
CHUNK_OVERLAP = 150

OLLAMA_HOST = "http://localhost:11434"

# ── Production system prompt (copied from src/llm_detector.py) ───────────────

SYSTEM_PROMPT = """\
You are a data privacy guardian for pentest reports. Identify strings that could identify a real company, person, or internal system. When in doubt, flag it.

FLAG (return exact substrings from input):
PERSON — first+last names in any language; dot-separated usernames like "john.smith", "rafael.moura" (first.last format = person, not generic words); national IDs (CPF, CNPJ, SSN)
ORGANIZATION — company/brand/project names (return the EXACT text with its capitalization and spaces, e.g., "Acme Corp" not "acme.corp"); all-caps Windows domain/workgroup names (4-15 chars, no TLD); WiFi SSID values; cloud resource names prefixed with the org name (buckets, K8s namespaces/secrets, GCP project IDs); AD CS/CA names; HTTP page titles revealing org
HOSTNAME — bare server names without FQDN: DC01, WEBSERVER01, FILESERVER-PRD, stellartech-app-01, FORTUNA-CA — anything that looks like a unique machine name in context
IP_ADDRESS / CIDR / DOMAIN — all IPs, CIDRs, subnets, internal domains, subdomains
USERNAME — service accounts (svc_*, ti_*, deploy_bot, db_admin); domain usernames (DOMAIN\\user, user@domain). When you see DOMAIN\\username:password, extract each part separately: the domain as ORGANIZATION, the username as USERNAME, the password as CREDENTIAL
CREDENTIAL — passwords, NTLM/MD5/SHA hashes, API keys, tokens, JWTs; cleartext passwords in hashcat/asleap output; PSK values; inline CLI passwords (-p value, PASSWORD=value); creds in URLs (redis://:pass@host)
PATH — file paths containing org name or username as a directory component
HASH — standalone hash strings not already caught as CREDENTIAL
TOKEN — API tokens, bearer tokens, OAuth tokens

DO NOT FLAG:
- Pentest tool names: nmap, metasploit, mimikatz, bloodhound, hashcat, crackmapexec, impacket, certipy, rubeus, secretsdump, meterpreter, kubectl, helm, terraform, evil-winrm
- Protocols: HTTP, HTTPS, SMB, SSH, RDP, LDAP, DNS, Kerberos, WinRM, NTLM, FTP, SMTP
- Tech products and versions: Apache, nginx, IIS, MySQL, PostgreSQL, OpenSSH, OpenSSL, PHP, Python, Windows, Ubuntu, Debian, and any version string
- Port numbers, CVE IDs, generic tech terms
- AD built-in accounts: administrator (standalone), krbtgt, Guest
- AD built-in groups: Domain Users, Domain Admins, Enterprise Admins, Administrators, Schema Admins
- Unix built-in accounts and system terms: root, nobody, daemon, www-data, bash, sh, zsh, passwd, shadow, sudoers
- Git structural keywords (the words themselves, not values after them): merge, branch, HEAD, origin, push, pull, diff, clone. Note: "Author: Pedro Alves" → "Pedro Alves" IS flaggable; "commit abc123" → the hash may be flaggable as IDENTIFIER but "commit" itself is not
- WiFi standards: WPA2, CCMP, TKIP, RADIUS, EAP, PSK (the word, not the value), BSSID
- Git config key names: user.name, user.email, core.editor, push.default
- CSV/table column headers: Nome, CPF, Email, Telefone, Cargo, Departamento, Data, ID
- K8s API types: Secret, Opaque, Deployment, Pod, ConfigMap, Service, Namespace (the type words, not resource names)
- Attack technique names: DCSync, AS-REP, Kerberoasting, Pass-the-Hash, Golden Ticket, Silver Ticket, PKINIT, ESC1 through ESC13, RBCD
- SAM/LDAP numeric IDs and UIDs: bare numbers like 500, 501, 1000, 1001, 0, 1 are not PII
- Bare words with no context: admin, panel, server, client, user, host, group, domain — only flag if they are clearly an entity name, not a generic label

CRITICAL: Return the EXACT substring as it appears in the input. Never normalize, lowercase, abbreviate, or modify the text.

Return ONLY valid JSON:
{"entities": [{"text": "<exact substring from input>", "type": "ORGANIZATION|PERSON|IP_ADDRESS|CIDR|HOSTNAME|DOMAIN|USERNAME|EMAIL_ADDRESS|CREDENTIAL|HASH|IDENTIFIER|PATH|TOKEN|OTHER"}]}
Nothing found: {"entities": []}"""


# ── Test cases ────────────────────────────────────────────────────────────────

@dataclass
class Case:
    name: str
    description: str
    text: str
    must_find: list[str]
    must_not_find: list[str] = field(default_factory=list)


CASES = [
    # 1. Org name in free text — no label, no TLD, not all-caps
    Case(
        name="org_free_text",
        description="Company name embedded in analyst note",
        text="Scope confirmed with the client. The target is Stellartech, a mid-size logistics company in Sao Paulo. Their IT team is small — about 12 people — and uses mostly Windows infrastructure.",
        must_find=["Stellartech"],
        must_not_find=["Windows"],
    ),

    # 2. Multi-word org name — requires understanding of context
    Case(
        name="org_multiword",
        description="Multi-word company name in engagement header",
        text="Engagement: External pentest for Meridional Energia S.A.\nScope: internet-facing assets only. No social engineering authorized.",
        must_find=["Meridional Energia S.A."],
        must_not_find=["External", "pentest"],
    ),

    # 3. Person first name only — single word, no last name, no dot notation
    Case(
        name="person_firstname_only",
        description="First name reference in conversation context",
        text="Talked to Bruno today — he confirmed that Carlos still has admin access after the layoff. Need to flag this.",
        must_find=["Bruno", "Carlos"],
        must_not_find=["admin"],
    ),

    # 4. Person full name in prose
    Case(
        name="person_fullname_prose",
        description="Full person name in analyst note",
        text="According to the org chart leaked via SMB, Pedro Alves is the IT director and reports directly to Fernanda Oliveira (CEO).",
        must_find=["Pedro Alves", "Fernanda Oliveira"],
        must_not_find=["SMB", "IT"],
    ),

    # 5. Hostname in natural language
    Case(
        name="hostname_in_prose",
        description="Bare server name mentioned casually",
        text="Found open RDP on WEBAPP01 and FILESERVER-PRD. Both are joined to the domain. WEBAPP01 runs the client portal.",
        must_find=["WEBAPP01", "FILESERVER-PRD"],
        must_not_find=["RDP", "domain"],
    ),

    # 6. Internal project / product name
    Case(
        name="internal_project_name",
        description="Internal product name with no structured context",
        text="The ERP system is called Projeto Helios and runs on port 8443. The dev team refers to the old system as Legado.",
        must_find=["Projeto Helios"],
        must_not_find=["ERP", "dev"],
    ),

    # 7. Short username (not svc_ prefix, not first.last format)
    Case(
        name="short_username_prose",
        description="Short username mentioned in recon notes",
        text="User carlos has local admin on all workstations. The account jsilva also appeared in BloodHound shortest-path results.",
        must_find=["carlos", "jsilva"],
        must_not_find=["BloodHound", "admin"],
    ),

    # 8. Internal department/team used as org identifier
    Case(
        name="department_as_identifier",
        description="Internal department name that doubles as org identifier",
        text="The Conecta team manages all VPN access. Their Slack workspace is conecta-ti.slack.com and they use Jira project CONE for tickets.",
        must_find=["Conecta", "CONE", "conecta-ti.slack.com"],
        must_not_find=["VPN", "Jira"],
    ),

    # 9. Mix of contextual + tokens that regex misses
    Case(
        name="mixed_contextual_tokens",
        description="Pentest notes with org name, username, and a non-standard API token",
        text="Extracted from Helios portal config: org_name=helios_producao, deploy_user=marcos.vinicius, internal_api_token=int_tok_v2_9xKp2mNqR7sLwT4j",
        must_find=["helios_producao", "marcos.vinicius", "int_tok_v2_9xKp2mNqR7sLwT4j"],
        must_not_find=["config", "deploy_user"],
    ),

    # 10. Git log with author and org-specific branch names
    Case(
        name="git_log_author",
        description="Git log with real author names and org-specific branch names",
        text=(
            "commit a3f9d21\n"
            "Author: Rafael Torres <rafael.torres@stellartech.com.br>\n"
            "Date:   Mon Jan 15 09:33:01 2024\n"
            "\n"
            "    Fix: login redirect for stellartech-sso branch\n"
            "\n"
            "commit 7b2c841\n"
            "Author: Ana Lima <ana.lima@stellartech.com.br>\n"
            "Date:   Fri Jan 12 17:22:40 2024\n"
            "\n"
            "    Add Helios API key rotation script\n"
        ),
        must_find=[
            "Rafael Torres", "rafael.torres@stellartech.com.br",
            "Ana Lima", "ana.lima@stellartech.com.br",
            "stellartech.com.br",
        ],
        must_not_find=["commit", "Author", "Date", "merge", "branch"],
    ),

    # 11. No PII — all generic technical content
    Case(
        name="no_pii_technical",
        description="Pure technical content — nothing should be flagged",
        text="Port 445 is open. SMB signing is disabled. The host is running Windows Server 2019. No guest access. Kerberos pre-auth required.",
        must_find=[],
        must_not_find=["SMB", "Windows", "Kerberos", "445", "2019"],
    ),

    # 12. Slack/Teams message with person names and org artifact
    Case(
        name="slack_message_names",
        description="Internal message mentioning team members and project",
        text=(
            "[09:14] Lucas Pereira: hey @Camila the Nexus repo for projeto-delta is down\n"
            "[09:15] Camila Rocha: yeah I know, infra team is looking into it\n"
            "[09:16] Lucas Pereira: can you ping Rodrigo? he has access to the NAS\n"
        ),
        must_find=["Lucas Pereira", "Camila", "projeto-delta", "Camila Rocha", "Rodrigo"],
        must_not_find=["infra", "NAS"],
    ),

    # 13. Cloud resource names — org-prefixed but no standard token format
    Case(
        name="cloud_resource_names",
        description="Cloud resource names with org prefix — not caught by regex",
        text=(
            "Found exposed GCS bucket: gs://stellartech-backups-2024/\n"
            "Lambda function: stellartech-prod-api-handler\n"
            "ECR repository: stellartech/backend-api:latest\n"
            "Namespace: stellartech-production\n"
        ),
        must_find=[
            "stellartech-backups-2024",
            "stellartech-prod-api-handler",
            "stellartech/backend-api",
            "stellartech-production",
        ],
        must_not_find=["GCS", "Lambda", "ECR"],
    ),

    # 14. Pentest report snippet — narrative with embedded PII
    Case(
        name="report_narrative",
        description="Draft pentest report paragraph with embedded identifiers",
        text=(
            "During the assessment of Fortuna Logistica's infrastructure, the tester identified "
            "that the service account svc_fortuna_erp had been granted SeImpersonatePrivilege on "
            "the host FORTUNA-APP02. Exploitation of this misconfiguration allowed privilege "
            "escalation to NT AUTHORITY\\SYSTEM. The finding was communicated to the IT lead, "
            "Gustavo Martins, on the last day of the engagement."
        ),
        must_find=[
            "Fortuna Logistica",
            "svc_fortuna_erp",
            "FORTUNA-APP02",
            "Gustavo Martins",
        ],
        must_not_find=["SeImpersonatePrivilege", "SYSTEM", "NT AUTHORITY\\SYSTEM"],
    ),
]


# ── Chunking (mirrors production llm_detector.py) ─────────────────────────────

def _split_chunks(text: str, size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> list[str]:
    if len(text) <= size:
        return [text]
    chunks, start = [], 0
    while start < len(text):
        end = min(start + size, len(text))
        chunks.append(text[start:end])
        if end == len(text):
            break
        start += size - overlap
    return chunks


# ── Ollama call ───────────────────────────────────────────────────────────────

async def _ollama_call(
    chunk: str,
    model: str,
    full_text: str,
    timeout: int,
) -> tuple[list[dict], float, float]:
    """Single chunk call. hallu-guard against full_text."""
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": chunk},
        ],
        "stream": False,
        "format": "json",
        "keep_alive": -1,
        "options": {"temperature": 0, "think": False, "num_thread": 6},
    }
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(f"{OLLAMA_HOST}/api/chat", json=payload)

    data = resp.json()
    prefill_ms = data.get("prompt_eval_duration", 0) / 1e6
    gen_ms     = data.get("eval_duration", 0) / 1e6
    raw = data.get("message", {}).get("content", "")

    raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
    m = re.search(r"\{.*\}", raw, re.DOTALL)
    raw = m.group(0) if m else raw

    try:
        entities = json.loads(raw).get("entities", [])
        entities = [e for e in entities if e.get("text", "") in full_text]
    except Exception:
        entities = []

    return entities, prefill_ms, gen_ms


async def ollama_detect(
    text: str,
    model: str,
    timeout: int = 90,
    chunked: bool = False,
) -> tuple[list[dict], float, float]:
    """Returns (entities, total_prefill_ms, total_gen_ms).

    If chunked=True, splits text into production-sized chunks and merges results.
    """
    chunks = _split_chunks(text) if chunked else [text]

    all_entities: list[dict] = []
    total_prefill = total_gen = 0.0

    for chunk in chunks:
        ents, p, g = await _ollama_call(chunk, model, text, timeout)
        total_prefill += p
        total_gen     += g
        for e in ents:
            if not any(x["text"] == e["text"] for x in all_entities):
                all_entities.append(e)

    return all_entities, total_prefill, total_gen


# ── Scoring ───────────────────────────────────────────────────────────────────

def score(entities: list[dict], case: Case) -> tuple[int, int, int]:
    found = {e["text"] for e in entities}
    found_lower = {t.lower() for t in found}

    hits = sum(
        1 for m in case.must_find
        if m in found or m.lower() in found_lower
        or any(m.lower() in f for f in found_lower)
    )
    misses = len(case.must_find) - hits
    fps = sum(
        1 for m in case.must_not_find
        if m in found or m.lower() in found_lower
        or any(m.lower() in f for f in found_lower)
    )
    return hits, misses, fps


# ── Runner ────────────────────────────────────────────────────────────────────

async def warmup(model: str) -> None:
    print(f"  Warming up {model}...", flush=True)
    t0 = time.perf_counter()
    async with httpx.AsyncClient(timeout=180) as client:
        await client.post(
            f"{OLLAMA_HOST}/api/generate",
            json={"model": model, "prompt": "", "keep_alive": -1},
        )
    print(f"  Warm-up done in {(time.perf_counter()-t0)*1000:.0f}ms", flush=True)


async def run_benchmark(model: str, timeout: int, chunked: bool = False) -> dict:
    B, NC, G, R, Y = "\033[1m", "\033[0m", "\033[0;32m", "\033[0;31m", "\033[1;33m"

    chunk_label = f"  [chunked ≤{CHUNK_SIZE}c]" if chunked else "  [no chunking]"
    print(f"\n{'='*62}")
    print(f"{B}OLLAMA — {model}{NC}{chunk_label}")
    print(f"{'='*62}\n")

    await warmup(model)
    print()

    total_hits = total_misses = total_fps = 0
    total_prefill = total_gen = 0.0
    results = []

    for i, case in enumerate(CASES):
        print(f"  [{case.name}]", flush=True)
        print(f"  {case.description}", flush=True)

        try:
            n_chunks = len(_split_chunks(case.text)) if chunked else 1
            entities, prefill_ms, gen_ms = await ollama_detect(case.text, model, timeout, chunked=chunked)
            hits, misses, fps = score(entities, case)

            total_hits    += hits
            total_misses  += misses
            total_fps     += fps
            total_prefill += prefill_ms
            total_gen     += gen_ms

            cache_note = " [KV-cache]" if i > 0 else " [cold]"
            chunk_note = f" [{n_chunks}chunks]" if chunked and n_chunks > 1 else ""
            status = (
                f"{G}✓{NC}" if misses == 0 and fps == 0
                else (f"{R}!{NC}" if misses > 0 else f"{Y}~{NC}")
            )
            total_ms = prefill_ms + gen_ms
            print(
                f"  {status} prefill={prefill_ms:.0f}ms  gen={gen_ms:.0f}ms"
                f"  total={total_ms:.0f}ms{cache_note}{chunk_note}"
                f"  hits={hits}/{len(case.must_find)}  fps={fps}",
                flush=True,
            )

            if misses:
                missed = [
                    m for m in case.must_find
                    if not any(m.lower() in e["text"].lower() for e in entities)
                ]
                print(f"    {R}MISSED:{NC} {missed}", flush=True)

            if fps:
                fp_list = [
                    m for m in case.must_not_find
                    if any(m.lower() in e["text"].lower() for e in entities)
                ]
                print(f"    {Y}FP:{NC} {fp_list}", flush=True)

            if entities and (misses or fps or i < 3):
                print(f"    Entities found:", flush=True)
                for e in entities:
                    print(f"      [{e['type']}] {e['text']!r}", flush=True)

        except Exception as exc:
            print(f"  {R}ERROR:{NC} {exc}", flush=True)
            misses = len(case.must_find)
            total_misses += misses

        results.append({
            "case": case.name,
            "hits": hits if "hits" in dir() else 0,
            "misses": misses,
            "fps": fps if "fps" in dir() else 0,
        })
        print(flush=True)

    n = len(CASES)
    catch = total_hits / max(1, total_hits + total_misses) * 100
    avg_prefill = total_prefill / n
    avg_gen = total_gen / n

    print(f"  {B}SUMMARY{NC}: catch={G if catch > 85 else R}{catch:.1f}%{NC}"
          f"  fp={total_fps}"
          f"  avg_prefill={avg_prefill:.0f}ms"
          f"  avg_gen={avg_gen:.0f}ms"
          f"  avg_total={(avg_prefill+avg_gen):.0f}ms")

    return {
        "model": model,
        "catch_pct": catch,
        "total_fp": total_fps,
        "avg_prefill_ms": avg_prefill,
        "avg_gen_ms": avg_gen,
    }


# ── Main ──────────────────────────────────────────────────────────────────────

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model",   default=None,  help="Single model to test (default: all available)")
    parser.add_argument("--timeout", type=int, default=90, help="Per-case timeout in seconds")
    parser.add_argument("--chunk",   action="store_true", help=f"Split inputs into {CHUNK_SIZE}-char chunks (mirrors production)")
    args = parser.parse_args()

    # Discover available models
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{OLLAMA_HOST}/api/tags")
            available = [m["name"] for m in resp.json().get("models", [])]
            print(f"Ollama models available: {available}")
    except Exception as e:
        print(f"Ollama unavailable: {e}")
        return

    candidates = [args.model] if args.model else ["qwen3:1.7b", "qwen3:4b"]
    summaries = []

    for model in candidates:
        if model in available:
            s = await run_benchmark(model, args.timeout, chunked=args.chunk)
            summaries.append(s)
        else:
            print(f"\n[SKIP] {model} not available")

    # Final comparison table
    if len(summaries) > 1:
        print(f"\n\n{'='*62}")
        print(f"\033[1mFINAL COMPARISON — contextual detection (LLM layer only)\033[0m")
        print(f"{'='*62}")
        print(f"  {'Model':<20} {'Catch':>7} {'FP':>5} {'Prefill':>10} {'Generate':>10} {'Total':>10}")
        print(f"  {'-'*20} {'-'*7} {'-'*5} {'-'*10} {'-'*10} {'-'*10}")
        for s in summaries:
            total = s['avg_prefill_ms'] + s['avg_gen_ms']
            print(
                f"  {s['model']:<20} {s['catch_pct']:>6.1f}% {s['total_fp']:>5}"
                f"  {s['avg_prefill_ms']:>8.0f}ms  {s['avg_gen_ms']:>8.0f}ms  {total:>8.0f}ms"
            )

    print("\n\nDone.")


if __name__ == "__main__":
    asyncio.run(main())
