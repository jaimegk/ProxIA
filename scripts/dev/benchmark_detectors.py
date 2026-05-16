#!/usr/bin/env python3
"""
Benchmark: GLiNER vs Ollama for pentest PII detection.

Compares detection speed and quality across realistic pentest tool outputs.
Run on the VPS (or any machine with Ollama + internet access for GLiNER download).

Usage:
    pip install gliner httpx
    python3 benchmark_detectors.py
"""
import asyncio
import json
import time
from dataclasses import dataclass, field

import httpx

# ── Test cases ────────────────────────────────────────────────────────────────
# Each case has a text and the entities we EXPECT to find (ground truth).
# "must_find" = critical, should never miss.
# "must_not_find" = FP check, tool names / protocols that must survive.

@dataclass
class Case:
    name: str
    text: str
    must_find: list[str]
    must_not_find: list[str] = field(default_factory=list)

CASES = [
    Case(
        name="nmap_basic",
        text="Nmap scan report for 192.168.10.45 (dc01.dynacare.local)\n"
             "Host is up (0.0010s latency).\n"
             "80/tcp  open  http    Microsoft IIS 10.0\n"
             "443/tcp open  https\n"
             "MAC Address: 00:1A:2B:3C:4D:5E (Unknown)",
        must_find=["192.168.10.45", "dc01.dynacare.local", "00:1A:2B:3C:4D:5E"],
        must_not_find=["nmap", "Microsoft IIS", "http", "https"],
    ),
    Case(
        name="mimikatz_lsass",
        text="Authentication Id : 0 ; 123456 (00000000:0001e240)\n"
             "Session           : Interactive from 1\n"
             "User Name         : john.ferreira\n"
             "Domain            : DYNACARE\n"
             "Logon Server      : DC01\n"
             " * Username : john.ferreira\n"
             " * Domain   : DYNACARE\n"
             " * NTLM     : aad3b435b51404eeaad3b435b51404ee\n"
             " * Password : Dynacare@2024!",
        must_find=["john.ferreira", "DYNACARE", "DC01",
                   "aad3b435b51404eeaad3b435b51404ee", "Dynacare@2024!"],
        must_not_find=["mimikatz", "NTLM", "Username", "Domain"],
    ),
    Case(
        name="bloodhound_users",
        text="Users with DCSync rights on DYNACARE.LOCAL:\n"
             "  DYNACARE\\svc_backup\n"
             "  DYNACARE\\ti_helpdesk\n"
             "  DYNACARE\\rafael.moura\n"
             "Shortest path to Domain Admin: rafael.moura → DC01.DYNACARE.LOCAL",
        must_find=["DYNACARE", "svc_backup", "ti_helpdesk", "rafael.moura", "DC01"],
        must_not_find=["DCSync", "Domain Admin"],
    ),
    Case(
        name="aws_credentials",
        text="[default]\n"
             "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
             "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
             "region = us-east-1\n"
             "# account: dynacare-prod (123456789012)",
        must_find=["AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                   "dynacare-prod"],
        must_not_find=["aws_access_key_id", "region"],
    ),
    Case(
        name="free_text_contextual",
        text="Found admin panel for Dynacare Corp at 10.0.0.5.\n"
             "Credentials: john.smith / Summer2024!\n"
             "The svc_gitlab account also has local admin.",
        must_find=["Dynacare Corp", "10.0.0.5", "john.smith", "Summer2024!", "svc_gitlab"],
        must_not_find=["admin", "panel"],
    ),
    Case(
        name="kerberoast_output",
        text="$krb5tgs$23$*svc_mssql$DYNACARE.LOCAL$dynacare/svc_mssql*$"
             "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6\n"
             "Hashcat result: svc_mssql:Mssql@Corp2024",
        must_find=["svc_mssql", "DYNACARE.LOCAL", "Mssql@Corp2024"],
        must_not_find=["hashcat", "krb5tgs"],
    ),
    Case(
        name="simple_no_pii",
        text="80/tcp open  http\n443/tcp open  https\nHost is up.\nnmap done.",
        must_find=[],
        must_not_find=["nmap", "http", "https"],
    ),
]

# ── Ollama detector ───────────────────────────────────────────────────────────
OLLAMA_HOST = "http://localhost:11434"

SYSTEM_PROMPT = """\
You are a strict data privacy guardian. Detect entities that could identify a target organization, person, or system.

FLAG: person names (PERSON), organization/company names (ORGANIZATION), internal hostnames (HOSTNAME), \
IP addresses (IP_ADDRESS), domain names (DOMAIN), usernames/service accounts (USERNAME), \
passwords/hashes/tokens/keys (CREDENTIAL), file paths with org identifiers (PATH).

DO NOT FLAG: tool names (nmap, mimikatz, bloodhound), protocols (http, https, smb, ldap), \
generic Windows built-ins (Domain Users, Administrators), CVE IDs, port numbers, \
technology product names (IIS, Apache, MySQL).

Return ONLY valid JSON:
{"entities": [{"text": "<exact substring>", "type": "ORGANIZATION|PERSON|IP_ADDRESS|HOSTNAME|DOMAIN|USERNAME|CREDENTIAL|PATH|HASH|TOKEN|OTHER"}]}
Nothing found: {"entities": []}"""


async def ollama_detect(text: str, model: str) -> tuple[list[dict], float, float]:
    """Returns (entities, prompt_ms, generate_ms)."""
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": text},
        ],
        "stream": False,
        "format": "json",
        "keep_alive": -1,
        "options": {"temperature": 0, "think": False, "num_thread": 6},
    }
    async with httpx.AsyncClient(timeout=180) as client:
        t0 = time.perf_counter()
        resp = await client.post(f"{OLLAMA_HOST}/api/chat", json=payload)
        elapsed = (time.perf_counter() - t0) * 1000

    data = resp.json()
    prompt_ms  = data.get("prompt_eval_duration", 0) / 1e6
    gen_ms     = data.get("eval_duration", 0) / 1e6
    raw = data.get("message", {}).get("content", "")
    try:
        entities = json.loads(raw).get("entities", [])
    except Exception:
        entities = []
    return entities, prompt_ms, gen_ms


# ── GLiNER detector ───────────────────────────────────────────────────────────
# Entity labels use natural language — GLiNER maps them to spans.
GLINER_LABELS = [
    "person name",
    "organization name",
    "internal hostname",
    "ip address",
    "domain name",
    "username",
    "service account",
    "password",
    "api key",
    "secret key",
    "hash",
    "file path",
]

_gliner_model = None

def _load_gliner(model_name: str):
    global _gliner_model
    if _gliner_model is None:
        from gliner import GLiNER
        print(f"  Loading GLiNER model {model_name}...", flush=True)
        t0 = time.perf_counter()
        _gliner_model = GLiNER.from_pretrained(model_name)
        print(f"  Loaded in {(time.perf_counter()-t0)*1000:.0f}ms", flush=True)
    return _gliner_model


def gliner_detect(text: str, model_name: str) -> tuple[list[dict], float]:
    """Returns (entities, inference_ms). Model is loaded once and reused."""
    model = _load_gliner(model_name)
    t0 = time.perf_counter()
    predictions = model.predict_entities(text, GLINER_LABELS, threshold=0.35)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    entities = [{"text": p["text"], "type": p["label"]} for p in predictions]
    return entities, elapsed_ms


# ── Scoring ───────────────────────────────────────────────────────────────────
def score(entities: list[dict], case: Case) -> tuple[int, int, int]:
    """Returns (hits, misses, false_positives)."""
    found_texts = {e["text"].lower() for e in entities}

    hits = sum(
        1 for m in case.must_find
        if any(m.lower() in ft or ft in m.lower() for ft in found_texts)
    )
    misses = len(case.must_find) - hits
    fps = sum(
        1 for m in case.must_not_find
        if any(m.lower() in ft or ft in m.lower() for ft in found_texts)
    )
    return hits, misses, fps


# ── Main ──────────────────────────────────────────────────────────────────────
def print_entities(entities: list[dict], indent: int = 4) -> None:
    pad = " " * indent
    if not entities:
        print(f"{pad}(none)")
        return
    for e in entities:
        print(f"{pad}[{e['type']}] {e['text']!r}")


async def run_ollama_benchmark(model: str) -> None:
    print(f"\n{'='*60}")
    print(f"OLLAMA — {model}")
    print('='*60)

    total_hits = total_misses = total_fps = 0
    total_prompt_ms = total_gen_ms = 0.0

    for case in CASES:
        print(f"\n  [{case.name}]")
        try:
            entities, prompt_ms, gen_ms = await ollama_detect(case.text, model)
            hits, misses, fps = score(entities, case)
            total_hits += hits; total_misses += misses; total_fps += fps
            total_prompt_ms += prompt_ms; total_gen_ms += gen_ms
            total_ms = prompt_ms + gen_ms
            status = "✓" if misses == 0 and fps == 0 else ("!" if misses > 0 else "~")
            print(f"  {status} prefill={prompt_ms:.0f}ms  gen={gen_ms:.0f}ms  total={total_ms:.0f}ms"
                  f"  hits={hits}/{len(case.must_find)}  fps={fps}")
            if misses:
                missed = [m for m in case.must_find
                          if not any(m.lower() in e["text"].lower() for e in entities)]
                print(f"    MISSED: {missed}")
            if fps:
                fp_list = [m for m in case.must_not_find
                           if any(m.lower() in e["text"].lower() for e in entities)]
                print(f"    FP: {fp_list}")
        except Exception as exc:
            print(f"  ERROR: {exc}")

    total = len(CASES)
    catch_rate = total_hits / max(1, total_hits + total_misses) * 100
    print(f"\n  SUMMARY: catch={catch_rate:.1f}%  fp={total_fps}"
          f"  avg_prefill={total_prompt_ms/total:.0f}ms"
          f"  avg_gen={total_gen_ms/total:.0f}ms"
          f"  avg_total={(total_prompt_ms+total_gen_ms)/total:.0f}ms")


def run_gliner_benchmark(model_name: str) -> None:
    global _gliner_model
    _gliner_model = None  # reset so each model loads fresh

    print(f"\n{'='*60}")
    print(f"GLINER — {model_name}")
    print('='*60)

    total_hits = total_misses = total_fps = 0
    total_ms = 0.0

    for case in CASES:
        print(f"\n  [{case.name}]")
        try:
            entities, elapsed_ms = gliner_detect(case.text, model_name)
            hits, misses, fps = score(entities, case)
            total_hits += hits; total_misses += misses; total_fps += fps
            total_ms += elapsed_ms
            status = "✓" if misses == 0 and fps == 0 else ("!" if misses > 0 else "~")
            print(f"  {status} inference={elapsed_ms:.0f}ms"
                  f"  hits={hits}/{len(case.must_find)}  fps={fps}")
            if misses:
                missed = [m for m in case.must_find
                          if not any(m.lower() in e["text"].lower() for e in entities)]
                print(f"    MISSED: {missed}")
            if fps:
                fp_list = [m for m in case.must_not_find
                           if any(m.lower() in e["text"].lower() for e in entities)]
                print(f"    FP: {fp_list}")
        except Exception as exc:
            print(f"  ERROR: {exc}")

    total = len(CASES)
    catch_rate = total_hits / max(1, total_hits + total_misses) * 100
    print(f"\n  SUMMARY: catch={catch_rate:.1f}%  fp={total_fps}"
          f"  avg_inference={total_ms/total:.0f}ms")


async def main():
    try:
        import gliner  # noqa: F401
        print("GLiNER ready.\n")
    except ImportError:
        import subprocess, sys
        print("Installing GLiNER...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "gliner", "--break-system-packages", "--quiet"],
            stdout=subprocess.DEVNULL,
        )
        print("GLiNER ready.\n")

    # ── Ollama benchmarks ─────────────────────────────────────────────────────
    # Check available models
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{OLLAMA_HOST}/api/tags")
            models = [m["name"] for m in resp.json().get("models", [])]
            print(f"Ollama models available: {models}")
    except Exception as e:
        print(f"Ollama unavailable: {e}")
        models = []

    for model in ["smollm2:135m", "qwen3:0.6b", "qwen3:1.7b", "qwen3:4b"]:
        if any(model in m for m in models):
            await run_ollama_benchmark(model)
        else:
            print(f"\n[SKIP] {model} not available in Ollama")

    # ── GLiNER benchmarks ─────────────────────────────────────────────────────
    for gliner_model in [
        "urchade/gliner_small-v2.1",
        "urchade/gliner_medium-v2.1",
        "urchade/gliner_large-v2.1",
    ]:
        run_gliner_benchmark(gliner_model)

    print("\n\nDone.")


if __name__ == "__main__":
    asyncio.run(main())
