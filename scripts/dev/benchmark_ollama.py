#!/usr/bin/env python3
"""
scripts/benchmark_ollama.py — Ollama performance benchmark for the LLM anonymizer.

Measures:
  - Inference time per chunk (ms)
  - Throughput (chars/s and tokens/s)
  - Total cost per request (including chunking overhead)
  - Comparison with previous runs (saved to data/benchmark_results.jsonl)

Usage:
    python -m scripts.benchmark_ollama
    python -m scripts.benchmark_ollama --host http://localhost:11434
    python -m scripts.benchmark_ollama --model qwen3:1.7b --warmup 3
    python -m scripts.benchmark_ollama --no-save  # skip saving to history
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

# ── ANSI colours ──────────────────────────────────────────────────────────────
R  = "\033[0;31m"
G  = "\033[0;32m"
Y  = "\033[1;33m"
C  = "\033[0;36m"
B  = "\033[1m"
D  = "\033[2m"
NC = "\033[0m"

def _hr(w=72): return f"{D}{'─' * w}{NC}"
def _ok(m):    print(f"  {G}✓{NC} {m}")
def _warn(m):  print(f"  {Y}⚠{NC} {m}")
def _err(m):   print(f"  {R}✗{NC} {m}")
def _info(m):  print(f"    {m}")
def _head(m):  print(f"\n{B}{m}{NC}")


# ── Payloads realistas de pentest (tamanhos diferentes) ───────────────────────

PAYLOADS: list[dict[str, Any]] = [
    {
        "label": "S  (nmap host)",
        "chars": None,  # computed below
        "text": """\
Nmap scan report for dc01.contoso.local (10.10.50.5)
Host is up. PORT 445/tcp open microsoft-ds Windows Server 2019
""",
    },
    {
        "label": "M  (mimikatz dump)",
        "chars": None,
        "text": """\
mimikatz # sekurlsa::logonpasswords
Authentication Id : 0 ; 63929
User Name         : john.smith
Domain            : CONTOSO
Logon Server      : DC01
 * Username : john.smith
 * Domain   : CONTOSO
 * NTLM     : 8846f7eaee8fb117ad06bdd830b7586c
 * Password : C0nt0s0@2024!
Authentication Id : 0 ; 71234
User Name         : jane.doe
Domain            : CONTOSO
 * NTLM     : 5f4dcc3b5aa765d61d8327deb882cf99
User Name         : svc_mssql
 * NTLM     : 31d6cfe0d16ae931b73c59d7e0c089c0
""",
    },
    {
        "label": "L  (nmap full + CME)",
        "chars": None,
        "text": """\
Starting Nmap 7.94 at 2024-01-15 10:23 EST
Nmap scan report for dc01.contoso.local (10.10.50.5)
Host is up (0.0012s latency).
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: CONTOSO.LOCAL)
445/tcp   open  microsoft-ds  Windows Server 2008 R2 (workgroup: CONTOSO)
| ssl-cert: Subject: commonName=dc01.contoso.local
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
Nmap scan report for webserver01.contoso.local (10.10.50.15)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS 10.0
Nmap scan report for fileserver-prd.contoso.local (10.10.50.20)
PORT    STATE SERVICE VERSION
445/tcp open  microsoft-ds
Nmap done: 10.10.50.0/24 (256 hosts) scanned in 127.33 seconds

SMB  10.10.50.5   445  DC01         [*] Windows Server 2008 R2 (name:DC01) (domain:CONTOSO.LOCAL)
SMB  10.10.50.5   445  DC01         [+] CONTOSO.LOCAL\\administrator:Admin@Contoso2024 (Pwn3d!)
SMB  10.10.50.15  445  WEBSERVER01  [*] Windows Server 2016
SMB  10.10.50.15  445  WEBSERVER01  [+] CONTOSO.LOCAL\\john.smith:C0nt0s0@2024! (Pwn3d!)
SMB  10.10.50.20  445  FILESERVER-PRD [-] CONTOSO.LOCAL\\guest: STATUS_LOGON_FAILURE

bloodhound-python -u john.smith -p 'C0nt0s0@2024!' -ns 10.10.50.5 -d contoso.local -c all
INFO: Found AD domain: contoso.local
INFO: Enumeration done in 8.24s
""",
    },
    {
        "label": "XL (secretsdump + bloodhound + k8s)",
        "chars": None,
        "text": r"""\
impacket-secretsdump CONTOSO.LOCAL/administrator:'Admin@Contoso2024'@10.10.50.5
[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xdeadbeefcafe1234abcd5678efgh9012
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
CONTOSO.LOCAL/john.smith:$DCC2$10240#john.smith#2f36bd5a5e817b3c6f80d6cfb26b4e55
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
CONTOSO\DC01$:plain_password_hex:57006f0072006b00670072006f007500700021
CONTOSO\DC01$:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
[*] DPAPI_SYSTEM
dpapi_machinekey: 0x01020304050607deadbeefcafe
dpapi_userkey: 0xfeedface12345678abcdef
[*] NL$KM
NL$KM:feedfacedeadbeefdeadbeeffeedface
[*] Cleaning up...

-- BloodHound data collected --
Found 47 users, 12 computers, 8 groups in CONTOSO.LOCAL
High Value Targets:
  john.smith (MemberOf: Domain Admins)
  svc_mssql (Kerberoastable, SPN: MSSQLSvc/sql01.contoso.local:1433)
  jane.doe (ASREPRoastable)
Shortest path to DA: john.smith@contoso.local → CONTOSO-CA → Domain Admins

-- Kubernetes secrets dump --
kubectl get secrets -n producao -o yaml
apiVersion: v1
kind: Secret
metadata:
  name: vortex-db-credentials
  namespace: producao
data:
  DB_HOST: c3FsMDEuY29udG9zby5sb2NhbA==     # sql01.contoso.local
  DB_USER: dm9ydGV4X3Byb2Q=                  # vortex_prod
  DB_PASS: UHJvZFZvcnRleEAyMDI0IQ==         # ProdVortex@2024!
  JWT_SECRET: dG9wc2VjcmV0and0c2VjcmV0       # topsecretjwtsecret
---
apiVersion: v1
kind: Secret
metadata:
  name: vortex-smtp-config
  namespace: producao
data:
  SMTP_HOST: bWFpbC5jb250b3NvLmxvY2Fs       # mail.contoso.local
  SMTP_PASS: TWFpbEAyMDI0IQ==               # Mail@2024!

-- AWS CloudTrail --
{
  "userIdentity": {
    "type": "IAMUser",
    "arn": "arn:aws:iam::123456789012:user/deploy_bot",
    "accessKeyId": "AKIAIOSFODNN7EXAMPLE"
  },
  "eventSource": "s3.amazonaws.com",
  "eventName": "GetObject",
  "resources": [{"ARN": "arn:aws:s3:::contoso-prod-backups/db-dump-2024.tar.gz"}]
}

-- Bloodhound ACL findings --
CONTOSO\\john.smith has GenericAll on CONTOSO\\svc_mssql
CONTOSO\\jane.doe has WriteDACL on CONTOSO.LOCAL (Domain Object)
Certificate Template: FortunaUserAuth allows client auth for Domain Users
CA Name: FORTUNA-CA  → ESC1 vulnerable
""",
    },
]


# ── Chunker (mirrors default config) ─────────────────────────────────────────

def _chunks(text: str, size: int = 1500, overlap: int = 150) -> list[tuple[str, int]]:
    result = []
    i = 0
    while i < len(text):
        result.append((text[i: i + size], i))
        if i + size >= len(text):
            break
        i += size - overlap
    return result


# ── Ollama call ───────────────────────────────────────────────────────────────

async def _infer(
    client: httpx.AsyncClient,
    host: str,
    model: str,
    system_prompt: str,
    user_text: str,
    timeout: float = 120.0,
) -> dict:
    t0 = time.perf_counter()
    resp = await client.post(
        f"{host}/api/chat",
        json={
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_text},
            ],
            "stream": False,
            "format": "json",
            "keep_alive": -1,
            "options": {
                "temperature": 0,
                "think": False,
            },
        },
        timeout=timeout,
    )
    elapsed_ms = (time.perf_counter() - t0) * 1000
    resp.raise_for_status()
    data = resp.json()

    prompt_eval_count  = data.get("prompt_eval_count", 0)
    eval_count         = data.get("eval_count", 0)
    eval_duration_ns   = data.get("eval_duration", 0)
    prompt_duration_ns = data.get("prompt_eval_duration", 0)
    total_duration_ns  = data.get("total_duration", 0)

    tokens_per_sec = (eval_count / eval_duration_ns * 1e9) if eval_duration_ns else 0

    return {
        "elapsed_ms":        elapsed_ms,
        "ollama_total_ms":   total_duration_ns / 1e6,
        "prompt_tokens":     prompt_eval_count,
        "output_tokens":     eval_count,
        "tokens_per_sec":    round(tokens_per_sec, 1),
        "response_chars":    len(data.get("message", {}).get("content", "")),
    }


async def _warmup(client: httpx.AsyncClient, host: str, model: str, n: int) -> None:
    print(f"  Aquecendo modelo com {n} inferências…")
    for i in range(n):
        try:
            await _infer(client, host, model, "You are helpful.", "ping", timeout=120)
            print(f"    warm {i+1}/{n} ok")
        except Exception as e:
            _warn(f"warmup {i+1} falhou: {e}")


async def _check_ollama(host: str) -> dict:
    async with httpx.AsyncClient(timeout=8) as client:
        resp = await client.get(f"{host}/api/tags")
        resp.raise_for_status()
        data = resp.json()
    models = [m["name"] for m in data.get("models", [])]
    return {"models": models, "host": host}


# ── Benchmark ─────────────────────────────────────────────────────────────────

async def run_benchmark(
    host: str,
    model: str,
    system_prompt: str,
    warmup: int,
    repeats: int,
    chunk_size: int,
    chunk_overlap: int,
) -> list[dict]:
    async with httpx.AsyncClient(timeout=180) as client:

        if warmup > 0:
            await _warmup(client, host, model, warmup)

        results = []

        for payload in PAYLOADS:
            label = payload["label"]
            text  = payload["text"].strip()
            payload["chars"] = len(text)

            chunks = _chunks(text, size=chunk_size, overlap=chunk_overlap)
            n_chunks = len(chunks)

            _head(f"Payload {label}  ({len(text)} chars, {n_chunks} chunk{'s' if n_chunks!=1 else ''})")

            run_timings: list[dict] = []

            for rep in range(repeats):
                chunk_results = []
                for chunk_text, offset in chunks:
                    try:
                        r = await _infer(client, host, model, system_prompt, chunk_text)
                        chunk_results.append(r)
                    except httpx.TimeoutException:
                        _err(f"  rep {rep+1} chunk@{offset}: TIMEOUT")
                        chunk_results.append({"elapsed_ms": None})
                    except Exception as e:
                        _err(f"  rep {rep+1} chunk@{offset}: {e}")
                        chunk_results.append({"elapsed_ms": None})

                # Aggregate across chunks (concurrent chunks would be parallel,
                # but here sequential for clean per-chunk measurement)
                total_ms     = sum(r["elapsed_ms"] for r in chunk_results if r.get("elapsed_ms"))
                prompt_toks  = sum(r.get("prompt_tokens", 0) for r in chunk_results)
                output_toks  = sum(r.get("output_tokens", 0) for r in chunk_results)
                avg_tps      = (
                    sum(r.get("tokens_per_sec", 0) for r in chunk_results if r.get("tokens_per_sec"))
                    / max(1, sum(1 for r in chunk_results if r.get("tokens_per_sec")))
                )

                run_timings.append({
                    "total_ms":    round(total_ms, 1),
                    "n_chunks":    n_chunks,
                    "prompt_toks": prompt_toks,
                    "output_toks": output_toks,
                    "avg_tps":     round(avg_tps, 1),
                    "chars_per_s": round(len(text) / total_ms * 1000, 0) if total_ms else 0,
                })

                status = f"{total_ms:.0f}ms  {avg_tps:.1f} tok/s"
                _ok(f"rep {rep+1}/{repeats}: {status}")

            # Summary stats across repeats
            valid_runs = [r for r in run_timings if r["total_ms"]]
            if valid_runs:
                avg_ms  = sum(r["total_ms"] for r in valid_runs) / len(valid_runs)
                min_ms  = min(r["total_ms"] for r in valid_runs)
                max_ms  = max(r["total_ms"] for r in valid_runs)
                avg_tps = sum(r["avg_tps"] for r in valid_runs) / len(valid_runs)
                avg_cps = sum(r["chars_per_s"] for r in valid_runs) / len(valid_runs)
            else:
                avg_ms = min_ms = max_ms = avg_tps = avg_cps = 0

            entry = {
                "label":      label,
                "n_chars":    len(text),
                "n_chunks":   n_chunks,
                "avg_ms":     round(avg_ms, 1),
                "min_ms":     round(min_ms, 1),
                "max_ms":     round(max_ms, 1),
                "avg_tps":    round(avg_tps, 1),
                "avg_cps":    round(avg_cps, 0),
            }
            results.append(entry)

            _info(f"  avg={avg_ms:.0f}ms  min={min_ms:.0f}ms  max={max_ms:.0f}ms  "
                  f"{avg_tps:.1f} tok/s  {avg_cps:.0f} chars/s")

    return results


# ── Historical trending ───────────────────────────────────────────────────────

HISTORY_FILE = ROOT / "data" / "benchmark_results.jsonl"

def _load_history(n: int = 5) -> list[dict]:
    if not HISTORY_FILE.exists():
        return []
    lines = HISTORY_FILE.read_text().strip().splitlines()
    runs = []
    for line in lines[-n:]:
        try:
            runs.append(json.loads(line))
        except Exception:
            pass
    return runs


def _save_run(run: dict) -> None:
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    with HISTORY_FILE.open("a") as f:
        f.write(json.dumps(run) + "\n")


def _delta_str(current: float, previous: float | None) -> str:
    if previous is None or previous == 0:
        return ""
    delta_pct = (current - previous) / previous * 100
    if abs(delta_pct) < 2:
        return f"  {D}(~){NC}"
    arrow = "▲" if delta_pct > 0 else "▼"
    color = R if delta_pct > 0 else G  # red = slower, green = faster
    return f"  {color}{arrow}{abs(delta_pct):.0f}%{NC}"


def _print_summary(results: list[dict], host: str, model: str, history: list[dict]) -> None:
    print(f"\n{_hr()}")
    print(f"{B}Benchmark Summary{NC}  {D}model={model}  host={host}{NC}")
    print(_hr())

    # Column headers
    hdr = (
        f"  {'Payload':<28} {'Chars':>7} {'Chunks':>6} "
        f"{'Avg ms':>8} {'Min ms':>8} {'Max ms':>8} "
        f"{'tok/s':>7} {'chars/s':>8}"
    )
    print(f"{D}{hdr}{NC}")
    print(f"  {D}{'─'*95}{NC}")

    prev_run = history[-1] if history else None
    prev_by_label: dict[str, dict] = {}
    if prev_run:
        for r in prev_run.get("results", []):
            prev_by_label[r["label"]] = r

    for r in results:
        prev = prev_by_label.get(r["label"])
        prev_avg = prev["avg_ms"] if prev else None
        delta = _delta_str(r["avg_ms"], prev_avg)
        print(
            f"  {r['label']:<28} {r['n_chars']:>7} {r['n_chunks']:>6} "
            f"{r['avg_ms']:>8.0f} {r['min_ms']:>8.0f} {r['max_ms']:>8.0f} "
            f"{r['avg_tps']:>7.1f} {r['avg_cps']:>8.0f}"
            f"{delta}"
        )

    print(_hr())

    if len(history) > 1:
        print(f"\n{D}Historical avg_ms (last {len(history)} runs):{NC}")
        # Print only XL payload trend as proxy for overall perf
        xl_label = PAYLOADS[-1]["label"]
        xl_history = [
            next((r["avg_ms"] for r in run.get("results", []) if r["label"] == xl_label), None)
            for run in history
        ]
        bars = ""
        for v in xl_history:
            if v is None:
                bars += " ?"
            else:
                bars += f" {v:.0f}ms"
        print(f"  {xl_label}:{bars}")


# ── Main ──────────────────────────────────────────────────────────────────────

async def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark Ollama LLM performance")
    parser.add_argument("--host",    default=os.getenv("OLLAMA_HOST", "http://localhost:11434"))
    parser.add_argument("--model",   default=os.getenv("OLLAMA_MODEL", "qwen3:1.7b"))
    parser.add_argument("--warmup",  type=int, default=2, help="Nº de warm-up antes do benchmark")
    parser.add_argument("--repeats", type=int, default=3, help="Repetições por payload")
    parser.add_argument("--chunk-size",    type=int, default=1500)
    parser.add_argument("--chunk-overlap", type=int, default=150)
    parser.add_argument("--no-save", action="store_true", help="Skip saving result to history")
    args = parser.parse_args()

    print(f"\n{B}pentest-proxy — Ollama Benchmark{NC}")
    print(_hr())

    # 1. Check connection
    _head("Checking Ollama…")
    try:
        info = await _check_ollama(args.host)
    except Exception as e:
        _err(f"Ollama not reachable at {args.host}: {e}")
        _err("Open the SSH tunnel first: python3 wizard.py connect")
        sys.exit(1)

    _ok(f"Connected at {args.host}")
    _info(f"Available models: {', '.join(info['models']) or '(none)'}")

    # Detect VPS vs local by hostname
    is_vps_tunnel = "localhost" in args.host and os.getenv("SSH_AUTH_SOCK", "")
    location_hint = "VPS (via SSH tunnel)" if is_vps_tunnel else "local"
    _info(f"Inferred location: {location_hint}")

    # 2. Carregar system prompt do projeto
    prompt_path = ROOT / "data" / "system_prompt.txt"
    if prompt_path.exists():
        system_prompt = prompt_path.read_text(encoding="utf-8").strip()
        _info(f"System prompt: {prompt_path.name} ({len(system_prompt)} chars)")
    else:
        # Minimal fallback so the benchmark doesn't depend on the full module
        system_prompt = (
            'You are a data privacy guardian. Return JSON: '
            '{"entities": [{"text": "...", "type": "HOSTNAME|IP_ADDRESS|CREDENTIAL|..."}]}'
        )
        _warn("data/system_prompt.txt not found — using minimal fallback prompt")

    # 3. Previous history
    history = _load_history(n=10)
    if history:
        last_ts = history[-1].get("ts", "?")
        _info(f"History: {len(history)} previous runs (last: {last_ts})")

    print()
    print(f"  Modelo:  {B}{args.model}{NC}")
    print(f"  Warmup:  {args.warmup}  Repeats: {args.repeats}")
    print(f"  Chunks:  size={args.chunk_size}  overlap={args.chunk_overlap}")

    # 4. Benchmark
    results = await run_benchmark(
        host=args.host,
        model=args.model,
        system_prompt=system_prompt,
        warmup=args.warmup,
        repeats=args.repeats,
        chunk_size=args.chunk_size,
        chunk_overlap=args.chunk_overlap,
    )

    # 5. Resumo
    _print_summary(results, args.host, args.model, history)

    # 6. Bottleneck analysis
    print(f"\n{B}Analysis:{NC}")
    xl = next((r for r in results if "XL" in r["label"]), results[-1])
    ms_per_chunk = xl["avg_ms"] / max(1, xl["n_chunks"])
    _info(f"XL payload: {xl['avg_ms']:.0f}ms total ({xl['n_chunks']} chunks × ~{ms_per_chunk:.0f}ms/chunk)")

    # Projection: typical request with medium-sized messages
    typical_chars  = 2000
    typical_chunks = max(1, typical_chars // (args.chunk_size - args.chunk_overlap))
    m_payload      = next((r for r in results if r["label"].startswith("M")), results[1])
    projected_ms   = m_payload["avg_ms"] * typical_chunks
    _info(f"Estimated typical request (~{typical_chars} chars): {projected_ms:.0f}ms")

    if xl["avg_tps"] < 20:
        _warn("Throughput < 20 tok/s — model likely running on CPU only. Consider GPU.")
    elif xl["avg_tps"] < 50:
        _info("Throughput 20-50 tok/s — fast CPU or small GPU.")
    else:
        _ok(f"Throughput {xl['avg_tps']:.0f} tok/s — good performance.")

    # 7. Salvar
    if not args.no_save:
        run_record = {
            "ts":      datetime.now(timezone.utc).isoformat(),
            "host":    args.host,
            "model":   args.model,
            "warmup":  args.warmup,
            "repeats": args.repeats,
            "chunk_size": args.chunk_size,
            "results": results,
        }
        _save_run(run_record)
        _ok(f"Resultado salvo em {HISTORY_FILE.relative_to(ROOT)}")
    else:
        _warn("--no-save: resultado NÃO salvo no histórico")

    print()


if __name__ == "__main__":
    asyncio.run(main())
