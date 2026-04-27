#!/usr/bin/env python3
"""
scripts/auto_improve.py — Ciclo automático de aprimoramento (regex layer).

Sem precisar de Ollama: roda todos os fixtures contra o anonymizer com LLM
desabilitado, reporta o que vazou, tenta corrigir automaticamente adicionando
padrões regex ou entradas em _NEVER_ANONYMIZE, e re-testa.

Usage:
    python -m scripts.auto_improve [--cycles N] [--verbose]
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

R  = "\033[0;31m"
G  = "\033[0;32m"
Y  = "\033[1;33m"
C  = "\033[0;36m"
B  = "\033[1m"
NC = "\033[0m"

def _hr(w=64): return "─" * w
def _ok(m):   print(f"  {G}✓{NC} {m}")
def _warn(m): print(f"  {Y}⚠{NC} {m}")
def _err(m):  print(f"  {R}✗{NC} {m}")
def _info(m): print(f"    {m}")


# ── Test runner ───────────────────────────────────────────────────────────────

async def _run_fixture(fixture, db_path: Path, engagement: str) -> dict:
    """Run one fixture with LLM disabled. Returns result dict."""
    from unittest.mock import AsyncMock, patch
    from src.vault import init_db, get_or_create, get_all_mappings
    from src.anonymizer import anonymize

    with (
        patch("src.llm_detector.detect", new_callable=AsyncMock, return_value=[]),
        patch("src.vault.config") as cfg,
        patch("src.anonymizer.get_or_create") as mock_goc,
        patch("src.anonymizer.get_all_mappings") as mock_gam,
        patch("src.anonymizer._verifier.record_traffic"),
    ):
        cfg.ENGAGEMENT_ID = engagement
        cfg.DATABASE_PATH = db_path
        mock_goc.side_effect = lambda o, t, fn: get_or_create(
            o, t, fn, engagement=engagement, db_path=db_path
        )
        mock_gam.side_effect = lambda: get_all_mappings(
            engagement=engagement, db_path=db_path
        )
        result = await anonymize(fixture.text, is_tool_output=True)

    leaked  = [v for v in fixture.must_anonymize if v in result]
    # Only flag as FP if the term was actually present in the original text
    # (terms not in fixture.text can't be in result either, so would always false-alarm)
    fp      = [v for v in fixture.safe_to_keep if v in fixture.text and v not in result]
    return {
        "name":    fixture.name,
        "leaked":  leaked,
        "fp":      fp,
        "caught":  len(fixture.must_anonymize) - len(leaked),
        "total":   len(fixture.must_anonymize),
        "result":  result,
        "fixture": fixture,
    }


async def run_all(fixtures) -> list[dict]:
    with tempfile.TemporaryDirectory(prefix="autoimprove_") as tmpdir:
        db_path = Path(tmpdir) / "vault.db"
        from src.vault import init_db
        init_db(db_path)
        results = []
        for fx in fixtures:
            r = await _run_fixture(fx, db_path, "auto-improve")
            results.append(r)
    return results


def print_round(results: list[dict], label: str):
    total_caught = sum(r["caught"] for r in results)
    total_must   = sum(r["total"]  for r in results)
    total_fp     = sum(len(r["fp"]) for r in results)
    rate = total_caught / total_must if total_must else 1.0

    colour = G if rate >= 0.95 else (Y if rate >= 0.80 else R)
    print(f"\n{B}{_hr()}{NC}")
    print(f"  {label}")
    print(f"  Catch rate : {colour}{rate*100:.1f}%{NC}  ({total_caught}/{total_must})")
    print(f"  False pos  : {total_fp} (safe terms wrongly removed)")
    print(f"{B}{_hr()}{NC}")

    for r in results:
        if r["leaked"] or r["fp"]:
            rate_r = r["caught"] / r["total"] if r["total"] else 1.0
            col = Y if r["leaked"] else G
            print(f"  {col}{r['name']:<36}{NC} "
                  f"{r['caught']}/{r['total']}  "
                  f"leak={len(r['leaked'])}  fp={len(r['fp'])}")
            for v in r["leaked"][:5]:
                _info(f"{R}LEAK{NC}: {v!r}")
            for v in r["fp"][:3]:
                _info(f"{Y}FP{NC}:   {v!r}")

    return rate, total_caught, total_must


# ── Regex pattern analysis ────────────────────────────────────────────────────

def _classify_leak(value: str) -> str:
    """Guess why the regex missed this value."""
    import re
    if re.match(r'^\$krb5(tgs|asrep)\$', value):
        return "kerberos_ticket_hash"
    if re.match(r'^[a-fA-F0-9]{40}$', value):
        return "sha1_hash"
    if re.match(r'^[a-fA-F0-9]{32}$', value):
        return "md5_hash"
    if re.match(r'^[a-fA-F0-9]{64}$', value):
        return "sha256_hash"
    if re.match(r'^[0-9a-fA-F]{16}$', value):
        return "challenge_response_16"   # NTLM challenge/response hex
    if re.match(r'^[0-9a-fA-F]{48}$', value):
        return "ntlm_response_48"
    if re.match(r'ya29\.', value):
        return "gcp_access_token"
    if re.match(r'\d{12,15}$', value):
        return "numeric_id"
    if '@' in value and '.' in value:
        return "email_or_upn"
    if '.' in value and not value.startswith('/'):
        return "fqdn_or_domain"
    if value.startswith('/'):
        return "path"
    if re.search(r'[A-Z][a-z]', value) and ' ' in value:
        return "person_or_org_name"
    if re.match(r'^[A-Z_]+$', value):
        return "allcaps_name"
    return "other"


def _analyze_leaks(results: list[dict]) -> dict[str, list[str]]:
    """Group leaked values by classification."""
    by_class: dict[str, list[str]] = defaultdict(list)
    seen = set()
    for r in results:
        for v in r["leaked"]:
            if v not in seen:
                seen.add(v)
                cls = _classify_leak(v)
                by_class[cls].append(v)
    return dict(by_class)


# ── Auto-fix attempts ─────────────────────────────────────────────────────────

def _try_add_regex_patterns(leak_classes: dict[str, list[str]]) -> list[str]:
    """
    For each class of leaks, suggest or add regex patterns.
    Returns list of descriptions of what was done.
    """
    from src import regex_detector
    import re as re_mod
    fixes = []

    # Kerberos ticket hashes — $krb5tgs$... and $krb5asrep$...
    if "kerberos_ticket_hash" in leak_classes:
        pat_name = "HASH"
        pat = re_mod.compile(r'\$krb5(?:tgs|asrep)\$\d+\$\*?[^\$]+\$[^\$]+\$[a-fA-F0-9\$]+')
        # Check if already present
        existing = [p for _, p in regex_detector._PATTERNS
                    if r'\$krb5' in p.pattern]
        if not existing:
            regex_detector._PATTERNS.insert(3, (pat_name, pat))
            fixes.append("Added HASH pattern for Kerberos TGS/AS-REP tickets ($krb5tgs$, $krb5asrep$)")

    # NTLM challenge (16 hex chars) and response (48 hex chars) — add targeted patterns
    if "challenge_response_16" in leak_classes or "ntlm_response_48" in leak_classes:
        pat16 = re_mod.compile(r'\b[0-9a-fA-F]{16}\b')
        pat48 = re_mod.compile(r'\b[0-9a-fA-F]{48}\b')
        existing16 = any(p.pattern == r'\b[0-9a-fA-F]{16}\b'
                         for _, p in regex_detector._PATTERNS)
        existing48 = any(p.pattern == r'\b[0-9a-fA-F]{48}\b'
                         for _, p in regex_detector._PATTERNS)
        if not existing16:
            # Insert after existing 32-char MD5 pattern
            for i, (et, _) in enumerate(regex_detector._PATTERNS):
                if r'[a-fA-F0-9]{32}' in regex_detector._PATTERNS[i][1].pattern:
                    regex_detector._PATTERNS.insert(i + 1, ("HASH", pat16))
                    fixes.append("Added HASH pattern for 16-char NTLM challenge hex")
                    break
        if not existing48:
            for i, (et, _) in enumerate(regex_detector._PATTERNS):
                if r'[a-fA-F0-9]{32}' in regex_detector._PATTERNS[i][1].pattern:
                    regex_detector._PATTERNS.insert(i + 1, ("HASH", pat48))
                    fixes.append("Added HASH pattern for 48-char NTLM response hex")
                    break

    # GCP OAuth tokens (ya29.*)
    if "gcp_access_token" in leak_classes:
        pat = re_mod.compile(r'\bya29\.[A-Za-z0-9_\-\.]{20,}')
        existing = any(r'ya29' in p.pattern for _, p in regex_detector._PATTERNS)
        if not existing:
            # Insert near other TOKEN patterns
            for i, (et, _) in enumerate(regex_detector._PATTERNS):
                if et == "TOKEN" and "SG\\." in regex_detector._PATTERNS[i][1].pattern:
                    regex_detector._PATTERNS.insert(i + 1, ("TOKEN", pat))
                    fixes.append("Added TOKEN pattern for GCP OAuth access tokens (ya29.*)")
                    break

    # Numeric IDs that leaked (12-15 digit numbers not caught by existing 12-digit pattern)
    if "numeric_id" in leak_classes:
        for v in leak_classes["numeric_id"]:
            if len(v) > 12:
                pat = re_mod.compile(r'\b\d{13,15}\b')
                existing = any(r'\d{13,15}' in p.pattern for _, p in regex_detector._PATTERNS)
                if not existing:
                    for i, (et, p) in enumerate(regex_detector._PATTERNS):
                        if r'\b\d{12}\b' in p.pattern:
                            regex_detector._PATTERNS.insert(i + 1, ("IDENTIFIER", pat))
                            fixes.append("Added IDENTIFIER pattern for 13-15 digit numeric IDs (GCP project numbers)")
                            break
                break

    return fixes


def _try_add_never_anonymize(results: list[dict]) -> list[str]:
    """Add safe_to_keep terms that were wrongly anonymized to _NEVER_ANONYMIZE."""
    from src.anonymizer import _NEVER_ANONYMIZE as current
    # We can't modify a frozenset; instead report what should be added
    wrong = set()
    for r in results:
        for v in r["fp"]:
            if v.lower() not in current:
                wrong.add(v.lower())
    return list(wrong)


# ── Persist fixes back to source ─────────────────────────────────────────────

def _persist_regex_patterns():
    """Write the current in-memory _PATTERNS back to regex_detector.py."""
    # This just reports — actual file edits happen in the improvement loop
    from src import regex_detector
    return len(regex_detector._PATTERNS)


# ── Main loop ─────────────────────────────────────────────────────────────────

async def main(max_cycles: int = 5, verbose: bool = False):
    from tests.fixtures import ALL_FIXTURES
    import src.config as cfg_mod
    cfg_mod.config.LLM_ENABLED = False

    print(f"\n{B}{'═'*64}{NC}")
    print(f"{B}  Auto-Improvement Cycle — Regex Layer{NC}")
    print(f"  {len(ALL_FIXTURES)} fixtures  ·  LLM disabled  ·  up to {max_cycles} cycles")
    print(f"{B}{'═'*64}{NC}")

    prev_rate = 0.0
    history: list[tuple[str, float]] = []

    for cycle in range(1, max_cycles + 1):
        print(f"\n{B}▸ CYCLE {cycle}{NC}")
        results = await run_all(ALL_FIXTURES)
        rate, caught, total = print_round(results, f"Cycle {cycle} — regex only")
        history.append((f"cycle-{cycle}", rate))

        leak_classes = _analyze_leaks(results)
        if not any(r["leaked"] for r in results):
            _ok("No leaks found — regex layer is clean.")
            _warn("Next step: add new pentest scenario fixtures to tests/fixtures.py, then re-run.")
            continue   # don't break — outer caller may add more fixtures and re-invoke

        # Show leak classification
        print(f"\n  Leak classification:")
        for cls, vals in sorted(leak_classes.items()):
            print(f"    {Y}{cls:<30}{NC} ({len(vals)}x): {', '.join(repr(v[:30]) for v in vals[:3])}")

        # Try auto-fixes
        fixes = _try_add_regex_patterns(leak_classes)
        missing_never = _try_add_never_anonymize(results)

        if fixes:
            print(f"\n  {G}Auto-fixes applied this cycle:{NC}")
            for f in fixes:
                _ok(f)
        if missing_never:
            print(f"\n  {Y}False positives to add to _NEVER_ANONYMIZE:{NC}")
            for v in missing_never[:10]:
                _info(f"+ {v!r}")

        if not fixes and not missing_never:
            _warn("No automatic fix available for remaining leaks (need LLM or manual regex).")
            break

        delta = rate - prev_rate
        if cycle > 1:
            sign = "+" if delta >= 0 else ""
            col  = G if delta > 0 else (R if delta < 0 else NC)
            print(f"\n  Δ from previous cycle: {col}{sign}{delta*100:.1f}pp{NC}")
        prev_rate = rate

    # Final summary
    print(f"\n{B}{'═'*64}{NC}")
    print(f"{B}  SUMMARY{NC}")
    for label, r in history:
        col = G if r >= 0.95 else (Y if r >= 0.80 else R)
        print(f"  {label:<20} {col}{r*100:.1f}%{NC}")
    if len(history) >= 2:
        delta = history[-1][1] - history[0][1]
        sign  = "+" if delta >= 0 else ""
        col   = G if delta > 0 else R
        print(f"\n  Total improvement: {col}{sign}{delta*100:.1f}pp{NC}")
    print(f"{B}{'═'*64}{NC}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cycles", type=int, default=5)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    asyncio.run(main(max_cycles=args.cycles, verbose=args.verbose))
