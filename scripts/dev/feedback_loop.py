#!/usr/bin/env python3
"""
scripts/feedback_loop.py — Anonymization quality feedback loop.

Self-evaluation cycle:

  Round 1  — runs all fixtures against the current prompt
             • scores ground truth (must_anonymize that survived = leak)
             • calls Ollama as an adversarial judge on each anonymized output
  If leaks: asks Ollama to improve the _SYSTEM_PROMPT based on the errors
             → Round 2 with the improved prompt
  Report   — catch rate delta between rounds, suggestion saved to data/

Usage:
    cd /path/to/pentest-proxy
    source .venv/bin/activate
    python -m scripts.feedback_loop [--rounds N] [--no-judge] [--no-improve]
"""
from __future__ import annotations

import argparse
import asyncio
import importlib
import json
import logging
import re
import sqlite3
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx

# ── project root on path ─────────────────────────────────────────────────────
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from tests.fixtures import ALL_FIXTURES, PentestFixture

# ── logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.WARNING,          # suppress proxy noise during tests
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
log = logging.getLogger("feedback-loop")

# ── terminal colours ──────────────────────────────────────────────────────────
R  = "\033[0;31m"   # red
G  = "\033[0;32m"   # green
Y  = "\033[1;33m"   # yellow
C  = "\033[0;36m"   # cyan
B  = "\033[1m"      # bold
NC = "\033[0m"      # reset

def _hr(char="─", width=62):
    return char * width

def _banner(msg: str):
    print(f"\n{B}{_hr('═')}{NC}")
    print(f"{B}  {msg}{NC}")
    print(f"{B}{_hr('═')}{NC}")

def _section(msg: str):
    print(f"\n{B}▸ {msg}{NC}")

def _ok(msg: str):
    print(f"  {G}✓{NC} {msg}")

def _warn(msg: str):
    print(f"  {Y}⚠{NC} {msg}")

def _err(msg: str):
    print(f"  {R}✗{NC} {msg}")

def _info(msg: str):
    print(f"    {msg}")


# ── Ollama helpers ────────────────────────────────────────────────────────────

import os
OLLAMA_HOST  = os.getenv("OLLAMA_HOST",  "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3:1.7b")

# JUDGE prompt: acts as an adversary trying to re-identify the target
_JUDGE_PROMPT = """\
You are a red-team reviewer. You received a text that was processed by an
anonymization system meant to hide all information identifying the real target
organisation, its users, and its infrastructure.

Your task: find any value in the text below that STILL reveals the real target.

SURROGATES already in use (do NOT flag these — they are synthetic replacements):
  - IPs in ranges 10.200.x.x / 10.201.x.x / 172.28.x.x → already replaced
  - Domains ending .pentest.local → already replaced
  - Emails ending @example.pentest → already replaced
  - Tokens like [CRED_XXXXXXXX], [TOKEN_XXX], [REDACTED_XXX] → already replaced
  - Usernames like user_xxxx → already replaced
  - Hostnames like srv-NNNN, host-NNNN → already replaced

FLAG if you see:
  - A real company or organisation name
  - A real person name (not user_xxxx format)
  - A real IP address NOT in the surrogate ranges above
  - A real domain (not .pentest.local)
  - A real credential, password, hash, or token
  - Any value that uniquely identifies the real engagement target

Return ONLY valid JSON, no explanation, no markdown:
{"leaked": [{"text": "<exact substring from the text>", "concern": "<why sensitive>"}]}

If nothing real leaked: {"leaked": []}
"""

# IMPROVER prompt: receives the current prompt + errors and generates an improved version
_IMPROVER_PROMPT_TPL = """\
You are improving a PII / sensitive-data detection system prompt used inside a
penetration testing anonymization proxy. The prompt instructs a local LLM to
identify sensitive values in raw tool output (nmap, mimikatz, CrackMapExec, etc.)
so they can be replaced with synthetic surrogates.

CURRENT SYSTEM PROMPT:
---
{current_prompt}
---

During automated testing, the following sensitive values WERE NOT caught:
{missed_list}

These came from realistic pentest tool outputs. For each missed value, consider:
  • Why might the current prompt fail to flag it?
  • Is the entity type missing from the FLAG list?
  • Is the pattern too context-specific for the LLM to recognise?

Write an IMPROVED system prompt that would catch all of these. Preserve every
existing rule. Add or clarify only what is needed to cover the gaps.

Return ONLY the improved system prompt, no explanation, no markdown, no fences.
"""


def _strip_think(text: str) -> str:
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


def _extract_json(raw: str) -> dict:
    cleaned = _strip_think(raw)
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, re.DOTALL)
    if m:
        cleaned = m.group(1)
    else:
        m = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if m:
            cleaned = m.group(0)
    try:
        return json.loads(cleaned)
    except Exception:
        return {}


async def _ollama_chat(messages: list[dict], timeout: int = 90) -> str:
    """Call Ollama /api/chat, return content string. Empty string on error."""
    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            resp = await client.post(
                f"{OLLAMA_HOST}/api/chat",
                json={
                    "model": OLLAMA_MODEL,
                    "messages": messages,
                    "stream": False,
                    "format": "json",
                    "options": {"temperature": 0, "think": False},
                },
            )
            resp.raise_for_status()
            return resp.json().get("message", {}).get("content", "")
        except Exception as exc:
            log.debug(f"Ollama call failed: {exc}")
            return ""


async def judge_text(anonymized: str) -> list[dict]:
    """
    Ask the Ollama judge whether any real sensitive data survived in the
    anonymized text. Returns list of {text, concern} dicts.
    """
    raw = await _ollama_chat([
        {"role": "system", "content": _JUDGE_PROMPT},
        {"role": "user",   "content": anonymized},
    ])
    if not raw:
        return []
    data = _extract_json(raw)
    return [
        item for item in data.get("leaked", [])
        if isinstance(item, dict) and item.get("text", "").strip()
    ]


async def ask_improver(current_prompt: str, missed: list[str]) -> str:
    """
    Ask Ollama to produce an improved _SYSTEM_PROMPT given the list of
    values that were missed. Returns the improved prompt string.
    """
    if not missed:
        return current_prompt

    missed_list = "\n".join(f"  • {v}" for v in missed)
    user_msg = _IMPROVER_PROMPT_TPL.format(
        current_prompt=current_prompt,
        missed_list=missed_list,
    )
    # IMPORTANT: no "format": "json" here — improver returns plain text
    async with httpx.AsyncClient(timeout=120) as client:
        try:
            resp = await client.post(
                f"{OLLAMA_HOST}/api/chat",
                json={
                    "model": OLLAMA_MODEL,
                    "messages": [{"role": "user", "content": user_msg}],
                    "stream": False,
                    "options": {"temperature": 0, "think": False},
                },
            )
            resp.raise_for_status()
            raw = resp.json().get("message", {}).get("content", "")
        except Exception as exc:
            log.debug(f"Improver Ollama call failed: {exc}")
            return current_prompt

    improved = _strip_think(raw).strip()
    # Sanity check: must look like a system prompt, not a JSON blob
    if not improved or len(improved) < 100 or improved.startswith("{"):
        log.warning("Improver returned invalid content — keeping current prompt")
        return current_prompt
    return improved


# ── Anonymizer runner ─────────────────────────────────────────────────────────

@dataclass
class FixtureResult:
    fixture:      PentestFixture
    anonymized:   str
    caught:       list[str]    = field(default_factory=list)   # must_anonymize items removed
    leaked:       list[str]    = field(default_factory=list)   # must_anonymize items still present
    fp_removed:   list[str]    = field(default_factory=list)   # safe_to_keep items wrongly removed
    judge_leaks:  list[dict]   = field(default_factory=list)   # Ollama judge findings
    elapsed_s:    float        = 0.0

    @property
    def catch_rate(self) -> float:
        total = len(self.caught) + len(self.leaked)
        return len(self.caught) / total if total else 1.0

    @property
    def fp_rate(self) -> float:
        total = len(self.fixture.safe_to_keep)
        return len(self.fp_removed) / total if total else 0.0


@dataclass
class RoundResult:
    round_num:     int
    prompt_label:  str
    fixture_results: list[FixtureResult] = field(default_factory=list)
    elapsed_s:     float = 0.0

    @property
    def total_must(self) -> int:
        return sum(len(r.caught) + len(r.leaked) for r in self.fixture_results)

    @property
    def total_caught(self) -> int:
        return sum(len(r.caught) for r in self.fixture_results)

    @property
    def total_leaked(self) -> int:
        return sum(len(r.leaked) for r in self.fixture_results)

    @property
    def catch_rate(self) -> float:
        return self.total_caught / self.total_must if self.total_must else 1.0

    @property
    def all_leaked(self) -> list[str]:
        seen = set()
        result = []
        for r in self.fixture_results:
            for v in r.leaked:
                if v not in seen:
                    seen.add(v)
                    result.append(v)
        return result

    @property
    def judge_leak_count(self) -> int:
        return sum(len(r.judge_leaks) for r in self.fixture_results)


_SYSTEM_PROMPT_FILE = ROOT / "data" / "system_prompt.txt"


def _patch_llm_detector(new_prompt: str):
    """Replace _SYSTEM_PROMPT in the already-imported llm_detector module."""
    import src.llm_detector as mod
    mod._SYSTEM_PROMPT = new_prompt
    # Also patch the cache so get_system_prompt() returns the new value immediately
    mod._prompt_cache["text"] = new_prompt
    mod._prompt_cache["checked_at"] = float("inf")  # skip disk re-read during tests


def _apply_prompt(prompt: str) -> Path:
    """Write an improved prompt to data/system_prompt.txt for hot-reload by the proxy."""
    _SYSTEM_PROMPT_FILE.parent.mkdir(parents=True, exist_ok=True)
    _SYSTEM_PROMPT_FILE.write_text(prompt, encoding="utf-8")
    return _SYSTEM_PROMPT_FILE


def _load_active_prompt() -> str:
    """Return the currently active system prompt (file > hardcoded)."""
    if _SYSTEM_PROMPT_FILE.exists():
        try:
            text = _SYSTEM_PROMPT_FILE.read_text(encoding="utf-8").strip()
            if text and len(text) > 100:
                return text
        except Exception:
            pass
    import src.llm_detector as mod
    return mod._SYSTEM_PROMPT


def _failures_as_fixtures() -> tuple[list, list[int]]:
    """
    Read pending failures from data/verify.db and convert to PentestFixture objects.
    Returns (fixtures, failure_ids) — call mark_failures_used(failure_ids) after a
    successful improvement round.
    """
    sys.path.insert(0, str(ROOT))
    from src.verifier import get_pending_failures

    failures = get_pending_failures(limit=30)
    if not failures:
        return [], []

    from tests.fixtures import PentestFixture
    fixtures: list[PentestFixture] = []
    failure_ids: list[int] = []

    for f in failures:
        original = f.get("original", "")
        leaked_text = f.get("leaked_text", "")
        if not original or not leaked_text:
            continue
        fixture = PentestFixture(
            name=f"traffic-failure-{f['id']}",
            text=original,
            must_anonymize=[leaked_text],
            safe_to_keep=[],
        )
        fixtures.append(fixture)
        failure_ids.append(f["id"])

    return fixtures, failure_ids


async def _run_fixture(
    fixture: PentestFixture,
    db_path: Path,
    engagement: str,
    use_judge: bool,
) -> FixtureResult:
    """Anonymize one fixture, score it, optionally judge the output."""
    # Import fresh (module may have been patched between rounds)
    import src.anonymizer as anon_mod
    import src.vault as vault_mod

    t0 = time.perf_counter()

    # Monkeypatch vault to use isolated test DB
    original_engagement = vault_mod.config.ENGAGEMENT_ID
    original_db_path    = vault_mod.config.DATABASE_PATH
    vault_mod.config.ENGAGEMENT_ID = engagement
    vault_mod.config.DATABASE_PATH = db_path

    try:
        anonymized = await anon_mod.anonymize(fixture.text, is_tool_output=True)
    finally:
        vault_mod.config.ENGAGEMENT_ID = original_engagement
        vault_mod.config.DATABASE_PATH = original_db_path

    elapsed = time.perf_counter() - t0

    # Score ground truth
    caught   = [v for v in fixture.must_anonymize if v not in anonymized]
    leaked   = [v for v in fixture.must_anonymize if v in anonymized]
    fp_removed = [v for v in fixture.safe_to_keep if v not in anonymized]

    # Optional Ollama judge
    judge_leaks: list[dict] = []
    if use_judge and anonymized.strip():
        judge_leaks = await judge_text(anonymized)

    return FixtureResult(
        fixture=fixture,
        anonymized=anonymized,
        caught=caught,
        leaked=leaked,
        fp_removed=fp_removed,
        judge_leaks=judge_leaks,
        elapsed_s=elapsed,
    )


async def run_round(
    round_num: int,
    prompt_label: str,
    fixtures: list[PentestFixture],
    use_judge: bool,
) -> RoundResult:
    """Run all fixtures for one round, sequentially (vault is not thread-safe)."""
    with tempfile.TemporaryDirectory(prefix="pproxy_test_") as tmpdir:
        db_path = Path(tmpdir) / "vault.db"
        engagement = f"test-round-{round_num}"

        from src.vault import init_db
        init_db(db_path)

        t0 = time.perf_counter()
        results: list[FixtureResult] = []
        for fx in fixtures:
            fr = await _run_fixture(fx, db_path, engagement, use_judge)
            results.append(fr)

        return RoundResult(
            round_num=round_num,
            prompt_label=prompt_label,
            fixture_results=results,
            elapsed_s=time.perf_counter() - t0,
        )


# ── Reporting ─────────────────────────────────────────────────────────────────

def _pct(value: float, width: int = 5) -> str:
    s = f"{value*100:.1f}%"
    return s.rjust(width)


def print_round(rr: RoundResult):
    _section(f"ROUND {rr.round_num}  [{rr.prompt_label}]")
    print(f"  {'Fixture':<30} {'Caught':>8}  {'Leaked':>8}  {'FP':>4}  {'Judge':>6}")
    print(f"  {_hr('-', 60)}")

    for fr in rr.fixture_results:
        total = len(fr.caught) + len(fr.leaked)
        caught_str = f"{len(fr.caught)}/{total}"
        pct_str    = _pct(fr.catch_rate)
        leaked_str = str(len(fr.leaked)) if fr.leaked else "-"
        fp_str     = str(len(fr.fp_removed)) if fr.fp_removed else "-"
        judge_str  = f"{len(fr.judge_leaks)}!" if fr.judge_leaks else "-"

        colour = G if not fr.leaked else (Y if fr.catch_rate >= 0.8 else R)
        print(f"  {fr.fixture.name:<30} {caught_str:>8} {colour}{pct_str}{NC}  "
              f"{leaked_str:>8}  {fp_str:>4}  {judge_str:>6}")

        if fr.leaked:
            for v in fr.leaked[:4]:
                _info(f"{R}LEAK{NC}: {v!r}")
            if len(fr.leaked) > 4:
                _info(f"  … +{len(fr.leaked)-4} more")

        if fr.judge_leaks:
            for jl in fr.judge_leaks[:3]:
                _info(f"{Y}JUDGE{NC}: {jl.get('text','')!r} — {jl.get('concern','')}")
            if len(fr.judge_leaks) > 3:
                _info(f"  … +{len(fr.judge_leaks)-3} more")

    print(f"  {_hr('-', 60)}")
    colour = G if rr.catch_rate >= 0.95 else (Y if rr.catch_rate >= 0.80 else R)
    print(f"  Overall catch rate : {colour}{_pct(rr.catch_rate)}{NC}  "
          f"({rr.total_caught}/{rr.total_must} entities)")
    print(f"  Judge extra leaks  : {rr.judge_leak_count}")
    print(f"  Wall time          : {rr.elapsed_s:.1f}s")


def print_summary(rounds: list[RoundResult], improved_prompt_path: Optional[Path]):
    _banner("SUMMARY")

    for rr in rounds:
        colour = G if rr.catch_rate >= 0.95 else (Y if rr.catch_rate >= 0.80 else R)
        print(f"  Round {rr.round_num}  [{rr.prompt_label:<20}]  "
              f"{colour}{_pct(rr.catch_rate)}{NC}  "
              f"({rr.total_caught}/{rr.total_must})")

    if len(rounds) >= 2:
        delta = rounds[-1].catch_rate - rounds[0].catch_rate
        sign  = "+" if delta >= 0 else ""
        colour = G if delta > 0 else (R if delta < 0 else NC)
        print(f"\n  Improvement: {colour}{sign}{delta*100:.1f}pp{NC}")

    if improved_prompt_path and improved_prompt_path.exists():
        print(f"\n  Improved prompt saved: {C}{improved_prompt_path}{NC}")
        print(f"  To apply permanently, replace _SYSTEM_PROMPT in src/llm_detector.py")

    print()


# ── Main ──────────────────────────────────────────────────────────────────────

async def _one_cycle(
    cycle_num:    int,
    max_rounds:   int,
    use_judge:    bool,
    use_improve:  bool,
    auto_apply:   bool,
    from_failures:bool,
) -> tuple[list[RoundResult], Optional[Path]]:
    """
    Run one full improvement cycle (baseline + up to max_rounds of improvement).
    Returns (rounds, improved_prompt_path).
    """
    # ── Choose test fixtures for this cycle ───────────────────────────────────
    failure_ids: list[int] = []
    if from_failures:
        fixtures, failure_ids = _failures_as_fixtures()
        if not fixtures:
            _warn("No pending failures in data/verify.db — falling back to static fixtures.")
            fixtures = ALL_FIXTURES
        else:
            _ok(f"Using {len(fixtures)} real-traffic failure cases from verify.db")
            # Also include static fixtures to avoid regression
            fixtures = fixtures + list(ALL_FIXTURES)
    else:
        fixtures = ALL_FIXTURES

    _section(f"Fixtures: {len(fixtures)} test cases")
    for fx in fixtures[:20]:
        _info(f"{fx.name:<36} {len(fx.must_anonymize):>2} must-anon  "
              f"{len(fx.safe_to_keep):>2} safe-keep")
    if len(fixtures) > 20:
        _info(f"  … +{len(fixtures)-20} more")

    current_prompt = _load_active_prompt()
    rounds: list[RoundResult] = []
    improved_prompt_path: Optional[Path] = None

    for round_num in range(1, max_rounds + 1):
        label = "baseline" if round_num == 1 else f"improved-r{round_num-1}"
        print(f"\n{B}{_hr()}{NC}")
        _info(f"Cycle {cycle_num}  Round {round_num} ({label})…")

        _patch_llm_detector(current_prompt)

        rr = await run_round(round_num, label, fixtures, use_judge)
        rounds.append(rr)
        print_round(rr)

        if rr.catch_rate >= 1.0:
            _ok("100% catch rate — stopping early.")
            break

        if round_num == max_rounds or not use_improve:
            break

        # ── Gather missed entities ────────────────────────────────────────────
        all_missed = rr.all_leaked
        for fr in rr.fixture_results:
            for jl in fr.judge_leaks:
                t = jl.get("text", "").strip()
                if t and t not in all_missed and t in fr.fixture.text:
                    all_missed.append(t)
        all_missed = list(dict.fromkeys(all_missed))

        if not all_missed:
            _ok("No missed entities — no prompt improvement needed.")
            break

        _section(f"Asking Ollama to improve prompt ({len(all_missed)} missed entities)…")
        for v in all_missed[:10]:
            _info(f"• {v!r}")
        if len(all_missed) > 10:
            _info(f"  … +{len(all_missed)-10} more")

        improved = await ask_improver(current_prompt, all_missed)
        if improved == current_prompt:
            _warn("Improver returned unchanged prompt — stopping.")
            break

        # Save versioned copy
        out_dir = ROOT / "data"
        out_dir.mkdir(exist_ok=True)
        improved_prompt_path = out_dir / f"improved_prompt_c{cycle_num}_r{round_num}.txt"
        improved_prompt_path.write_text(improved, encoding="utf-8")
        _ok(f"Improved prompt saved → {improved_prompt_path.relative_to(ROOT)}")

        # ── Auto-apply: write to data/system_prompt.txt if score improved ────
        if auto_apply and rounds:
            prev_rate = rounds[0].catch_rate
            # Quick test with the new prompt
            _patch_llm_detector(improved)
            test_rr = await run_round(round_num + 1, "test-improved", fixtures, use_judge=False)
            if test_rr.catch_rate >= prev_rate:
                applied_path = _apply_prompt(improved)
                _ok(f"{G}Auto-applied improved prompt → {applied_path.relative_to(ROOT)}{NC}")
                _ok(f"Proxy will pick it up within {60}s (hot-reload TTL)")
                improved_prompt_path = applied_path
                # Mark real-traffic failures as consumed
                if failure_ids:
                    from src.verifier import mark_failures_used
                    mark_failures_used(failure_ids)
                    _ok(f"Marked {len(failure_ids)} failure records as used")
            else:
                _warn(f"New prompt scored {test_rr.catch_rate*100:.1f}% vs "
                      f"{prev_rate*100:.1f}% baseline — NOT auto-applied (no regression).")
            rounds.append(test_rr)

        current_prompt = improved

    return rounds, improved_prompt_path


async def _wait_until_idle(proxy_url: str, idle_minutes: int) -> None:
    """
    Block until the proxy has been idle (no /v1/messages requests) for at least
    idle_minutes. Polls every 60s and prints a status line each time it waits.
    """
    threshold = idle_minutes * 60
    poll_interval = 60  # check every minute

    while True:
        idle_seconds: float | None = None
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(f"{proxy_url}/last-activity")
                if r.status_code == 200:
                    data = r.json()
                    idle_seconds = data.get("idle_seconds")
        except Exception:
            pass  # proxy unreachable → assume idle

        if idle_seconds is None:
            # No request ever made — treat as if a request just happened (0s idle)
            # so the improver waits a full idle window before its first cycle.
            idle_seconds = 0

        if idle_seconds >= threshold:
            _ok(f"Proxy idle for {idle_seconds:.0f}s (≥ {threshold}s) — starting cycle.")
            return

        remaining = threshold - idle_seconds
        _info(
            f"Proxy was active {idle_seconds:.0f}s ago — "
            f"waiting {remaining:.0f}s more before starting cycle…"
        )
        try:
            await asyncio.sleep(min(poll_interval, remaining + 5))
        except asyncio.CancelledError:
            return


async def main(
    max_rounds:    int  = 2,
    use_judge:     bool = True,
    use_improve:   bool = True,
    auto_apply:    bool = False,
    from_failures: bool = False,
    continuous:    bool = False,
    idle_minutes:  int  = 30,
    proxy_url:     str  = "",
) -> None:
    _banner("PenTest Proxy — Anonymization Feedback Loop")

    # ── Check Ollama ──────────────────────────────────────────────────────────
    _section("Checking Ollama...")
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(f"{OLLAMA_HOST}/api/tags")
            r.raise_for_status()
        _ok(f"Ollama reachable at {OLLAMA_HOST}")
    except Exception:
        _warn("Ollama not reachable — LLM layer disabled.")
        _warn("Start Ollama and re-run for full evaluation.")
        use_judge   = False
        use_improve = False

    import src.config as cfg_mod
    # Sync Ollama settings from env vars so the in-process detector uses the
    # same host/model as the feedback loop (e.g. VPS Ollama via SSH tunnel).
    cfg_mod.config.OLLAMA_HOST  = OLLAMA_HOST
    cfg_mod.config.OLLAMA_MODEL = OLLAMA_MODEL
    cfg_mod.config.LLM_ENABLED  = bool(use_judge)
    if not use_judge:
        _warn("LLM detection disabled — regex only.")

    if auto_apply:
        _ok(f"Auto-apply ON — improvements written to data/system_prompt.txt")
    if from_failures:
        _ok("From-failures mode ON — will use real traffic failure cases")
    if continuous:
        _ok(f"Continuous mode ON — idle threshold: {idle_minutes} min (Ctrl+C to stop)")
    if proxy_url:
        _ok(f"Proxy activity check: {proxy_url}/last-activity")

    cycle_num = 0
    all_rounds: list[RoundResult] = []
    improved_path: Optional[Path] = None

    while True:
        # ── Wait until proxy has been idle for idle_minutes ───────────────────
        if continuous and proxy_url:
            _section(f"Waiting for proxy to be idle ≥ {idle_minutes} min…")
            await _wait_until_idle(proxy_url, idle_minutes)

        cycle_num += 1
        rounds, path = await _one_cycle(
            cycle_num=cycle_num,
            max_rounds=max_rounds,
            use_judge=use_judge,
            use_improve=use_improve,
            auto_apply=auto_apply,
            from_failures=from_failures,
        )
        all_rounds.extend(rounds)
        if path:
            improved_path = path

        print_summary(rounds, path)

        if not continuous:
            break

        # After a cycle: sleep a bit then re-check idle status
        _section(f"Cycle done. Will run again after next {idle_minutes} min idle window…")
        try:
            await asyncio.sleep(60)   # short pause, then re-enter the idle check
        except asyncio.CancelledError:
            break

        # Only continue if there are new failures (or always if using static fixtures)
        if from_failures:
            from src.verifier import get_pending_failures
            pending = get_pending_failures(limit=1)
            if not pending:
                _info("No new failures in verify.db — will keep waiting for traffic…")
                # Don't skip — the idle check will just block again

    if len(all_rounds) >= 2 and continuous:
        print_summary(all_rounds, improved_path)


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Anonymization quality feedback loop for pentest-proxy"
    )
    parser.add_argument(
        "--rounds", type=int, default=2,
        help="Max improvement rounds per cycle (default: 2)"
    )
    parser.add_argument(
        "--no-judge", action="store_true",
        help="Skip adversarial judge step"
    )
    parser.add_argument(
        "--no-improve", action="store_true",
        help="Evaluate only — no prompt improvement"
    )
    parser.add_argument(
        "--auto-apply", action="store_true",
        help="Write improved prompts to data/system_prompt.txt (proxy hot-reloads them)"
    )
    parser.add_argument(
        "--from-failures", action="store_true",
        help="Improve from real-traffic failures in data/verify.db (in addition to fixtures)"
    )
    parser.add_argument(
        "--continuous", action="store_true",
        help="Run indefinitely, cycling whenever new failures appear"
    )
    parser.add_argument(
        "--idle-minutes", type=int, default=30,
        help="Minutes of proxy inactivity required before starting a cycle (default: 30)"
    )
    parser.add_argument(
        "--proxy-url", type=str, default="http://localhost:5555",
        help="Proxy base URL for activity check (default: http://localhost:5555)"
    )
    args = parser.parse_args()

    try:
        asyncio.run(main(
            max_rounds=args.rounds,
            use_judge=not args.no_judge,
            use_improve=not args.no_improve,
            auto_apply=args.auto_apply,
            from_failures=args.from_failures,
            continuous=args.continuous,
            idle_minutes=args.idle_minutes,
            proxy_url=args.proxy_url,
        ))
    except KeyboardInterrupt:
        print(f"\n{Y}Stopped.{NC}")
