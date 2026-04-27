"""
src/timing.py — Per-request performance tracking.

Each proxy request resets the ContextVar accumulators before calling into
anonymizer.py.  The anonymizer adds to them as it runs LLM and regex detection.
After the request completes, main.py reads the accumulators and records the
full timing breakdown to an in-memory ring buffer exposed on /audit.

Usage (in main.py):
    timing.reset()
    body = await _anon_request(body)
    snap = timing.snapshot()        # {llm_ms, regex_ms}
    ...
    timing.record({**snap, 'api_ms': ..., 'deanon_ms': ..., 'total_ms': ...})

Usage (in anonymizer.py):
    timing.add_llm_ms(elapsed * 1000)
    timing.add_regex_ms(elapsed * 1000)
"""
from __future__ import annotations

import time
from collections import deque
from contextvars import ContextVar

# ── Per-request accumulators (reset at the start of each proxy request) ───────
_ctx_llm_ms:   ContextVar[float] = ContextVar("llm_ms",   default=0.0)
_ctx_regex_ms: ContextVar[float] = ContextVar("regex_ms", default=0.0)


def reset() -> None:
    """Call at the start of each request to zero the accumulators."""
    _ctx_llm_ms.set(0.0)
    _ctx_regex_ms.set(0.0)


def add_llm_ms(ms: float) -> None:
    _ctx_llm_ms.set(_ctx_llm_ms.get() + ms)


def add_regex_ms(ms: float) -> None:
    _ctx_regex_ms.set(_ctx_regex_ms.get() + ms)


def snapshot() -> dict[str, float]:
    """Return current accumulated LLM + regex times (call after _anon_request)."""
    return {
        "llm_ms":   round(_ctx_llm_ms.get(), 1),
        "regex_ms": round(_ctx_regex_ms.get(), 1),
    }


# ── Ring buffer of completed request timings ──────────────────────────────────
_MAX_RECORDS = 200
_records: deque[dict] = deque(maxlen=_MAX_RECORDS)


def record(entry: dict) -> None:
    """
    Store a completed request timing record.

    Expected keys:
        ts          — ISO timestamp string
        total_ms    — wall clock from request start to response sent
        anon_ms     — total anonymization time (llm_ms + regex_ms + replace_ms)
        llm_ms      — LLM detector time
        regex_ms    — regex detector time
        api_ms      — Anthropic API round-trip
        deanon_ms   — deanonymization time
        entities    — number of entities anonymized
        model       — Anthropic model name
    """
    _records.append(entry)


def get_recent(n: int = 100) -> list[dict]:
    """Return up to n most-recent timing records (newest first)."""
    items = list(_records)
    items.reverse()
    return items[:n]
