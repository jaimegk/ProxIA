# Threat Model

## What DontFeedTheAI is

A **risk-reduction layer**, not a privacy guarantee.

## What it prevents

- Claude receiving real IPs, hostnames, credentials, or org names in its context
- Those values appearing in Anthropic's logs or training pipeline

## What it does not prevent

- Correlation via query patterns
- Prompt injection embedded in tool output *(e.g. a target server returning `Ignore previous instructions...` in a banner)*
- Compromise of the proxy process itself
- **Access to `/audit` by an attacker who reaches the proxy host** — see below

## The `/audit` page

`/audit` is a **debug tool**, not an operational interface.

It shows the full transformation log: every `ORIGINAL → SURROGATE` mapping stored in the vault for the current engagement. This makes it easy to verify that anonymization worked correctly and to diagnose leaks during development.

The security implication is significant: **whoever can reach `/audit` can reverse the entire anonymization**. A single endpoint hands an attacker a complete lookup table for the session.

This is an accepted trade-off for now, because the proxy is designed to run locally or on a VPS reachable only via SSH tunnel. The tunnel is the access control.

**On the roadmap:** make the vault write-only from the outside. The audit log will remain available to the operator in-session, but the surrogate → original lookup will not be exposed over HTTP. An attacker who compromises the proxy host should not be able to undo all engagements from one URL.

## On trusting a local LLM as a security layer

The regex layer is the deterministic floor — measurable, tested, 0 false positives.
The LLM is additive: it catches what regex provably cannot (context-dependent entities).
If the LLM fails, the regex catches survive.
Coverage is not a claim — it is a test result any contributor can reproduce.

## Limitations

- **Regex cannot catch context-dependent entities.**
  Bare hostnames, org names in prose, and person names in free text require the LLM layer.
  If Ollama is unavailable, coverage drops.
- **Dense or long outputs can cause LLM misses.**
  Tune `LLM_CHUNK_SIZE` if you see leaks on large tool outputs.
- **Not a substitute for contract review.**
  Verify what your NDA and engagement contract allow before using any cloud AI on client data.

## Roadmap

- [ ] **Write-only vault** — `/audit` shows what was anonymized but the reverse lookup (surrogate → original) is never exposed over HTTP; operators export the mapping offline at session close
- [ ] Ephemeral vault — in-memory only, zero persistence after session
- [ ] Prompt injection detection — scan tool output before forwarding
- [ ] Streaming deanonymization — currently buffers full response
- [ ] Audit log export — JSONL of every entity detected per engagement
- [ ] Coverage dashboard — per-fixture catch rates over time
