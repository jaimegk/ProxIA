# DontFeedTheAI

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License">
  <img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/LLM-Ollama-green.svg" alt="Ollama">
  <img src="https://img.shields.io/badge/proxy-FastAPI-009688.svg" alt="FastAPI">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg" alt="Platform">
</p>

A transparent proxy that strips IPs, credentials, hostnames, and PII from every request before it reaches the AI — and restores them on the way back.

```mermaid
flowchart TD
    shell["🖥️ Your Shell\nnmap -sV dc01.acmecorp.local"]
    proxy["🛡️ DontFeedTheAI\ndc01.acmecorp.local → srv-0042.pentest.local\n10.20.0.10 → 203.0.113.47\nAdmin@Acme2024! → [CRED_XK9A2B3C]"]
    api["☁️ Anthropic API\nsees only\nsrv-0042.pentest.local\n203.0.113.47"]

    shell -- "① real data" --> proxy
    proxy -- "② surrogates only" --> api
    api -- "③ response + surrogates" --> proxy
    proxy -- "④ real data restored" --> shell
```

| Layer | Detects |
|---|---|
| 🧠 **Ollama (local LLM)** | hostnames, org names, credentials in prose |
| 🔍 **Regex** | IPs, hashes, tokens, API keys |

Both run on your machine. Nothing sensitive crosses the boundary.

### Cloud anonymization APIs exist
but they mean a second bill and a second third party with your data.

You're already paying Claude for reasoning. 

The AI doesn't need your real data for that — only the structure and meaning of your questions.

---

| Who | How it helps |
|-----|-------------|
| **Pentesters** | Run nmap, mimikatz, bloodhound output through Claude without exposing client infrastructure |
| **Developers & SREs** | Debug with production data or internal configs in regulated environments |
| **Legal & consulting** | Anonymize client contracts, case files, or proprietary IP in AI-assisted reviews |
| **Finance & compliance** | Analyze reports or audit scripts without exposing account details |
| **Researchers** | Query LLMs on confidential datasets |

---

## Why not just Ollama or Claude directly?

**❌ Cloud anonymization API + Claude** — two bills, two third parties. Your sensitive data still leaves the machine, just through more hands.

```mermaid
flowchart LR
    s0["🖥️ Your Shell\nreal data"] --> a0["☁️ Anonymization API\nsees everything\nbill #1"]
    a0 --> c0["☁️ Anthropic API\nbill #2"]
```

**❌ Ollama alone** — your data never leaves the machine, but Ollama has no awareness of what's sensitive.
It reasons on whatever you paste: real IPs, real credentials, real hostnames.

```mermaid
flowchart LR
    s1["🖥️ Your Shell\nreal data"] --> o1["🧠 Ollama\nno interception\nreasons on real data"]
```

**❌ Claude directly** — best reasoning quality, but everything lands in Anthropic's infrastructure.
Real client IPs, credentials, org names in their API logs — one policy change or breach away from a problem.

```mermaid
flowchart LR
    s2["🖥️ Your Shell\nreal data"] --> c1["☁️ Anthropic API\nsees everything\nlogs your real data"]
```

**✅ DontFeedTheAI** — Claude's reasoning, Ollama's local detection, nothing sensitive crosses the boundary.

```mermaid
flowchart LR
    s3["🖥️ Your Shell\nreal data"] --> p["🛡️ DontFeedTheAI"]
    o2["🧠 Ollama\nlocal detector\nnever leaves machine"] --> p
    p --> c2["☁️ Anthropic API\nsees only surrogates"]
```

→ See [docs/architecture.md](docs/architecture.md) for the full technical breakdown.

---

## Quick Start

```bash
git clone https://github.com/zeroc00I/DontFeedTheAI
cd DontFeedTheAI
pip install -r requirements.txt
python3 wizard.py
```

The wizard asks everything — engagement name, where to run it, VPS address, model — then deploys, opens the tunnel, and launches Claude with the proxy active. Works on Windows, macOS, and Linux.

```bash
python3 wizard.py --help   # all available commands
```

---

## Docs

| Doc | About |
|--|--|
| [Architecture](docs/architecture.md) | Two-layer pipeline, what gets anonymized and what doesn't, config reference |
| [Contributing](docs/contributing.md) | How to add fixtures, run the improvement loop, open areas |
| [Threat Model](docs/threat-model.md) | What this protects against, what it doesn't, limitations, roadmap |

---

## Verifying coverage & contributing improvements

Two tools ship with DontFeedTheAI to help you validate coverage and extend it.

**Visual audit** — open in browser while the proxy is running:

```bash
python3 wizard.py tunnel --audit
```

Shows every `ORIGINAL → SURROGATE` mapping logged during the session, filterable by entity type (DOMAIN, CREDENTIAL, TOKEN, HASH…) with per-request timing breakdown. Use it to spot leaks at a glance instead of grepping logs.

![audit dashboard](docs/audit-screenshot.png)

> The audit page is a **debug tool**. It exposes the full surrogate → original lookup table, which is why it only runs behind the SSH tunnel. Making this write-only (no reverse lookup over HTTP) is on the roadmap — see [Threat Model](docs/threat-model.md).

**Testing the full pipeline** — requires Ollama running:

```bash
python3 wizard.py test --integration
```

Runs all 53 fixtures through the complete pipeline (LLM + regex) and asserts zero leaks. Without `--integration`, the LLM is mocked and only the regex layer is validated — useful for fast iteration but not a substitute for the full run.

**Auto-improvement loop** — regex layer only, no Ollama required:

```bash
python3 wizard.py improve --cycles 3
```

Runs all fixtures through the regex layer, reports leaks and false positives, and tells you exactly which strings slipped through. The contribution cycle is: add a fixture for a real tool you use → run the loop → add a regex pattern for each leak → repeat. See [Contributing](docs/contributing.md).

The two commands complement each other: `improve` tightens the regex floor fast; `test --integration` confirms the full pipeline holds.

---

## A note from the author

> I'm a pentester, not a software architect.
>
> This wasn't built to be innovative — there are already cloud APIs that do LLM-based anonymization. But that means sending your data to yet another third party, and I refuse. If you work in security, you already know why.
>
> I built this so the architecture would be available to everyone, and so the community could help expand its effectiveness for free. You're paying for context processing — the AI doesn't need your real data for that.
>
> — *zeroc00I*

---

## License

[MIT](LICENSE)
