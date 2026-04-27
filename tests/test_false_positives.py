"""
Automated false-positive tests for the anonymization pipeline.

Verifies that common English/Portuguese words, protocol names, tool names,
and generic technical terms are NEVER anonymized — regardless of LLM output.

All tests run with LLM mocked to return a controlled entity list so we can
test the post-processing filters in isolation, without requiring Ollama.
"""
import asyncio
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from src.llm_detector import LLMMatch
from src.vault import init_db, get_or_create, get_all_mappings


# ── Helpers ────────────────────────────────────────────────────────────────────

def _run(coro):
    return asyncio.run(coro)


async def _anonymize_with_llm(text: str, llm_entities: list[tuple[str, str]]) -> str:
    """Run anonymize() with LLM mocked to return a specific entity list."""
    matches = [LLMMatch(text=t, entity_type=et) for t, et in llm_entities]
    with tempfile.TemporaryDirectory(prefix="fp_test_") as tmpdir:
        db_path = Path(tmpdir) / "vault.db"
        init_db(db_path)
        with (
            patch("src.llm_detector.detect", new_callable=AsyncMock, return_value=matches),
            patch("src.anonymizer._text_needs_llm", return_value=True),
            patch("src.vault.config") as cfg,
            patch("src.anonymizer.get_or_create") as mock_goc,
            patch("src.anonymizer.get_all_mappings") as mock_gam,
            patch("src.anonymizer._verifier.record_traffic"),
        ):
            cfg.ENGAGEMENT_ID = "fp-test"
            cfg.DATABASE_PATH = db_path
            mock_goc.side_effect = lambda o, t, fn: get_or_create(
                o, t, fn, engagement="fp-test", db_path=db_path
            )
            mock_gam.side_effect = lambda: get_all_mappings(
                engagement="fp-test", db_path=db_path
            )
            from src.anonymizer import anonymize
            return await anonymize(text, is_tool_output=True)


# ── Common-word false-positive tests ──────────────────────────────────────────

COMMON_ENGLISH_WORDS = [
    "mapping", "output", "scanning", "running", "enabled", "disabled",
    "target", "source", "interface", "connection", "session", "process",
    "service", "server", "client", "network", "address", "status",
    "version", "system", "config", "setup", "install", "update",
    "active", "inactive", "online", "offline", "success", "failure",
    "error", "warning", "debug", "verbose", "protocol", "packet",
    "buffer", "memory", "storage", "resource", "policy", "filter",
    "handler", "worker", "manager", "controller", "listener",
]

COMMON_PORTUGUESE_WORDS = [
    "mapeamento", "servidor", "sistema", "rede", "senha", "conexão",
    "usuário", "processo", "serviço", "configuração", "versão",
    "resultado", "entrada", "saída", "origem", "destino", "ativo",
    "inativo", "habilitado", "desabilitado", "sucesso", "falha",
    "erro", "aviso", "depuração",
]


@pytest.mark.parametrize("word", COMMON_ENGLISH_WORDS)
def test_common_english_word_not_anonymized_as_other(word: str):
    """Common English words flagged as OTHER by LLM must be filtered out."""
    text = f"The {word} is running on port 443."
    result = _run(_anonymize_with_llm(text, [(word, "OTHER")]))
    assert word in result, (
        f"Common English word {word!r} was incorrectly anonymized (type=OTHER)"
    )


@pytest.mark.parametrize("word", COMMON_PORTUGUESE_WORDS)
def test_common_portuguese_word_not_anonymized_as_other(word: str):
    """Common Portuguese words flagged as OTHER by LLM must be filtered out."""
    text = f"O {word} está ativo na porta 443."
    result = _run(_anonymize_with_llm(text, [(word, "OTHER")]))
    assert word in result, (
        f"Common Portuguese word {word!r} was incorrectly anonymized (type=OTHER)"
    )


def test_common_word_not_anonymized_as_organization():
    """Single common words flagged as ORGANIZATION must be filtered."""
    for word in ["mapping", "running", "scanning", "network", "interface"]:
        text = f"Detected {word} on target host."
        result = _run(_anonymize_with_llm(text, [(word, "ORGANIZATION")]))
        assert word in result, (
            f"Common word {word!r} was incorrectly anonymized as ORGANIZATION"
        )


def test_common_word_not_anonymized_as_hostname():
    """Single common words flagged as HOSTNAME by LLM must be filtered.
    Text must not contain labeled-field prefixes (Computer:, Logon Server:)
    to avoid triggering the regex hostname patterns."""
    for word in ["mapping", "scanning", "running", "output"]:
        text = f"Connected to {word} on port 445."
        result = _run(_anonymize_with_llm(text, [(word, "HOSTNAME")]))
        assert word in result, (
            f"Common word {word!r} was incorrectly anonymized as HOSTNAME"
        )


# ── Proper entities MUST still be anonymized ──────────────────────────────────

def test_org_name_still_anonymized():
    """Rare org names must still be anonymized even with wordfreq filter active."""
    for org in ["Contoso", "Nordvento", "Helios", "Vortex", "StellarTech"]:
        text = f"Target organization: {org} Corporation."
        result = _run(_anonymize_with_llm(text, [(org, "ORGANIZATION")]))
        assert org not in result, (
            f"Org name {org!r} was NOT anonymized — wordfreq filter too aggressive"
        )


def test_person_name_still_anonymized():
    """Person names must still be anonymized (PERSON type bypasses wordfreq)."""
    text = "User: Fernanda Oliveira logged in from 10.0.0.1."
    result = _run(_anonymize_with_llm(text, [("Fernanda Oliveira", "PERSON")]))
    assert "Fernanda Oliveira" not in result, (
        "Person name 'Fernanda Oliveira' was NOT anonymized"
    )


def test_rare_single_word_org_not_filtered():
    """Rare single-word org names (zero wordfreq) must NOT be filtered."""
    for org in ["Contoso", "Nordvento", "HELIOS", "Vortex"]:
        text = f"Domain: {org}"
        result = _run(_anonymize_with_llm(text, [(org, "ORGANIZATION")]))
        assert org not in result, (
            f"Rare org {org!r} was incorrectly kept by wordfreq filter"
        )


# ── Tool names must never be anonymized ──────────────────────────────────────

TOOL_NAMES = [
    "nmap", "mimikatz", "metasploit", "bloodhound", "hashcat",
    "crackmapexec", "impacket", "responder", "certipy", "rubeus",
]


@pytest.mark.parametrize("tool", TOOL_NAMES)
def test_tool_name_not_anonymized(tool: str):
    """Security tool names must survive anonymization regardless of LLM output."""
    text = f"Running {tool} against the target host."
    result = _run(_anonymize_with_llm(text, [(tool, "ORGANIZATION")]))
    assert tool in result, (
        f"Tool name {tool!r} was incorrectly anonymized"
    )


# ── Pre-screening tests ────────────────────────────────────────────────────────

def test_prescreening_skips_llm_for_structured_data():
    """Pre-screening must skip LLM for text that is purely structured (hashes, IPs)."""
    from src.anonymizer import _text_needs_llm
    structured_texts = [
        "8846f7eaee8fb117ad06bdd830b7586c",
        "10.10.50.5:445 open smb",
        "SMB 10.0.0.1 445 [*] open",
        "PORT STATE SERVICE\n80/tcp open http",
    ]
    for text in structured_texts:
        assert not _text_needs_llm(text), (
            f"Pre-screening incorrectly marked structured text as needing LLM: {text!r}"
        )


def test_prescreening_calls_llm_for_contextual_data():
    """Pre-screening must trigger LLM when proper nouns or usernames are present."""
    from src.anonymizer import _text_needs_llm
    contextual_texts = [
        "Domain: CONTOSO  Logon Server: DC01",
        "john.smith logged in from 10.0.0.5",
        "Target: Nordvento Corporation",
        "WORKGROUP: HELIOS",
    ]
    for text in contextual_texts:
        assert _text_needs_llm(text), (
            f"Pre-screening incorrectly skipped LLM for contextual text: {text!r}"
        )


# ── Regression: known production FPs ──────────────────────────────────────────

def test_regression_mapping_not_anonymized():
    """Regression: 'mapping' reported as production FP must never be anonymized."""
    text = "Port mapping complete: 80/tcp open http, 443/tcp open https."
    result = _run(_anonymize_with_llm(text, [("mapping", "OTHER")]))
    assert "mapping" in result


def test_regression_output_not_anonymized():
    """Regression: 'output' must never be anonymized."""
    text = "Scan output saved to /tmp/results.txt"
    result = _run(_anonymize_with_llm(text, [("output", "OTHER")]))
    assert "output" in result
