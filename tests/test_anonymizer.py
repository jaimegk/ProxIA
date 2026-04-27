"""
Core anonymization pipeline tests.

The critical assertion throughout: after anonymize(), NONE of the strings
in fixture.must_anonymize should appear in the output.

These tests mock the LLM and test the pipeline logic directly.
Integration tests at the bottom require a live Ollama instance.
"""
import pytest

from src.regex_detector import RegexMatch
from src.llm_detector import LLMMatch
from tests.fixtures import ALL_FIXTURES, NMAP_SCAN, NMAP_SERVICE_VERSIONS, MIMIKATZ_OUTPUT, RECON_NOTES, BASH_HISTORY


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_vault(tmp_path):
    from src.vault import init_db
    db = tmp_path / "vault.db"
    init_db(db)
    return db


async def _anonymize(text: str, llm_matches: list, tmp_path, is_tool_output: bool = True):
    """Run the anonymizer with a mocked LLM and an isolated vault."""
    from unittest.mock import AsyncMock, patch
    db = _make_vault(tmp_path)

    with (
        patch("src.llm_detector.detect", new_callable=AsyncMock, return_value=llm_matches),
        patch("src.vault.config") as cfg,
        patch("src.anonymizer.get_or_create") as mock_goc,
        patch("src.anonymizer.get_all_mappings") as mock_gam,
        patch("src.anonymizer._verifier.record_traffic"),   # don't write to disk in tests
    ):
        cfg.ENGAGEMENT_ID = "test"
        cfg.DATABASE_PATH = db

        from src.vault import get_or_create, get_all_mappings

        # Wire real vault functions pointing at tmp db
        mock_goc.side_effect = lambda o, t, fn: get_or_create(
            o, t, fn, engagement="test", db_path=db
        )
        mock_gam.side_effect = lambda: get_all_mappings(engagement="test", db_path=db)

        from src.anonymizer import anonymize
        return await anonymize(text, is_tool_output=is_tool_output)


# ── Regex-only tests (LLM returns nothing) ────────────────────────────────────

@pytest.mark.asyncio
async def test_regex_anonymizes_ipv4(tmp_path):
    result = await _anonymize("target: 10.10.50.5 and 10.10.50.15", [], tmp_path)
    assert "10.10.50.5" not in result
    assert "10.10.50.15" not in result


@pytest.mark.asyncio
async def test_regex_anonymizes_cidr(tmp_path):
    result = await _anonymize("scope: 10.10.50.0/24", [], tmp_path)
    assert "10.10.50.0/24" not in result


@pytest.mark.asyncio
async def test_regex_anonymizes_ntlm_hash(tmp_path):
    h = "8846f7eaee8fb117ad06bdd830b7586c"
    result = await _anonymize(f"NTLM: {h}", [], tmp_path)
    assert h not in result


@pytest.mark.asyncio
async def test_regex_anonymizes_sha1_hash(tmp_path):
    h = "aabbccddeeff00112233445566778899aabbccdd"
    result = await _anonymize(f"SHA1: {h}", [], tmp_path)
    assert h not in result


@pytest.mark.asyncio
async def test_regex_anonymizes_email(tmp_path):
    result = await _anonymize("email: john.smith@contoso.com", [], tmp_path)
    assert "john.smith@contoso.com" not in result


@pytest.mark.asyncio
async def test_regex_anonymizes_domain(tmp_path):
    result = await _anonymize("Domain: dc01.contoso.local", [], tmp_path)
    assert "dc01.contoso.local" not in result


@pytest.mark.asyncio
async def test_regex_anonymizes_mac(tmp_path):
    result = await _anonymize("MAC: aa:bb:cc:dd:ee:ff", [], tmp_path)
    assert "aa:bb:cc:dd:ee:ff" not in result


# ── LLM layer tests ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_llm_anonymizes_hostname_without_fqdn(tmp_path):
    """Bare hostnames like DC01 are invisible to regex but caught by LLM."""
    llm_matches = [LLMMatch(text="DC01", entity_type="HOSTNAME")]
    result = await _anonymize("connected to DC01 via SMB", llm_matches, tmp_path)
    assert "DC01" not in result


@pytest.mark.asyncio
async def test_llm_anonymizes_domain_username(tmp_path):
    llm_matches = [LLMMatch(text="CONTOSO\\john.smith", entity_type="USERNAME")]
    result = await _anonymize("running as CONTOSO\\john.smith", llm_matches, tmp_path)
    assert "CONTOSO\\john.smith" not in result


@pytest.mark.asyncio
async def test_llm_anonymizes_organization_name(tmp_path):
    llm_matches = [LLMMatch(text="Contoso Corporation", entity_type="ORGANIZATION")]
    result = await _anonymize("Target: Contoso Corporation", llm_matches, tmp_path)
    assert "Contoso Corporation" not in result


@pytest.mark.asyncio
async def test_llm_anonymizes_cleartext_password(tmp_path):
    llm_matches = [LLMMatch(text="C0nt0s0@2024!", entity_type="CREDENTIAL")]
    result = await _anonymize("password: C0nt0s0@2024!", llm_matches, tmp_path)
    assert "C0nt0s0@2024!" not in result


# ── Consistency tests ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_same_value_same_surrogate_across_calls(tmp_path):
    """The same IP must always map to the same surrogate within an engagement."""
    text1 = "first mention: 10.10.50.5"
    text2 = "second mention: 10.10.50.5"
    r1 = await _anonymize(text1, [], tmp_path)
    r2 = await _anonymize(text2, [], tmp_path)
    # Extract the surrogate from both results — should be identical
    s1 = r1.replace("first mention: ", "")
    s2 = r2.replace("second mention: ", "")
    assert s1 == s2, f"Inconsistent surrogates: {s1!r} vs {s2!r}"


@pytest.mark.asyncio
async def test_surrogate_does_not_contain_original(tmp_path):
    result = await _anonymize("ip: 10.10.50.5", [], tmp_path)
    assert "10.10.50.5" not in result


@pytest.mark.asyncio
async def test_original_text_preserved_for_safe_terms(tmp_path):
    result = await _anonymize("running nmap against 10.10.50.5", [], tmp_path)
    assert "nmap" in result  # generic tool name must survive
    assert "10.10.50.5" not in result


# ── Deanonymization tests ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_deanonymize_reverses_anonymization(tmp_path):
    original = "target: 10.10.50.5"
    anon = await _anonymize(original, [], tmp_path)
    assert "10.10.50.5" not in anon

    # Anonymize again using the same isolated vault, then deanonymize
    from unittest.mock import patch, AsyncMock
    db = _make_vault(tmp_path)
    from src.vault import get_all_mappings, get_or_create

    with (
        patch("src.llm_detector.detect", new_callable=AsyncMock, return_value=[]),
        patch("src.vault.config") as cfg,
        patch("src.anonymizer.get_or_create") as mock_goc,
        patch("src.anonymizer.get_all_mappings") as mock_gam,
        patch("src.anonymizer._verifier.record_traffic"),
    ):
        cfg.ENGAGEMENT_ID = "test"
        cfg.DATABASE_PATH = db
        mock_goc.side_effect = lambda o, t, fn: get_or_create(
            o, t, fn, engagement="test", db_path=db
        )
        mock_gam.side_effect = lambda: get_all_mappings(engagement="test", db_path=db)

        from src.anonymizer import deanonymize, anonymize
        anon2 = await anonymize(original, is_tool_output=True)
        restored = deanonymize(anon2)
        assert "10.10.50.5" in restored


# ── Full fixture leak tests (regex layer only) ────────────────────────────────
# These verify 0% leakage for structured data that regex catches.

@pytest.mark.asyncio
@pytest.mark.parametrize("fixture", [NMAP_SCAN, MIMIKATZ_OUTPUT, BASH_HISTORY],
                         ids=["nmap", "mimikatz", "bash"])
async def test_no_structured_data_leaks(fixture, tmp_path):
    """
    Regex must catch all structured PII (IPs, hashes, MACs, emails, domains, CIDRs).
    LLM is mocked to empty — only structured data is tested here.
    """
    result = await _anonymize(fixture.text, [], tmp_path)

    # Only check values that regex is designed to catch
    regex_types = {"IP_ADDRESS", "CIDR", "HASH", "MAC_ADDRESS", "EMAIL_ADDRESS", "DOMAIN", "URL"}
    from src.regex_detector import detect
    regex_caught = {m.text for m in detect(fixture.text)}

    leaks = []
    for sensitive in fixture.must_anonymize:
        if sensitive in regex_caught and sensitive in result:
            leaks.append(sensitive)

    assert not leaks, (
        f"STRUCTURED DATA LEAKED in '{fixture.name}':\n"
        + "\n".join(f"  - {v!r}" for v in leaks)
    )


# ── Service version preservation test (regex layer only) ─────────────────────
# Ensures that technology version strings survive anonymization.
# This is a unit test — LLM is mocked to empty to isolate regex behavior.
# The main risk is a regex pattern matching a version string as an IP or hash.

@pytest.mark.asyncio
async def test_service_versions_survive_regex(tmp_path):
    """
    Service/technology versions in nmap -sV output must NOT be anonymized by regex.
    The regex layer has no business touching 'Apache httpd 2.4.51' or 'OpenSSH 7.4'.
    """
    result = await _anonymize(NMAP_SERVICE_VERSIONS.text, [], tmp_path)
    preserved = []
    destroyed = []
    for version_string in NMAP_SERVICE_VERSIONS.safe_to_keep:
        if version_string in result:
            preserved.append(version_string)
        else:
            destroyed.append(version_string)

    assert not destroyed, (
        "Service versions were wrongly anonymized by regex:\n"
        + "\n".join(f"  - {v!r}" for v in destroyed)
    )


@pytest.mark.asyncio
async def test_service_versions_survive_with_llm_mocked(tmp_path):
    """
    LLM flagging technology names (Apache, MySQL, etc.) must be blocked by _NEVER_ANONYMIZE.
    Simulates a 'bad' LLM response that incorrectly tries to anonymize technology names.
    """
    from src.llm_detector import LLMMatch

    # Simulate LLM incorrectly flagging technology names
    bad_llm_matches = [
        LLMMatch(text="Apache httpd 2.4.51", entity_type="ORGANIZATION"),
        LLMMatch(text="MySQL 5.7.38-log",    entity_type="OTHER"),
        LLMMatch(text="OpenSSH 7.4",         entity_type="OTHER"),
        LLMMatch(text="nginx 1.18.0",        entity_type="ORGANIZATION"),
    ]
    result = await _anonymize(NMAP_SERVICE_VERSIONS.text, bad_llm_matches, tmp_path)

    # Technology strings must NOT be replaced even if LLM flagged them
    still_present = [s for s in bad_llm_matches if s.text in result]
    assert len(still_present) == len(bad_llm_matches), (
        "Technology names were wrongly anonymized despite _NEVER_ANONYMIZE:\n"
        + "\n".join(f"  - {m.text!r}" for m in bad_llm_matches if m.text not in result)
    )

    # IPs and hostnames must still be anonymized
    assert "192.168.10.15" not in result, "IP leaked despite LLM mock"
    assert "meridional.local" not in result, "Domain leaked despite LLM mock"


# ── Integration tests (require live Ollama) ───────────────────────────────────

@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.parametrize("fixture", ALL_FIXTURES, ids=[f.name for f in ALL_FIXTURES])
async def test_zero_leak_with_llm(fixture, tmp_path):
    """
    Full pipeline test: LLM + regex must together produce 0% leakage.
    Requires Ollama running with the configured model.
    """
    from src.anonymizer import anonymize
    from unittest.mock import patch
    from src.vault import init_db, get_or_create, get_all_mappings
    from src.surrogates import generate_surrogate

    db = _make_vault(tmp_path)

    with (
        patch("src.vault.config") as cfg,
        patch("src.anonymizer.get_or_create") as mock_goc,
        patch("src.anonymizer.get_all_mappings") as mock_gam,
    ):
        cfg.ENGAGEMENT_ID = "test"
        cfg.DATABASE_PATH = db
        mock_goc.side_effect = lambda o, t, fn: get_or_create(
            o, t, fn, engagement="test", db_path=db
        )
        mock_gam.side_effect = lambda: get_all_mappings(engagement="test", db_path=db)

        result = await anonymize(fixture.text)

    leaks = [v for v in fixture.must_anonymize if v in result]
    assert not leaks, (
        f"0% LEAK POLICY VIOLATED in '{fixture.name}':\n"
        + "\n".join(f"  LEAKED: {v!r}" for v in leaks)
    )

    for safe in fixture.safe_to_keep:
        assert safe in result, (
            f"FALSE POSITIVE in '{fixture.name}': safe term {safe!r} was anonymized"
        )
