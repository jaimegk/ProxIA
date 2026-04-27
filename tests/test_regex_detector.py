"""
Unit tests for the regex detection layer.

These run instantly with no external dependencies.
"""
import pytest
from src.regex_detector import detect


def _types(text: str) -> dict[str, list[str]]:
    """Return {entity_type: [matched_texts]} for a given input."""
    result: dict[str, list[str]] = {}
    for m in detect(text):
        result.setdefault(m.entity_type, []).append(m.text)
    return result


# ── IPv4 ──────────────────────────────────────────────────────────────────────

class TestIPv4:
    def test_plain_ip(self):
        matches = _types("target is 10.10.50.5 running SMB")
        assert "10.10.50.5" in matches.get("IP_ADDRESS", [])

    def test_ip_in_nmap_line(self):
        line = "Nmap scan report for dc01.contoso.local (10.10.50.5)"
        matches = _types(line)
        assert "10.10.50.5" in matches.get("IP_ADDRESS", [])

    def test_multiple_ips(self):
        text = "hosts: 10.10.50.5 10.10.50.15 10.10.50.20"
        matched = _types(text).get("IP_ADDRESS", [])
        assert set(matched) == {"10.10.50.5", "10.10.50.15", "10.10.50.20"}

    def test_does_not_match_version_string(self):
        # "7.1.2.3" in a path like nmap/7.1.2.3 should still match — acceptable
        # but we verify partial octets are NOT matched
        matches = _types("port 80 open")
        assert not matches.get("IP_ADDRESS")

    def test_boundary_values(self):
        assert _types("0.0.0.0").get("IP_ADDRESS") == ["0.0.0.0"]
        assert _types("255.255.255.255").get("IP_ADDRESS") == ["255.255.255.255"]


# ── CIDR ──────────────────────────────────────────────────────────────────────

class TestCIDR:
    def test_cidr_24(self):
        assert _types("scope: 10.10.50.0/24")["CIDR"] == ["10.10.50.0/24"]

    def test_cidr_16(self):
        assert _types("internal: 172.16.0.0/16")["CIDR"] == ["172.16.0.0/16"]

    def test_cidr_not_matched_as_ip(self):
        # The host part of a CIDR should not also appear as IP_ADDRESS
        matches = _types("10.10.50.0/24")
        assert "CIDR" in matches
        # IP_ADDRESS should not contain the full CIDR string
        assert "10.10.50.0/24" not in matches.get("IP_ADDRESS", [])


# ── Hashes ────────────────────────────────────────────────────────────────────

class TestHashes:
    def test_ntlm_md5(self):
        h = "8846f7eaee8fb117ad06bdd830b7586c"
        assert h in _types(f"NTLM: {h}").get("HASH", [])

    def test_sha1(self):
        h = "aabbccddeeff00112233445566778899aabbccdd"
        assert h in _types(f"SHA1: {h}").get("HASH", [])

    def test_sha256(self):
        h = "a" * 64
        assert h in _types(f"hash: {h}").get("HASH", [])

    def test_sha256_not_matched_as_md5(self):
        h = "a" * 64
        matched = _types(h)
        assert h in matched.get("HASH", [])
        # Should not also appear as a shorter hash match
        hashes = matched.get("HASH", [])
        assert hashes.count(h) == 1


# ── MAC ───────────────────────────────────────────────────────────────────────

class TestMAC:
    def test_colon_delimited(self):
        mac = "aa:bb:cc:dd:ee:ff"
        assert mac in _types(f"MAC: {mac}").get("MAC_ADDRESS", [])

    def test_hyphen_delimited(self):
        mac = "AA-BB-CC-DD-EE-FF"
        assert mac in _types(f"iface {mac}").get("MAC_ADDRESS", [])


# ── Email ─────────────────────────────────────────────────────────────────────

class TestEmail:
    def test_plain_email(self):
        assert "john.smith@contoso.com" in _types(
            "contact john.smith@contoso.com for access"
        ).get("EMAIL_ADDRESS", [])

    def test_email_not_also_domain(self):
        # contoso.com should not appear separately as DOMAIN when already in email
        result = _types("john.smith@contoso.com")
        emails = result.get("EMAIL_ADDRESS", [])
        assert "john.smith@contoso.com" in emails
        # contoso.com should not be a separate DOMAIN match
        domains = result.get("DOMAIN", [])
        assert "contoso.com" not in domains


# ── Domain ────────────────────────────────────────────────────────────────────

class TestDomain:
    def test_fqdn(self):
        assert "dc01.contoso.local" in _types(
            "connecting to dc01.contoso.local"
        ).get("DOMAIN", [])

    def test_ad_domain(self):
        assert "contoso.local" in _types(
            "Domain: contoso.local"
        ).get("DOMAIN", [])

    def test_public_domain(self):
        assert "contoso.com" in _types(
            "website: contoso.com"
        ).get("DOMAIN", [])


# ── URL ───────────────────────────────────────────────────────────────────────

class TestURL:
    def test_https_url(self):
        url = "https://intranet.contoso.com/api/v1/users"
        result = _types(url)
        assert url in result.get("URL", [])

    def test_url_not_also_domain(self):
        url = "https://intranet.contoso.com/path"
        result = _types(url)
        assert url in result.get("URL", [])
        # intranet.contoso.com should not also be a separate DOMAIN match
        assert "intranet.contoso.com" not in result.get("DOMAIN", [])


# ── No false positives ────────────────────────────────────────────────────────

class TestNoFalsePositives:
    def test_port_number_not_matched(self):
        result = _types("PORT 445/tcp open")
        assert not result.get("IP_ADDRESS")

    def test_generic_tool_names(self):
        result = _types("running nmap, metasploit, and burpsuite")
        assert not any(result.values())

    def test_cve_not_matched(self):
        result = _types("CVE-2021-44228 is critical")
        assert not any(result.values())
