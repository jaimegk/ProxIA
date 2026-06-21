"""
Surrogate (fake value) generator.

Rules:
  - Surrogates must be realistic in format but clearly not real data
  - IPs use RFC 5737 TEST-NET ranges (192.0.2.x, 198.51.100.x, 203.0.113.x)
  - Domains/emails use RFC 2606 reserved names (.example.com) — never resolve
  - Cards/IBANs/IDs/phones preserve shape (length, separators, valid checksums)
  - Hashes maintain length and hex format
  - Credentials are replaced with a clear REDACTED marker
"""
import random
import string

from faker import Faker

fake = Faker()
_used: set[str] = set()

# Private ranges that look like internal networks but are obscure enough
# that Claude won't treat them as "special" (unlike RFC 5737 TEST-NETs
# which Claude knows as documentation ranges and comments on them).
_TEST_NETS = [
    (10, 200, 99),
    (10, 201, 88),
    (172, 28, 199),
]


def generate_surrogate(original: str, entity_type: str) -> str:
    generators = {
        "IP_ADDRESS":    _fake_ip,
        "CIDR":          _fake_cidr,
        "HOSTNAME":      _fake_hostname,
        "DOMAIN":        _fake_domain,
        "USERNAME":      _fake_username,
        "EMAIL_ADDRESS": _fake_email,
        "EMAIL":         _fake_email,
        "URL":           _fake_url,
        "ORGANIZATION":  _fake_org,
        "PERSON":        _fake_name,
        "CREDENTIAL":    _fake_credential,
        "HASH":          _fake_hash,
        "MAC_ADDRESS":   _fake_mac,
        "PATH":          _fake_path,
        "TOKEN":         _fake_token_smart,
        "IDENTIFIER":    _fake_identifier_smart,
        # ── Generic PII families ──────────────────────────────────────────
        "CREDIT_CARD":     _fake_credit_card,
        "IBAN":            _fake_iban,
        "SWIFT":           _fake_swift,
        "BANK_ACCOUNT":    _fake_bank_account,
        "NATIONAL_ID":     _fake_national_id,
        "PHONE":           _fake_phone,
        "DATE_OF_BIRTH":   _fake_dob,
        "HEALTH_ID":       _fake_health_id,
        "POSTAL_ADDRESS":  _fake_postal_address,
    }
    fn = generators.get(entity_type, _fake_generic)
    return fn(original)


# ── Shape-preserving helpers for generic PII ──────────────────────────────────

def _mask_digits(original: str) -> str:
    """Replace every digit with a random digit; keep all other chars (separators,
    letters, '+', parentheses) exactly in place. Used for phones, accounts, IDs."""
    return "".join(random.choice(string.digits) if c.isdigit() else c for c in original)


def _luhn_check_digit(partial: str) -> str:
    """Return the check digit that makes `partial` (without it) Luhn-valid."""
    digits = [int(c) for c in partial]
    total = 0
    # `partial` has no check digit yet; the check digit will sit at an even index
    # from the right (position 0), so existing digits start doubling at position 1.
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return str((10 - total % 10) % 10)


def _fake_credit_card(original: str) -> str:
    """Same length and separator layout, regenerated digits, valid Luhn."""
    def _gen() -> str:
        positions = [i for i, c in enumerate(original) if c.isdigit()]
        n = len(positions)
        if n < 13:
            return _mask_digits(original)
        body = [random.choice(string.digits) for _ in range(n - 1)]
        check = _luhn_check_digit("".join(body))
        new_digits = body + [check]
        chars = list(original)
        for pos, d in zip(positions, new_digits):
            chars[pos] = d
        return "".join(chars)
    return _unique(_gen)


def _fake_iban(original: str) -> str:
    """Keep the 2-letter country code and length; regenerate BBAN with valid
    ISO 7064 mod-97 check digits."""
    compact = "".join(ch for ch in original if not ch.isspace())
    country = compact[:2].upper() if compact[:2].isalpha() else "ES"
    bban_len = max(len(compact) - 4, 11)

    def _gen() -> str:
        bban = "".join(random.choices(string.digits, k=bban_len))
        rearranged = bban + country + "00"
        numeric = "".join(str(int(c, 36)) for c in rearranged)
        check = 98 - (int(numeric) % 97)
        iban = f"{country}{check:02d}{bban}"
        # Re-apply the original spacing pattern if it had grouped blocks.
        if " " in original:
            return " ".join(iban[i:i + 4] for i in range(0, len(iban), 4))
        return iban
    return _unique(_gen)


def _fake_swift(original: str) -> str:
    """BIC shape: 4-letter bank + 2-letter country + 2 alnum location + optional
    3 alnum branch. Preserves the original length (8 or 11)."""
    def _gen() -> str:
        bank = "".join(random.choices(string.ascii_uppercase, k=4))
        country = "".join(random.choices(string.ascii_uppercase, k=2))
        loc = "".join(random.choices(string.ascii_uppercase + string.digits, k=2))
        branch = ""
        if len(original.strip()) > 8:
            branch = "".join(random.choices(string.ascii_uppercase + string.digits, k=3))
        return bank + country + loc + branch
    return _unique(_gen)


def _fake_bank_account(original: str) -> str:
    return _unique(lambda: _mask_digits(original))


_DNI_CONTROL = "TRWAGMYFPDXBNJZSQVHLCKE"


def _fake_national_id(original: str) -> str:
    """Mask digits, keep separators/letters. For Spanish DNI/NIE the trailing
    control letter is recomputed so the surrogate still validates (mod-23)."""
    import re as _re
    dni = _re.fullmatch(r"([XYZ]?)(\d{7,8})[-]?([A-HJ-NP-TV-Z])", original.upper())
    if dni:
        prefix = dni.group(1)
        n_digits = len(dni.group(2))

        def _gen() -> str:
            number = "".join(random.choices(string.digits, k=n_digits))
            nie_map = {"X": "0", "Y": "1", "Z": "2"}
            numeric = (nie_map.get(prefix, "") + number) if prefix else number
            letter = _DNI_CONTROL[int(numeric) % 23] if len(numeric) == 8 else "Z"
            sep = "-" if "-" in original else ""
            return f"{prefix}{number}{sep}{letter}"
        return _unique(_gen)
    return _unique(lambda: _mask_digits(original))


def _fake_phone(original: str) -> str:
    return _unique(lambda: _mask_digits(original))


def _fake_dob(original: str) -> str:
    """Plausible birth date in the same delimiter/ordering as the original."""
    import re as _re
    sep_m = _re.search(r"[-/.]", original)
    sep = sep_m.group() if sep_m else "-"
    y = random.randint(1950, 2005)
    mo = random.randint(1, 12)
    d = random.randint(1, 28)
    parts = original.split(sep)
    # ISO (YYYY first) vs day-first layouts — match whichever the original used.
    if parts and len(parts[0]) == 4:
        return _unique(lambda: f"{y:04d}{sep}{mo:02d}{sep}{d:02d}")
    return _unique(lambda: f"{d:02d}{sep}{mo:02d}{sep}{y:04d}")


def _fake_health_id(original: str) -> str:
    """Keep any leading letter prefix and separators; randomize the digits."""
    return _unique(lambda: _mask_digits(original))


def _fake_postal_address(_original: str) -> str:
    return _unique(lambda: fake.address().replace("\n", ", "))


def _unique(fn) -> str:
    for _ in range(200):
        val = fn()
        if val not in _used:
            _used.add(val)
            return val
    return fn()  # give up dedup after 200 tries


def _fake_ip(_original: str) -> str:
    net = random.choice(_TEST_NETS)
    return _unique(lambda: f"{net[0]}.{net[1]}.{net[2]}.{random.randint(1, 254)}")


def _fake_cidr(_original: str) -> str:
    net = random.choice(_TEST_NETS)
    prefix = random.randint(16, 30)
    return f"{net[0]}.{net[1]}.{net[2]}.0/{prefix}"


def _fake_hostname(_original: str) -> str:
    prefixes = ["srv", "host", "node", "dc", "box", "ws", "app", "db"]
    return _unique(
        lambda: f"{random.choice(prefixes)}-{''.join(random.choices(string.digits, k=4))}"
    )


def _fake_domain(_original: str) -> str:
    # RFC 2606 reserved TLD/domain — guaranteed never to resolve to a real host.
    return _unique(lambda: fake.lexify("??????").lower() + ".example.com")


def _fake_username(_original: str) -> str:
    return _unique(lambda: "user_" + fake.lexify("????").lower())


def _fake_email(_original: str) -> str:
    # RFC 2606 reserved domain — never a real mailbox.
    return _unique(lambda: fake.lexify("??????").lower() + "@example.com")


def _fake_url(_original: str) -> str:
    net = random.choice(_TEST_NETS)
    ip = f"{net[0]}.{net[1]}.{net[2]}.{random.randint(1, 254)}"
    return f"http://{ip}/path"


def _fake_org(_original: str) -> str:
    return _unique(lambda: fake.company())


def _fake_name(_original: str) -> str:
    return _unique(lambda: fake.name())


def _fake_credential(_original: str) -> str:
    tag = "".join(random.choices(string.ascii_uppercase + string.digits, k=8))
    return f"[CRED_{tag}]"


def _fake_hash(original: str) -> str:
    length = len(original)
    return _unique(lambda: "".join(random.choices("abcdef0123456789", k=length)))


def _fake_mac(_original: str) -> str:
    return _unique(
        lambda: ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))
    )


def _fake_path(_original: str) -> str:
    return _unique(lambda: f"/home/user_{fake.lexify('????').lower()}/data")


def _fake_token(_original: str) -> str:
    tag = "".join(random.choices(string.ascii_letters + string.digits, k=32))
    return f"[TOKEN_{tag}]"


def _fake_token_smart(original: str) -> str:
    """
    Shape-preserving token replacement.
    - AWS key IDs (AKIA/ASIA/…) → same prefix + random 16 uppercase alphanum
    - JWTs → same header, shuffled payload, shuffled sig
    - Other → generic token marker
    """
    # AWS Access Key ID
    _AWS_PREFIXES = ("AKIA", "ASIA", "AROA", "AIPA", "ANPA", "ANVA", "APKA")
    if any(original.startswith(p) for p in _AWS_PREFIXES) and len(original) == 20:
        prefix = original[:4]
        suffix = "".join(random.choices(string.ascii_uppercase + string.digits, k=16))
        return _unique(lambda: prefix + "".join(
            random.choices(string.ascii_uppercase + string.digits, k=16)
        ))
    # JWT (three base64url parts separated by dots)
    if original.count(".") == 2 and original.startswith("eyJ"):
        parts = original.split(".")
        shuffled = [
            parts[0],                                           # keep header (alg/typ)
            "".join(random.choices(string.ascii_letters + string.digits + "_-", k=len(parts[1]))),
            "".join(random.choices(string.ascii_letters + string.digits + "_-", k=len(parts[2]))),
        ]
        return ".".join(shuffled)
    # Fallback
    tag = "".join(random.choices(string.ascii_letters + string.digits, k=32))
    return f"[TOKEN_{tag}]"


def _fake_identifier_smart(original: str) -> str:
    """
    Shape-preserving identifier replacement.
    - UUID (8-4-4-4-12) → same structure, random hex
    - 12-digit AWS account ID → random 12-digit number
    - ARN → same service/region structure, fake account + resource
    - Brazilian phone (+55 XX 9 XXXX-XXXX) → same format, random digits
    - Other → generic redacted
    """
    import re as _re
    # UUID
    if _re.fullmatch(
        r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
        original, _re.IGNORECASE
    ):
        def _uuid():
            parts = [
                "".join(random.choices("abcdef0123456789", k=8)),
                "".join(random.choices("abcdef0123456789", k=4)),
                "4" + "".join(random.choices("abcdef0123456789", k=3)),
                random.choice("89ab") + "".join(random.choices("abcdef0123456789", k=3)),
                "".join(random.choices("abcdef0123456789", k=12)),
            ]
            return "-".join(parts)
        return _unique(_uuid)
    # 12-digit AWS account ID
    if _re.fullmatch(r'\d{12}', original):
        return _unique(lambda: "".join(random.choices(string.digits, k=12)))
    # AWS ARN
    if original.startswith("arn:aws:"):
        parts = original.split(":")
        if len(parts) >= 5:
            fake_account = "".join(random.choices(string.digits, k=12))
            parts[4] = fake_account
            return ":".join(parts)
    # Brazilian phone number — preserve format, randomize digits
    phone_m = _re.match(r'(\+55\s*)(\d{2})(\s*)(9?\s*)(\d{4})([-\s]?)(\d{4})', original)
    if phone_m:
        ddd = str(random.randint(11, 99))
        mob = "9" if phone_m.group(4).strip() else ""
        part1 = "".join(random.choices(string.digits, k=4))
        part2 = "".join(random.choices(string.digits, k=4))
        return _unique(lambda: f"+55 {ddd} {mob}{part1}-{part2}".strip())
    tag = "".join(random.choices(string.ascii_uppercase, k=6))
    return f"[REDACTED_{tag}]"


def _fake_generic(_original: str) -> str:
    tag = "".join(random.choices(string.ascii_uppercase, k=6))
    return f"[REDACTED_{tag}]"
