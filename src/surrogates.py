"""
Surrogate (fake value) generator.

Rules:
  - Surrogates must be realistic in format but clearly not real data
  - IPs use RFC 5737 TEST-NET ranges (192.0.2.x, 198.51.100.x, 203.0.113.x)
  - Domains use .pentest.local TLD
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
    }
    fn = generators.get(entity_type, _fake_generic)
    return fn(original)


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
    return _unique(lambda: fake.lexify("??????").lower() + ".pentest.local")


def _fake_username(_original: str) -> str:
    return _unique(lambda: "user_" + fake.lexify("????").lower())


def _fake_email(_original: str) -> str:
    return _unique(lambda: fake.lexify("??????").lower() + "@example.pentest")


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
