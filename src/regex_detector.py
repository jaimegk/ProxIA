"""
Regex-based PII detector — safety net layer.

Catches deterministic structured data (IPs, hashes, MACs, emails, etc.)
that the LLM might miss in long or dense tool outputs.

Patterns are ordered from most-specific to most-general to avoid partial overlaps
(e.g. CIDR must be matched before bare IP, SHA256 before SHA1 before MD5).
"""
import re
from dataclasses import dataclass


@dataclass
class RegexMatch:
    text: str
    entity_type: str


# ── Willow contribution (PR #2 by @rudi193-cmd) ───────────────────────────
# Patterns marked "(Willow PR #2)" below were originally written for the
# Willow project (https://github.com/rudi193-cmd/willow-1.9) and contributed
# via PR #2. Integrated into _PATTERNS rather than as a parallel module so
# there is one source of truth for RegexMatch and the pattern list.


# (entity_type, compiled_pattern) — order matters
_PATTERNS: list[tuple[str, re.Pattern]] = [
    # CIDR before IP — avoid matching just the host part
    ("CIDR", re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'
        r'/(?:[12]?\d|3[0-2])\b'
    )),
    # IPv4
    ("IP_ADDRESS", re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    )),
    # IPv6 — full, compressed, and loopback variants
    ("IP_ADDRESS", re.compile(
        r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
        r'|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b'
        r'|\bfe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+\b'
        r'|\b::(?:[fF]{4}(?::0{1,4})?:)?(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'
        r'(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b'
    )),
    # Hashes — longest first to avoid SHA1 matching inside SHA256
    ("HASH", re.compile(r'\b[a-fA-F0-9]{64}\b')),   # SHA-256
    ("HASH", re.compile(r'\b[a-fA-F0-9]{48}\b')),   # NTLM response (48-char)
    ("HASH", re.compile(r'\b[a-fA-F0-9]{40}\b')),   # SHA-1 / NTLM+LM pair
    ("HASH", re.compile(r'\b[a-fA-F0-9]{32}\b')),   # MD5 / NTLM
    ("HASH", re.compile(r'\b[0-9a-fA-F]{16}\b')),   # NTLM challenge (16-char)
    # MSSQL SHA-512 password hash: 0x0200 prefix + 64 hex chars
    ("HASH", re.compile(r'\b0x0200[0-9a-fA-F]{64}\b')),
    # 0x-prefixed raw hex blobs (DPAPI master key, symmetric keys, etc.) — min 16 hex chars
    # Must come AFTER the more specific MSSQL pattern above (overlap detection handles dedup)
    ("TOKEN", re.compile(r'\b0x[0-9a-fA-F]{16,}\b')),
    # MAC address
    ("MAC_ADDRESS", re.compile(
        r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'
    )),
    # Email before domain — avoid consuming @domain as a separate DOMAIN match
    ("EMAIL_ADDRESS", re.compile(
        r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
    )),
    # URL before domain
    ("URL", re.compile(
        r'https?://[^\s<>"\'{}|\\^`\[\]\)\(]+'
    )),
    # Cloud provider credentials — must come before generic hash patterns
    # AWS key IDs: Access (AKIA) = 20 chars; entity IDs (AIDA/AROA/etc.) = 21 chars.
    # Suffix length: AKIA access keys use 16 chars; IAM user/role IDs use 17 chars.
    ("TOKEN", re.compile(
        r'\b(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|APKA)[A-Z0-9]{16,17}\b'
    )),
    # Stripe / payment API keys (sk_live_, sk_test_, pk_live_, rk_live_, whsec_)
    ("TOKEN", re.compile(
        r'\b(?:sk_live|sk_test|pk_live|pk_test|rk_live|whsec)_[A-Za-z0-9]{10,64}\b'
    )),
    # SendGrid, Twilio and similar Bearer tokens starting with SG., AC, SK patterns
    ("TOKEN", re.compile(
        r'\bSG\.[A-Za-z0-9_\-]{20,}\b'
    )),
    # GCP OAuth2 access tokens: ya29.<long string>
    ("TOKEN", re.compile(
        r'\bya29\.[A-Za-z0-9_\-\.]{20,}\b'
    )),
    # AWS Secret Access Key: 40-char base64-like string that appears after
    # AWS_SECRET_ACCESS_KEY= or aws_secret_access_key = in config/env context.
    # Uses a lookahead on the variable name to avoid false positives.
    ("TOKEN", re.compile(
        r'(?<=AWS_SECRET_ACCESS_KEY=)[A-Za-z0-9/+]{40}\b'
        r'|(?<=aws_secret_access_key\s=\s)[A-Za-z0-9/+]{40}\b',
        re.MULTILINE,
    )),
    # GitHub PATs and similar tokens
    ("TOKEN", re.compile(
        r'\bgh[pousr]_[A-Za-z0-9]{36,}\b'    # GitHub PAT (gho_, ghp_, ghu_, ghs_, ghr_)
    )),
    # Slack tokens — all variants use the xox[b/p/a/s/e/r]-prefix scheme:
    #   xoxb = bot token, xoxp = user/legacy token, xoxa = app-level, xoxs = workspace, etc.
    ("TOKEN", re.compile(
        r'\bxox[bpasreg]-[0-9A-Za-z\-]{10,}\b'
    )),
    # Square payment tokens:
    #   App ID / Client Secret: sq0[three lowercase letters]-[22-43 alphanumeric/hyphen/underscore]
    #   OAuth access token: EAAA[60 alphanumeric chars]
    ("TOKEN", re.compile(
        r'\bsq0[a-z]{3}-[0-9A-Za-z_\-]{22,43}\b'
    )),
    ("TOKEN", re.compile(
        r'\bEAAA[a-zA-Z0-9]{57,63}\b'    # Square OAuth access token — exactly ~60 chars after EAAA
    )),
    # Mailgun private API key: key-[32 alphanumeric chars]
    ("TOKEN", re.compile(
        r'\bkey-[0-9a-zA-Z]{32}\b'
    )),
    # MailChimp API key: <32-char hex>-us<1-2 digit datacenter>
    ("TOKEN", re.compile(
        r'\b[0-9a-f]{32}-us\d{1,2}\b'
    )),
    # Twilio Account SID: AC followed by 32 hex chars (distinct from AWS AKIA prefix pattern)
    ("TOKEN", re.compile(
        r'\bAC[a-f0-9]{32}\b'
    )),
    # Google API key (browser/server key): AIza followed by 35 alphanumeric/dash/underscore chars
    # Also covers Gemini AIzaSy* keys (subset of the same Google key family).
    ("TOKEN", re.compile(
        r'\bAIza[0-9A-Za-z_\-]{35}\b'
    )),
    # AI/LLM provider API keys (Willow PR #2).
    # Common leak: a `.env` with the dev's OWN key gets read by Claude Code
    # during a pentest and forwarded upstream in cleartext.
    ("TOKEN", re.compile(r'\bsk-ant-[A-Za-z0-9_\-]{8,}\b')),    # Anthropic
    ("TOKEN", re.compile(r'\bgsk_[A-Za-z0-9]{8,}\b')),           # Groq
    ("TOKEN", re.compile(r'\bcsk-[A-Za-z0-9]{8,}\b')),           # Cerebras
    ("TOKEN", re.compile(r'\bsk_sn-[A-Za-z0-9_\-]{8,}\b')),      # SambaNova
    # Shopify app/access tokens: shpat_ (access), shppa_ (private app), shpca_ (custom app)
    ("TOKEN", re.compile(
        r'\bshp(?:at|pa|ca|ss|ua)_[0-9a-fA-F]{32}\b'
    )),
    # Generic high-entropy API key (32–64 printable alphanum chars after = or : in .env context)
    # Only match when preceded by KEY/TOKEN/SECRET/PASS/PWD/API in the same line
    # (done via inline context — Python re doesn't have lookbehind for variable length,
    #  so we match the whole assignment and capture the value)
    # Covered by LLM layer — skip here to avoid false positives
    # AWS Account ID (12-digit — only when clearly an AWS context)
    ("IDENTIFIER", re.compile(r'\b\d{12}\b')),
    # GCP service account unique client IDs (20-21 digit numbers)
    ("IDENTIFIER", re.compile(r'\b\d{20,21}\b')),
    # AWS ARN
    ("IDENTIFIER", re.compile(
        r'\barn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d{12}:[^\s]+'
    )),
    # JSON "client_id" field — GCP service account numeric IDs: "client_id": "12345..."
    ("IDENTIFIER", re.compile(
        r'"client_id"\s*:\s*"(\d{15,22})"',
    )),
    # GCP Service Account email (ends with .iam.gserviceaccount.com)
    ("EMAIL_ADDRESS", re.compile(
        r'\b[a-z0-9\-]+@[a-z0-9\-]+\.iam\.gserviceaccount\.com\b',
        re.IGNORECASE,
    )),
    # Azure / generic UUIDs — tenant IDs, client IDs, subscription IDs
    ("IDENTIFIER", re.compile(
        r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
    )),
    # Private keys / PEM blocks (first line)
    ("CREDENTIAL", re.compile(
        r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'
    )),
    # JWT tokens (three base64url segments separated by dots)
    ("TOKEN", re.compile(
        r'\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b'
    )),
    # National identity documents (shape-preserving NATIONAL_ID surrogate)
    ("NATIONAL_ID", re.compile(r'\b\d{3}\.\d{3}\.\d{3}-\d{2}\b')),           # CPF (BR)
    ("NATIONAL_ID", re.compile(r'\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b')),     # CNPJ (BR)
    ("NATIONAL_ID", re.compile(r'\b\d{2}\.\d{3}\.\d{3}-[\dXx]\b')),          # RG (BR)
    # US SSN with built-in invalid-range filter: area (000/666/9xx), group (00),
    # serial (0000) — all known-invalid by the SSA. (Willow PR #2)
    ("NATIONAL_ID", re.compile(
        r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'
    )),
    # Brazilian phone numbers: +55 XX 9 XXXX-XXXX or +55 XX XXXX-XXXX (mobile + landline)
    ("IDENTIFIER", re.compile(
        r'\+55\s*\d{2}\s*(?:9\s*)?\d{4}[-\s]?\d{4}\b'
    )),
    # Domain names — restricted TLD list reduces false positives on file extensions.
    # Placed before ORGANIZATION so "contoso.local" is captured as DOMAIN, not just
    # "contoso" as an ORGANIZATION (the labeled context pattern would otherwise consume
    # the span and block the DOMAIN match).
    ("DOMAIN", re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
        r'+(?:com|org|net|edu|gov|io|co|uk|de|fr|br|ar|pt|int|info'
        r'|biz|app|dev|cloud|local|internal|corp|mil|ad|lan|test)\b',
        re.IGNORECASE,
    )),
    # Windows AD/NetBIOS names in labeled context — catches MERIDIONAL in:
    #   workgroup: MERIDIONAL | Domain: MERIDIONAL | NetBIOS: MERIDIONAL
    #   workgroup: CONTOSO (bare name, no TLD)
    # Captures only the name word (not the label keyword).
    # DOMAIN pattern above fires first, so "contoso.local" → DOMAIN, not ORGANIZATION.
    # Inline (?i:...) makes only the label keyword case-insensitive while keeping the
    # capture group case-sensitive — prevents "Domain Users" / "Domain Admins" from
    # matching (mixed-case words fail [A-Z][A-Z0-9\-]{2,24} in case-sensitive mode).
    ("ORGANIZATION", re.compile(
        r'(?i:workgroup|domain(?:\s+name)?|NetBIOS(?:\s+name)?)\s*[:\s]+([A-Z][A-Z0-9\-]{2,24})\b',
    )),
    # Inline credentials in pentest CLI commands — catches password after -p / --password flag.
    # Matches quoted and unquoted forms:
    #   crackmapexec smb IP -u user -p 'P@ssw0rd'
    #   evil-winrm -i IP -u user -p P@ssw0rd
    #   impacket-xxx DOMAIN/user:'P@ssw0rd'@IP
    ("CREDENTIAL", re.compile(
        r"(?:(?<=\s-p\s')|(?<=\s-p\s\"))([^'\"]{4,64})(?:'|\")"    # -p 'pass' or -p "pass"
        r"|(?:(?<=\s-p\s))([^\s'\"]{4,64})(?=\s|$)"                # -p pass (unquoted)
        r"|(?<=:')([^'@]{4,64})(?='@)",                             # DOMAIN/user:'pass'@IP
        re.MULTILINE,
    )),
    # Mimikatz wdigest / cleartext password field: "* Password : P@ssw0rd"
    ("CREDENTIAL", re.compile(
        r'\*\s+Password\s*:\s+(\S{4,128})',
    )),
    # Shell environment variable assignments with sensitive values in one-liners:
    #   PASSWORD=value command  |  SECRET_KEY=value  |  DB_PASS=value
    ("CREDENTIAL", re.compile(
        r'(?:PASSWORD|PASSWD|SECRET(?:_KEY)?|DB_PASS(?:WORD)?|API_KEY|TOKEN|AUTH(?:_TOKEN)?)'
        r'=([^\s\'"]{4,128})',
        re.IGNORECASE,
    )),
    # SMTP sasl_passwd format: [smtp.host]:port user@domain:password
    # Match the full user@domain:password assignment; capture only the password.
    ("CREDENTIAL", re.compile(
        r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+:([^\s:]{6,128})$',
        re.MULTILINE,
    )),
    # CrackMapExec / impacket inline credential: DOMAIN\user:Password (Pwn3d!) or end-of-line
    # Captures the password after the colon. One backslash in text (Python "\\").
    # Lookahead accepts both " (Pwn3d!)" suffix and bare end-of-line (no local admin case).
    ("CREDENTIAL", re.compile(
        r'(?:\\|/)(?:[a-zA-Z0-9._\-]{2,40}):([A-Za-z0-9@!#$%^&*()\-_=+\[\]{};:,.<>?/]{6,128})(?=\s+\(|\s*$)',
        re.MULTILINE,
    )),
    # Impacket-style DOMAIN/user:password@target (mssqlclient, psexec, secretsdump, etc.)
    # Captures password between colon and @ sign; stops before @ to handle password@host boundary.
    ("CREDENTIAL", re.compile(
        r'/(?:[a-zA-Z0-9._\-]{1,40}):([A-Za-z0-9!#$%^&*()\-_=+\[\]{};,.<>?/$\']{6,128})@',
    )),
    # Hashcat cracked Kerberos ticket: $krb5tgs$23$*svc_x$...:  CrackedPassword
    ("CREDENTIAL", re.compile(
        r'\$krb5(?:tgs|asrep)\$[^\n:]{10,}:\s*(\S{4,128})',
        re.IGNORECASE,
    )),
    # Hashcat potfile / cracked output: hash:cleartext on its own line
    # Matches: ^<32-hex>:<cleartext>$ — hashcat --show / -o output format
    # The ^ anchor prevents matching SAM dump lines (which start with username, not hash)
    ("CREDENTIAL", re.compile(
        r'^[a-fA-F0-9]{32}:(\S{4,128})\s*$',
        re.MULTILINE,
    )),
    # Redis URL password: redis://:password@host or redis://user:password@host
    ("CREDENTIAL", re.compile(
        r'(?i:redis)://[^:@\s]*:([^@\s]{4,128})@',
    )),
    # JSON credential/secret field: "password": "val", "api_key": "val", "debug_pass": "val"
    # Matches any JSON key whose name ends with a sensitive-value suffix.
    ("CREDENTIAL", re.compile(
        r'"[^"]*(?:password|passwd|pass|secret|api_key|token|auth)"\s*:\s*"([^"]{4,128})"',
        re.IGNORECASE,
    )),
    # YAML/config quoted password: password: "value" or password: 'value'
    ("CREDENTIAL", re.compile(
        r'(?i:password|passwd):\s+["\']([^"\'\n]{4,128})["\']',
    )),
    # WiFi PSK / WPA pre-shared key label
    ("CREDENTIAL", re.compile(
        r'(?i:PSK|WPA(?:2)?\s+(?:Key|Pass(?:phrase)?)):\s+(\S{4,128})',
    )),
    # Standalone password line: "password:     Solar@WiFi2024!" or "Password   : Oliveira@Portal2024!"
    # \s* before colon handles Windows Credential Manager format with spaces before ':'
    ("CREDENTIAL", re.compile(
        r'^\s*password\s*:\s+(\S{4,128})\s*$',
        re.MULTILINE | re.IGNORECASE,
    )),
    # AutoLogon / Unattend setup credentials: "DefaultPassword : NordV3nt0@2024!"
    # Also: "Setup password  : AdminSetup!2023" (WinPEAS Unattend.xml extraction)
    ("CREDENTIAL", re.compile(
        r'(?i:DefaultPassword|AltDefaultPassword|Setup\s+password)\s*:\s+(\S{4,128})',
    )),
    # Password after em dash (BloodHound output: "— Password: Solaris@ERP2024!")
    ("CREDENTIAL", re.compile(
        r'[—–]\s+Password:\s+(\S{4,128})',
        re.IGNORECASE,
    )),
    # Jenkins credential store dump: "cred-id : username : Password"
    # Format produced by iterating Jenkins CredentialsProvider in Groovy console
    ("CREDENTIAL", re.compile(
        r'\S+\s+:\s+\S+\s+:\s+([A-Za-z0-9!@#$%^&*()\-_=+]{6,128})\s*$',
        re.MULTILINE,
    )),
    # Bearer token in HTTP headers or curl commands: Bearer <token>
    # Captures tokens that are not JWT (those are handled separately above).
    ("TOKEN", re.compile(
        r'(?i:bearer\s+)([A-Za-z0-9_\-]{12,128})\b',
    )),
    # GitHub / GitLab org and repo slugs in GITHUB_REPOSITORY, GITHUB_ORG env vars:
    #   GITHUB_REPOSITORY=org/repo  |  GITHUB_ORG=org-name
    ("ORGANIZATION", re.compile(
        r'(?:GITHUB_(?:REPOSITORY|ORG|OWNER)|GITLAB_(?:PROJECT|NAMESPACE))\s*=\s*([^\s\'"]+)',
        re.IGNORECASE,
    )),
    # S3 / cloud storage bucket names — catches the VALUE of bucket env vars:
    #   S3_BUCKET=acme-prod-backups | S3_BACKUP_BUCKET=name | BUCKET_NAME=name
    # Also catches inline: s3://bucket-name/path
    ("IDENTIFIER", re.compile(
        r'(?:S3_(?:\w+_)?BUCKET|BUCKET_NAME|GCS_BUCKET|AZURE_CONTAINER)\s*=\s*([^\s\'"]{3,63})',
        re.IGNORECASE,
    )),
    ("IDENTIFIER", re.compile(
        r's3://([a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9])(?:/|$)',
    )),
    # Kubernetes secrets and config map values (base64 or plaintext after ': ')
    # kubectl get secret -o yaml outputs:  key: base64value
    ("TOKEN", re.compile(
        r'(?<=:\s)[A-Za-z0-9+/]{20,}={0,2}(?=\s*$)',
        re.MULTILINE,
    )),
    # Windows service account usernames: svc_mssql, svc_web, svc_backup, svc_erp
    # Also handles reversed form: delta_svc, deploy_svc
    ("USERNAME", re.compile(
        r'\b(?:svc_[a-zA-Z0-9_]{2,40}|[a-zA-Z0-9]{2,40}_svc)\b',
    )),
    # Short hostname in (name:HOSTNAME) context — CrackMapExec / Nmap SMB scripts
    #   (name:DC01) (name:WEBSERVER01) (name:FILESERVER-PRD)
    ("HOSTNAME", re.compile(
        r'\(name:([A-Za-z][A-Za-z0-9\-]{1,30})\)',
    )),
    # Docker short container ID in shell prompt: root@3f8a92b1c4d5:/# or user@abc123def456:~$
    ("HOSTNAME", re.compile(
        r'(?<=@)([0-9a-f]{12})(?=:)',
    )),
    # DOMAIN/username and DOMAIN\username notation (Windows AD) — captures the domain part.
    # Matches CORP/user, CORP\user (one backslash in text from Python "\\").
    # r'\\' in raw string = regex \\ = matches one literal backslash.
    ("ORGANIZATION", re.compile(
        r'\b([A-Z][A-Z0-9\-]{2,20})(?:/|\\)(?:[a-zA-Z0-9._\-]{2,40})',
    )),
    # Usernames after -u / --username flag in pentest tools:
    #   crackmapexec -u john.smith  |  evil-winrm -u admin  |  bloodhound-python -u user
    ("USERNAME", re.compile(
        r'(?:(?<=-u\s)|(?<=-u\t))([a-zA-Z][a-zA-Z0-9._\-]{2,40})\b',
    )),
    # SMTP AuthPass / mail config password after keyword
    ("CREDENTIAL", re.compile(
        r'(?:AuthPass|smtp_password|auth_pass|AuthUser(?:name)?)\s+([^\s]{4,128})',
        re.IGNORECASE,
    )),
    # Lowercase dot/underscore username after "Username :" or "User Name :" (mimikatz, LSASS, logs)
    #   * Username : fernanda.oliveira
    #   User Name         : lucas.pereira
    ("USERNAME", re.compile(
        r'(?:User(?:\s+Name)?)\s*:\s+([a-z][a-z0-9._\-]{2,40})\b',
    )),
    # enum4linux account listing: "Account: john.smith"
    # Inline (?i:...) scopes case-insensitivity to label only; capture is case-sensitive (lowercase).
    ("USERNAME", re.compile(
        r'(?i:Account):\s{1,20}([a-z][a-z0-9._\-]{2,40})\b',
    )),
    # LDAP sAMAccountName attribute: "sAMAccountName: diana.costa"
    ("USERNAME", re.compile(
        r'(?i:sAMAccountName):\s+([a-z][a-z0-9._\-]{2,40})\b',
    )),
    # JSON/form username field: "username": "john.smith"
    ("USERNAME", re.compile(
        r'(?i:"(?:username|user|login)")\s*:\s*"([a-z][a-z0-9._\-]{2,40})"',
    )),
    # LDAP DN common name (CN=): CN=john.smith,OU=IT or CN=svc_backup,OU=ServiceAccounts
    # Case-sensitive capture — requires lowercase-first to filter out group names (CN=Domain Admins)
    ("USERNAME", re.compile(
        r'\bCN=([a-z][a-z0-9._\-]{2,40})(?=,)',
    )),
    # Username after backslash in NTDS dump: domain.corp\carlos.mendez:1105:hash
    # Lookbehind for backslash; lookahead for colon (RID or password separator).
    # Only lowercase-first to avoid matching system account names like SYSTEM or uppercase hostnames.
    ("USERNAME", re.compile(
        r'(?<=\\)([a-z][a-z0-9._\-]{2,40})(?=:)',
    )),
    # Person names in CSV rows — "First Last," at start of a CSV line.
    # Requires both words to start with uppercase and be followed by a comma,
    # reducing false positives on other capitalized strings.
    ("PERSON", re.compile(
        r'^([A-ZÀ-Ÿ][a-zà-ÿ]{1,20}\s+[A-ZÀ-Ÿ][a-zà-ÿ]{1,20})(?=,)',
        re.MULTILINE,
    )),
    # Person name as git config value:  name = First Last
    ("PERSON", re.compile(
        r'(?:^|\n)\s*name\s*=\s*([A-ZÀ-Ÿ][a-zà-ÿ]{1,20}\s+[A-ZÀ-Ÿ][a-zà-ÿ]{1,20})\s*$',
        re.MULTILINE,
    )),
    # Person name after 'Name:' label — enum4linux format: "Name: John Smith   Desc:"
    # Restricted to lines where Desc: follows or 3+ spaces (avoids "Host Name: Windows Server")
    ("PERSON", re.compile(
        r'\bName:\s+([A-ZÀ-Ÿ][a-zà-ÿ]{1,20}\s+[A-ZÀ-Ÿ][a-zà-ÿ]{1,20})(?=\s+Desc:|\s{3,}|$)',
        re.MULTILINE,
    )),
    # Git Author line: "Author: First Last <email@domain>" — extract display name
    ("PERSON", re.compile(
        r'^Author:\s+([A-ZÀ-Ÿ][a-zà-ÿ]{1,20}(?:\s+[A-ZÀ-Ÿ][a-zà-ÿ]{1,20})+)\s+<',
        re.MULTILINE,
    )),
    # Chat log sender: "[HH:MM] First Last: message" — extract display name
    ("PERSON", re.compile(
        r'^\[\d{1,2}:\d{2}\]\s+([A-ZÀ-Ÿ][a-zà-ÿ]{1,20}(?:\s+[A-ZÀ-Ÿ][a-zà-ÿ]{1,20})+):',
        re.MULTILINE,
    )),
    # JSON "domain" field with all-caps NetBIOS value: "domain": "CONTOSO"
    ("ORGANIZATION", re.compile(
        r'"domain"\s*:\s*"([A-Z][A-Z0-9\-]{2,24})"',
    )),
    # LDAP DN domain component (DC=): DC=NORDVENTO,DC=LOCAL → captures NORDVENTO
    # Negative lookahead excludes common generic TLD-like values (LOCAL, CORP, COM, etc.)
    ("ORGANIZATION", re.compile(
        r'\bDC=(?!LOCAL\b|CORP\b|COM\b|NET\b|ORG\b|INT\b|IO\b|AD\b|GOV\b|INTERNAL\b)'
        r'([A-Z][A-Z0-9]{3,24})(?=,)',
    )),
    # WiFi SSID / ESSID in airodump-ng output — last field after AUTH column (MGT/PSK/WPA2):
    #   " AA:BB:CC:...  WPA2 CCMP   MGT   CORPORATE-NET"
    # Matches uppercase/mixed org-specific names (4-30 chars, letters/digits/hyphen/underscore)
    ("ORGANIZATION", re.compile(
        r'(?:MGT|PSK)\s{2,}([A-Za-z][A-Za-z0-9_\-]{3,30})\s*$',
        re.MULTILINE,
    )),
    # Labeled ESSID / SSID value: "ESSID: CORPORATE-NET" or "SSID: Corp-WiFi"
    ("ORGANIZATION", re.compile(
        r'(?i:ESSID|SSID):\s+([A-Za-z][A-Za-z0-9_\-]{3,40})\b',
    )),

    # ── Hostname extraction ───────────────────────────────────────────────────

    # CrackMapExec SMB host column: "SMB  IP  PORT  HOSTNAME  [*]/[+]/[-]"
    # Catches bare hostnames in CME output that lack a (name:X) annotation.
    ("HOSTNAME", re.compile(
        r'\bSMB\s+\S+\s+\d+\s+([A-Za-z][A-Za-z0-9\-]{1,30})\s+\[',
    )),
    # Shell prompt hostname (letter-starting): root@nuvem-prod-01:/# or user@host:~$
    # Distinct from the 12-hex Docker container ID pattern above.
    ("HOSTNAME", re.compile(
        r'(?<=@)([A-Za-z][A-Za-z0-9\-]{2,40})(?=:[/#~$])',
    )),
    # K8s pod name in "kubectl get pods" table: NAME  READY  STATUS (Running/Pending/...)
    ("HOSTNAME", re.compile(
        r'^([a-z][a-z0-9\-]{3,63})\s+\d+/\d+\s+(?:Running|Pending|CrashLoopBackOff|Completed|Failed|Terminating)',
        re.MULTILINE,
    )),
    # AD machine account in NTDS dump: domain\HOSTNAME$:RID:lmhash
    # Machine accounts end with $ and are uppercase; requires uppercase-first to avoid username collision.
    ("HOSTNAME", re.compile(
        r'(?<=\\)([A-Za-z][A-Za-z0-9\-]{1,30})\$(?=:\d+:)',
    )),
    # MSSQL instance INFO line: INFO(PRATICA-SQL01\SQLEXPRESS): Line 1: ...
    ("HOSTNAME", re.compile(
        r'\bINFO\(([A-Za-z][A-Za-z0-9\-]{1,30})\\',
    )),

    # ── Username extraction ───────────────────────────────────────────────────

    # NTDS dump username without domain prefix: john.smith:1105:LMHASH:NTHASH:::
    # Lookahead prevents the hash from being included in the match span (avoids
    # overlap with the HASH patterns that fire earlier in the list).
    ("USERNAME", re.compile(
        r'^([a-z][a-z0-9._\-]{2,40})(?=:\d{1,6}:[0-9a-fA-F]{32}:)',
        re.MULTILINE,
    )),
    # /etc/shadow username: nuvem_deploy:$6$salt$hash  (crypt(3) format)
    # Common system accounts (root, ubuntu, etc.) are filtered by _NEVER_ANONYMIZE.
    ("USERNAME", re.compile(
        r'^([a-z][a-z0-9_\-]{2,40}):\$[0-9]\$',
        re.MULTILINE,
    )),
    # MSSQL sys.sql_logins dump: username        0x0200<64-hex-hash>
    # Lookahead avoids overlap with the TOKEN pattern that catches 0x0200... blobs.
    ("USERNAME", re.compile(
        r'^([a-z][a-z0-9_\-]{2,40})(?=\s+0x0200)',
        re.MULTILINE,
    )),
    # Jenkins credential store dump — USERNAME in 2nd field: "cred-id : username : Password"
    # Lookahead for " : " avoids consuming the password that the CREDENTIAL pattern already covers.
    ("USERNAME", re.compile(
        r'^\S+\s+:\s+([a-zA-Z][a-zA-Z0-9_\-]{2,40})(?=\s+:\s+\S)',
        re.MULTILINE,
    )),
    # CN= with ALL-CAPS name — machine names (HELIOS-TERM02) and service accounts (IT_HELPDESK).
    # Allows hyphen so Windows computer names (e.g. SSL: CN=HELIOS-RDP01, ...) are captured.
    ("USERNAME", re.compile(
        r'\bCN=([A-Z][A-Z0-9_\-]{3,40})(?=,)',
    )),
    # Username in SSH/tool user@IP format: deploy_bot@10.30.8.50
    # Lookahead keeps the @IP out of the match span (IP is already covered by IP_ADDRESS).
    ("USERNAME", re.compile(
        r'\b([a-z][a-z0-9._\-]{2,40})(?=@(?:\d{1,3}\.){3}\d{1,3}\b)',
    )),
    # Username in shell prompt user@hostname:~$  (e.g. deploy_bot@stellartech-app-01:~$)
    # Lookahead for @letter-starting hostname + colon keeps the hostname span separate.
    ("USERNAME", re.compile(
        r'\b([a-z][a-z0-9._\-]{2,40})(?=@[A-Za-z][A-Za-z0-9\-]{2,}:[/#~$])',
    )),
    # DB_USER / username in config files: DB_USER=acme_prod | username: acme_db_user
    ("USERNAME", re.compile(
        r'(?i:db_user(?:name)?|username)\s*[=:]\s*["\']?([a-z][a-z0-9._\-]{2,40})["\']?(?=\s|$)',
        re.MULTILINE,
    )),
    # user / password pairs in freeform notes: john.smith / C0nt0s0@2024!
    # Negative lookbehind prevents matching inside longer words; lookahead for " / <password>"
    # keeps the credential span separate from this USERNAME match.
    ("USERNAME", re.compile(
        r'(?<!\w)([a-z][a-z0-9._\-]{2,40})(?=\s+/\s+[A-Za-z0-9!@#$%^&*()\-_=+]{4,64})',
        re.MULTILINE,
    )),
    # IAM user in JSON date-keyed array: ["rafael.torres","2021-09-01"]
    ("USERNAME", re.compile(
        r'"([a-z][a-z0-9._\-]{2,40})"(?=,"\d{4}-\d{2}-\d{2}")',
    )),

    # ── Credential extraction ─────────────────────────────────────────────────

    # user / password pairs in freeform notes: john.smith / C0nt0s0@2024!
    # Lookbehind for word char prevents matching URL path separators.
    # Dot excluded from char class so trailing "..." ellipsis is not consumed.
    ("CREDENTIAL", re.compile(
        r'(?<=[a-z0-9_\-])\s+/\s+([A-Za-z0-9!@#$%^&*()\-_=+]{4,64})(?=[.\s]|$)',
        re.MULTILINE,
    )),
    # Portuguese "senha" (password) label: nova senha VPN: Nexus@VPN2024#
    ("CREDENTIAL", re.compile(
        r'(?i:senha)\s+\S+:\s+(\S{4,64})',
    )),

    # ── Organization / K8s / cloud resource extraction ────────────────────────

    # K8s namespace from kubectl -n flag: kubectl get secrets -n producao
    ("ORGANIZATION", re.compile(
        r'(?:^|\s)-n\s+([a-z][a-z0-9\-]{2,40})(?=\s|$)',
        re.MULTILINE,
    )),
    # K8s namespace in YAML metadata block
    ("ORGANIZATION", re.compile(
        r'^\s+namespace:\s+([a-z][a-z0-9\-]{2,40})\s*$',
        re.MULTILINE,
    )),
    # K8s secret / configmap names in kubectl get table: NAME  TYPE  DATA  AGE
    # Matches resource names followed by a K8s type identifier (Opaque, kubernetes.io/..., helm.sh/...).
    ("ORGANIZATION", re.compile(
        r'^([a-z][a-z0-9\-]{3,63})\s+(?:Opaque|kubernetes\.io/|helm\.sh/)',
        re.MULTILINE,
    )),
    # Helm release name embedded in K8s managed field: sh.helm.release.v1.RELEASE.vN
    ("ORGANIZATION", re.compile(
        r'\bsh\.helm\.release\.v\d+\.([a-z][a-z0-9\-]{2,40})\.v\d+\b',
    )),
    # AD CS Certificate Authority name: "CA Name  : FORTUNA-CA"
    ("ORGANIZATION", re.compile(
        r'(?i:CA\s+Name)\s*:\s+([A-Za-z][A-Za-z0-9\-]{2,40})\b',
    )),
    # AD CS certificate template name: "Template Name  : FortunaUserAuth"
    ("ORGANIZATION", re.compile(
        r'(?i:Template\s+Name)\s*:\s+([A-Za-z][A-Za-z0-9]{3,60})\b',
    )),
    # Azure AD / Jenkins DisplayName field (single-word or hyphenated, not proper names):
    #   DisplayName  : acme-github-actions   (but NOT "Acme Corp" — has a space, needs LLM)
    ("ORGANIZATION", re.compile(
        r'(?i:DisplayName)\s*:\s+([a-z][a-z0-9\-_]{2,60})\s*$',
        re.MULTILINE,
    )),
    # GCP project ID standalone row in "gcloud projects list" table:
    #   acme-prod-441210       Acme Corp   441210987654
    ("ORGANIZATION", re.compile(
        r'^([a-z][a-z0-9\-]{3,29}-\d{4,12})\s+\S',
        re.MULTILINE,
    )),
    # GCP project_id in service account JSON: "project_id": "omega-producao-441210"
    ("ORGANIZATION", re.compile(
        r'"project_id"\s*:\s*"([a-z][a-z0-9\-]{3,40})"',
    )),
    # GCS bucket URL: gs://bucket-name/path
    ("IDENTIFIER", re.compile(
        r'gs://([a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9])(?:/|$)',
    )),
    # S3 bucket names in "aws s3 ls" dated output: "2024-01-10  acme-prod-backups"
    ("IDENTIFIER", re.compile(
        r'^\d{4}-\d{2}-\d{2}\s+([a-z][a-z0-9\-\.]{1,61}[a-z0-9])\s*$',
        re.MULTILINE,
    )),

    # ── Path extraction ───────────────────────────────────────────────────────

    # Full path after "Saved to:" / "logged to ... under" keywords (sqlmap, ldapdomaindump, etc.)
    # Optional colon handles both "Saved to: /path" and "Saved to /path" forms.
    ("PATH", re.compile(
        r"(?i:saved\s+to|logged\s+to[^\n]*under)\s*:?\s*['\"]?(/[A-Za-z0-9][A-Za-z0-9_/.\-]{4,120}/?)['\"]?",
    )),
    # Path after the -o flag in pentest CLI tools: ldapdomaindump -o /tmp/quantum_ldap/
    # Only matches paths under /tmp, /home/<user>, /root, /var/www, /opt.
    ("PATH", re.compile(
        r"\s-o\s(/(?:tmp|home/[a-zA-Z0-9_]+|root|var/www|opt)/[A-Za-z][A-Za-z0-9_/.\-]{2,120}/?)",
    )),
    # Path discovered by a tool: "[+] Found .env file at /path/to/.env"
    ("PATH", re.compile(
        r"(?i:found\s+\S+(?:\s+file)?\s+at)\s+(/[A-Za-z0-9][A-Za-z0-9_/.\-]{4,120})",
    )),

    # ── SQL / database extraction ─────────────────────────────────────────────

    # Database name in SQLmap / app config output: "Database: solaris_erp_prod"
    ("ORGANIZATION", re.compile(
        r'(?i:database)\s*[=:]\s*["\']?([a-z][a-z0-9_\-]{2,40})["\']?(?=\s|$)',
        re.MULTILINE,
    )),
    # SQL dump table row: "| username_value | hex32hash |" — catches usernames in
    # SQL injection output where column position next to MD5/NTLM hash identifies it.
    ("USERNAME", re.compile(
        r'\|\s+([a-z][a-z0-9._\-]{2,40})\s+\|\s+[0-9a-fA-F]{32}\s+\|',
    )),

    # ── Misc ─────────────────────────────────────────────────────────────────

    # REDIS_PASS / REDIS_PASSWORD env var credential
    ("CREDENTIAL", re.compile(
        r'(?i:REDIS_PASS(?:WORD)?)=([^\s\'"]{4,128})',
    )),
    # LDAP DN lowercase domain component: DC=quantum (not LOCAL/CORP/COM/etc.)
    # Complements the existing uppercase DC= pattern.
    ("ORGANIZATION", re.compile(
        r'\bDC=(?!local\b|corp\b|com\b|net\b|org\b|int\b|io\b|ad\b|gov\b|internal\b)'
        r'([a-z][a-z0-9]{3,24})(?=,)',
    )),
    # Jenkins shell prompt: [hostname]$ command (script console SSH)
    ("HOSTNAME", re.compile(
        r'\[([A-Za-z][A-Za-z0-9\-]{2,40})\]\$\s',
    )),
    # AWS EC2 instance Name tag value: {"Key":"Name","Value":"acme-api-prod"}
    ("HOSTNAME", re.compile(
        r'"Key"\s*:\s*"Name"[^\}]*"Value"\s*:\s*"([a-z][a-z0-9\-]{2,63})"',
    )),

    # ── Hostname: Windows / UNC / table formats ───────────────────────────────

    # Windows labeled field: "Computer     : WEBSERVER01"  "Logon Server      : DC01"
    # Catches meterpreter sysinfo and mimikatz logon info.
    ("HOSTNAME", re.compile(
        r'(?i:Computer|Logon\s+Server)\s*:\s+([A-Za-z][A-Za-z0-9\-]{1,30})\b',
    )),
    # Infrastructure table: "  DC01  10.10.50.5  dc01.contoso.local"
    # Indented line with all-caps hostname (must contain a digit) followed by an IP.
    # Digit requirement avoids generic labels like VPN, MAIL.
    ("HOSTNAME", re.compile(
        r'^\s{1,8}([A-Z][A-Z0-9\-]*\d[A-Z0-9\-]*)\s+(?:\d{1,3}\.){3}\d{1,3}\b',
        re.MULTILINE,
    )),
    # UNC path hostname: \\fileserver01\hr\confidential
    # Two leading backslashes + hostname + one backslash (share separator).
    ("HOSTNAME", re.compile(
        r'\\\\([A-Za-z][A-Za-z0-9\-]{2,40})\\',
    )),

    # ── Username: RADIUS / hostapd-wpe / Windows labeled field ───────────────

    # hostapd-wpe RADIUS capture and Windows config: "username: DOMAIN\user" or "username: domain\user"
    # Handles both uppercase (RADIUS) and lowercase (WinPEAS Unattend, Credential Manager) domains.
    ("USERNAME", re.compile(
        r'(?i:username|user)\s*:\s+[A-Za-z][A-Za-z0-9\-]*\\([a-z][a-z0-9._\-]{2,40})\b',
    )),

    # ── Credential: K8s YAML inline comment ───────────────────────────────────

    # K8s YAML base64 value with cleartext comment: "DB_PASS: base64==   # CleartextPwd"
    # Captures the human-readable cleartext annotation after the base64 value.
    ("CREDENTIAL", re.compile(
        r'[A-Za-z0-9+/]{16,}={0,2}\s{2,}#\s+([A-Za-z0-9][A-Za-z0-9!@#$%^&*()\-_=+.]{3,64})\s*$',
        re.MULTILINE,
    )),

    # ── Organization: Jenkins cred IDs, GCP display names, page titles ────────

    # Jenkins credential store dump — credential ID (first field): "stellartech-deploy-key : user : pass"
    # Matches lines where the first hyphenated identifier is org-specific.
    # \s+ allows single or multiple spaces (Jenkins sometimes pads, sometimes does not).
    ("ORGANIZATION", re.compile(
        r'^([a-z][a-z0-9\-]{4,60})\s+:\s+[a-zA-Z][a-zA-Z0-9_\-]{1,40}\s+:\s+\S',
        re.MULTILINE,
    )),
    # GCP gcloud projects list display name: "acme-prod-441210  Acme Corp  441210987654"
    # Captures the display name (may include accented chars) between project ID and project number.
    ("ORGANIZATION", re.compile(
        r'^[a-z][a-z0-9\-]{3,29}-\d{4,12}\s{2,}([A-Za-zÀ-ÿ][A-Za-zÀ-ÿ0-9\s]{1,40}?)\s{2,}\d{9,12}\s*$',
        re.MULTILINE,
    )),
    # Azure AD tenant name label: "Tenant Name    : Acme Corp"
    ("ORGANIZATION", re.compile(
        r'(?i:Tenant\s+Name)\s*:\s+(.+?)\s*$',
        re.MULTILINE,
    )),
    # HTTP page title from nmap script output: "| http-title: Acme Intranet Portal"
    # Only multi-word titles (min 6 chars including space) to skip short generic titles.
    ("ORGANIZATION", re.compile(
        r'\|\s+http-title:\s+([A-Za-z][A-Za-z0-9\s\-\.]{5,60}?)\s*$',
        re.MULTILINE,
    )),
    # Company name in parentheses after CNPJ: "CNPJ: 12.345.678/0001-99 (Acme Corp Ltda)"
    ("ORGANIZATION", re.compile(
        r'(?i:CNPJ)\s*:?\s*\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\s*\(([^)]{3,60})\)',
    )),
    # Engagement notes target label: "Target: Contoso Corporation (HQ Austin TX)"
    # Captures 1-4 title-case words; lookahead stops before a parenthetical or end-of-line.
    ("ORGANIZATION", re.compile(
        r'(?i:Target)\s*:\s+([A-Z][A-Za-z]{1,30}(?:\s+[A-Za-z][A-Za-z]{0,30}){0,3})(?=\s+\(|\s*$)',
        re.MULTILINE,
    )),

    # ── Person: name before <email> and in DisplayName field ──────────────────

    # Person name before angle-bracket email: "Michael Johnson <michael.johnson@contoso.com>"
    ("PERSON", re.compile(
        r'([A-ZÀ-Ÿ][a-zà-ÿ]{1,20}\s+[A-ZÀ-Ÿ][a-zà-ÿ]{1,20})(?=\s+<[A-Za-z0-9._%+\-]+@)',
    )),
    # Person proper name in DisplayName labeled field: "DisplayName       : Roberto Alves"
    # Complements the lowercase-org ORGANIZATION DisplayName pattern above.
    ("PERSON", re.compile(
        r'(?i:DisplayName)\s*:\s+([A-ZÀ-Ÿ][a-zà-ÿ]{1,20}\s+[A-ZÀ-Ÿ][a-zà-ÿ]{1,20})\s*$',
        re.MULTILINE,
    )),

    # ── Path: /opt/, /var/www/ and similar app directories ────────────────────

    # Filesystem paths under common app directories: /opt/stellartech/config/db.conf
    # Requires at least 3 components (/dir/org/something) to avoid matching bare tool paths.
    # Excludes well-known tool/shared directories that are not org-specific:
    #   wordlists, rules, payloads, tools, share — present on any Kali/pentest distro.
    ("PATH", re.compile(
        r'(?<![a-zA-Z0-9])(/(?:opt|app|apps|srv|data)/'
        r'(?!(?:wordlists?|rules?|payloads?|tools?|share|modules?)\b)'
        r'[A-Za-z][A-Za-z0-9\-_]{1,60}/[A-Za-z0-9][A-Za-z0-9_/.\-]{2,120})',
    )),
    # /var/www/ web-root paths: /var/www/praxis-portal/config/.env
    # Requires at least one subdirectory under the web root (org or app name).
    ("PATH", re.compile(
        r'(?<![a-zA-Z0-9])(/var/www/[A-Za-z][A-Za-z0-9\-_]{1,60}(?:/[A-Za-z0-9\.][A-Za-z0-9_/.\-]{0,120})?)',
    )),
    # ~/.aws, ~/.ssh, ~/.gnupg credential paths discovered by LinPEAS / recon tools:
    #   /home/deploy/.aws/credentials  |  /root/.ssh/id_rsa
    ("PATH", re.compile(
        r'(?<![a-zA-Z0-9])(/(?:home/[A-Za-z][A-Za-z0-9_\-]{1,40}|root)/\.(?:aws|ssh|gnupg|config)/[A-Za-z0-9_\-\.]{1,80})',
    )),

    # ── Pacu / AWS exploitation framework ────────────────────────────────────

    # Pacu session name in prompt: "Pacu (omegacorp_session:omegacorp_admin) >"
    # Two patterns — one for the session name, one for the active key name after ":".
    ("ORGANIZATION", re.compile(
        r'\bPacu\s+\(([a-z][a-z0-9_]{3,60})(?=:)',
    )),
    ("ORGANIZATION", re.compile(
        r'\bPacu\s+\([a-z][a-z0-9_]{3,60}:([a-z][a-z0-9_]{3,60})\)',
    )),
    # Pacu IAM user listing: "    ana.lima (arn:aws:iam::...)"
    # Username appears before the ARN parenthetical.
    ("USERNAME", re.compile(
        r'^\s{2,}([a-z][a-z0-9._\-]{2,40})\s+\(arn:aws:',
        re.MULTILINE,
    )),
    # Pacu / Vault secrets manager path: "  Secret: org/env/name-of-secret"
    # Slash-separated hierarchical secret names — always org-specific.
    ("ORGANIZATION", re.compile(
        r'^\s*(?i:Secret)\s*:\s+([a-z][a-z0-9/\-]{4,80}(?:/[a-z][a-z0-9\-]{2,40})+)\s*$',
        re.MULTILINE,
    )),
    # Pacu / tool indented "Name: resource-name" label (EC2 instance names, K8s names, etc.)
    # 2+ spaces indent + Name label + hyphenated lowercase value = org/infra resource.
    ("ORGANIZATION", re.compile(
        r'^\s{2,}(?i:Name)\s*:\s+([a-z][a-z0-9\-]{3,63})\s*$',
        re.MULTILINE,
    )),

    # ── Shodan / OSINT labeled fields ────────────────────────────────────────

    # "Organization: Helios Energia" — Shodan host detail output
    ("ORGANIZATION", re.compile(
        r'(?i:^Organization)\s*:\s+([A-Za-zÀ-ÿ][A-Za-zÀ-ÿ0-9\s\-\.]{2,60}?)\s*$',
        re.MULTILINE,
    )),
    # "Title: Helios Energia — Portal do Colaborador" — Shodan / web scan page title
    # Multi-word org-specific titles; ignores short generic strings (< 8 chars with space).
    ("ORGANIZATION", re.compile(
        r'(?i:^\s*Title)\s*:\s+([A-Za-zÀ-ÿ][A-Za-zÀ-ÿ0-9\s\-\.—–]{7,80}?)\s*$',
        re.MULTILINE,
    )),

    # ── GoPhish / phishing campaign credential table ──────────────────────────

    # GoPhish timeline line: "HH:MM:SS  IP  email@domain.tld  Password123"
    # Password is the last whitespace-separated token on lines that contain an email address.
    # Forward match: email@domain followed by 2+ spaces then the password value.
    ("CREDENTIAL", re.compile(
        r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\s{2,}(\S{4,128})\s*$',
        re.MULTILINE,
    )),

    # ── Windows CLI username patterns ────────────────────────────────────────

    # "net user USERNAME /domain" — username as positional arg to net user
    ("USERNAME", re.compile(
        r'(?i:net\s+user)\s+([a-z][a-z0-9._\-]{2,40})\b',
    )),

    # ── Volatility / forensics ────────────────────────────────────────────────

    # Volatility/Foremost -f FILE flag: "vol -f /evidence/acmecorp-dc01.vmem ..."
    ("PATH", re.compile(
        r'\s-f\s+(/[A-Za-z0-9][A-Za-z0-9_/.\-]{4,120})',
    )),
    # Volatility hashdump / NTDS dump with domain prefix (no colon separator):
    #   "acmecorp\john.smith  1105  LMHash  NTHash"
    # Captures the domain (group 1) and the username after the backslash (group 2).
    # Two separate patterns — one ORGANIZATION, one USERNAME.
    ("ORGANIZATION", re.compile(
        r'^([a-z][a-z0-9\-]{2,24})\\[A-Za-z][A-Za-z0-9._\-]{1,40}\s+\d{3,5}',
        re.MULTILINE,
    )),
    ("USERNAME", re.compile(
        r'^[a-z][a-z0-9\-]{2,24}\\([a-z][a-z0-9._\-]{2,40})\s+\d{3,5}',
        re.MULTILINE,
    )),

    # ── AWS / cloud resource IDs ───────────────────────────────────────────────

    # AWS EC2 and VPC resource IDs: i-0a1b2c3d4e5f67890, vol-xxx, sg-xxx, subnet-xxx, etc.
    # No capturing group — match the FULL ID so the whole thing becomes the entity, not just
    # the prefix letter (which would cause mass replacement of every "i" in the document).
    ("IDENTIFIER", re.compile(
        r'\b(?:i|vol|snap|sg|subnet|igw|vpc|ami|eni|rtb|acl|cgw|vgw|vpn|tgw|eip)-[0-9a-f]{8,17}\b',
    )),

    # ── IAM / secretsmanager CLI patterns ────────────────────────────────────

    # AWS CLI --user-name flag: --user-name dev-julia.santos
    ("USERNAME", re.compile(
        r'--user-name\s+([a-z][a-z0-9._\-]{2,40})\b',
    )),
    # AWS secretsmanager --secret-id flag: --secret-id apex-db-prod-creds
    ("ORGANIZATION", re.compile(
        r'--secret-id\s+([a-z][a-z0-9\-]{2,63})\b',
    )),
    # IAM policy name in JSON: "PolicyName": "ApexDevReadWrite"
    ("ORGANIZATION", re.compile(
        r'"PolicyName"\s*:\s*"([A-Za-z][A-Za-z0-9_\-]{3,64})"',
    )),
    # AWS SecretAccessKey in create-access-key JSON output: "SecretAccessKey": "key"
    ("TOKEN", re.compile(
        r'"SecretAccessKey"\s*:\s*"([A-Za-z0-9/+]{30,64})"',
    )),

    # ── Azure CLI patterns ────────────────────────────────────────────────────

    # az keyvault --vault-name VALUE (Key Vault name is always org-specific)
    ("ORGANIZATION", re.compile(
        r'--vault-name\s+([a-z][a-z0-9\-]{2,63})\b',
    )),
    # Azure Key Vault JSON "value" field — secret string returned by az keyvault secret show
    # Restricted to lines where the field is the only key-value pair (typical az CLI output).
    # Min 8 chars to avoid matching short generic config values.
    ("CREDENTIAL", re.compile(
        r'^\s*"value"\s*:\s*"([^"]{8,128})"\s*$',
        re.MULTILINE,
    )),

    # ── Person: name before email in table columns ────────────────────────────

    # az ad user list table / LDAP DisplayName table: "Carlos Mendez      carlos.mendez@org.com"
    # Two title-case words followed by 2+ spaces then an email address (no angle brackets).
    ("PERSON", re.compile(
        r'([A-ZÀ-Ÿ][a-zà-ÿ]{1,20}\s+[A-ZÀ-Ÿ][a-zà-ÿ]{1,20})(?=\s{2,}[a-z][a-z0-9._\-]+@)',
    )),

    # ── Person: Windows net user Full Name field ──────────────────────────────

    # Windows "net user" output: "Full Name                    James Wilson"
    # 3+ spaces between label and value (alignment padding, not colon).
    ("PERSON", re.compile(
        r'(?i:Full\s+Name)\s{3,}([A-ZÀ-Ÿ][a-zà-ÿ]{1,20}\s+[A-ZÀ-Ÿ][a-zà-ÿ]{1,20})\s*$',
        re.MULTILINE,
    )),

    # ── Person: Slack / Teams communication formats ───────────────────────────

    # Slack/Teams @mention: "@Sara Oliveira-Santos" — name immediately after @ sign.
    # Handles plain two-word names and hyphenated last names (Oliveira-Santos).
    # Capturing group strips the @ so only the name text becomes the entity.
    ("PERSON", re.compile(
        r'@([A-ZÀ-Ÿ][a-zà-ÿ]{1,20}\s+(?:[A-ZÀ-Ÿ][a-zà-ÿ]{1,20}-)?[A-ZÀ-Ÿ][a-zà-ÿ]{1,20})\b',
    )),
    # Slack/Teams message-author format: "Alex Torres  [14h06]"
    # Name followed by 1+ spaces then a bracketed timestamp ([HHhMM] or [HH:MM]).
    # Capturing group extracts only the name; the timestamp stays in the text.
    ("PERSON", re.compile(
        r'\b([A-ZÀ-Ÿ][a-zà-ÿ]{1,20}\s+(?:[A-ZÀ-Ÿ][a-zà-ÿ]{1,20}-)?[A-ZÀ-Ÿ][a-zà-ÿ]{1,20})\s+\[\d{1,2}[h:]\d{2}\]',
    )),

    # ── Hostname: sudo -l output ───────────────────────────────────────────────

    # sudo -l output: "User deploy can run the following commands on praxis-srv01:"
    ("HOSTNAME", re.compile(
        r'(?i:can\s+run\s+the\s+following\s+commands\s+on)\s+([A-Za-z][A-Za-z0-9\-]{1,40})(?=:)',
    )),

    # ── JSON db_name / database_name / db fields ────────────────────────────────

    # Terraform / app config JSON: "db_name": "stratus_production"
    # Also "db": "vertexcorp_prod" in ad-hoc query APIs.
    ("ORGANIZATION", re.compile(
        r'"(?:db_name|database_name|database|db)"\s*:\s*"([a-z][a-z0-9_\-]{2,40})"',
    )),

    # ── Escaped JSON credentials (AWS secretsmanager SecretString) ────────────

    # Double-encoded JSON: \"username\":\"apex_dba\"  (appears in aws secretsmanager output)
    ("USERNAME", re.compile(
        r'\\"(?:username|user)\\"\s*:\s*\\"([a-z][a-z0-9._\-]{2,40})\\"',
    )),
    # Double-encoded JSON password: \"password\":\"Apex#DBPr0d2024!\"
    ("CREDENTIAL", re.compile(
        r'\\"(?:password|passwd|pass)\\"\s*:\s*\\"([^"\\]{4,128})\\"',
    )),

    # ── Windows domain\user format (CME user listing, Responder, etc.) ──────────

    # CrackMapExec user enumeration: "aurora.local\bianca.ferrari     badpwdcount:"
    # Captures the username part after the domain\backslash.
    # Domain must contain a dot (avoids matching single-word\value) and be all-lowercase.
    ("USERNAME", re.compile(
        r'[A-Za-z0-9\-]+\.[a-z]{2,10}\\([a-z][a-z0-9._\-]{2,40})\b',
    )),

    # ── Windows machine names in free-form comments/logs ─────────────────────────

    # Zeek / IDS analyst notes: "from NOVA-WKS14 (172.16.5.45)"
    # "Targeting NOVA-DC02 (...) and NOVA-PROXY01 (...)" / "connection to NOVA-WEBAPP01 (...)"
    # Captures all-caps name with optional trailing digits before a space+paren or EOL.
    ("HOSTNAME", re.compile(
        r'(?:from|[Tt]argeting|connection\s+to|\band)\s+([A-Z][A-Z0-9\-]{3,24})(?=\s)',
    )),
    # Source: / Target: / Host: label in analyst comments
    ("HOSTNAME", re.compile(
        r'(?:Source|Target|Host):\s+([A-Z][A-Z0-9\-]{3,24})\b',
    )),

    # ── Generic user: label without domain prefix ────────────────────────────────

    # Zeek analyst comment: "user: fernanda.xavier" — no domain\user backslash notation.
    # Uses word boundary for 'user' to avoid matching mid-word.
    ("USERNAME", re.compile(
        r'(?<!\w)user:\s+([a-z][a-z0-9._\-]{2,40})\b',
    )),

    # ── Organization name after explicit label ────────────────────────────────────

    # Analyst notes / Zeek comments: "# Internal org: Novatech Sistemas"
    # Captures 1-3 title-case words (org name) after org-labelling keywords.
    ("ORGANIZATION", re.compile(
        r'(?i:internal\s+org|org(?:anization)?)\s*:\s+([A-Z][A-Za-z]{1,30}(?:\s+[A-Z][A-Za-z]{1,30}){0,2})\s*$',
        re.MULTILINE,
    )),

    # ── Custom HTTP token headers ─────────────────────────────────────────────────

    # Non-standard X-*-Token headers: "X-Internal-Token: int_tok_v2_..."
    # Covers X-Internal-Token, X-Auth-Token, X-API-Token, X-Access-Token, X-Secret-Token.
    ("TOKEN", re.compile(
        r'X-(?:Internal|Auth|API|Access|Secret)-Token:\s+(\S{10,128})',
    )),

    # ── Extended env-var credential patterns ─────────────────────────────────────

    # Shell env assignments with suffix-keyed variable names: AURORA_INTERNAL_PASS=..., ENCRYPTION_KEY=...
    # Catches variables not already covered by the PREFIX-only pattern above.
    # Suffix list: _PASS, _PASSWORD, _SECRET, _KEY (min 6-char value to avoid short config noise).
    ("CREDENTIAL", re.compile(
        r'\b[A-Z][A-Z0-9_]{1,40}_(?:PASS(?:WORD)?|SECRET|KEY)\s*=\s*([^\s\'"]{6,128})',
    )),

    # ── ADB / mobile device identifiers ──────────────────────────────────────────

    # ADB device serial in "adb devices" output: "R38M9T2K44A    device"
    # Serial is alphanumeric 8-20 chars, followed by device state keyword.
    ("IDENTIFIER", re.compile(
        r'^([A-Za-z0-9][A-Za-z0-9:._-]{7,19})\s+(?:device|offline|unauthorized)\s*$',
        re.MULTILINE,
    )),
    # ADB -s flag: "adb -s R38M9T2K44A shell" — serial as positional arg after -s
    ("IDENTIFIER", re.compile(
        r'\badb\s+(?:(?:-\w+\s+)*-s\s+)([A-Za-z0-9:._-]{8,20})\b',
    )),

    # ── Pentest artifact filenames with org-name prefix ───────────────────────────

    # Org-prefixed hashcat / scanner output filenames: delta_ntlm_hashes.txt, helios_nuclei.txt
    # Suffixes are pentest-specific enough that a prefix word uniquely identifies the org.
    ("PATH", re.compile(
        r'\b([a-z][a-z0-9_]{2,30}_(?:ntlm(?:_hashes)?|cracked|nuclei|loot|shadow)\.txt)\b',
        re.IGNORECASE,
    )),
    # Hashcat --potfile-path argument: --potfile-path delta.pot
    ("PATH", re.compile(
        r'--potfile-path\s+(\S+\.pot)\b',
    )),
    # Hashcat Hash.Target status field — the input hash file path
    ("PATH", re.compile(
        r'Hash\.Target\s*[.:]+\s+(\S+)',
        re.MULTILINE,
    )),

    # Person name after a common record label, in EN/ES/PT:
    #   "Patient: Daniel Fuentes", "paciente Marcos Tovar (DNI …)",
    #   "Account holder: Olivia Brennan", "Manager: Sofia Castellano",
    #   "titular: …", "transfer to Marcus Lindqvist for …".
    # Both words must be Title-case (first upper, rest lower) so all-caps labels
    # like "IT Team" or "Domain Admins" do not match.
    ("PERSON", re.compile(
        r'(?i:patient|paciente|account\s+holder|cardholder|titular|policy\s*holder|'
        r'beneficiary|beneficiario|asegurado|attending\s+physician|physician|'
        r'm[ée]dico|doctora?|manager|client|customer|cliente|holder|emplead[oa]|'
        r'funcion[áa]ri[oa]|destinatario|remitente|'
        r'transfer\s+to|paid\s+to|payable\s+to|transferencia\s+a|pagar\s+a|a\s+favor\s+de)'
        r'\s*:?\s+(?:Dr\.?\s+|Dra\.?\s+|Mr\.?\s+|Mrs\.?\s+|Ms\.?\s+|D\.?\s+|D[ñn]a\.?\s+)?'
        r'([A-ZÀ-Ÿ][a-zà-ÿ]{1,20}\s+[A-ZÀ-Ÿ][a-zà-ÿ]{1,20})\b',
    )),
    # Person name immediately before a parenthetical national ID: "Marcos Tovar (DNI …"
    # A full name followed by "(DNI"/"(NIE"/"(SSN"/"(CPF" is an unambiguous person.
    ("PERSON", re.compile(
        r'([A-ZÀ-Ÿ][a-zà-ÿ]{1,20}\s+[A-ZÀ-Ÿ][a-zà-ÿ]{1,20})\s*\((?i:DNI|NIE|SSN|CPF|CNPJ|ID)\b',
    )),

    # ── Generic PII families (financial / identity / contact / health) ─────────

    # International phone numbers in E.164 / formatted form: +34 612 345 678,
    # +1 (555) 123-4567, +44 20 7946 0958. Requires a leading "+" and country
    # code to avoid matching version strings or bare digit runs. The BR-specific
    # +55 pattern above fires first for Brazilian numbers (overlap dedup).
    ("PHONE", re.compile(
        r'\+[1-9]\d{0,2}(?:[\s\-]?\(?\d{1,4}\)?){1,5}\d{2,4}'
    )),
    # Phone after explicit label (national format without +): "Phone: 612 345 678",
    # "Tel: (555) 123-4567", "Teléfono: 91 234 56 78", "Mobile: 07700 900123"
    ("PHONE", re.compile(
        r'(?i:tel(?:efono|éfono|ephone)?|phone|mobile|m[oó]vil|celular|fax|whatsapp)'
        r'\s*[:#]?\s*(\(?\d[\d\s\-().]{6,17}\d)',
    )),
    # SWIFT / BIC bank code (labeled, to avoid matching any 8 uppercase letters):
    #   "SWIFT: BSCHESMMXXX"  "BIC: DEUTDEFF"
    ("SWIFT", re.compile(
        r'(?i:SWIFT(?:[\s/]?BIC)?|BIC)\s*(?:code)?\s*[:#]?\s+([A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b',
    )),
    # Bank account after label (generic, contextual): "Account No: 12345678",
    # "Cuenta: 0049 1500 05 1234567892", "Routing: 021000021"
    ("BANK_ACCOUNT", re.compile(
        r'(?i:account\s*(?:no|number|#)?|cuenta|routing(?:\s*number)?|sort\s*code|aba)'
        r'\s*[:#]?\s*([\d][\d\s\-]{5,32}\d)',
    )),
    # Date of birth (labeled). Captures ISO and DD/MM/YYYY style dates only when a
    # birth-context label precedes them — avoids anonymizing every date in a log.
    ("DATE_OF_BIRTH", re.compile(
        r'(?i:date\s+of\s+birth|d\.?o\.?b\.?|born(?:\s+on)?|fecha\s+de\s+nacimiento|'
        r'nacimiento|nascimento|geburtsdatum|geboren)'
        r'\s*[:#]?\s*(\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4})',
    )),
    # Medical record number / health identifiers (labeled):
    #   "MRN: A1234567"  "Medical Record No: 0099887"  "Historia clínica: HC-44821"
    ("HEALTH_ID", re.compile(
        r'(?i:MRN|medical\s+record\s*(?:number|no|#)?|patient\s+id|health\s+id|'
        r'historia\s+cl[ií]nica|n[º°]?\s*historia|NHS\s*(?:number)?)'
        r'\s*[:#]?\s*([A-Z]{0,3}[-]?\d[A-Z0-9\-]{3,19})',
    )),
]


# ── Payment card numbers (Willow PR #2) ───────────────────────────────────
# Regex matches digit runs; detect() gates each match on _luhn_valid()
# because regex cannot compute the Luhn checksum.

_PAN_RE = re.compile(
    r"\b(?:\d{4}[\s\-]?){3}\d{4}\b"
    r"|\b\d{13,19}\b"
)


def _luhn_valid(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ── IBAN (validated via mod-97, like PAN's Luhn gate) ──────────────────────
# Raw shape: 2 country letters + 2 check digits + 11–30 alphanumeric (BBAN),
# optionally grouped in spaces of 4. detect() validates ISO 7064 mod-97-10.
_IBAN_RE = re.compile(
    r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}[ ]?[A-Z0-9]{0,3}\b"
)


def _iban_valid(candidate: str) -> bool:
    iban = re.sub(r"\s", "", candidate).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", iban):
        return False
    rearranged = iban[4:] + iban[:4]
    # Map letters A–Z to 10–35, then compute the integer mod 97.
    digits = "".join(str(int(c, 36)) for c in rearranged)
    return int(digits) % 97 == 1


# ── Spanish DNI / NIE (validated via mod-23 control letter) ────────────────
_DNI_RE = re.compile(r"\b[XYZ]?\d{7,8}[-]?[A-HJ-NP-TV-Z]\b")
_DNI_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"


def _dni_valid(candidate: str) -> bool:
    s = candidate.replace("-", "").upper()
    m = re.fullmatch(r"([XYZ]?)(\d{7,8})([A-HJ-NP-TV-Z])", s)
    if not m:
        return False
    prefix, number, letter = m.groups()
    nie_map = {"X": "0", "Y": "1", "Z": "2"}
    numeric = (nie_map.get(prefix, "") + number) if prefix else number
    if len(numeric) != 8:
        return False
    return _DNI_LETTERS[int(numeric) % 23] == letter


def detect(text: str) -> list[RegexMatch]:
    """Run all patterns on text. Returns deduplicated matches (no overlaps).

    If a pattern uses capturing groups, the FIRST non-None group is used as the
    matched text (allows context-sensitive patterns that anchor on a label but only
    capture the sensitive value).

    Coverage tracking uses the CAPTURED GROUP span (not the full match span) when
    a group is present.  This allows two patterns to extract independent entities
    from the same line — e.g., CME CREDENTIAL captures the password while a later
    USERNAME pattern captures the domain\\user on the same line without collision.
    Patterns WITHOUT capturing groups still mark the full match as covered.
    """
    matches: list[RegexMatch] = []
    covered: list[tuple[int, int]] = []

    def _overlaps(s: int, e: int) -> bool:
        return any(s < ce and e > cs for cs, ce in covered)

    # ── Validated numeric PII passes run FIRST ────────────────────────────────
    # Credit cards, IBANs and national IDs are digit/alnum runs that a generic
    # hash/identifier pattern would otherwise claim with the wrong type (and thus
    # the wrong surrogate shape). Running their checksum-gated passes before the
    # main pattern loop lets them reserve their span with the correct entity type.
    for m in _PAN_RE.finditer(text):
        if _overlaps(m.start(), m.end()):
            continue
        digits = re.sub(r"\D", "", m.group())
        if len(digits) >= 13 and _luhn_valid(digits):
            matches.append(RegexMatch(text=m.group().strip(), entity_type="CREDIT_CARD"))
            covered.append((m.start(), m.end()))

    for m in _IBAN_RE.finditer(text):
        if _overlaps(m.start(), m.end()):
            continue
        if _iban_valid(m.group()):
            matches.append(RegexMatch(text=m.group().strip(), entity_type="IBAN"))
            covered.append((m.start(), m.end()))

    for m in _DNI_RE.finditer(text):
        if _overlaps(m.start(), m.end()):
            continue
        if _dni_valid(m.group()):
            matches.append(RegexMatch(text=m.group().strip(), entity_type="NATIONAL_ID"))
            covered.append((m.start(), m.end()))

    for entity_type, pattern in _PATTERNS:
        for m in pattern.finditer(text):
            # Determine entity span: captured group if present, else full match.
            # Using GROUP span for both the FIRE DECISION and COVERAGE means:
            #   - Patterns whose label/context overlaps an already-covered span can
            #     still fire if the VALUE they extract is in a fresh region.
            #   - CME hostname column can fire even though the IP in the same line is
            #     already covered, because the hostname VALUE span is elsewhere.
            captured_idx = next(
                (i + 1 for i, g in enumerate(m.groups()) if g is not None), None
            )
            if captured_idx is not None:
                entity_start = m.start(captured_idx)
                entity_end = m.end(captured_idx)
                value = m.group(captured_idx)
            else:
                entity_start = m.start()
                entity_end = m.end()
                value = m.group()

            if not _overlaps(entity_start, entity_end):
                if value and value.strip():
                    matches.append(RegexMatch(text=value.strip(), entity_type=entity_type))
                covered.append((entity_start, entity_end))

    return matches
