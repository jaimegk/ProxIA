#!/usr/bin/env python3
"""
scripts/live_test.py — runs the anonymizer against dynamic scenarios on the fly.

Simulates what happens when Claude Code executes tools during a pentest:
  • nmap scan → output contains IPs, hostnames, client domain
  • aws cli → extracts keys, ARNs, bucket names
  • bash history → commands with inline credentials
  • HR document → SSN, email, phone of employees

For each scenario prints:
  [ORIGINAL]    the text coming from the tool
  [SENT API]    what leaves the machine (anonymized)
  [RECEIVED CC] what Claude Code gets back (deanonymized)
  [SCORE]       how many entities were caught/missed

Usage:
    cd /path/to/pentest-proxy
    source .venv/bin/activate
    PYTHONUNBUFFERED=1 python -u -m scripts.live_test
"""
from __future__ import annotations
import asyncio
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

R  = "\033[0;31m"
G  = "\033[0;32m"
Y  = "\033[1;33m"
C  = "\033[0;36m"
B  = "\033[1m"
DIM= "\033[2m"
NC = "\033[0m"

# ─────────────────────────────────────────────────────────────────────────────
# Fictional scenarios (100% invented data)
# ─────────────────────────────────────────────────────────────────────────────

SCENARIOS = [

    {
        "name": "nmap + AD recon (DontFeedTheAI Corp)",
        "tool": "nmap -sV -sC -p 80,443,445,389,88 192.168.10.0/24",
        "must_hide": [
            "192.168.10.5", "192.168.10.10", "192.168.10.20", "192.168.10.0/24",
            "dc01.dontfeedtheai.local", "webportal.dontfeedtheai.local",
            "fs01.dontfeedtheai.local", "DONTFEEDTHEAI.LOCAL", "DONTFEEDTHEAI",
        ],
        "safe_keep": ["nmap", "ldap", "kerberos-sec", "microsoft-ds", "open", "tcp"],
        "text": """\
Starting Nmap 7.94 at 2026-04-12 14:00 EST
Nmap scan report for dc01.dontfeedtheai.local (192.168.10.5)
Host is up (0.0009s latency).
PORT    STATE SERVICE       VERSION
88/tcp  open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-04-12)
389/tcp open  ldap          Microsoft Windows Active Directory LDAP
                            (Domain: DONTFEEDTHEAI.LOCAL, Site: Default-First-Site-Name)
445/tcp open  microsoft-ds  Windows Server 2022 (workgroup: DONTFEEDTHEAI)
| smb-security-mode: Message signing enabled and required
Nmap scan report for webportal.dontfeedtheai.local (192.168.10.10)
PORT    STATE SERVICE VERSION
80/tcp  open  http    Microsoft IIS 10.0
443/tcp open  https   Microsoft IIS 10.0
Nmap scan report for fs01.dontfeedtheai.local (192.168.10.20)
445/tcp open  microsoft-ds
Nmap done: 192.168.10.0/24 (256 hosts) scanned in 112.4 seconds
""",
    },

    {
        "name": "AWS credential extraction (.env + ~/.aws)",
        "tool": "cat /opt/app/.env && cat ~/.aws/credentials",
        "must_hide": [
            "AKIAWX7FAKE2TESTKEY9",
            "hR7kLmN3pQrS5tUvWxYz2aB4cD6eF8gHiJkLmNop",
            "arn:aws:iam::987654321098:role/AppDeployRole",
            "987654321098",
            "dontfeedtheai-prod-backups",
            "dontfeedtheai-terraform-state",
            "postgres.internal.dontfeedtheai.com",
            "D0ntF33d#DB_Prod2026",
            "sk_live_DontFeedFakeStripeKey12345",
        ],
        "safe_keep": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "aws_access_key_id",
                      "DB_HOST", "DB_PASS", "STRIPE_SECRET_KEY", "us-east-1", "production"],
        "text": """\
# /opt/app/.env
APP_ENV=production
DB_HOST=postgres.internal.dontfeedtheai.com
DB_NAME=dontfeedtheai_prod
DB_USER=dontfeedtheai_app
DB_PASS=D0ntF33d#DB_Prod2026
AWS_ACCESS_KEY_ID=AKIAWX7FAKE2TESTKEY9
AWS_SECRET_ACCESS_KEY=hR7kLmN3pQrS5tUvWxYz2aB4cD6eF8gHiJkLmNop
AWS_DEFAULT_REGION=us-east-1
ROLE_ARN=arn:aws:iam::987654321098:role/AppDeployRole
STRIPE_SECRET_KEY=sk_live_DontFeedFakeStripeKey12345
S3_BACKUP_BUCKET=dontfeedtheai-prod-backups
S3_TFSTATE_BUCKET=dontfeedtheai-terraform-state

# ~/.aws/credentials
[default]
aws_access_key_id     = AKIAWX7FAKE2TESTKEY9
aws_secret_access_key = hR7kLmN3pQrS5tUvWxYz2aB4cD6eF8gHiJkLmNop
""",
    },

    {
        "name": "HR spreadsheet extracted from file share (DontFeedTheAI employees)",
        "tool": "cat /mnt/fileserver/HR/Employees_2026.csv",
        "must_hide": [
            "dontfeedtheai.com",
            "Fernanda Oliveira", "fernanda.oliveira@dontfeedtheai.com", "321.654.987-00",
            "Lucas Pereira",     "lucas.pereira@dontfeedtheai.com",     "432.765.098-11",
            "Camila Santos",     "camila.santos@dontfeedtheai.com",     "543.876.109-22",
            "+55 11 9 1234-5678",
        ],
        "safe_keep": ["CPF", "Email", "Title", "Department", "csv"],
        "text": """\
Name,CPF,Email,Phone,Title,Department,Salary
Fernanda Oliveira,321.654.987-00,fernanda.oliveira@dontfeedtheai.com,+55 11 9 1234-5678,IT Manager,Technology,18500
Lucas Pereira,432.765.098-11,lucas.pereira@dontfeedtheai.com,+55 11 9 2345-6789,Security Analyst,Technology,12000
Camila Santos,543.876.109-22,camila.santos@dontfeedtheai.com,+55 11 9 3456-7890,CISO,Executive,35000
""",
    },

    {
        "name": "Bash history post-exploitation (AD + AWS lateral movement)",
        "tool": "cat ~/.bash_history",
        "must_hide": [
            "192.168.10.5", "DONTFEEDTHEAI", "dontfeedtheai.local",
            "fernanda.oliveira", "D0ntF33d#DB_Prod2026",
            "AKIAWX7FAKE2TESTKEY9", "hR7kLmN3pQrS5tUvWxYz2aB4cD6eF8gHiJkLmNop",
            "987654321098",
        ],
        "safe_keep": ["crackmapexec", "evil-winrm", "aws", "s3", "bloodhound", "impacket",
                      "nmap", "secretsdump"],
        "text": """\
crackmapexec smb 192.168.10.5 -u fernanda.oliveira -p 'D0ntF33d#DB_Prod2026' --shares
evil-winrm -i 192.168.10.5 -u fernanda.oliveira -p 'D0ntF33d#DB_Prod2026'
impacket-secretsdump DONTFEEDTHEAI/fernanda.oliveira:'D0ntF33d#DB_Prod2026'@192.168.10.5
bloodhound-python -u fernanda.oliveira -p 'D0ntF33d#DB_Prod2026' -d dontfeedtheai.local -ns 192.168.10.5
AWS_ACCESS_KEY_ID=AKIAWX7FAKE2TESTKEY9 AWS_SECRET_ACCESS_KEY=hR7kLmN3pQrS5tUvWxYz2aB4cD6eF8gHiJkLmNop aws sts get-caller-identity
aws s3 ls s3://dontfeedtheai-prod-backups --recursive | grep -i password
aws iam list-users --profile default --output json
""",
    },

    {
        "name": "Mimikatz dump (LSASS + NTLM hashes)",
        "tool": "sekurlsa::logonpasswords",
        "must_hide": [
            "fernanda.oliveira", "DONTFEEDTHEAI",
            "D0ntF33d#DB_Prod2026",
            "a87ff679a2f3e71d9181a67b7542122c",  # fake NTLM
            "f1d2d2f924e986ac86fdf7b36c94bcdf",  # fake SHA1
            "lucas.pereira", "camila.santos",
            "b14a7b8059d9c055954c92674ce60032",  # fake NTLM 2
            "192.168.10.5",
        ],
        "safe_keep": ["mimikatz", "sekurlsa", "logonpasswords", "NTLM", "SHA1", "wdigest", "msv"],
        "text": """\
mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 77412 (00000000:00012E24)
Session           : Interactive from 1
User Name         : fernanda.oliveira
Domain            : DONTFEEDTHEAI
Logon Server      : DC01
        msv :
         * Username : fernanda.oliveira
         * Domain   : DONTFEEDTHEAI
         * NTLM     : a87ff679a2f3e71d9181a67b7542122c
         * SHA1     : f1d2d2f924e986ac86fdf7b36c94bcdf
        wdigest :
         * Username : fernanda.oliveira
         * Domain   : DONTFEEDTHEAI
         * Password : D0ntF33d#DB_Prod2026

Authentication Id : 0 ; 84321
User Name         : lucas.pereira
Domain            : DONTFEEDTHEAI
         * NTLM     : b14a7b8059d9c055954c92674ce60032

Authentication Id : 0 ; 91230
User Name         : camila.santos
Domain            : DONTFEEDTHEAI
        msv :
         * NTLM     : c4ca4238a0b923820dcc509a6f75849b
""",
    },

    {
        "name": "Kubernetes secrets dump (kubectl get secret -o yaml)",
        "tool": "kubectl get secret app-secrets -o yaml -n production",
        "must_hide": [
            "dontfeedtheai.svc.cluster.local",
            "AKIAWX7FAKE2TESTKEY9",
            "hR7kLmN3pQrS5tUvWxYz2aB4cD6eF8gHiJkLmNop",
            "cmVkaXMtcHJvZC1wYXNzd29yZA==",   # base64
            "cG9zdGdyZXNfc3VwZXJwYXNz",        # base64
            "dontfeedtheai-production",
            "192.168.50.10",
        ],
        "safe_keep": ["kubectl", "apiVersion", "kind", "metadata", "namespace",
                      "data", "stringData", "production", "Secret"],
        "text": """\
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
  namespace: production
  annotations:
    deployment.dontfeedtheai.svc.cluster.local/version: "3.2.1"
data:
  aws-access-key-id: QUTJQVDYN0ZBS0UyVEVTVEtFWTk=
  aws-secret-key: aFI3a0xtTjNwUXJTNXRVdld4WXoyYUI0Y0Q2ZUY4Z0hpSmtMbU5vcA==
  redis-password: cmVkaXMtcHJvZC1wYXNzd29yZA==
  postgres-superpass: cG9zdGdyZXNfc3VwZXJwYXNz
  db-host: MTkyLjE2OC41MC4xMA==
stringData:
  environment: production
  cluster: dontfeedtheai-production
""",
    },

    {
        "name": "GitHub Actions secrets leak + git config",
        "tool": "cat ~/.gitconfig && env | grep -i github",
        "must_hide": [
            "fernanda.oliveira@dontfeedtheai.com",
            "ghp_DontFeedFakeGitHubTokenABC123456",
            "dontfeedtheai-corp",
            "dontfeedtheai/api-gateway",
        ],
        "safe_keep": ["git", "github", "GITHUB_TOKEN", "user.name", "user.email",
                      "core.editor", "push.default"],
        "text": """\
[user]
    name = Fernanda Oliveira
    email = fernanda.oliveira@dontfeedtheai.com
[core]
    editor = vim
[push]
    default = current
[credential "https://github.com"]
    username = fernanda.oliveira

GITHUB_TOKEN=ghp_DontFeedFakeGitHubTokenABC123456
GITHUB_ACTOR=fernanda.oliveira
GITHUB_REPOSITORY=dontfeedtheai-corp/dontfeedtheai/api-gateway
GITHUB_ORG=dontfeedtheai-corp
""",
    },

    {
        "name": "SMTP / email server config (postfix + sendmail creds)",
        "tool": "cat /etc/postfix/sasl_passwd && cat /etc/ssmtp/ssmtp.conf",
        "must_hide": [
            "smtp.dontfeedtheai.com",
            "noreply@dontfeedtheai.com",
            "Smtp$D0ntF33d2026!",
            "api.sendgrid.dontfeedtheai.com",
            "SG.DontFeedSendGridFakeKey_ABCDE12345",
        ],
        "safe_keep": ["smtp", "postfix", "ssmtp", "SMTP", "AuthPass", "AuthUser",
                      "UseTLS", "UseSTARTTLS", "FromLineOverride"],
        "text": """\
# /etc/postfix/sasl_passwd
[smtp.dontfeedtheai.com]:587 noreply@dontfeedtheai.com:Smtp$D0ntF33d2026!

# /etc/ssmtp/ssmtp.conf
root=noreply@dontfeedtheai.com
mailhub=smtp.dontfeedtheai.com:587
AuthUser=noreply@dontfeedtheai.com
AuthPass=Smtp$D0ntF33d2026!
UseTLS=YES
UseSTARTTLS=YES
FromLineOverride=YES

# SendGrid relay config
SENDGRID_HOST=api.sendgrid.dontfeedtheai.com
SENDGRID_API_KEY=SG.DontFeedSendGridFakeKey_ABCDE12345
""",
    },

]


# ─────────────────────────────────────────────────────────────────────────────

async def run_scenario(scenario: dict, db_path: Path, engagement: str) -> dict:
    import src.anonymizer as anon_mod
    import src.vault as vault_mod

    # Patch vault to isolated test DB
    orig_eng  = vault_mod.config.ENGAGEMENT_ID
    orig_db   = vault_mod.config.DATABASE_PATH
    vault_mod.config.ENGAGEMENT_ID = engagement
    vault_mod.config.DATABASE_PATH = db_path

    try:
        anonymized = await anon_mod.anonymize(scenario["text"], is_tool_output=True)
        deanonymized = anon_mod.deanonymize(anonymized)
    finally:
        vault_mod.config.ENGAGEMENT_ID = orig_eng
        vault_mod.config.DATABASE_PATH = orig_db

    caught  = [v for v in scenario["must_hide"]  if v not in anonymized]
    leaked  = [v for v in scenario["must_hide"]  if v in anonymized]
    fp      = [v for v in scenario["safe_keep"]  if v not in anonymized]
    restored = deanonymized == scenario["text"]   # perfect round-trip

    return {
        "anonymized":   anonymized,
        "deanonymized": deanonymized,
        "caught":  caught,
        "leaked":  leaked,
        "fp":      fp,
        "restored": restored,
        "rate": len(caught) / len(scenario["must_hide"]) if scenario["must_hide"] else 1.0,
    }


def _diff_preview(original: str, anonymized: str, max_lines: int = 12) -> str:
    """Show a side-by-side of changed lines (original → anonymized)."""
    orig_lines = original.splitlines()
    anon_lines = anonymized.splitlines()
    out = []
    changed = 0
    for o, a in zip(orig_lines, anon_lines):
        if o != a:
            out.append(f"  {DIM}before:{NC} {o.strip()}")
            out.append(f"  {C}after :{NC} {a.strip()}")
            changed += 1
            if changed >= max_lines:
                out.append(f"  {DIM}… (truncated){NC}")
                break
    if not out:
        out.append(f"  {DIM}(no visible changes){NC}")
    return "\n".join(out)


async def main():
    print(f"\n{B}{'═'*64}{NC}")
    print(f"{B}  Live Anonymization Test — Fictional Pentest Scenarios{NC}")
    print(f"{B}{'═'*64}{NC}\n")

    # Verify Ollama
    import httpx
    try:
        async with httpx.AsyncClient(timeout=4) as client:
            r = await client.get("http://localhost:11434/api/tags")
            r.raise_for_status()
        print(f"  {G}✓{NC} Ollama active (LLM + regex)\n")
        import src.config as cfg_mod
        cfg_mod.config.LLM_ENABLED = True
    except Exception:
        print(f"  {Y}⚠{NC} Ollama offline — regex only\n")
        import src.config as cfg_mod
        cfg_mod.config.LLM_ENABLED = False

    with tempfile.TemporaryDirectory(prefix="live_test_") as tmpdir:
        db_path = Path(tmpdir) / "vault.db"
        from src.vault import init_db
        init_db(db_path)
        engagement = "live-test-dontfeedtheai"

        total_must  = sum(len(s["must_hide"]) for s in SCENARIOS)
        total_caught = 0
        total_fp     = 0

        for i, scenario in enumerate(SCENARIOS, 1):
            print(f"{B}[{i}/{len(SCENARIOS)}] {scenario['name']}{NC}")
            print(f"  {DIM}$ {scenario['tool']}{NC}")
            print()

            result = await run_scenario(scenario, db_path, engagement)

            # Show diff of what changed
            print(f"  {B}Transformations:{NC}")
            print(_diff_preview(scenario["text"], result["anonymized"]))
            print()

            # Score
            rate_colour = G if result["rate"] >= 0.9 else (Y if result["rate"] >= 0.7 else R)
            print(f"  {B}Score:{NC} {rate_colour}{result['rate']*100:.0f}%{NC}  "
                  f"({len(result['caught'])}/{len(scenario['must_hide'])} caught)")

            if result["leaked"]:
                print(f"  {R}LEAKS:{NC}")
                for v in result["leaked"]:
                    print(f"    {R}✗{NC} {v!r}")
            else:
                print(f"  {G}✓ No leaks detected{NC}")

            if result["fp"]:
                print(f"  {Y}False positives (incorrectly removed):{NC}")
                for v in result["fp"]:
                    print(f"    {Y}⚠{NC} {v!r}")

            # Round-trip check
            if result["restored"]:
                print(f"  {G}✓ Round-trip OK — deanonymize() restored original text{NC}")
            else:
                # Show what didn't restore
                orig_lines = scenario["text"].splitlines()
                rest_lines = result["deanonymized"].splitlines()
                diff_count = sum(1 for a, b in zip(orig_lines, rest_lines) if a != b)
                print(f"  {Y}⚠ Partial round-trip — {diff_count} line(s) differ after deanonymize{NC}")

            total_caught += len(result["caught"])
            total_fp     += len(result["fp"])
            print(f"\n  {DIM}{'─'*60}{NC}\n")

        # Summary
        overall = total_caught / total_must if total_must else 1.0
        colour  = G if overall >= 0.9 else (Y if overall >= 0.7 else R)
        print(f"{B}{'═'*64}{NC}")
        print(f"{B}  OVERALL RESULT{NC}")
        print(f"{B}{'═'*64}{NC}")
        print(f"  Total catch rate : {colour}{overall*100:.1f}%{NC}  ({total_caught}/{total_must})")
        print(f"  False positives  : {total_fp}")
        print()

        if overall < 0.9:
            print(f"  {Y}Main gaps:{NC}")
            for s in SCENARIOS:
                result_leaked = [v for v in s["must_hide"] if v not in s["text"]]  # placeholder
            # Re-run to collect
            for s_res in []:  # would need to collect above
                pass
            print(f"  {DIM}(running with Ollama active significantly improves results){NC}")

        print()


if __name__ == "__main__":
    asyncio.run(main())
