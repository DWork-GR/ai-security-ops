from sqlalchemy.orm import Session

from app.database.db import SessionLocal
from app.database.models import CVE

CVE_DATA = [
    {
        "cve_id": "CVE-2021-44228",
        "cvss": 10.0,
        "severity": "CRITICAL",
        "description": "Apache Log4j JNDI lookup remote code execution (Log4Shell).",
        "mitigation": "Upgrade Log4j to 2.17.1+ and remove vulnerable lookup patterns.",
    },
    {
        "cve_id": "CVE-2017-0144",
        "cvss": 8.1,
        "severity": "HIGH",
        "description": "SMBv1 remote code execution in Microsoft Windows (EternalBlue).",
        "mitigation": "Apply MS17-010 patches and disable SMBv1 where possible.",
    },
    {
        "cve_id": "CVE-2023-34362",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "description": "MOVEit Transfer SQL injection leading to unauthorized data access.",
        "mitigation": "Upgrade MOVEit Transfer, rotate credentials, and inspect logs.",
    },
    {
        "cve_id": "CVE-2022-1388",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "description": "F5 BIG-IP iControl REST authentication bypass and command execution.",
        "mitigation": "Apply vendor fix and restrict management interfaces.",
    },
    {
        "cve_id": "CVE-2019-0708",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "description": "Remote Desktop Services pre-authentication remote code execution (BlueKeep).",
        "mitigation": "Patch affected Windows versions and limit RDP exposure.",
    },
    {
        "cve_id": "CVE-2020-1472",
        "cvss": 10.0,
        "severity": "CRITICAL",
        "description": "Netlogon privilege escalation vulnerability (Zerologon).",
        "mitigation": "Apply Microsoft Netlogon fixes and enforce secure RPC.",
    },
    {
        "cve_id": "CVE-2021-41773",
        "cvss": 7.5,
        "severity": "HIGH",
        "description": "Apache HTTP Server path traversal and file disclosure.",
        "mitigation": "Upgrade Apache HTTP Server and disable vulnerable path normalization behavior.",
    },
    {
        "cve_id": "CVE-2021-42013",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "description": "Apache HTTP Server path traversal leading to potential RCE.",
        "mitigation": "Patch Apache to secure versions and review exposed CGI handlers.",
    },
    {
        "cve_id": "CVE-2024-3094",
        "cvss": 10.0,
        "severity": "CRITICAL",
        "description": "XZ Utils backdoor affecting SSH authentication flows in compromised builds.",
        "mitigation": "Remove compromised packages and reinstall trusted versions.",
    },
    {
        "cve_id": "CVE-2018-15473",
        "cvss": 5.3,
        "severity": "MEDIUM",
        "description": "OpenSSH user enumeration via differences in authentication behavior.",
        "mitigation": "Upgrade OpenSSH and enforce strong authentication controls.",
    },
    {
        "cve_id": "CVE-2022-0543",
        "cvss": 10.0,
        "severity": "CRITICAL",
        "description": "Redis Lua sandbox escape in Debian-derived packages.",
        "mitigation": "Patch Redis packages and restrict network exposure.",
    },
    {
        "cve_id": "CVE-2020-1938",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "description": "Apache Tomcat AJP file read/inclusion issue (Ghostcat).",
        "mitigation": "Disable or secure AJP connector and update Tomcat.",
    },
    {
        "cve_id": "CVE-2022-22965",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "description": "Spring Framework expression injection (Spring4Shell).",
        "mitigation": "Upgrade Spring Framework and apply vendor hardening guidance.",
    },
    {
        "cve_id": "CVE-2023-4966",
        "cvss": 9.4,
        "severity": "CRITICAL",
        "description": "Citrix NetScaler information disclosure vulnerability (CitrixBleed).",
        "mitigation": "Update NetScaler appliances and rotate exposed session tokens.",
    },
    {
        "cve_id": "CVE-2021-34527",
        "cvss": 8.8,
        "severity": "HIGH",
        "description": "Windows Print Spooler remote code execution (PrintNightmare).",
        "mitigation": "Apply patches, disable spooler where unnecessary, and constrain printer drivers.",
    },
    {
        "cve_id": "CVE-2022-26134",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "description": "Atlassian Confluence OGNL injection with unauthenticated RCE.",
        "mitigation": "Upgrade Confluence and isolate vulnerable instances.",
    },
    {
        "cve_id": "CVE-2022-30190",
        "cvss": 7.8,
        "severity": "HIGH",
        "description": "Microsoft Support Diagnostic Tool code execution (Follina).",
        "mitigation": "Apply Microsoft updates and disable vulnerable protocol handlers.",
    },
    {
        "cve_id": "CVE-2023-23397",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "description": "Microsoft Outlook NTLM hash leak via crafted calendar/task reminder.",
        "mitigation": "Patch Outlook and audit suspicious NTLM authentication attempts.",
    },
    {
        "cve_id": "CVE-2016-10033",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "description": "PHPMailer command injection allowing remote execution.",
        "mitigation": "Upgrade PHPMailer and sanitize mail command parameters.",
    },
    {
        "cve_id": "CVE-2014-0160",
        "cvss": 7.5,
        "severity": "HIGH",
        "description": "OpenSSL Heartbleed memory disclosure vulnerability.",
        "mitigation": "Upgrade OpenSSL, revoke/replace certificates, and rotate keys.",
    },
]


def seed():
    db: Session = SessionLocal()

    for item in CVE_DATA:
        exists = db.query(CVE).filter(CVE.cve_id == item["cve_id"]).first()
        if exists:
            continue
        db.add(CVE(**item))

    db.commit()
    db.close()
    print(f"CVE data seeded successfully: {len(CVE_DATA)} records")


if __name__ == "__main__":
    seed()
