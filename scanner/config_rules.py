import re
from typing import List, Dict

RULES = [
    {
        "id": "DEBUG_MODE",
        "desc": "Debug mode enabled in production (e.g., Flask/Django).",
        "regex": re.compile(r"(?i)debug\s*=\s*(True|1)"),
        "severity": "high",
        "fix": "Set DEBUG=False in production and guard with environment variables.",
        "refs": ["OWASP A05: Security Misconfiguration"]
    },
    {
        "id": "OPEN_HOSTS",
        "desc": "Overly permissive ALLOWED_HOSTS / CORS settings (\"*\").",
        "regex": re.compile(r"(?i)(allowed_hosts|cors_allowed_origins)[^\n]*\*"),
        "severity": "medium",
        "fix": "Specify exact hosts/origins; never use wildcard in production.",
        "refs": ["OWASP A01/A05", "CWE-16 Configuration"]
    },
    {
        "id": "HARDCODED_SECRET",
        "desc": "Hardcoded secret, API key, or password found in code.",
        "regex": re.compile(
            r"(?i)(api[_\-]?key|secret[_\-]?key|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9_\-\/=]{8,}['\"]?"
        ),
        "severity": "critical",
        "fix": "Move hardcoded credentials to a .env file and load securely with environment variables.",
        "refs": ["OWASP A02: Cryptographic Failures", "CWE-798: Hardcoded Credentials"]
    },
]

def scan_text(path: str, text: str) -> List[Dict]:
    findings = []
    for rule in RULES:
        for m in rule["regex"].finditer(text):
            findings.append({
                "id": rule["id"],
                "path": path,
                "desc": rule["desc"],
                "severity": rule["severity"],
                "fix": rule["fix"],
                "ref": ", ".join(rule["refs"])
            })
    return findings
