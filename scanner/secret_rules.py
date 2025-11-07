# scanner/secret_rules.py
import re
from typing import List, Dict

PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    (
        "AWS Secret Key",
        re.compile(
            r"(?i)aws(.{0,20})?(secret|sk|secret_access_key)\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?"
        ),
    ),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Generic Bearer Token", re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*")),
    ("Slack Token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,48}")),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----")),
    (
        "Password Hardcode",
        re.compile(
            r"(?i)password\s*[:=]\s*['\"]?(admin123|12345|password|qwerty|letmein)['\"]?"
        ),
    ),
]

# Directories and file types to skip when scanning
SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv"}
SKIP_EXT = {"jpg", "jpeg", "png", "gif", "woff", "woff2", "ttf", "otf", "min.js"}


def scan_text(path: str, text: str) -> List[Dict]:
    """
    Scan a given text for secret patterns (API keys, tokens, passwords, etc.)
    Returns a list of finding dicts.
    """
    findings: List[Dict] = []
    for name, rx in PATTERNS:
        for m in rx.finditer(text):
            snippet = text[max(0, m.start() - 20) : m.end() + 20]
            findings.append(
                {
                    "type": name,
                    "path": path,
                    "match": m.group(0)[:8] + "…",  # don’t leak real secrets
                    "severity": "critical" if "Private Key" in name else "high",
                    "fix": _fix_for(name),
                }
            )
    return findings


def _fix_for(name: str) -> str:
    """
    Suggests a recommended fix for each secret type.
    """
    mapping = {
        "Private Key": "Remove the private key from the repo, rotate it, and store in a secret manager.",
        "AWS Access Key": "Rotate the key, invalidate the old one, and move to environment variables or a secret manager.",
        "AWS Secret Key": "Same as above; use IAM roles where possible.",
        "Google API Key": "Regenerate the key, restrict by IP/referrer, and use environment variables or a secret manager.",
        "Generic Bearer Token": "Revoke the token and load it at runtime via environment variables.",
        "Slack Token": "Regenerate and store securely; use a vault or secret manager.",
        "Password Hardcode": "Use a strong unique password via an environment variable or password manager.",
    }
    return mapping.get(name, "Remove from source, rotate, and load via env/secret manager.")
