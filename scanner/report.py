# scanner/report.py
from __future__ import annotations
from typing import Dict, List, Any
import re

HEADER = """\
# Cyber Health Report

This quick scan highlights risky items that map to OWASP Top 10, NIST SSDF, and CWE categories.
Fix the items in the Safe Fix Checklist to improve your score and reduce risk of leaks or downtime.
"""


# --- Helpers for friendlier language ---------------------------------------
def _vuln_remedy_text(vuln: Dict[str, Any]) -> str:
    """
    Return a short remedy like:
      "upgrade to 2.3.2 or later."
    or a generic 'check OSV' fallback.
    """
    # Prefer explicit fixed hint (string like "Upgrade to ≥ 2.0.7")
    fixed_hint = vuln.get("fixed_hint") or ""
    if fixed_hint:
        # try to extract a version number
        m = re.search(r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)", fixed_hint)
        if m:
            ver = m.group(1)
            return f"upgrade to {ver} or later."
        return fixed_hint

    # If the vuln has a 'fixed' list, choose first
    fixed_list = vuln.get("fixed") or vuln.get("fixed_versions") or []
    if fixed_list:
        ver = fixed_list[0]
        return f"upgrade to {ver} or later."

    # Fallback generic
    return "upgrade to a non-vulnerable version (see OSV)."


def _secret_short_line(s: Dict[str, Any]) -> str:
    typ = s.get("type", "").lower()
    path = s.get("path", "<file>")
    if "password" in typ or "hardcode" in typ:
        return f"🚨 Weak password detected in {path} — change immediately."
    if "aws access key" in typ or "aws secret" in typ:
        return f"🔑 AWS credentials found in {path} — rotate and move to a secret manager."
    if "google api key" in typ or "api key" in typ or "bearer token" in typ or "slack" in typ:
        return f"🔑 API key/token found in {path} — move it to a secure file or secret manager."
    if "private key" in typ:
        return f"🔐 Private key detected in {path} — remove from repo and rotate immediately."
    # generic fallback
    return f"🔑 Secret pattern ({s.get('type')}) found in {path} — remove and rotate."


def _config_short_line(c: Dict[str, Any]) -> str:
    desc = c.get("desc", "Insecure configuration")
    path = c.get("path", "<file>")
    # Map a few common IDs to friendlier text
    cid = c.get("id", "").upper()
    if "DEBUG" in cid or "DEBUG" in desc.upper():
        return f"🛠️ Debug mode enabled in {path} — disable in production (DEBUG=False)."
    if "OPEN_HOSTS" in cid or "ALLOWED_HOSTS" in desc.upper():
        return f"🛠️ Wildcard hosts/CORS in {path} — specify exact hosts/origins."
    return f"🛠️ {desc} ({path}) — {c.get('fix','Review and fix this configuration.')}"

# --- One-line findings generator ------------------------------------------
def one_liners(findings: Dict) -> List[str]:
    lines: List[str] = []

    # Vulnerabilities: findings["vulns"] expected to be a list of dicts.
    for v in findings.get("vulns", []):
        pkg = v.get("package", "package")
        version = v.get("version", "")
        # severity may be list or simplified; try to pick a friendly label
        sev = v.get("our_severity") or (v.get("severity") and ",".join([str(x) for x in v.get("severity")])) or "medium"
        remedy = _vuln_remedy_text(v)
        # friendly sentence
        lines.append(f"⚠️ {pkg} {version} is outdated — {remedy}")

    # Secrets
    for s in findings.get("secrets", []):
        lines.append(_secret_short_line(s))

    # Configs
    for c in findings.get("configs", []):
        lines.append(_config_short_line(c))

    return lines


# --- Safe Fix Checklist ---------------------------------------------------
def fix_checklist(findings: Dict) -> List[str]:
    fixes: List[str] = []

    # Secrets first (priority)
    for s in findings.get("secrets", []):
        typ = s.get("type", s.get("match", "secret"))
        path = s.get("path", "<file>")
        if "password" in typ.lower() or "hardcode" in typ.lower():
            fixes.append(f"Change the weak password found in {path}; store credentials in env vars or a password manager.")
        else:
            fixes.append(f"Rotate and remove secret: {typ} found in {path} (store in secret manager).")

    # Vulnerabilities
    for v in findings.get("vulns", []):
        pkg = v.get("package", "package")
        remedy = _vuln_remedy_text(v)
        # make checklist item concise
        fixes.append(f"Upgrade {pkg} {v.get('version','')} — {remedy}")

    # Configs
    for c in findings.get("configs", []):
        fixes.append(f"{c.get('fix','Fix configuration')} ({c.get('path','<file>')})")

    # Deduplicate preserve order
    seen = set()
    uniq: List[str] = []
    for f in fixes:
        if f not in seen:
            uniq.append(f)
            seen.add(f)
    return uniq


# --- Render full report ---------------------------------------------------
def render(score: int, findings: Dict) -> str:
    body = [HEADER, f"\n**Cyber Health Score:** {score}/100\n"]
    body.append("\n## Findings (Quick Read)\n")
    for line in one_liners(findings):
        body.append(f"- {line}")
    body.append("\n## Safe Fix Checklist\n")
    for item in fix_checklist(findings):
        body.append(f"- [ ] {item}")
    return "\n".join(body)
