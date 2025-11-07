# scanner/scorer.py
from __future__ import annotations
from typing import Dict, List

# Severity weights for scoring
SEV_WEIGHTS = {"critical": 10, "high": 7, "medium": 4, "low": 1}


def score_findings(vulns: List[Dict], secrets: List[Dict], configs: List[Dict]) -> Dict:
    """
    Compute a unified 'Cyber Health Score' (0–100) based on vulnerabilities,
    exposed secrets, and insecure configurations.
    """
    # Helper: map OSV CVSS -> simplified severity level
    def sev_from_cvss(entry: Dict) -> str:
        # OSV severity may look like: [{"type": "CVSS_V3", "score": "9.8"}]
        score = None
        for s in entry.get("severity", []):
            try:
                score = float(s.get("score", 0))
                break
            except Exception:
                pass

        if score is None:
            return "medium"
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        return "low"

    points = 0
    details = {"vulns": [], "secrets": secrets, "configs": configs}

    # Score vulnerabilities from OSV
    for v in vulns:
        sev = sev_from_cvss(v)
        details["vulns"].append({**v, "our_severity": sev})
        points += SEV_WEIGHTS[sev]

    # Score secrets
    for s in secrets:
        sev = s.get("severity", "medium")
        points += SEV_WEIGHTS.get(sev, 4)

    # Score configs
    for c in configs:
        sev = c.get("severity", "medium")
        points += SEV_WEIGHTS.get(sev, 4)

    # Normalize to a 0–100 score (higher = better)
    # Assume 60 total points = "very bad" → score 0
    max_bad = 60
    raw = max(0, min(points, max_bad))
    score = int(round(100 - (raw / max_bad) * 100))

    return {"score": score, "points": points, "details": details}
