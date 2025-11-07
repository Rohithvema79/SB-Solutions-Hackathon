# scanner/osv_client.py (updated flatten_vulns)

from __future__ import annotations
import requests
from typing import List, Dict, Any

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_QUERY_BATCH_URL = "https://api.osv.dev/v1/querybatch"


class OSVClient:
    def __init__(self, session: requests.Session | None = None, timeout: int = 15):
        self.s = session or requests.Session()
        self.timeout = timeout

    def query_pkg(self, name: str, version: str, ecosystem: str = "PyPI") -> Dict[str, Any]:
        payload = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
        r = self.s.post(OSV_QUERY_URL, json=payload, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def query_batch(self, items: List[Dict[str, str]], ecosystem: str = "PyPI") -> List[Dict[str, Any]]:
        queries = [
            {"package": {"name": it["name"], "ecosystem": ecosystem}, "version": it["version"]}
            for it in items
        ]
        r = self.s.post(OSV_QUERY_BATCH_URL, json={"queries": queries}, timeout=self.timeout)
        r.raise_for_status()
        data = r.json()
        results = []
        for i, q in enumerate(items):
            vulns = data.get("results", [{}])[i].get("vulns", []) if data else []
            results.append({"name": q["name"], "version": q["version"], "vulns": vulns})
        return results

    @staticmethod
    def flatten_vulns(batch_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Flattens OSV batch results into simplified vulnerability entries
        while deduplicating and adding 'fixed' version info if available.
        """
        flat: List[Dict[str, Any]] = []
        seen_ids = set()

        for r in batch_results:
            pkg = r["name"]
            ver = r["version"]
            vulns = r.get("vulns", [])
            for v in vulns:
                vid = v.get("id")
                if vid in seen_ids:
                    continue
                seen_ids.add(vid)

                # extract fixed version info
                fixed_versions = []
                for aff in v.get("affected", []):
                    for rng in aff.get("ranges", []):
                        for event in rng.get("events", []):
                            if "fixed" in event:
                                fixed_versions.append(event["fixed"])

                fixed_hint = ""
                if fixed_versions:
                    fixed_hint = f"Upgrade to ≥ {fixed_versions[0]}"

                flat.append(
                    {
                        "package": pkg,
                        "version": ver,
                        "id": vid,
                        "aliases": v.get("aliases", []),
                        "summary": v.get("summary", ""),
                        "severity": v.get("severity", []),
                        "fixed": fixed_versions,
                        "fixed_hint": fixed_hint,
                    }
                )

        # Merge multiple advisories for the same package into one entry with IDs combined
        merged: Dict[str, Dict] = {}
        for v in flat:
            key = (v["package"], v["version"])
            if key not in merged:
                merged[key] = {
                    "package": v["package"],
                    "version": v["version"],
                    "ids": [v["id"]],
                    "aliases": v["aliases"],
                    "summary": v["summary"],
                    "severity": v["severity"],
                    "fixed_hint": v["fixed_hint"],
                }
            else:
                merged[key]["ids"].append(v["id"])

        # Convert merged dict to list
        return [
            {
                "package": v["package"],
                "version": v["version"],
                "ids": v["ids"],
                "summary": v["summary"],
                "severity": v["severity"],
                "fixed_hint": v.get("fixed_hint", ""),
            }
            for v in merged.values()
        ]
