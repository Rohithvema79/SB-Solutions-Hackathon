# scanner/parsers.py
from __future__ import annotations
import re
from packaging.version import Version, InvalidVersion
from typing import List, Dict

# Regex pattern to match lines like:
# flask==2.1.0  OR  requests>=2.20
REQ_LINE = re.compile(
    r"^(?P<name>[A-Za-z0-9_.-]+)\s*([=~!<>]{1,2}\s*(?P<ver>[A-Za-z0-9_.+-]+))?"
)

# -------------------------------------------------------------------
# Very small parser for requirements.txt style pinned dependencies
# -------------------------------------------------------------------

def parse_requirements_txt(text: str) -> List[Dict[str, str]]:
    """
    Parse a requirements.txt-like string and extract name + version pairs.
    Only keeps dependencies with specific pinned versions.
    """
    items: List[Dict[str, str]] = []

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        m = REQ_LINE.match(line)
        if not m:
            continue

        name = m.group("name")
        ver = m.group("ver") or "*"

        # Only send pinned versions to OSV; skip wildcards
        if ver != "*":
            # Normalize version string if possible
            try:
                ver = str(Version(ver))
            except InvalidVersion:
                pass

            items.append({"name": name, "version": ver})

    return items
