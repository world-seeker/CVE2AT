"""Stage 2a: tabulate the CVE json files into cve_data.xlsx (the curation table)."""
from __future__ import annotations

import pandas as pd

from . import console
from .config import Workspace
from .cve_parse import cve_json_files, exposure_tags, extract_cvss, english_description, load_cve
from .errors import PipelineError

COLUMNS = [
    "CVE ID", "Description", "Weaknesses",
    "baseScore", "baseSeverity", "attackVector", "attackComplexity", "privilegesRequired",
    "userInteraction", "confidentialityImpact", "integrityImpact", "availabilityImpact",
    "exploitabilityScore", "CVSS Version", "exposure_tags",
]

# CWE placeholders NVD uses when there is no real weakness class - not useful for CAPEC mapping.
_NON_CWE = ("NVD-CWE-noinfo", "NVD-CWE-Other")


def _weakness_values(data: dict) -> list:
    """First English description of every weakness entry (one per CWE)."""
    values = []
    for weakness in data.get("weaknesses", []):
        for desc in weakness.get("description", []):
            if desc.get("lang") == "en":
                values.append(desc.get("value", ""))
                break
    return values


def clean_weaknesses(values) -> str:
    """De-duplicate, drop NVD-CWE-noinfo / NVD-CWE-Other, sort, join with '; '.
    Returns '' when no real CWE is left (those CVEs cannot be mapped further)."""
    items = {v for v in values if v}
    for placeholder in _NON_CWE:
        items.discard(placeholder)
    return "; ".join(sorted(items))


def tabulate_cves(ws: Workspace) -> pd.DataFrame:
    files = cve_json_files(ws.cve_dir)
    if not files:
        raise PipelineError(f"No CVE json files in '{ws.cve_dir}'. Run the fetch stage first.")

    rows = []
    for path in files:
        data = load_cve(path)
        cvss = extract_cvss(data.get("metrics", {}))
        description = english_description(data)
        rows.append({
            "CVE ID": data.get("id"),
            "Description": description,
            "Weaknesses": clean_weaknesses(_weakness_values(data)),
            "baseScore": cvss.get("baseScore"),
            "baseSeverity": cvss.get("baseSeverity"),
            "attackVector": cvss.get("attackVector"),
            "attackComplexity": cvss.get("attackComplexity"),
            "privilegesRequired": cvss.get("privilegesRequired"),
            "userInteraction": cvss.get("userInteraction"),
            "confidentialityImpact": cvss.get("confidentialityImpact"),
            "integrityImpact": cvss.get("integrityImpact"),
            "availabilityImpact": cvss.get("availabilityImpact"),
            "exploitabilityScore": cvss.get("exploitabilityScore"),
            "CVSS Version": cvss.get("CVSS Version"),
            "exposure_tags": ", ".join(exposure_tags(description)),
        })

    df = pd.DataFrame(rows, columns=COLUMNS)
    no_cwe = int((df["Weaknesses"] == "").sum())

    df.to_excel(ws.cve_xlsx, index=False)
    console.info(f"Extracted {len(df)} CVE entries with metrics and saved to {ws.cve_xlsx}.")
    if no_cwe:
        console.info(f"{no_cwe} CVE(s) have no usable CWE (none, NVD-CWE-noinfo or NVD-CWE-Other); "
                     "they stay in the table but drop out at the CWE merge step.")
    return df