"""Synthetic stand-ins for the NVD API and the CWE, CAPEC and ATT&CK workbooks.

The universe is small on purpose, so the expected numbers are known:
  * per-tactic paths          = 9
  * earliest-tactic paths     = 7   (CWE-732 / CAPEC-17 / T1574.010 sits under 3 tactics, so 2 are pruned)
  * rows dropped as incomplete: the chain through deprecated CAPEC-7
"""
from __future__ import annotations

import pandas as pd

CPE = "cpe:2.3:h:acme:test_pump:-:*:*:*:*:*:*:*"


# fake NVD
def _weakness(*cwes):
    out = []
    for i, cwe in enumerate(cwes):
        out.append({"source": "nvd@nist.gov", "type": "Primary" if i == 0 else "Secondary",
                    "description": [{"lang": "en", "value": cwe}]})
    return out


def _v3(key, score, sev, vector="NETWORK"):
    return {key: [{"cvssData": {"baseScore": score, "baseSeverity": sev, "attackVector": vector,
                                "attackComplexity": "LOW", "privilegesRequired": "NONE",
                                "userInteraction": "NONE", "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH", "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH", "vectorString": "CVSS:3.x/AV:N"},
                   "exploitabilityScore": 3.9, "impactScore": 5.9}]}


def _v2():
    return {"cvssMetricV2": [{"cvssData": {"baseScore": 5.0, "accessVector": "NETWORK",
                                           "accessComplexity": "LOW", "authentication": "NONE",
                                           "confidentialityImpact": "PARTIAL", "integrityImpact": "NONE",
                                           "availabilityImpact": "NONE", "vectorString": "AV:N/AC:L"},
                              "baseSeverity": "MEDIUM", "userInteractionRequired": False,
                              "exploitabilityScore": 10.0, "impactScore": 2.9}]}


def _cve(cve_id, weaknesses, metrics, status="Analyzed", published="2024-01-02T10:00:00.000"):
    return {"cve": {
        "id": cve_id, "sourceIdentifier": "cve@example.org", "published": published,
        "lastModified": "2024-02-03T11:00:00.000", "vulnStatus": status,
        "descriptions": [{"lang": "es", "value": "descripcion"}, {"lang": "en", "value": f"Description of {cve_id}"}],
        "weaknesses": weaknesses, "metrics": metrics,
        "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": CPE}]}]}],
        "references": [{"url": "https://example.org/a", "tags": ["Vendor Advisory"]},
                       {"url": "https://example.org/a", "tags": ["Vendor Advisory"]}],
    }}


def fake_vulnerabilities():
    """8 CVEs: 7 usable/accepted + 1 Rejected."""
    return [
        _cve("CVE-2024-0001", _weakness("CWE-79", "CWE-20"), _v3("cvssMetricV31", 9.8, "CRITICAL")),
        _cve("CVE-2024-0002", _weakness("CWE-89"), _v3("cvssMetricV30", 7.5, "HIGH")),
        _cve("CVE-2023-0003", _weakness("CWE-287"), _v2(), published="2023-05-05T00:00:00.000"),
        _cve("CVE-2023-0004", _weakness("NVD-CWE-noinfo"), {}, published="2023-06-06T00:00:00.000"),
        _cve("CVE-2022-0005", [], {}, published="2022-07-07T00:00:00.000"),
        _cve("CVE-2022-0006", _weakness("CWE-732", "CWE-9999"), _v3("cvssMetricV31", 6.1, "MEDIUM", "LOCAL"),
             published="2022-08-08T00:00:00.000"),
        _cve("CVE-2021-0007", _weakness("CWE-400", "CWE-732"), _v3("cvssMetricV31", 5.3, "MEDIUM"),
             published="2021-09-09T00:00:00.000"),
        _cve("CVE-2021-0008", _weakness("CWE-79"), {}, status="Rejected", published="2021-10-10T00:00:00.000"),
    ]


class FakeResponse:
    def __init__(self, payload=None, status=200, text=""):
        self.status_code, self._payload, self.text = status, payload, text

    @property
    def ok(self):
        return self.status_code < 400

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


def make_fake_get(vulns, calls=None, fail_first=0, fail_status=403):
    """A stand-in for requests.Session.get that pages `vulns` like the NVD API does."""
    from urllib.parse import parse_qs, urlparse
    state = {"failed": 0}

    def fake_get(self, url, headers=None, timeout=None, **_):
        if calls is not None:
            calls.append({"url": url, "headers": headers})
        if state["failed"] < fail_first:
            state["failed"] += 1
            return FakeResponse(status=fail_status)
        q = parse_qs(urlparse(url).query)
        start, per = int(q["startIndex"][0]), int(q["resultsPerPage"][0])
        return FakeResponse({"totalResults": len(vulns), "startIndex": start,
                             "vulnerabilities": vulns[start:start + per]})
    return fake_get


# reference workbooks
_CWE_COLS = ["Name", "Abstraction", "Structure", "Status", "Description", "Extended_Description",
             "Related_Weaknesses", "Weakness_Ordinality", "Language_Name", "Technology_Class",
             "Alternate_Terms", "Alternate_Terms_With_Descriptions", "Background_Details",
             "Modes_Of_Introduction", "Likelihood_Of_Exploit", "Common_Consequences",
             "Detection_Methods", "Potential_Mitigations", "Demonstrative_Examples", "Observed_Examples"]
_CAPEC_COLS = ["Name", "Abstraction", "Status", "Description", "Extended_Description",
               "Likelihood_Of_Attack", "Typical_Severity", "Execution_Flow", "Prerequisites",
               "Skills_Required", "Resources_Required", "Consequences", "Mitigations",
               "Example_Instances", "Related_Weaknesses", "Taxonomy_Mappings"]
_TECH_COLS = ["detection", "platforms", "data sources", "defenses bypassed", "contributors",
              "permissions required", "system requirements", "effective permissions"]


def _row(cols, name, **over):
    row = {c: f"{c} of {name}" for c in cols}
    row.update(over)
    return row


def write_reference_datasets(directory):
    directory.mkdir(parents=True, exist_ok=True)

    cwe = [  # CWE_ID, name, CAPEC list
        (79, "Cross-site Scripting", "63,588"), (89, "SQL Injection", "66,7"),
        (287, "Improper Authentication", "16"), (732, "Incorrect Permission Assignment", "17"),
        (400, "Uncontrolled Resource Consumption", "125"), (20, "Improper Input Validation", ""),
    ]
    pd.DataFrame([{"CWE_ID": i, **_row(_CWE_COLS, n, Name=n), "Related_Attack_Patterns": p}
                  for i, n, p in cwe]).to_excel(directory / "cwe_data.xlsx", index=False)

    capec = [  # id, name, status, techniques
        (63, "Cross-Site Scripting", "Stable", "1059.007 - JavaScript"),
        (588, "DOM-Based XSS", "Draft", "1190 - Exploit Public-Facing Application || 1059.007 - JavaScript"),
        (66, "SQL Injection", "Stable", "1190 - Exploit Public-Facing Application"),
        (7, "Blind SQL Injection", "Deprecated", "1190 - Exploit Public-Facing Application"),
        (16, "Dictionary-based Password Attack", "Stable", "1110 - Brute Force"),
        (17, "Using Malicious Files", "Stable", "1574.010 - Services File Permissions Weakness"),
        (125, "Flooding", "Stable", "1499 - Endpoint Denial of Service"),
    ]
    pd.DataFrame([{"CAPEC_ID": i, **_row(_CAPEC_COLS, n, Name=n, Status=s), "Mitre_Techniques": t}
                  for i, n, s, t in capec]).to_excel(directory / "capec_data.xlsx", index=False)

    persist = "Persistence, Privilege Escalation, Defense Evasion"
    tech = [  # ID, name, tactics
        ("T1190", "Exploit Public-Facing Application", "Initial Access"),
        ("T1059", "Command and Scripting Interpreter", "Execution"),
        ("T1059.007", "JavaScript", "Execution"),
        ("T1110", "Brute Force", "Credential Access"),
        ("T1574", "Hijack Execution Flow", persist),
        ("T1574.010", "Services File Permissions Weakness", persist),
        ("T1499", "Endpoint Denial of Service", "Impact"),
    ]
    pd.DataFrame([{"ID": i, "name": n, "description": f"About {n}", "tactics": t,
                   **{c: f"{c} of {n}" for c in _TECH_COLS}, "supports remote": 1, "impact type": "Availability"}
                  for i, n, t in tech]).to_excel(directory / "techniques.xlsx", index=False)
