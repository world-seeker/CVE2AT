"""Helpers shared by the CVE tabulator and the formatted-workbook builder."""
from __future__ import annotations

import json
from pathlib import Path


def cve_json_files(directory) -> list:
    """All CVE json files in a folder, sorted so every run is deterministic."""
    d = Path(directory)
    return sorted(p for p in d.iterdir() if p.suffix == ".json") if d.is_dir() else []


def load_cve(path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def parse_cpe(cpe_str: str):
    """Parse CPE 2.3 URI into (vendor, product, version)."""
    parts = cpe_str.split(":")
    vendor = parts[3] if len(parts) > 3 else "N/A"
    product = parts[4] if len(parts) > 4 else "N/A"
    version = parts[5] if len(parts) > 5 else "N/A"
    return vendor.replace("_", " ").title(), product.replace("_", " ").title(), version


def _cvss_v3(version: str, raw: dict) -> dict:
    d = raw["cvssData"]
    return {
        "CVSS Version": version,
        "baseScore": d.get("baseScore"), "baseSeverity": d.get("baseSeverity"),
        "attackVector": d.get("attackVector"), "attackComplexity": d.get("attackComplexity"),
        "privilegesRequired": d.get("privilegesRequired"), "userInteraction": d.get("userInteraction"),
        "scope": d.get("scope"), "confidentialityImpact": d.get("confidentialityImpact"),
        "integrityImpact": d.get("integrityImpact"), "availabilityImpact": d.get("availabilityImpact"),
        "exploitabilityScore": raw.get("exploitabilityScore"), "impactScore": raw.get("impactScore"),
        "vectorString": d.get("vectorString"),
    }


def extract_cvss(metrics: dict) -> dict:
    """Normalised CVSS fields from a CVE's 'metrics' block, preferring v3.1, then v3.0, then v2.0."""
    if "cvssMetricV31" in metrics:
        return _cvss_v3("3.1", metrics["cvssMetricV31"][0])
    if "cvssMetricV30" in metrics:
        return _cvss_v3("3.0", metrics["cvssMetricV30"][0])
    if "cvssMetricV2" in metrics:
        raw = metrics["cvssMetricV2"][0]
        d = raw["cvssData"]
        return {
            "CVSS Version": "2.0",
            "baseScore": d.get("baseScore"), "baseSeverity": raw.get("baseSeverity"),
            "attackVector": d.get("accessVector"), "attackComplexity": d.get("accessComplexity"),
            "privilegesRequired": d.get("authentication"),
            "userInteraction": "REQUIRED" if raw.get("userInteractionRequired") else "NONE",
            "scope": "N/A",
            "confidentialityImpact": d.get("confidentialityImpact"),
            "integrityImpact": d.get("integrityImpact"),
            "availabilityImpact": d.get("availabilityImpact"),
            "exploitabilityScore": raw.get("exploitabilityScore"), "impactScore": raw.get("impactScore"),
            "vectorString": d.get("vectorString"),
        }
    return {}


def english_description(data: dict, default: str = "N/A") -> str:
    return next((d.get("value", default) for d in data.get("descriptions", [])
                 if d.get("lang") == "en"), default)


# exposure tags from the CVE description
# Tags come from a fixed keyword list applied to the CVE description. They are extra
# information for the node metadata panel; they never split a leaf and are not evidence for a path.
EXPOSURE_TAG_PATTERNS = {
    "FTP": r"\bftp\b",
    "Telnet": r"\btelnet\b",
    "SSH": r"\bssh\b",
    "HTTP/web": r"\bhttps?\b|\bweb (server|interface|application|page)\b|\bweb\b",
    "TFTP": r"\btftp\b",
    "SNMP": r"\bsnmp\b",
    "Modbus": r"\bmodbus\b",
    "UMAS": r"\bumas\b",
    "OPC": r"\bopc\b",
    "EtherNet/IP": r"ethernet/ip",
    "S7": r"\bs7\b|\bs7comm\b",
    "DNP3": r"\bdnp3\b",
    "CIP": r"\bcip protocol\b|common industrial protocol",
    "Wi-Fi/wireless": r"wi-?fi|wireless|\b802\.11\b",
    "Keypad/physical": r"keypad|physical(?:ly)? (?:access|entered)|front panel|console port|debug port",
    "Serial/USB/debug": r"\busb\b|\buart\b|\bserial\b",
    "Bluetooth": r"\bbluetooth\b",
    "SMB/RDP/VNC": r"\bsmb\b|\brdp\b|\bvnc\b",
    "DHCP/DNS/NTP": r"\bdhcp\b|\bdns\b|\bntp\b",
    "Cleartext": r"clear-?text|unencrypted|plain-?text",
    "Session/token": r"\bsession\b|\btoken\b|\bcookie\b",
}


def exposure_tags(description: str) -> list:
    """Interface/exposure tags found in a CVE description, as a sorted list (empty when none
    match). Plain keyword matching, so the result is repeatable.
    """
    import re
    text = str(description or "").lower()
    return sorted(name for name, pattern in EXPOSURE_TAG_PATTERNS.items() if re.search(pattern, text))