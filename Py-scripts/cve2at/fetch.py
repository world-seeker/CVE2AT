"""Stage 1: CPE name -> CVE json files.

Queries the NVD CVE API 2.0 for every CVE attached to one CPE name and writes each CVE to its
own json file: accepted CVEs to cve_data/, Rejected ones to rejected_cve_data/.
"""
from __future__ import annotations

import json
import os
import shutil
import time
from urllib.parse import quote

import requests

from . import console
from .config import Workspace
from .cve_parse import cve_json_files, load_cve
from .errors import FetchError

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_DELAY = 6.0            # NVD allows 5 requests / 30 s without an API key
DEFAULT_DELAY_WITH_KEY = 0.6   # ... and 50 requests / 30 s with one
RETRYABLE_STATUS = {403, 429, 500, 502, 503, 504}   # NVD answers 403 when rate limited
RETRY_WAIT = 10.0              # seconds, multiplied by the attempt number


def _get_json(session, url, headers, timeout, max_retries):
    """GET one page, retrying on rate-limit / transient errors. Raises FetchError when it gives up."""
    for attempt in range(max_retries + 1):
        last = attempt == max_retries
        wait = RETRY_WAIT * (attempt + 1)
        try:
            resp = session.get(url, headers=headers, timeout=timeout)
        except requests.exceptions.RequestException as e:
            if last:
                raise FetchError(f"Could not reach the NVD API: {e}") from e
            console.warn(f"Network error ({e}); retrying in {wait:.0f}s...")
            time.sleep(wait)
            continue

        if resp.status_code in RETRYABLE_STATUS:
            if last:
                raise FetchError(
                    f"NVD API kept answering HTTP {resp.status_code}. "
                    "If this is rate limiting, wait a minute or use an API key (--api-key / NVD_API_KEY)."
                )
            console.warn(f"NVD API answered HTTP {resp.status_code}; retrying in {wait:.0f}s...")
            time.sleep(wait)
            continue

        if not resp.ok:
            raise FetchError(
                f"NVD API answered HTTP {resp.status_code}. "
                "Check that the CPE name is an exact entry in the NVD CPE dictionary."
            )
        try:
            return resp.json()
        except ValueError as e:
            raise FetchError(f"NVD API returned something that is not JSON: {e}") from e
    raise FetchError("unreachable")  # pragma: no cover


def fetch_cves_by_cpe(cpe_name, results_per_page=2000, delay=DEFAULT_DELAY,
                      api_key=None, max_retries=3, timeout=30):
    """Fetch every CVE for a CPE name (pages through the results). Returns the raw 'vulnerabilities' list."""
    encoded_cpe = quote(cpe_name, safe="")
    headers = {"apiKey": api_key} if api_key else {}
    session = requests.Session()

    all_vulnerabilities = []
    start_index = 0

    console.info(f"Fetching CVEs for CPE: {cpe_name}")
    console.info(f"Using delay of {delay} seconds between requests...")

    while True:
        url = (f"{NVD_URL}?cpeName={encoded_cpe}"
               f"&resultsPerPage={results_per_page}&startIndex={start_index}")
        console.info(f"Fetching results starting from index {start_index}...")

        data = _get_json(session, url, headers, timeout, max_retries)
        vulnerabilities = data.get("vulnerabilities", [])
        total_results = data.get("totalResults", 0)
        console.info(f"Retrieved {len(vulnerabilities)} CVEs (Total: {total_results})")

        if not vulnerabilities:
            break
        all_vulnerabilities.extend(vulnerabilities)
        if len(all_vulnerabilities) >= total_results:
            break

        start_index += results_per_page
        console.info(f"Waiting {delay} seconds before next request...")
        time.sleep(delay)

    console.info(f"Total CVEs fetched: {len(all_vulnerabilities)}")
    return all_vulnerabilities


def _clear_json(directory) -> None:
    for p in cve_json_files(directory):
        p.unlink()


def process_and_save_cves(cpe_name, ws: Workspace, **fetch_kwargs) -> dict:
    """Fetch CVEs by CPE and organise them into accepted / rejected folders of this workspace."""
    vulnerabilities = fetch_cves_by_cpe(cpe_name, **fetch_kwargs)   # raises before touching any files

    ws.ensure()
    ws.cve_dir.mkdir(parents=True, exist_ok=True)
    ws.rejected_dir.mkdir(parents=True, exist_ok=True)
    # The workspace belongs to this CPE, so replace any previous fetch instead of mixing runs.
    _clear_json(ws.cve_dir)
    _clear_json(ws.rejected_dir)

    if not vulnerabilities:
        console.info("No CVEs found for the specified CPE.")
        return {"total": 0, "accepted": 0, "rejected": 0}

    accepted = rejected = 0
    console.info("\nProcessing and saving CVEs...")
    for vuln in vulnerabilities:
        cve_data = vuln.get("cve", {})
        cve_id = cve_data.get("id", "UNKNOWN")
        if cve_data.get("vulnStatus", "") == "Rejected":
            target_dir = ws.rejected_dir
            rejected += 1
        else:
            target_dir = ws.cve_dir
            accepted += 1
        try:
            with open(target_dir / f"{cve_id}.json", "w", encoding="utf-8") as f:
                json.dump(cve_data, f, indent=2, ensure_ascii=False)
        except OSError as e:
            console.warn(f"Error saving {cve_id}: {e}")

    total = len(vulnerabilities)
    console.info("=== PROCESSING COMPLETE ===")
    console.info(f"Total CVEs processed: {total}")
    console.info(f"Accepted CVEs saved to '{ws.cve_dir}': {accepted}")
    console.info(f"Rejected CVEs saved to '{ws.rejected_dir}': {rejected}")
    return {"total": total, "accepted": accepted, "rejected": rejected}


def sweep_rejected(ws: Workspace) -> dict:
    """Move any Rejected CVE still in cve_data/ to rejected_cve_data/ (useful after hand-editing
    cve_data/).
    """
    ws.rejected_dir.mkdir(parents=True, exist_ok=True)
    total_files = removed = 0
    for path in cve_json_files(ws.cve_dir):
        total_files += 1
        if load_cve(path).get("vulnStatus") == "Rejected":
            removed += 1
            dest = ws.rejected_dir / path.name
            if dest.exists():
                os.remove(dest)
            shutil.move(str(path), str(dest))
    console.info(f"Total files processed: {total_files}")
    console.info(f"Rejected CVEs moved: {removed}")
    console.info(f"Remaining CVEs in '{ws.cve_dir.name}': {total_files - removed}")
    return {"total": total_files, "moved": removed, "remaining": total_files - removed}
