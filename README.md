
# CVE2AT: code and case-study results

Given a device's CPE name, CVE2AT fetches its CVEs from NVD, maps them CVE -> CWE -> CAPEC -> MITRE ATT&CK
technique -> tactic, and builds tactic-level and comprehensive attack trees.

## Quick start

```bash
cd Py-scripts
pip install -e .
cve2at doctor                                   # checks Graphviz and the datasets
cve2at run "cpe:2.3:h:baxter:sigma_spectrum_infusion_system:-:*:*:*:*:*:*:*" --skip-fetch
```
`--skip-fetch` reuses the CVE JSON files already stored in each device's `cve_data/` folder (NVD content changes over time). See `Py-scripts/README.md` for the full command list.

To fetch the CVEs and rebuild every result for both case-study devices in one go, run `cve2at reproduce`. It writes to `Py-scripts/output/` and does not touch `case_study_results/`, which holds the stored results. To redraw only the combined figure, run `cve2at cti-summary` with two `-w` workspace folders (see `Py-scripts/README.md`).

## Contents

| Folder | What it is |
|---|---|
| [`Py-scripts/`](Py-scripts/) | The `cve2at` Python package (command-line tool), the reference datasets it needs, tests, and the default output folder. |
| [`case_study_results/`](case_study_results/) | The results for the two case studies (Baxter Sigma Spectrum infusion system, Schneider Electric Modicon M580), plus the combined CTI-chain figure and the manual validation of the Baxter paths. |

### `Py-scripts/`

| Path | Purpose |
|---|---|
| `cve2at/` | Source code. One module per pipeline stage (fetch, tabulate, merge, trees) plus tables, sensitivity analysis, insights and figure generation. |
| `datasets/` | Reference workbooks: `cwe_data.xlsx` (CWE v4.16), `capec_data.xlsx` (CAPEC v3.9), `techniques.xlsx` (ATT&CK Enterprise v16.1), and the notebooks and XML sources they were built from. |
| `tests/` | Test suite on a small synthetic device (no network needed). |
| `output/` | What `cve2at run` and `cve2at reproduce` write by default (`-o output`): the results for the two devices and the combined figure in `output/figures/`. Re-running overwrites it. |
| `README.md` | Installation, commands, and how to reproduce each table and figure. |
| `pyproject.toml`, `requirements.txt` | Dependencies (Python 3.9+, Graphviz for tree drawing). |

### `case_study_results/`

| Path | Purpose |
|---|---|
| `baxter_sigma_spectrum_infusion_system/` | 10 CVEs, 51 attack paths. |
| `schneider-electric_modicon_m580/` | 40 CVEs, 74 attack paths. |
| `figures/` | `cti_chain_share_combined` (`.pdf`, `.svg`, `.png`): share of each CTI layer that continues to the next, both devices in one figure. |
| `validation_Baxter/` | Two-annotator validation of the 51 Baxter paths (labels, rationale, agreement statistics, supporting documents). |
| `README.md` | Walk-through of the results from CVE to final output, with the file behind every number. The stored run times in each `run_summary.json` are the ones quoted in `Py-scripts/README.md`. |






