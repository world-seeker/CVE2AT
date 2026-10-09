# Results

One folder per device, named `<vendor>_<product>` after the CPE. The two folders here are the two case studies.

| Folder | Device | CVEs fetched | Attack paths |
|---|---|---|---|
| `baxter_sigma_spectrum_infusion_system/` | Baxter Sigma Spectrum infusion system (SSIP) | 10 | 51 |
| `schneider-electric_modicon_m580/` | Schneider Electric Modicon M580 | 40 | 74 |

The CVE records were fetched from NVD on 21 September 2026. NVD changes over time, so a new fetch can give
different CVEs. To rebuild the results from the stored records instead, reuse the shipped `cve_data/` folder:

```bash
cve2at run "<CPE>" --skip-fetch
```

## Inside a device folder

| Path | Made by | What it is |
|---|---|---|
| `cve_data/`, `rejected_cve_data/` | `fetch` | one NVD JSON file per accepted / Rejected CVE |
| `cve_data.xlsx`, `cve_data_formated.xlsx` | `tabulate` | CVE table and the four-sheet review workbook |
| `Device_Attack_Pattern.xlsx`, `device_compromise_dataset.xlsx` | `merge` | CVE -> CWE -> CAPEC -> ATT&CK chains; the second file is what the trees are built from |
| `incomplete_chains.csv` | `merge` | chains that were dropped, with the reason |
| `outputs/tactic_trees/` | `trees` | one tree per tactic (`.html` is interactive), `tactic_summary.csv` |
| `outputs/comprehensive_tree/` | `trees` | the combined tree and the deduplication comparison files |
| `outputs/tables/` | `tables` | `cves.csv`, `cwes.csv`, `capecs.csv`, `tables.xlsx` |
| `outputs/figures/cti_chain_figure.*` | `cti-figure` | layered CVE -> tactic figure of a sample of the CVEs (`.pdf`, `.svg`, `.png`, `.dot`) and the CSVs behind it (`_nodes`, `_edges`, `_cves`, `_checks`) |
| `outputs/figures/cti_chain_summary.*` | `cti-summary` | chain-share and path-matrix figure of the device (`.pdf`, `.svg`, `.png`) |
| `sensitivity.csv`, `sensitivity_critical_links.csv` | `sensitivity` | the Monte-Carlo results of the missing-link analysis |
| `run_summary.json` | `run` | counts per stage, timings and sizes |

Open the `.html` files in a browser to explore the trees. The `.svg` and `.png` files are static copies of the same trees.

## Regenerating

```bash
cve2at run "<CPE>" --skip-fetch -o output
cve2at tables "<CPE>" -o output
cve2at sensitivity "<CPE>" -o output
```

Re-running overwrites the files above. 
