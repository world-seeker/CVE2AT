
# CVE2AT

Given a device's **CPE name**, CVE2AT downloads the device's CVEs from NVD, maps them
CVE -> CWE -> CAPEC -> MITRE ATT&CK, and builds the tactic-level and comprehensive attack trees.

```bash
cve2at run "cpe:2.3:h:baxter:sigma_spectrum_infusion_system:-:*:*:*:*:*:*:*"
```

## Setup

1. **Python 3.9+** and **Graphviz** (`dot` draws the trees):
   `sudo apt install graphviz`, `brew install graphviz` or `winget install Graphviz.Graphviz`
2. Install the project:
```bash
pip install -e .          # gives you the `cve2at` command
# or: pip install -r requirements.txt   and use   python -m cve2at ...
```
3. Put `cwe_data.xlsx`, `capec_data.xlsx`, `techniques.xlsx` in `datasets/` (see `datasets/README.md`).  Currently it holds already used version and they are present in the repo. They can be updated with newer versions, if desired.
4. `cve2at doctor` checks that Graphviz and the datasets are found.

## Data versions

| Source | Version / date |
|---|---|
| NVD (CVE records) | queried via the NVD API on **21 September 2026** |
| CWE | v4.16 (`cwec_v4.16.xml`) |
| CAPEC | v3.9 (`capec_v3.9.xml`) |
| MITRE ATT&CK Enterprise | v16.1 (`enterprise-attack-v16.1`, snapshot of 4 April 2025) |

CWE, CAPEC and ATT&CK were downloaded in 2025. NVD content changes over time, so a fresh fetch may
return different CVEs than the ones stored in the `output/<device>/cve_data/` folders.

## Case-study CPEs

| Device | CPE | CVEs fetched |
|---|---|---|
| Baxter Sigma Spectrum Infusion System (SSIP) | `cpe:2.3:h:baxter:sigma_spectrum_infusion_system:-:*:*:*:*:*:*:*` | 10 |
| Schneider Electric Modicon M580 | `cpe:2.3:h:schneider-electric:modicon_m580:-:*:*:*:*:*:*:*` | 40 |

## Reproduce the results

One command fetches the CVEs and rebuilds everything for both case-study devices:

```bash
cve2at reproduce
```

For each device it downloads the CVEs from NVD, builds the trees, writes the CVE / CWE / CAPEC tables, runs the
sensitivity analysis (500 replicates, seed 2026), draws the CTI chain figure and the summary figures, and writes
the insights.
For the two default devices it also draws the combined chain-share figure (`output/figures/`). It prints
the number of attack paths and tree nodes per device at the end and exits with a non-zero code if a step fails.
Results are written to `output/<vendor>_<product>/`, and the results already stored in
`case_study_results/` stay as they are.

 Other options: `--skip-fetch` to reuse the CVE files already in `cve_data/`, `--no-png` to skip PNG
export of the trees, and one or more CPE names to process other devices.

The same steps can also be run one at a time:

```bash
SSIP="cpe:2.3:h:baxter:sigma_spectrum_infusion_system:-:*:*:*:*:*:*:*"
M580="cpe:2.3:h:schneider-electric:modicon_m580:-:*:*:*:*:*:*:*"

for CPE in "$SSIP" "$M580"; do
  cve2at run "$CPE"                       # fetch, tabulate, merge, trees (add --skip-fetch to reuse downloaded CVEs)
  cve2at tables "$CPE"                    # CVE / CWE / CAPEC tables
  cve2at sensitivity "$CPE"               # missing-link analysis (defaults: 500 reps, seed 2026)
  cve2at cti-figure "$CPE"                # layered CVE -> tactic figure of a sample of the CVEs
  cve2at cti-summary "$CPE"               # where the chain breaks, and which weaknesses feed which tactics
  cve2at insight "$CPE"                   # findings from the finished run
done

cve2at cti-summary "$SSIP" "$M580"        # combined chain-share figure, first device on top
```

| Result | File (in `output/<vendor>_<product>/`) |
|---|---|
| CVE records | `outputs/tables/cves.csv` |
| CWE classes | `outputs/tables/cwes.csv` |
| CAPEC patterns | `outputs/tables/capecs.csv` |
| Structural properties per tactic | `outputs/tactic_trees/tactic_summary.csv` |
| Sensitivity to missing links | `sensitivity.csv`, `sensitivity_critical_links.csv` |
| Intermediate mapping table (CVE, CWE, CAPEC, technique, tactic) | `device_compromise_dataset.xlsx` |
| Attack trees | `outputs/tactic_trees/`, `outputs/comprehensive_tree/` |
| CTI chain figure (layered CVE -> tactic figure, one device) | `outputs/figures/cti_chain_figure.{png,pdf,svg}`, with `.dot` and `_nodes.csv`, `_edges.csv`, `_cves.csv`, `_checks.csv` |
| Chain-share and path-matrix figure (one device) | `outputs/figures/cti_chain_summary.*` |
| Chain-share figure of both devices | `output/figures/cti_chain_share_combined.*` (next to the device folders) |
| Counts for the run (nodes, paths, CVEs retained) | `run_summary.json` |

The manual validation of the Baxter paths is not produced by this command. Its labels are in
`../case_study_results/validation_Baxter/Inter-annotator-reliability.xlsx` (`Results` sheet).

## Commands

```bash
cve2at run "<CPE>"                        # fetch -> tabulate -> merge -> trees
cve2at run "<CPE>" --skip-fetch           # reuse the CVEs already downloaded
cve2at run "<CPE>" --target-cve CVE-XXXX-YYYY --target-cve CVE-XXXX-ZZZZ   # only these CVEs
cve2at run "<CPE>" --no-png               # skip PNG export (faster on big trees)
cve2at run "<CPE>" --dedup-mode per_tactic
cve2at fetch | tabulate | merge | trees "<CPE>"   # single stages (they read the previous stage's output)
cve2at tables "<CPE>"                     # not part of `run`
cve2at sensitivity "<CPE>"                # not part of `run`
cve2at cti-figure "<CPE>"                 # layered CVE -> tactic figure of a sample of the CVEs; not part of `run`
cve2at cti-figure "<CPE>" --max-cves 15 --formats pdf svg   # sample size (default 15), image formats (default png pdf svg)
cve2at cti-summary "<CPE>"                # share of each layer that continues, plus paths by tactic and weakness; not part of `run`
cve2at cti-summary "<CPE1>" "<CPE2>"      # both devices, plus the combined chain-share figure (first on top)
cve2at insight "<CPE>"                    # findings from a finished run; not part of `run`
cve2at reproduce                          # fetch and run every step for both case-study devices
cve2at doctor                             # checks that Graphviz and the reference workbooks are found
```

Options: `-o/--output-dir` (default `./output`), `-w/--workspace`, `-d/--datasets-dir`
(default `./datasets` or `$CVE2AT_DATASETS_DIR`), `--api-key` / `$NVD_API_KEY`, `--delay`.
Without an NVD API key the fetcher waits 6 s between pages; a free key (https://nvd.nist.gov/developers/request-an-api-key) reduces this to 0.6 s.

## Output layout

| Path | Stage |
|---|---|
| `cve_data/`, `rejected_cve_data/` | fetch (one JSON per CVE) |
| `cve_data.xlsx`, `cve_data_formated.xlsx` | tabulate |
| `Device_Attack_Pattern.xlsx`, `device_compromise_dataset.xlsx`, `incomplete_chains.csv` | merge |
| `outputs/tactic_trees/<Tactic>.{svg,html,json,dot,png}`, `tactic_summary.csv` | trees (tactic level) |
| `outputs/comprehensive_tree/comprehensive_attack_tree.*` | trees (comprehensive) |
| `outputs/comprehensive_tree/{summary,dedup_comparison,pruned_duplicates}.csv` | trees (comprehensive) |
| `outputs/tables/` | tables |
| `outputs/figures/cti_chain_figure.*`, `outputs/figures/cti_chain_figure_{nodes,edges,cves,checks}.csv` | cti-figure |
| `outputs/figures/cti_chain_summary.*` | cti-summary |
| `<output-dir>/figures/cti_chain_share_combined.*` | cti-summary with two devices |
| `outputs/insights/insights.{md,html,json}` | insight |
| `sensitivity*.csv` | sensitivity |
| `run_summary.json` | run |

Open the `.html` files for the interactive trees.

## tables

`tables` needs only the tabulate stage. The CWE table (`cwes.csv`) lists every CWE the CVEs reference, with a
`Retained` column showing whether the CWE continues the CVE -> CWE -> CAPEC chain. The CAPEC table
(`capecs.csv`) is built from the retained CWEs only, so it can contain more patterns than reach the trees: the
later CAPEC -> ATT&CK step drops patterns with no technique mapping (SSIP: 29 CAPEC patterns, 20 in the trees).
The `Affected Components` column of the CVE table (`cves.csv`) is rebuilt from NVD's CPE data.
The CWE-255 row is correct against MITRE's live record but was entered by hand, because `cwe_data.xlsx` has no
Category rows (CWE-255 is a Category).

## Insights

```bash
cve2at insight "<CPE>"                    # prints the findings and writes outputs/insights/
cve2at insight "<CPE>" --no-color --no-files
```

Reads the finished workspace; nothing is simulated and no network is used. Three core insights
(a weakness recurring across tactics, path count against CVE count, reuse across tactics) are followed by four
more: which CVE fix removes the most paths, how easily the paths can be reached, which weakness feeds the most
paths, and where public mappings run out. Every number comes from the data, so the command works for any device.
`insights.html` opens in a browser with no other files.

## Sensitivity analysis

```bash
cve2at sensitivity "<CPE>"
cve2at sensitivity "<CPE>" --reps 1000 --levels 0.1 0.3 0.5 --convergence
```

Reads `device_compromise_dataset.xlsx` and, by Monte-Carlo simulation, removes links at random with
probability `p` and records which paths and tactics survive. The four link types are the four relations of
the CVE-to-tactic chain:

| `link` in the CSV | Relation | Meaning |
|---|---|---|
| `cve_cwe` | M_VW | CVE-CWE links from NVD records |
| `cwe_capec` | M_WC | CWE-CAPEC links |
| `capec_technique` | M_CK | CAPEC-ATT&CK technique links |
| `technique_tactic` | M_KT | technique-tactic memberships |

`all` perturbs all four together. Defaults: `p` = 0.1-0.5, 500 replicates per cell, seed 2026, percentile-bootstrap 95% CI.
The `retention` metric is the share of paths that survive and
`tactic_survival` the share of tactics that survive.

## CTI chain figure

```bash
cve2at cti-figure "<CPE>"
cve2at cti-figure "<CPE>" --max-cves 15 --no-tactic-labels
```

Draws how the CVEs of one device flow down the chain CVE -> CWE -> CAPEC -> ATT&CK technique -> sub-technique ->
tactic, one row per layer. It reads `device_compromise_dataset.xlsx`, `cve_data.xlsx` and `run_summary.json` of the
workspace and draws the same curated relation P that the attack trees are built from; nothing is typed in. It is
not part of `run`; `reproduce` runs it. `cti-summary` shows the same chain as shares per layer; `cti-figure`
shows the individual entries and the links between them.

**Row numerals (left column).** Each row starts with its layer name and two numerals, *total -> carried forward*,
and a bar with the same split. The first numeral is how many entries of that layer are in the device's data,
including those that stop early: CVEs fetched, CWEs named by those CVEs, CAPEC patterns and ATT&CK entries in the
merged dataset, and the 14 tactics of the ATT&CK matrix (read from `run_summary.json`; without it the tactic row
shows only the second numeral). The second is how many of them lie on a complete chain, i.e. are in P. In the
bar the dark part is the share carried forward and the dashed, empty part is the share that stops before a
tactic. These are counts for the whole device, not for the CVEs drawn.

| Row | M580 | SSIP |
|---|---|---|
| CVE | 40 -> 11 | 10 -> 9 |
| CWE | 13 -> 6 | 9 -> 5 |
| CAPEC | 123 -> 33 | 29 -> 20 |
| Technique | 38 -> 38 | 16 -> 16 |
| Sub-technique | 12 -> 12 | 12 -> 12 |
| Tactic | 14 -> 8 | 14 -> 8 |

The CWE total counts every CWE the CVEs name. Only some of them have a CAPEC pattern: 9 of the 13 for M580 and 5
of the 9 for SSIP (`distinct_cwe_ids_in_final` in `run_summary.json`). For both devices the technique and
sub-technique rows are full: every technique in the merged dataset is also on a complete chain.

**Nodes and links.**

* Shapes: circle = CVE, square = CWE, diamond = CAPEC, triangle = technique, pentagon = sub-technique,
  hexagon with a double outline = tactic. A filled node is on a complete chain. A white node with a dashed
  outline exists in the data but the chain stops there (a CVE with no complete chain, a CWE that does not
  continue for that CVE, or a stub that stands for the CAPEC patterns of one CWE that never reach a technique
  and tactic, for the CVEs drawn). A short end cap under a node marks where a chain stops. A stub carries no
  count in the compact figure; `--detailed` prints it as "+n CAPEC".
* Links: a solid link belongs to a complete chain and is coloured by the CWE it descends from (up to nine CWEs get
  a colour); a grey link is shared by several CWEs. A dashed grey link is a relation that exists but does not
  complete the chain ("missing link"). A link from a technique to a tactic that passes the sub-technique row
  without a node is a chain with no sub-technique; no sub-technique node is invented for it.
* Sample: at most `--max-cves` CVEs (default 15) are drawn in the top row. Every CVE with a complete chain is drawn
  first if it fits; the remaining places, and at least two when such CVEs exist, go to CVEs that stop early,
  taking turns between the three kinds of early stop (no technique or tactic, no CAPEC, no CWE). CVEs that are
  left out are not drawn at all; the CVE row just ends in three dots. For M580 this gives 11 + 4 drawn and 25
  left out; for SSIP all 10 are drawn (9 + 1).
* Dots: a row that has more entries in the data than are drawn ends in three dots. The technique, sub-technique
  and tactic rows always get them, because the ATT&CK matrix is larger than the chains.
* Labels: the coloured CWEs, the tactic names, and at most two of the best-connected technique entries and two
  sub-technique entries. CAPEC nodes carry no label, there are too many to print. Every ID and name is in
  `cti_chain_figure_nodes.csv`; the links are in `_edges.csv` and the status of each CVE (drawn or not) in
  `_cves.csv`.

**Checks.** Before anything is written the figure is checked against the data: every drawn entry and link must be
in the source data, every solid link must be a row of P, no complete chain may be hidden or invented, the
chains drawn must equal those the tree builder produces, and the counts must agree with `run_summary.json`. If a
check fails the command stops and writes nothing; after a passing run each check and its result are listed in
`cti_chain_figure_checks.csv`.

Other options: `--no-expand-incomplete` draws the CVEs that stop early as end-capped nodes without their dashed
branches, `--figsize W H` and `--dpi` set the size, `--no-tactic-labels` leaves out the tactic names, and
`--detailed` draws the older, larger version with a title, entry names and a statistics block instead of the row
numerals (`--title` is used only by that version). The command prints the natural size of the figure and the
width to include it at.

## Run time and scale

`run_summary.json` records how long a run took and how big the inputs were:

| Key | Meaning |
|---|---|
| `elapsed_seconds` | the whole run, **including the NVD fetch** |
| `timing_seconds` | seconds per stage (`fetch`, `tabulate`, `merge`, `tactic_trees`, `comprehensive_tree`) and `total`; `fetch` is `null` when `--skip-fetch` is used |
| `scale.attack_matrix` | tactics, techniques and sub-techniques in `techniques.xlsx` (14, 203 and 453 for ATT&CK v16.1 Enterprise) |
| `scale.chains_in_P` | complete (CVE, CWE, CAPEC, technique, tactic) chains kept in P |
| `scale.paths` | attack paths (leaves) over all tactics |
| `scale.tree_nodes`, `scale.tree_edges` | size of the comprehensive tree |

The whole ATT&CK Enterprise matrix is loaded on every run; its size does not depend on the device.
Times taken from `case_study_results/<device>/run_summary.json` (`--skip-fetch` with PNG export, Intel Core i5-1135G7, 8 GB RAM, Ubuntu 24.04, one run each). A new run writes its own `run_summary.json` into `output/<device>/`, so the times there, and on your machine, will differ.

| Device | Paths | Tree nodes | tabulate | merge | tactic trees | comprehensive tree | total |
|---|---|---|---|---|---|---|---|
| SSIP | 51 | 201 | 0.1 s | 0.7 s | 2.4 s | 2.5 s | 5.6 s |
| M580 | 74 | 283 | 0.6 s | 1.7 s | 3.2 s | 3.3 s | 8.7 s |

With `--no-png` the same runs took 4.2 s (SSIP) and 7.3 s (M580).


How the work grows with the input:

* Deduplication (`build_leaf_index`) makes one pass over the rows of P with a set or dict lookup per row,
  so it is linear in the number of rows of P.
* Building a tree scans, for every leaf, the rows of P that belong to the same CWE and tactic (to collect
  node metadata). For one CWE and tactic with `r` rows this is at most `r` squared steps; it is small
  for the two case studies but not linear in general.
* Graphviz layout is not linear in the number of nodes and takes most of the time on large trees.
  `--no-png` skips the PNG export only.

These are statements about the code and two measured runs, not benchmarks on larger devices.

## Behaviour that affects reproduction

* Each CPE has its own folder, and re-fetching a CPE replaces its old files.


## Folders

| Folder | What is in it |
|---|---|
| `cve2at/` | the package; `cve2at/README.md` maps each module to a pipeline stage |
| `datasets/` | the three reference workbooks (CWE, CAPEC, ATT&CK); see `datasets/README.md` |
| `output/` | one folder per device with the results of the case studies; see `output/README.md` |
| `tests/` | the test suite and its synthetic data; see `tests/README.md` |
