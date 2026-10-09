# cve2at package

The code behind the `cve2at` command. `python -m cve2at` and the `cve2at` script both call `cli.main`.

## Pipeline stages and where they live

| Stage | Module | Reads | Writes (in the workspace) |
|---|---|---|---|
| 1 fetch | `fetch.py` | NVD API | `cve_data/*.json`, `rejected_cve_data/*.json` |
| 2 tabulate | `tabulate.py`, `excel_report.py`, `cve_parse.py` | `cve_data/` | `cve_data.xlsx`, `cve_data_formated.xlsx` |
| 3 merge | `merge.py` | `cve_data.xlsx` + the three reference workbooks | `Device_Attack_Pattern.xlsx`, `device_compromise_dataset.xlsx`, `incomplete_chains.csv` |
| 4 tactic trees | `trees.py` + `attack_tree_lib.py` | `device_compromise_dataset.xlsx` | `outputs/tactic_trees/` |
| 5 comprehensive tree | `trees.py` + `attack_tree_lib.py` | `device_compromise_dataset.xlsx` | `outputs/comprehensive_tree/` |

`pipeline.py` runs the five stages in order, times each one and writes `run_summary.json`.
Each stage is also a CLI command and reads only the previous stage's files.

## Commands that sit outside `run`

| Command | Module | Purpose |
|---|---|---|
| `tables` | `tables.py` | CVE, CWE and CAPEC tables |
| `sensitivity` | `sensitivity.py` | Monte-Carlo removal of CTI links |
| `validate` | `validate_report.py` | blank annotation workbook for the path validation |
| `cti-summary` | `cti_funnel_figure.py` | where the chain breaks at each link, paths by tactic and weakness, and the combined chain-share figure of two devices |
| `cti-figure` | `cti_figure.py`, `cti_figure_compact.py` | layered CVE -> tactic figure of a sample of the CVEs, with a total -> carried-forward numeral and bar per row, and the node, edge, CVE and check CSVs |
| `doctor` | `cli.py` | checks Graphviz and the reference workbooks |

These read an existing workspace and do not change the files of stages 1 to 5.

## Supporting modules

| Module | Role |
|---|---|
| `cli.py` | argument parsing and one `cmd_*` function per command |
| `config.py` | CPE validation, the `Workspace` path layout, reference-file lookup |
| `console.py` | terminal output helpers |
| `errors.py` | exception types; the CLI prints them as one-line messages |

## Things worth knowing before changing the code

* `attack_tree_lib.py` is the only place that deduplicates chains and builds graphs. The tactic-level
  tree, the combined tree and the figure code all go through it.
* P, the curated relation, has one row per complete (CVE, CWE, CAPEC, technique, tactic) chain. Rows with
  a missing link are dropped and listed in `incomplete_chains.csv` with a reason code.
* `technique_key` is the leaf-level (sub-)technique id; `parent_technique_key` is the parent technique.
  Count techniques with the parent column.
* Path IDs in the validation workbook (`P001`, ...) come from enumeration order. Do not re-run
  `validate` on a workspace whose annotation round is still open (see the module docstring).
* `cti_figure.py` builds the figure's data (model, validation, `_layer_split`, which supplies the row numerals) and
  `cti_figure_compact.py` draws it; `--detailed` uses the older renderer inside `cti_figure.py`. The figure goes
  through `attack_tree_lib.py` for P and checks itself against `build_leaf_index` before writing. The row numerals
  are counted over the whole device data, not over the nodes drawn, which depend on the CVE sample (`--max-cves`).
* `tests/` has the expected numbers for a small synthetic device; run `pytest` after any change.
