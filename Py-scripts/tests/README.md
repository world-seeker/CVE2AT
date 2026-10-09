# Tests

```bash
pip install -e ".[dev]"
pytest                        # all tests, about 20 s
pytest tests/test_sensitivity.py -q
```

No network is needed. `conftest.py` replaces the NVD API with a fake and turns off the waiting between
requests; `sample_data.py` builds miniature CWE, CAPEC and ATT&CK workbooks.

## The synthetic device

`sample_data.py` describes 8 CVEs (7 accepted, 1 Rejected). The numbers below are known from the design of
the data and are asserted in `test_pipeline.py`:

| Quantity | Value |
|---|---|
| attack paths with `per_tactic` deduplication | 9 |
| attack paths with `earliest_tactic` deduplication | 7 (CWE-732 / CAPEC-17 / T1574.010 sits under 3 tactics, so 2 are pruned) |
| ATT&CK workbook | 7 tactics, 5 techniques, 2 sub-techniques |
| chain dropped as incomplete | the one through deprecated CAPEC-7 |

## What each file covers

| File | Covers |
|---|---|
| `test_pipeline.py` | CPE validation, CVSS parsing, NVD paging and retries, every stage, the full run and `run_summary.json` (counts, timings, scale), single-stage commands, the validation workbook (six sheets, consensus formulas, merge-on-rerun rules for both annotators and typed consensus labels), friendly error messages |
| `test_validate_docs.py` | document identity on re-run: CISA advisory fingerprints, renamed URLs keep their Doc ID, duplicate rows folded, alternate URLs, dangling Doc ID citations, backups |
| `test_cti_summary.py` | `cti-summary`: figure data against `tactic_summary.csv`, one- and two-device output, `--combined-only`, missing `incomplete_chains.csv`, clean errors, failed checks block the figure |
| `test_sensitivity.py` | closed-form retention on a hand-built relation, exact results at p = 0 and p = 1, reproducibility from the seed, agreement between simulation and closed form, confidence intervals, critical links and the greedy worst case, empty relations |

When you change the pipeline output, update the expected numbers in `test_pipeline.py` and say why in the
commit message.
