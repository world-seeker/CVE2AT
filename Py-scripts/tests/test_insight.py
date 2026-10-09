"""Tests for cve2at.insight (run alone with: pytest tests/test_insight.py -q).

The hand-built dataset INS has answers worked out by hand:

    CVE  CWE  CAPEC  step  tactic        leaf support
    V1   W1   C1     S1    TA_A          {V1, V2}
    V2   W1   C1     S1    TA_A
    V1   W1   C1     S2    TA_A          {V1}
    V3   W1   C2     S3    TA_B          {V3}
    V1   W1   C1     S1    TA_B          {V1}
    V4   W2   C3     S4    TA_B          {V4}
    V5   W3   C3     S4    TA_C          {V5}
    V6   W9   (no CAPEC: dropped)

    6 paths, 3 tactics (2 / 3 / 1 paths), 6 CVEs in scope, 5 reach a tactic.
    Best single fix V1 removes 2 paths; the best pair removes 3.
    CAPEC references 1 + 3 + 1 = 5 against 3 distinct.
"""
import json
from pathlib import Path

import pandas as pd
import pytest

from cve2at import insight
from cve2at.cli import main

COLS = ["CVE ID", "CWE ID", "cwe_Name", "CAPEC_ID", "capec_Name", "Technique_ID_Only", "technique",
        "technique_name", "subtechnique_name", "tactics", "baseScore", "attackVector",
        "attackComplexity", "privilegesRequired", "userInteraction"]


def _row(cve, cwe, capec, step, tech, tactic, score, vec, priv="NONE", ui="NONE"):
    return [cve, cwe, f"Name {cwe}" if cwe != "W3" else "Weak <Three>", capec, f"Pattern {capec}", step, tech,
            f"Tech {tech}", "", tactic, score, vec, "LOW", priv, ui]


INS = [_row("V1", "W1", "C1", "S1", "S1", "TA_A", 9.0, "NETWORK"),
       _row("V2", "W1", "C1", "S1", "S1", "TA_A", 8.0, "NETWORK"),
       _row("V1", "W1", "C1", "S2", "S2", "TA_A", 9.0, "NETWORK"),
       _row("V3", "W1", "C2", "S3", "S3", "TA_B", 2.0, "PHYSICAL"),
       _row("V1", "W1", "C1", "S1", "S1", "TA_B", 9.0, "NETWORK"),
       _row("V4", "W2", "C3", "S4", "S4", "TA_B", 6.0, "NETWORK", priv="LOW"),
       _row("V5", "W3", "C3", "S4", "S4", "TA_C", 5.0, "LOCAL"),
       _row("V6", "W9", "", "", "", "", 4.0, "NETWORK")]


@pytest.fixture
def ws(tmp_path):
    pd.DataFrame(INS, columns=COLS).to_excel(tmp_path / "device_compromise_dataset.xlsx", index=False)
    return tmp_path


def _report(ws):
    return insight.build_report(ws / "device_compromise_dataset.xlsx", device="demo")


def _by_key(rep):
    return {i.key: i for i in rep.core + rep.additional}


def test_overview_and_sections(ws):
    rep = _report(ws)
    assert dict(rep.overview) == {"CVEs in scope": 6, "CVEs reaching a tactic": 5, "Weaknesses": 3,
                                  "CAPEC patterns": 3, "Techniques": 4, "Tactics": 3, "Paths": 6}
    assert [i.key for i in rep.core] == ["weakness", "path_count", "redundancy"]
    assert [i.key for i in rep.additional] == ["leverage", "exposure", "concentration", "coverage"]


def test_weakness_across_stages(ws):
    ins = _by_key(_report(ws))["weakness"]
    assert "W1" in ins.headline and "3 of 6 CVEs" in ins.headline and "2 of 3 tactic subtrees" in ins.headline
    assert dict(ins.facts)["Lowest-scoring"].startswith("V3 (2.0")


def test_path_count_vs_cves(ws):
    ins = _by_key(_report(ws))["path_count"]
    assert [(a, v) for a, v, _ in ins.bars] == [("TA_A", 2), ("TA_B", 3), ("TA_C", 1)]
    assert dict(ins.facts)["Widest tactic"] == "TA_B: 3 paths from 3 CVEs"
    assert "tracks path count closely" in ins.headline          # rank correlation is 1.0 here


def test_redundancy_counts(ws):
    ins = _by_key(_report(ws))["redundancy"]
    facts = dict(ins.facts)
    assert facts["CAPEC references over all tactics"] == 5 and facts["Distinct CAPEC patterns"] == 3
    assert "5 CAPEC references collapse to 3" in ins.headline and "40.0%" in ins.headline
    assert {a.split()[0] for a, _, _ in ins.bars} == {"S1", "S4"}     # each appears under two tactics


def test_fix_leverage(ws):
    ins = _by_key(_report(ws))["leverage"]
    assert ins.table["rows"][0][:3] == [1, "V1", 2]
    assert ins.table["rows"][1][2] == 3 and ins.table["rows"][2][2] >= 3
    assert "V1 alone removes 2 of 6" in ins.headline
    assert dict(ins.facts)["Paths resting on one CVE"].startswith("5 of 6")


def test_exposure(ws):
    ins = _by_key(_report(ws))["exposure"]
    facts = dict(ins.facts)
    assert facts["Remote, no privileges, no interaction"].startswith("3 of 6")
    assert facts["Physical access is the only route"] == "1 of 6"


def test_concentration_and_coverage(ws):
    rep = _by_key(_report(ws))
    assert rep["concentration"].bars[0][1] == 4                     # W1 feeds 4 of 6 paths
    assert dict(rep["coverage"].facts)["Tactics reached"] == "3 of 14"
    assert dict(rep["coverage"].facts)["CVEs with a complete chain"] == "5 of 6"


def test_summary_supplies_full_cve_count(ws):
    (ws / "run_summary.json").write_text(json.dumps(
        {"stages": {"merge": {"coverage_funnel": {"cves_fetched_or_selected": 9,
                                                  "chain_break_reasons": {"NO_CAPEC": 3, "NO_TECHNIQUE": 1}}}}}))
    rep = insight.build_report(ws / "device_compromise_dataset.xlsx", ws / "run_summary.json")
    assert dict(rep.overview)["CVEs in scope"] == 9
    cov = _by_key(rep)["coverage"]
    assert cov.bars[0][:2] == ("CWE has no usable CAPEC pattern", 3)


def test_renderings(ws):
    rep = _report(ws)
    plain = insight.render_terminal(rep, color=False, width=80)
    assert "\x1b" not in plain and "CORE INSIGHTS" in plain and "ADDITIONAL INSIGHTS" in plain
    assert "\x1b[" in insight.render_terminal(rep, color=True, width=80)
    assert max(len(l) for l in plain.splitlines()) <= 80
    page = insight.render_html(rep)
    assert "Weak <Three>" not in page and "Weak &lt;Three&gt;" in page      # names are escaped
    assert "http" not in page and "<script" not in page                      # offline and inert
    md = insight.render_markdown(rep)
    assert md.startswith("# Insights: demo") and "### 1." in md
    for text in (plain, page, md, json.dumps(rep.to_dict())):
        assert "paper" not in text.lower()


def test_no_complete_chain(tmp_path):
    rows = [_row("V9", "W9", "", "", "", "", 4.0, "NETWORK")]
    pd.DataFrame(rows, columns=COLS).to_excel(tmp_path / "device_compromise_dataset.xlsx", index=False)
    rep = insight.build_report(tmp_path / "device_compromise_dataset.xlsx")
    assert rep.empty and "nothing to report" in insight.render_terminal(rep, color=False)


def test_single_tactic_and_no_shared_weakness(tmp_path):
    rows = [_row("V1", "W1", "C1", "S1", "S1", "TA_A", 9.0, "NETWORK"),
            _row("V2", "W2", "C2", "S2", "S2", "TA_A", 7.0, "NETWORK")]
    pd.DataFrame(rows, columns=COLS).to_excel(tmp_path / "device_compromise_dataset.xlsx", index=False)
    rep = _by_key(insight.build_report(tmp_path / "device_compromise_dataset.xlsx"))
    assert "No weakness is shared" in rep["weakness"].headline
    assert "Only one tactic" in rep["path_count"].headline
    assert "No CAPEC pattern is reused" in rep["redundancy"].headline


def test_cli_writes_files(ws, capsys):
    assert main(["insight", "-w", str(ws), "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "One weakness, many stages" in out and "\x1b" not in out
    d = ws / "outputs" / "insights"
    assert {p.name for p in d.iterdir()} == {"insights.md", "insights.html", "insights.json"}
    assert json.loads((d / "insights.json").read_text())["core_insights"][0]["key"] == "weakness"


def test_cli_no_files_and_missing_dataset(ws, tmp_path, capsys):
    assert main(["insight", "-w", str(ws), "--no-color", "--no-files"]) == 0
    assert not (ws / "outputs").exists()
    assert main(["insight", "-w", str(tmp_path / "empty")]) == 1
    assert "not found" in capsys.readouterr().err


SHIPPED = Path(__file__).parent.parent / "output" / "baxter_sigma_spectrum_infusion_system"


@pytest.mark.skipif(not (SHIPPED / "device_compromise_dataset.xlsx").is_file(), reason="shipped workspace absent")
def test_shipped_ssip_numbers():
    rep = insight.build_report(SHIPPED / "device_compromise_dataset.xlsx", SHIPPED / "run_summary.json")
    k = _by_key(rep)
    assert "CWE-798" in k["weakness"].headline and "5 of 10 CVEs" in k["weakness"].headline
    assert "5 of 8 tactic subtrees" in k["weakness"].headline
    assert "Defense Evasion has 14 paths from 7 CVEs" in k["path_count"].headline
    assert dict(k["path_count"].facts)["Dominant CVE there"].startswith("CVE-2020-12041 alone gives 9 of 14")
    assert "44 CAPEC references collapse to 20" in k["redundancy"].headline
    assert "CVE-2020-12041 alone removes 25 of 51" in k["leverage"].headline