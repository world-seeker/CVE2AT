"""Tests for `cve2at cti-summary` (run alone with: pytest tests/test_cti_summary.py -q)."""
import pandas as pd
import pytest

import sample_data as sd
from cve2at import cli, cti_funnel_figure as cs
from cve2at.config import Workspace
from cve2at.errors import Cve2atError, PipelineError


@pytest.fixture
def ws(tmp_path, datasets, fake_nvd):
    assert cli.main(["run", sd.CPE, "-d", str(datasets), "-o", str(tmp_path / "out"), "--no-png"]) == 0
    return Workspace(tmp_path / "out" / "acme_test_pump")


def test_collect_matches_the_tree_stage(ws):
    d = cs.collect(ws)
    assert all(ok for _, ok in cs.checks(d))
    # synthetic data: 8 CVEs fetched, 1 rejected, so the 7 accepted ones are what the analysis starts from
    assert d["n_cve"] == 7 and d["n_paths"] == 9


def test_matrix_sums_agree_with_tactic_summary(ws):
    d = cs.collect(ws)
    summ = pd.read_csv(ws.tactic_tree_dir / "tactic_summary.csv").set_index("tactic")["paths"]
    for t in d["tactics"]:
        assert sum(r.get(t, 0) for r in d["rows"].values()) == summ[t]


def test_one_device_writes_the_requested_formats(ws, tmp_path):
    out = tmp_path / "fig" / "one"
    assert cli.main(["cti-summary", "-w", str(ws.root), "--out", str(out), "--formats", "png", "svg"]) == 0
    assert out.with_suffix(".png").is_file() and out.with_suffix(".svg").is_file()
    assert not out.with_suffix(".pdf").exists()


def test_default_output_location(ws):
    assert cli.main(["cti-summary", "-w", str(ws.root), "--formats", "png"]) == 0
    assert (ws.figures_dir / "cti_chain_summary.png").is_file()


def test_two_devices_write_the_combined_figure(ws, tmp_path):
    out = tmp_path / "both"
    assert cli.main(["cti-summary", "-w", str(ws.root), "-w", str(ws.root), "--out", str(out),
                     "--formats", "png"]) == 0
    assert out.with_suffix(".png").is_file()
    assert (ws.figures_dir / "cti_chain_summary.png").is_file()


def test_combined_only_skips_the_per_device_figures(ws, tmp_path):
    out = tmp_path / "both"
    assert cli.main(["cti-summary", "-w", str(ws.root), "-w", str(ws.root), "--out", str(out),
                     "--formats", "png", "--combined-only"]) == 0
    assert out.with_suffix(".png").is_file()
    assert not (ws.figures_dir / "cti_chain_summary.png").exists()


def test_missing_incomplete_chains_file_is_tolerated(ws):
    (ws.root / "incomplete_chains.csv").unlink(missing_ok=True)
    d = cs.collect(ws)                      # no file: every CVE that did not reach a tactic counts as stopped early
    assert d["n_paths"] == 9 and sum(d["cve"].values()) == d["n_cve"]


def test_wrong_number_of_devices_is_a_clean_error(ws, capsys):
    assert cli.main(["cti-summary"]) != 0
    assert cli.main(["cti-summary", "-w", str(ws.root), "-w", str(ws.root), "-w", str(ws.root)]) != 0
    assert cli.main(["cti-summary", "-w", str(ws.root), "--combined-only"]) != 0


def test_missing_workspace_files_raise(tmp_path):
    with pytest.raises(Cve2atError):
        cs.collect(Workspace(tmp_path / "nope"))


def test_failed_check_blocks_the_figure(ws, monkeypatch):
    monkeypatch.setattr(cs, "checks", lambda d: [("forced", False)])
    with pytest.raises(PipelineError):
        cs.generate_summary_figure(ws, formats=("png",))
