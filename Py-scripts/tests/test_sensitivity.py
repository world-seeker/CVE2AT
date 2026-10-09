"""Tests for cve2at.sensitivity (run alone with: pytest tests/test_sensitivity.py -q).

The hand-built relation SYN has answers worked out by hand:

    chain (CVE, CWE, CAPEC, tech, tactic)
    a  V1 W1 C1 S1 TA1      leaves (TA1,W1,S1,C1), (TA1,W1,S2,C1) and (TA2,W1,S3,C1) share
    b  V1 W1 C1 S2 TA1      the single CWE->CAPEC link (W1,C1); leaf (TA1,W2,S1,C2) is
    c  V2 W1 C1 S3 TA2      supported by two CVEs (V3, V4).
    d  V3 W2 C2 S1 TA1
    e  V4 W2 C2 S1 TA1

    4 leaves; n(l) = 1, 1, 1, 2; 4 CVE->CWE, 2 CWE->CAPEC, 4 CAPEC->tech, 3 tech->tactic links.
"""
import random

import numpy as np
import pandas as pd
import pytest

from cve2at import sensitivity as sens

SYN = [("V1", "W1", "C1", "S1", "TA1"),
       ("V1", "W1", "C1", "S2", "TA1"),
       ("V2", "W1", "C1", "S3", "TA2"),
       ("V3", "W2", "C2", "S1", "TA1"),
       ("V4", "W2", "C2", "S1", "TA1")]


def _random_relation(seed=0):
    """A structurally consistent relation with shared links and multi-CVE leaves."""
    rnd = random.Random(seed)
    cwes = [f"W{i}" for i in range(12)]
    capec = {w: rnd.sample([f"C{i}" for i in range(25)], rnd.randint(1, 4)) for w in cwes}
    tech = {c: rnd.sample([f"S{i}" for i in range(20)], rnd.randint(1, 3))
            for cs in capec.values() for c in cs}
    tactic = {s: rnd.sample([f"TA{i}" for i in range(6)], rnd.randint(1, 2))
              for s in [f"S{i}" for i in range(20)]}
    chains = set()
    for v in range(40):
        for w in rnd.sample(cwes, rnd.randint(1, 3)):
            for c in capec[w]:
                for s in tech[c]:
                    for t in tactic[s]:
                        chains.add((f"V{v}", w, c, s, t))
    return sorted(chains)


REL = _random_relation()
ALL_TYPES = sens.LINK_TYPES + (sens.ALL,)


# closed form, hand-checked
def test_analytic_values_on_synthetic():
    assert sens.analytic_retention(SYN, "cwe_capec", 0.5) == pytest.approx(0.5)
    assert sens.analytic_retention(SYN, "cve_cwe", 0.5) == pytest.approx((3 * 0.5 + 0.75) / 4)
    assert sens.analytic_retention(SYN, "all", 0.5) == pytest.approx(0.5 ** 3 * 0.5625)


def test_analytic_monotone_in_p():
    for name in ALL_TYPES:
        vals = [sens.analytic_retention(REL, name, p) for p in (0.0, 0.1, 0.3, 0.5, 0.9, 1.0)]
        assert vals == sorted(vals, reverse=True)
        assert vals[0] == 1.0 and vals[-1] == 0.0


# exact boundaries
@pytest.mark.parametrize("p, expected", [(0.0, 1.0), (1.0, 0.0)])
def test_p0_and_p1_are_exact_for_every_metric(p, expected):
    res = sens.run_sensitivity_on_chains(REL, reps=25, levels=(p,), n_boot=50)
    df = res.to_frame()
    assert set(df["link"]) == set(ALL_TYPES) and set(df["metric"]) == set(sens.METRICS)
    for col in ("mean", "sd", "ci_lo", "ci_hi", "p05", "p50", "p95"):
        vals = df[col].to_numpy()
        if col == "sd":
            assert (vals == 0.0).all()
        else:
            assert (vals == expected).all(), col            # exact equality, not approx


# reproducibility
def test_same_seed_and_reps_are_bit_for_bit_identical():
    kw = dict(reps=60, levels=(0.2, 0.5), n_boot=100)
    a = sens.run_sensitivity_on_chains(REL, seed=7, **kw).to_frame()
    b = sens.run_sensitivity_on_chains(REL, seed=7, **kw).to_frame()
    pd.testing.assert_frame_equal(a, b, check_exact=True)
    c = sens.run_sensitivity_on_chains(REL, seed=8, **kw).to_frame()
    assert not a["mean"].equals(c["mean"])


def test_cell_result_does_not_depend_on_which_other_cells_run():
    full = sens.run_sensitivity_on_chains(REL, reps=40, seed=3, n_boot=50).to_frame()
    one = sens.run_sensitivity_on_chains(REL, reps=40, seed=3, n_boot=50,
                                         levels=(0.3,), link_types=("all",)).to_frame()
    ref = full[(full["link"] == "all") & (full["p"] == 0.3)].reset_index(drop=True)
    pd.testing.assert_frame_equal(ref, one.reset_index(drop=True), check_exact=True)


def test_seed_reps_and_ci_method_recorded():
    df = sens.run_sensitivity_on_chains(SYN, reps=30, seed=11, levels=(0.3,), n_boot=40).to_frame()
    assert (df["seed"] == 11).all() and (df["reps"] == 30).all() and (df["ci_method"] == "bootstrap").all()


# analytic vs simulation
def test_simulation_matches_closed_form_within_4_sem():
    res = sens.run_sensitivity_on_chains(REL, reps=1000, seed=2026, n_boot=200, ci_method="normal")
    chk = sens.verify_against_analytic(res, k=4.0)          # raises AssertionError on failure
    assert len(chk) == len(ALL_TYPES) * len(sens.LEVELS) and chk["ok"].all()


def test_simulation_matches_closed_form_on_synthetic():
    res = sens.run_sensitivity_on_chains(SYN, reps=2000, seed=5, n_boot=100, ci_method="normal")
    assert sens.verify_against_analytic(res, k=4.0)["ok"].all()


def test_verify_detects_a_wrong_closed_form():
    df = sens.run_sensitivity_on_chains(REL, reps=500, levels=(0.3,), n_boot=50).to_frame()
    df.loc[df["metric"] == "retention", "analytic_mean"] += 0.05
    with pytest.raises(AssertionError):
        sens.verify_against_analytic(df)


def test_convergence_check_sem_shrinks_and_error_within_tolerance():
    res = sens.run_sensitivity_on_chains(REL, reps=100, seed=1, n_boot=50, levels=(0.2, 0.4))
    conv = res.convergence_check((50, 200, 1000))
    assert set(conv["R"]) == {50, 200, 1000}
    sem = conv.groupby("R")["sem"].max()
    assert sem[1000] < sem[200] < sem[50]
    assert sem[1000] < 0.6 * sem[50]
    # same criterion as verify_against_analytic: 4 x SEM, floored at 3/R for rare-event cells
    assert (conv["abs_err"] <= conv["tol"]).all()


# CI behaviour
@pytest.mark.parametrize("method", ["bootstrap", "normal"])
def test_ci_width_shrinks_with_more_replicates(method):
    def width(R):
        d = sens.run_sensitivity_on_chains(REL, reps=R, seed=4, levels=(0.3,), link_types=("all",),
                                           ci_method=method, n_boot=300).to_frame()
        r = d[d["metric"] == "retention"].iloc[0]
        assert r["ci_lo"] <= r["mean"] <= r["ci_hi"]
        return r["ci_hi"] - r["ci_lo"]
    assert width(1600) < width(100) / 2                     # expected ratio ~4


def test_percentiles_ordered_and_bounded():
    df = sens.run_sensitivity_on_chains(REL, reps=200, seed=2, n_boot=50).to_frame()
    assert (df["p05"] <= df["p50"]).all() and (df["p50"] <= df["p95"]).all()
    assert df["mean"].between(0, 1).all() and df["sd"].ge(0).all()


# critical links / greedy on the synthetic relation
def test_critical_links_exact():
    assert sens.critical_links(SYN, "cwe_capec", top=None) == [(3, ("W1", "C1")), (1, ("W2", "C2"))]
    assert sens.critical_links(SYN, "technique_tactic", top=1) == [(2, ("S1", "TA1"))]
    assert [l for l, _ in sens.critical_links(SYN, "capec_technique", top=None)] == [1, 1, 1, 1]
    # cve_cwe: V1 is the sole support of two leaves, V2 of one, V3/V4 back each other up
    assert sens.critical_links(SYN, "cve_cwe", top=None) == [
        (2, ("V1", "W1")), (1, ("V2", "W1")), (0, ("V3", "W2")), (0, ("V4", "W2"))]


def test_greedy_worst_case_exact():
    steps = sens.greedy_worst_case(SYN, budget=5)
    assert [(s["link_type"], s["link"], s["marginal_paths_lost"], s["cumulative_paths_lost"])
            for s in steps] == [("cwe_capec", ("W1", "C1"), 3, 3), ("cwe_capec", ("W2", "C2"), 1, 4)]
    assert steps[-1]["retention_after"] == 0.0              # stops once nothing is left
    assert sens.greedy_worst_case(SYN, budget=1)[0]["retention_after"] == pytest.approx(0.25)
    with pytest.raises(ValueError):
        sens.greedy_worst_case(SYN, link_types=("cve_cwe",))


def test_greedy_first_step_equals_top_single_critical_link():
    for name in sens.PATTERN_LINK_TYPES:
        top_loss = sens.critical_links(REL, name, top=1)[0][0]
        first = sens.greedy_worst_case(REL, budget=1, link_types=(name,))[0]
        assert first["marginal_paths_lost"] == top_loss
    assert sens.greedy_worst_case(REL, budget=8)[-1]["cumulative_paths_lost"] > 0


def test_critical_frame_layout():
    res = sens.run_sensitivity_on_chains(SYN, reps=10, n_boot=10, levels=(0.2,))
    cf = res.critical_frame()
    assert set(cf["kind"]) == {"single", "greedy"} and res.n_leaves == 4
    g = cf[cf["kind"] == "greedy"]
    assert list(g["cumulative_paths_lost"]) == [3, 4] and list(g["cumulative_share"]) == [0.75, 1.0]


# edge cases
def test_empty_relation_gives_nan_and_never_raises():
    res = sens.run_sensitivity_on_chains([], reps=5, n_boot=5, levels=(0.2,))
    df = res.to_frame()
    assert len(df) == len(ALL_TYPES) * len(sens.METRICS)
    assert df["mean"].isna().all() and df["analytic_mean"].isna().all()
    assert np.isnan(sens.analytic_retention([], "all", 0.3))
    assert sens.critical_links([], "cwe_capec") == [] and sens.greedy_worst_case([]) == []
    assert sens.verify_against_analytic(res)["ok"].all()    # nothing to compare -> vacuously fine


@pytest.mark.parametrize("bad", [dict(reps=0), dict(levels=(1.2,)), dict(link_types=("nope",)),
                                 dict(ci_method="t"), dict(seed=-1)])
def test_bad_arguments_raise_valueerror(bad):
    with pytest.raises(ValueError):
        sens.run_sensitivity_on_chains(SYN, **bad)


def test_load_chains_maps_relation_columns(monkeypatch):
    P = pd.DataFrame({"CVE ID": ["V1", "V1", "V2"], "cwe": ["W1", "W1", "W1"],
                      "capec": ["C1", "C1", "C1"], "tech": ["S1", "S1", "S2"],
                      "tactics": ["TA1", "TA1", "TA2"]})
    keys = {"cwe_key": "cwe", "capec_key": "capec", "technique_key": "tech"}
    monkeypatch.setattr(sens.atl, "load_dataset", lambda path: "df")
    monkeypatch.setattr(sens.atl, "resolve_key_columns", lambda df: keys)
    monkeypatch.setattr(sens.atl, "build_curated_relation", lambda df, k: (P, None))
    assert sens.load_chains("x.xlsx") == [("V1", "W1", "C1", "S1", "TA1"), ("V2", "W1", "C1", "S2", "TA2")]
    monkeypatch.setattr(sens.atl, "build_curated_relation", lambda df, k: (P.iloc[0:0], None))
    assert sens.load_chains("x.xlsx") == []


def test_cli_registers_sensitivity_subcommand():
    from cve2at import cli
    args = cli.build_parser().parse_args(["sensitivity", "-w", "ws", "--reps", "10", "--levels", "0.1", "0.2"])
    assert args.func is cli.cmd_sensitivity and args.reps == 10 and args.levels == [0.1, 0.2]
    assert args.seed == 2026 and args.ci_method == "bootstrap"