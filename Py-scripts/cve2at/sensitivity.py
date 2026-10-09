"""Sensitivity of the attack trees to missing CTI links.

Question: if a fraction p of the CTI links that do exist in the public repositories were
missing, how incomplete would the generated trees be? This is not the coverage funnel in
merge.py, which counts links that never existed. This module measures robustness to links
that exist but are removed; it says nothing about mappings absent from the source
repositories. Random uniform removal models incompleteness, not a prediction of which links
will disappear.

Model
-----
Let P be the curated relation of complete chains (v, w, c, s, t) =
(CVE, CWE, CAPEC, technique, tactic). Its four link sets are the projections

    L1 = {(v, w)}   CVE -> CWE
    L2 = {(w, c)}   CWE -> CAPEC
    L3 = {(c, s)}   CAPEC -> technique
    L4 = {(s, t)}   technique -> tactic

A tactic-level attack path (leaf) is l = (t, w, s, c), and Pi is the set of leaves. For a leaf,
(w, c), (c, s) and (s, t) are each unique, while n(l) >= 1 distinct (v, w) links may support it.

Perturbation. For one link type (or all four together, condition "all"), every existing link
is removed independently with probability p and kept with probability 1 - p, for p in
{0.1, 0.2, 0.3, 0.4, 0.5} by default. This is i.i.d. Bernoulli removal, not removal of a fixed
fraction.

Survival. A leaf survives iff its (w, c), (c, s) and (s, t) links survive and at least one of
its n(l) supporting (v, w) links survives. Equivalently, a chain survives iff all four of its
links survive, and a leaf survives iff at least one of its chains does.

Metrics, each as a ratio to the unperturbed value:
    retention        |Pi'| / |Pi|                      share of paths kept
    tactic_survival  tactics with at least one surviving leaf / tactics in Pi
    cwe_survival     CWEs with at least one surviving leaf / CWEs in Pi
    cve_survival     CVEs in at least one surviving chain / CVEs in P

Closed form for retention, as an independent check on the simulation. By linearity of
expectation, which holds even though leaves share links:

    cwe_capec, capec_technique, technique_tactic :  1 - p
    cve_cwe                                       :  mean over leaves of (1 - p ** n(l))
    all (joint)                                   :  (1 - p)**3 * mean over leaves of (1 - p ** n(l))

The other three metrics involve unions over correlated leaves and have no simple closed form,
so they are simulated only.

Statistics
----------
Each (link type, p) cell is simulated R times (default R = 500). Retention lies in [0, 1], so
its SD is at most 0.5 and the Monte-Carlo standard error of the mean is at most 0.5 / sqrt(R),
about 0.022 at R = 500; `SensitivityResult.convergence_check` reports the actual values for
R in {50, 200, 1000}. For every metric and cell we report the mean, the sample SD (ddof = 1),
the SEM, the 5th, 50th and 95th percentiles, the skewness and a 95% CI for the mean.

CI method. The default is "bootstrap": a percentile bootstrap (n_boot resamples of the
replicates). Replicate distributions of a bounded ratio are skewed near p = 0 and p = 1, and
leaves that share links make replicates non-binomial, so a symmetric interval is not assumed.
"normal" (mean +/- 1.96 SEM) is available for comparison.

In rare-event cells (small p, leaves backed by many CVEs) no replicate may show a loss. The SD
is then 0 and the CI collapses to a point at 1.0 although the true expectation is slightly
lower. That is not zero uncertainty; in such cells use the analytic_mean column, which is the
exact expectation for retention. The CI covers the Monte-Carlo error of the estimated
expectation; the spread of a single perturbation draw is described by the SD and the 5th-95th
percentile range.

Reproducibility. Each cell draws from its own generator seeded from (seed, link type, p), so
its numbers do not depend on which other cells are requested, and a run is reproducible for a
given (seed, R) and numpy version. Seed, R, CI method and n_boot are recorded in every output
row. Replicates within a cell are drawn one after another, so the first R' replicates of an
R-replicate run equal the R'-replicate run (used by `convergence_check`).

Conventions. p = 0 gives exactly 1.0 and p = 1 exactly 0.0 for every metric (a link is kept iff
U >= p, with U uniform on [0, 1)). If a denominator is zero (empty relation) the metric is NaN:
undefined, not robust. It is never an exception and never a made-up 1.0.
"""
from __future__ import annotations

import math
import zlib
from collections import Counter, defaultdict
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from . import attack_tree_lib as atl
from .errors import PipelineError

LEVELS = (0.1, 0.2, 0.3, 0.4, 0.5)
ALL = "all"

# A chain tuple is (CVE, CWE, CAPEC, technique, tactic); link types index into it.
_LINKS = {
    "cve_cwe": (0, 1),
    "cwe_capec": (1, 2),
    "capec_technique": (2, 3),
    "technique_tactic": (3, 4),
}
LINK_TYPES = tuple(_LINKS)
PATTERN_LINK_TYPES = LINK_TYPES[1:]            # one link per leaf
METRICS = ("retention", "tactic_survival", "cwe_survival", "cve_survival")
CI_METHODS = ("bootstrap", "normal")
_Z95 = 1.959963984540054


# loading
def load_chains(dataset_path) -> list:
    """Load device_compromise_dataset.xlsx and return the curated chains as
    (CVE, CWE, CAPEC, technique, tactic) tuples, the same P that feeds the trees.
    Returns [] when the dataset has no complete chain (the analysis then reports NaN).
    """
    df = atl.load_dataset(str(dataset_path))
    key_cols = atl.resolve_key_columns(df)
    P, _dropped = atl.build_curated_relation(df, key_cols)
    if P.empty:
        return []
    if "CVE ID" not in P.columns:
        raise PipelineError("Dataset has no 'CVE ID' column; cannot attribute chains to CVEs.")
    rows = zip(P["CVE ID"], P[key_cols["cwe_key"]], P[key_cols["capec_key"]],
               P[key_cols["technique_key"]], P["tactics"])
    return _canonical(rows)


def _canonical(chains) -> list:
    """Deduplicated, deterministically ordered chain tuples (type-robust sort)."""
    return sorted({tuple(c) for c in chains}, key=lambda c: tuple(map(str, c)))


# integer index of a relation (the simulation runs on arrays, not tuples)
def _encode(values):
    ids, out = {}, np.empty(len(values), dtype=np.int64)
    for k, v in enumerate(values):
        out[k] = ids.setdefault(v, len(ids))
    return out, len(ids)


@dataclass(frozen=True)
class _Index:
    n_chains: int
    n_leaves: int
    n_tactics: int
    n_cwes: int
    n_cves: int
    n_links: dict            # link type -> number of distinct links
    link_of_chain: dict      # link type -> int array (n_chains,): id of the chain's link
    leaf_of_chain: np.ndarray
    cve_of_chain: np.ndarray
    tactic_of_leaf: np.ndarray
    cwe_of_leaf: np.ndarray
    support: np.ndarray      # n(l): distinct CVE->CWE links supporting each leaf

    @property
    def denominators(self) -> np.ndarray:            # same order as METRICS
        return np.array([self.n_leaves, self.n_tactics, self.n_cwes, self.n_cves])


def _build_index(chains) -> _Index:
    chains = list(chains)
    cve, n_cve = _encode([c[0] for c in chains])
    cwe, n_cwe = _encode([c[1] for c in chains])
    tac, n_tac = _encode([c[4] for c in chains])
    leaf, n_leaf = _encode([(c[4], c[1], c[3], c[2]) for c in chains])
    link_of_chain, n_links = {}, {}
    for name, (i, j) in _LINKS.items():
        link_of_chain[name], n_links[name] = _encode([(c[i], c[j]) for c in chains])
    tactic_of_leaf = np.zeros(n_leaf, dtype=np.int64)
    cwe_of_leaf = np.zeros(n_leaf, dtype=np.int64)
    tactic_of_leaf[leaf] = tac                        # a leaf fixes its tactic and CWE
    cwe_of_leaf[leaf] = cwe
    width = max(n_links["cve_cwe"], 1)
    pairs = np.unique(leaf * width + link_of_chain["cve_cwe"])
    support = np.bincount(pairs // width, minlength=n_leaf)
    return _Index(len(chains), n_leaf, n_tac, n_cwe, n_cve, n_links, link_of_chain,
                  leaf, cve, tactic_of_leaf, cwe_of_leaf, support)


def _counts(idx: _Index, alive: np.ndarray) -> np.ndarray:
    """Surviving (leaves, tactics, CWEs, CVEs) given a boolean mask over chains."""
    leaf_alive = np.zeros(idx.n_leaves, dtype=bool)
    leaf_alive[idx.leaf_of_chain[alive]] = True
    tac = np.zeros(idx.n_tactics, dtype=bool)
    tac[idx.tactic_of_leaf[leaf_alive]] = True
    cwe = np.zeros(idx.n_cwes, dtype=bool)
    cwe[idx.cwe_of_leaf[leaf_alive]] = True
    cve = np.zeros(idx.n_cves, dtype=bool)
    cve[idx.cve_of_chain[alive]] = True
    return np.array([leaf_alive.sum(), tac.sum(), cwe.sum(), cve.sum()])


# validation and seeding
def _check_name(name, allow_all=True) -> None:
    ok = LINK_TYPES + ((ALL,) if allow_all else ())
    if name not in ok:
        raise ValueError(f"unknown link type {name!r}; choose from {ok}")


def _check_p(p) -> None:
    if not (0.0 <= p <= 1.0):
        raise ValueError(f"perturbation level p must be in [0, 1], got {p}")


def _cell_rng(seed: int, name: str, p: float, stream: int) -> np.random.Generator:
    """Independent generator per (seed, link type, p, stream); stream 0 = perturbation
    draws, 1 = bootstrap resampling."""
    if int(seed) != seed or seed < 0:
        raise ValueError(f"seed must be a non-negative integer, got {seed!r}")
    entropy = [int(seed), zlib.crc32(name.encode()), int(round(p * 1_000_000)), int(stream)]
    return np.random.default_rng(np.random.SeedSequence(entropy))


# closed form
def _analytic(idx: _Index, name: str, p: float) -> float:
    if idx.n_leaves == 0:
        return float("nan")
    at_least_one_cve = float(np.mean(1.0 - np.power(float(p), idx.support)))
    if name == "cve_cwe":
        return at_least_one_cve
    if name == ALL:
        return (1.0 - p) ** 3 * at_least_one_cve
    return 1.0 - p


def analytic_retention(chains, name: str, p: float) -> float:
    """Closed-form expected leaf retention under i.i.d. Bernoulli link removal with
    probability p (see the module docstring). name is a link type or "all". NaN for an
    empty relation."""
    _check_name(name)
    _check_p(p)
    return _analytic(_build_index(_canonical(chains)), name, p)


# Monte-Carlo
def _simulate_cell(idx: _Index, name: str, p: float, reps: int, seed: int) -> np.ndarray:
    """(reps, 4) array of metric ratios (columns = METRICS) for one (link type, p) cell."""
    perturbed = LINK_TYPES if name == ALL else (name,)
    rng = _cell_rng(seed, name, p, 0)
    counts = np.empty((reps, len(METRICS)), dtype=np.int64)
    for r in range(reps):
        alive = np.ones(idx.n_chains, dtype=bool)
        for n in perturbed:
            keep = rng.random(idx.n_links[n]) >= p        # kept with probability exactly 1 - p
            alive &= keep[idx.link_of_chain[n]]
        counts[r] = _counts(idx, alive)
    den = idx.denominators
    safe = np.where(den > 0, den, 1)
    return np.where(den > 0, counts / safe, np.nan)


def _summarize(x: np.ndarray, ci_method: str, rng: np.random.Generator, n_boot: int) -> dict:
    nan = float("nan")
    out = dict(mean=nan, sd=nan, sem=nan, ci_lo=nan, ci_hi=nan, p05=nan, p50=nan, p95=nan, skew=nan)
    x = np.asarray(x, dtype=float)
    R = len(x)
    if R == 0 or np.isnan(x).any():
        return out
    if np.ptp(x) == 0.0:                                   # degenerate (e.g. p = 0 or p = 1)
        v = float(x[0])
        return dict(mean=v, sd=0.0, sem=0.0, ci_lo=v, ci_hi=v, p05=v, p50=v, p95=v, skew=nan)
    mean = float(x.mean())
    sd = float(x.std(ddof=1)) if R > 1 else nan
    sem = sd / math.sqrt(R) if R > 1 else nan
    out.update(mean=mean, sd=sd, sem=sem)
    out["p05"], out["p50"], out["p95"] = (float(v) for v in np.percentile(x, [5, 50, 95]))
    m2 = float(np.mean((x - mean) ** 2))
    out["skew"] = float(np.mean((x - mean) ** 3) / m2 ** 1.5)
    if ci_method == "normal":
        if R > 1:
            out["ci_lo"], out["ci_hi"] = mean - _Z95 * sem, mean + _Z95 * sem
    else:                                                   # percentile bootstrap of the mean
        means = np.empty(n_boot)
        step = max(1, 2_000_000 // R)                       # bound memory of the resample matrix
        for s in range(0, n_boot, step):
            e = min(n_boot, s + step)
            means[s:e] = x[rng.integers(0, R, size=(e - s, R))].mean(axis=1)
        out["ci_lo"], out["ci_hi"] = (float(v) for v in np.percentile(means, [2.5, 97.5]))
    return out


# worst-case analyses
def critical_links(chains, name: str, top=5) -> list:
    """Rank single links by the paths lost when each is removed: [(paths_lost, link), ...],
    largest loss first (ties broken by the link's repr, so the order is deterministic).

    A leaf is lost only if the removed link is its sole supporting link of that type. That is
    always the case for the three pattern-side types, and only for single-CVE leaves for
    cve_cwe. top=None returns all.
    """
    _check_name(name, allow_all=False)
    i, j = _LINKS[name]
    chains = _canonical(chains)
    supports = defaultdict(set)
    for c in chains:
        supports[(c[4], c[1], c[3], c[2])].add((c[i], c[j]))
    loss = Counter()
    for links in supports.values():
        if len(links) == 1:
            loss[next(iter(links))] += 1
    res = [(loss.get(l, 0), l) for l in {(c[i], c[j]) for c in chains}]
    res.sort(key=lambda t: (-t[0], repr(t[1])))
    return res if top is None else res[:top]


def greedy_worst_case(chains, budget: int = 5, link_types=PATTERN_LINK_TYPES) -> list:
    """Greedy adversarial removal: repeatedly delete the single link (of the allowed types)
    whose removal destroys the most leaves still alive. Returns one dict per step: step,
    link_type, link, marginal_paths_lost, cumulative_paths_lost, retention_after.

    Only the pattern-side types are supported. Each leaf has exactly one link of each, so the
    objective is maximum coverage, for which greedy is a (1 - 1/e)-approximation of the true worst
    case for that budget. cve_cwe is excluded: a leaf survives while any supporting CVE link
    remains, which breaks that guarantee (and the marginal gain of one CVE link is often 0 until
    its siblings are gone). Ties are broken by link-type order, then by the link's repr.
    """
    link_types = tuple(link_types)
    for n in link_types:
        if n not in PATTERN_LINK_TYPES:
            raise ValueError(f"greedy_worst_case supports {PATTERN_LINK_TYPES}, got {n!r}")
    leaves = sorted({(c[4], c[1], c[3], c[2]) for c in chains}, key=lambda l: tuple(map(str, l)))
    if not leaves:
        return []
    covers = defaultdict(set)                                # (link type, link) -> leaf ids
    for k, (t, w, s, c) in enumerate(leaves):
        per_type = {"cwe_capec": (w, c), "capec_technique": (c, s), "technique_tactic": (s, t)}
        for n in link_types:
            covers[(n, per_type[n])].add(k)
    order = {n: k for k, n in enumerate(link_types)}
    alive, steps = set(range(len(leaves))), []
    for step in range(1, int(budget) + 1):
        if not alive:
            break
        gains = {key: len(ls & alive) for key, ls in covers.items()}
        best = min(gains, key=lambda key: (-gains[key], order[key[0]], repr(key[1])))
        alive -= covers[best]
        cum = len(leaves) - len(alive)
        steps.append(dict(step=step, link_type=best[0], link=best[1],
                          marginal_paths_lost=gains[best], cumulative_paths_lost=cum,
                          retention_after=len(alive) / len(leaves)))
    return steps


# result container
def _fmt_link(link) -> str:
    return " -> ".join(map(str, link))


@dataclass
class SensitivityResult:
    rows: list = field(default_factory=list)       # one dict per (link, p, metric)
    critical: dict = field(default_factory=dict)   # link type -> [(paths_lost, link), ...]
    greedy: list = field(default_factory=list)     # greedy_worst_case steps
    seed: int = 0
    reps: int = 0
    ci_method: str = "bootstrap"
    n_boot: int = 0
    levels: tuple = ()
    link_types: tuple = ()
    n_chains: int = 0
    n_leaves: int = 0
    chains: list = field(default_factory=list, repr=False)

    def to_frame(self) -> pd.DataFrame:
        """Tidy frame: one row per (link, p, metric) with mean, sd, sem, 95% CI,
        p05/p50/p95, skew, seed, reps, and (retention only) the analytic value and z-score."""
        return pd.DataFrame(self.rows)

    def critical_frame(self) -> pd.DataFrame:
        """Single-link criticality (kind='single') and the greedy worst case (kind='greedy')."""
        n = self.n_leaves or float("nan")
        nan = float("nan")
        rows = []
        for name, items in self.critical.items():
            for rank, (loss, link) in enumerate(items, 1):
                rows.append(dict(kind="single", link_type=name, rank=rank, link=_fmt_link(link),
                                 paths_lost=loss, share_of_paths=loss / n,
                                 cumulative_paths_lost=nan, cumulative_share=nan))
        for s in self.greedy:
            rows.append(dict(kind="greedy", link_type=s["link_type"], rank=s["step"],
                             link=_fmt_link(s["link"]), paths_lost=s["marginal_paths_lost"],
                             share_of_paths=s["marginal_paths_lost"] / n,
                             cumulative_paths_lost=s["cumulative_paths_lost"],
                             cumulative_share=s["cumulative_paths_lost"] / n))
        return pd.DataFrame(rows, columns=["kind", "link_type", "rank", "link", "paths_lost",
                                           "share_of_paths", "cumulative_paths_lost",
                                           "cumulative_share"])

    def convergence_check(self, R_values=(50, 200, 1000)) -> pd.DataFrame:
        """Does the retention mean settle as R grows?

        For every (link, p) cell and every R in R_values: mean, SEM, CI (this result's ci_method),
        the analytic value, the absolute error and the tolerance used by verify_against_analytic.
        Replicates are nested (the first R of the largest run), so the table is one running estimate
        read at several R, computed with this result's seed.
        """
        R_values = sorted({int(r) for r in R_values})
        if not R_values or R_values[0] < 2:
            raise ValueError("R_values must contain integers >= 2")
        idx = _build_index(self.chains)
        rows = []
        for name in self.link_types:
            for p in self.levels:
                x = _simulate_cell(idx, name, p, R_values[-1], self.seed)[:, 0]
                an = _analytic(idx, name, p)
                for R in R_values:
                    rng = _cell_rng(self.seed, name, p, 1)
                    s = _summarize(x[:R], self.ci_method, rng, self.n_boot or 2000)
                    rows.append(dict(link=name, p=p, R=R, seed=self.seed, mean=s["mean"],
                                     sem=s["sem"], ci_lo=s["ci_lo"], ci_hi=s["ci_hi"],
                                     analytic_mean=an, abs_err=abs(s["mean"] - an),
                                     tol=float(_tolerance(s["sem"], R)) if idx.n_leaves else float("nan")))
        return pd.DataFrame(rows)


def _tolerance(sem, reps, k: float = 4.0, rare_events: float = 3.0, atol: float = 1e-12):
    """max(k * SEM, rare_events / reps, atol); see verify_against_analytic."""
    return np.maximum(np.maximum(k * np.asarray(sem, dtype=float), rare_events / np.asarray(reps, dtype=float)),
                      atol)


def verify_against_analytic(result_or_frame, k: float = 4.0, rare_events: float = 3.0,
                            atol: float = 1e-12, strict: bool = True) -> pd.DataFrame:
    """Check that the simulated retention mean matches the closed form. A cell passes iff

        |mean - analytic| <= max(k * SEM, rare_events / reps, atol)

    k = 4 rather than 2 because about 30 cells are tested at once (with k = 2, about 1.5 correct
    cells would fail by chance in every run). The second term is a rare-event floor: for small p,
    leaves backed by many CVEs are lost with probability around 1e-4 per replicate, and when no
    replicate shows a loss the replicates coincide (SEM = 0) although the true expectation is
    slightly below 1. Losing such a cluster costs at most 1.0 of retention, and the rule of three
    bounds the probability of a never-observed event by 3 / reps, so 3 / reps bounds the
    undetectable bias. atol covers p = 0 and p = 1, where the result must be exact.

    Needs reps >= 2. Returns the checked rows with `tol` and `ok` columns; with strict=True it
    raises AssertionError listing any failing cell.
    """
    df = result_or_frame.to_frame() if hasattr(result_or_frame, "to_frame") else result_or_frame
    df = df[(df["metric"] == "retention") & df["analytic_mean"].notna()].copy()
    df["tol"] = _tolerance(df["sem"], df["reps"], k, rare_events, atol)
    df["abs_err"] = (df["mean"] - df["analytic_mean"]).abs()
    df["ok"] = df["abs_err"].to_numpy() <= df["tol"].to_numpy()
    if strict and not df["ok"].all():
        raise AssertionError("simulated retention deviates from the closed form:\n"
                             + df.loc[~df["ok"], ["link", "p", "mean", "analytic_mean", "sem", "tol"]]
                             .to_string(index=False))
    return df


# drivers
def run_sensitivity_on_chains(chains, reps: int = 500, seed: int = 2026, levels=LEVELS,
                              link_types=LINK_TYPES + (ALL,), top_critical: int = 5,
                              ci_method: str = "bootstrap", n_boot: int = 2000,
                              greedy_budget: int = 5) -> SensitivityResult:
    """Engine behind run_sensitivity, on an in-memory list of chain tuples."""
    if int(reps) != reps or reps < 1:
        raise ValueError(f"reps must be a positive integer, got {reps!r}")
    if ci_method not in CI_METHODS:
        raise ValueError(f"ci_method must be one of {CI_METHODS}, got {ci_method!r}")
    if int(n_boot) != n_boot or n_boot < 1:
        raise ValueError(f"n_boot must be a positive integer, got {n_boot!r}")
    levels, link_types = tuple(float(p) for p in levels), tuple(link_types)
    for p in levels:
        _check_p(p)
    for n in link_types:
        _check_name(n)
    chains = _canonical(chains)
    idx = _build_index(chains)
    rows = []
    for name in link_types:
        for p in levels:
            ratios = _simulate_cell(idx, name, p, int(reps), seed)
            rng = _cell_rng(seed, name, p, 1)
            an = _analytic(idx, name, p)
            for m, metric in enumerate(METRICS):
                s = _summarize(ratios[:, m], ci_method, rng, int(n_boot))
                row = dict(link=name, p=p, metric=metric, n_base=int(idx.denominators[m]),
                           reps=int(reps), seed=int(seed), ci_method=ci_method,
                           n_boot=int(n_boot) if ci_method == "bootstrap" else float("nan"), **s,
                           analytic_mean=an if metric == "retention" else float("nan"))
                sem = row["sem"]
                row["z_vs_analytic"] = ((row["mean"] - an) / sem
                                        if metric == "retention" and sem and sem > 0
                                        else float("nan"))
                rows.append(row)
    critical = {n: critical_links(chains, n, top_critical) for n in LINK_TYPES}
    greedy = greedy_worst_case(chains, greedy_budget)
    return SensitivityResult(rows=rows, critical=critical, greedy=greedy, seed=int(seed),
                             reps=int(reps), ci_method=ci_method,
                             n_boot=int(n_boot) if ci_method == "bootstrap" else 0,
                             levels=levels, link_types=link_types, n_chains=idx.n_chains,
                             n_leaves=idx.n_leaves, chains=chains)


def run_sensitivity(dataset_path, reps: int = 500, seed: int = 2026, levels=LEVELS,
                    link_types=LINK_TYPES + (ALL,), top_critical: int = 5,
                    ci_method: str = "bootstrap", n_boot: int = 2000,
                    greedy_budget: int = 5) -> SensitivityResult:
    """Engine of the `sensitivity` CLI subcommand. Reads a device's curated chains from
    device_compromise_dataset.xlsx (no NVD traffic) and returns per-(link type, p, metric)
    statistics, the most critical single links per link type and a greedy worst case.
    """
    return run_sensitivity_on_chains(load_chains(dataset_path), reps=reps, seed=seed,
                                     levels=levels, link_types=link_types,
                                     top_critical=top_critical, ci_method=ci_method,
                                     n_boot=n_boot, greedy_budget=greedy_budget)