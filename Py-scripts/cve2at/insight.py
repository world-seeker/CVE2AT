"""Plain-language findings read from a finished workspace.

`build_report` reads device_compromise_dataset.xlsx (and, if present, run_summary.json) and
returns a Report: an overview line, three core insights and four additional ones. Every number
is computed from the data, so the same code serves any device. Nothing is simulated.

Definitions
-----------
Path   one tactic-level attack path: (weakness, technique, sub-technique, CAPEC, tactic).
Support  the set of CVEs whose chains lead to a path.
A path is removed by fixing CVEs only when every CVE in its support set is fixed.

`render_terminal`, `render_markdown`, `render_html` and `report.to_dict()` show the same Report.
"""
from __future__ import annotations

import html as _html
import json
import os
import shutil
import sys
import textwrap
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from itertools import combinations
from math import comb
from pathlib import Path

import numpy as np
import pandas as pd

from . import attack_tree_lib as atl
from .errors import PipelineError

TOP = 3                                    # rows in the short rankings
EXHAUSTIVE_LIMIT = 50_000                  # largest set of CVE combinations tried exactly
_VECTOR_RANK = {"NETWORK": 0, "ADJACENT_NETWORK": 1, "ADJACENT": 1, "LOCAL": 2, "PHYSICAL": 3}
_BREAK_LABELS = {
    "NO_CWE": "CVE has no CWE",
    "CWE_UNKNOWN": "CWE not in the reference set",
    "NO_CAPEC": "CWE has no usable CAPEC pattern",
    "CAPEC_INACTIVE": "CAPEC pattern deprecated or missing",
    "NO_TECHNIQUE": "CAPEC pattern has no ATT&CK technique",
    "TECHNIQUE_UNKNOWN": "technique not in the ATT&CK matrix",
    "NO_TACTIC": "technique has no tactic",
}


# result containers
@dataclass
class Insight:
    key: str
    title: str
    headline: str
    facts: list = field(default_factory=list)       # [(label, value)]
    bars_title: str = ""
    bars: list = field(default_factory=list)        # [(label, value, annotation)]
    table: dict = field(default_factory=dict)       # {"columns": [...], "rows": [[...]]}
    note: str = ""


@dataclass
class Report:
    device: str
    overview: list = field(default_factory=list)    # [(label, value)]
    core: list = field(default_factory=list)
    additional: list = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not (self.core or self.additional)

    def to_dict(self) -> dict:
        def one(i: Insight) -> dict:
            return {"key": i.key, "title": i.title, "headline": i.headline,
                    "facts": [{"label": a, "value": b} for a, b in i.facts],
                    "bars": [{"label": a, "value": b, "annotation": c} for a, b, c in i.bars],
                    "table": i.table, "note": i.note}
        return {"device": self.device,
                "overview": [{"label": a, "value": b} for a, b in self.overview],
                "core_insights": [one(i) for i in self.core],
                "additional_insights": [one(i) for i in self.additional]}


# small helpers
def _pct(part, whole) -> str:
    return f"{100.0 * part / whole:.1f}%" if whole else "n/a"


def _plural(n, word, many=None) -> str:
    return f"{n} {word if n == 1 else (many or word + 's')}"


def _join(items) -> str:
    return ", ".join(items)


def _spearman(x, y):
    """Rank correlation without scipy; None when it is undefined."""
    if len(x) < 3:
        return None
    rx, ry = pd.Series(x).rank().to_numpy(), pd.Series(y).rank().to_numpy()
    if rx.std() == 0 or ry.std() == 0:
        return None
    return float(np.corrcoef(rx, ry)[0, 1])


def _order(items) -> list:
    """MITRE kill-chain order; unrecognised names follow alphabetically (never set order)."""
    return atl.mitre_order(sorted(items))


def _clean(v) -> str:
    v = "" if v is None else str(v).strip()
    return "" if v.lower() == "nan" else v


# the data behind every insight
class _Model:
    def __init__(self, dataset_path, summary_path=None):
        df = atl.load_dataset(str(dataset_path))
        if "CVE ID" not in df.columns:
            raise PipelineError("Dataset has no 'CVE ID' column; cannot attribute paths to CVEs.")
        kc = atl.resolve_key_columns(df)
        P, _ = atl.build_curated_relation(df, kc)
        self.cves_in_scope = sorted(c for c in set(map(_clean, df["CVE ID"])) if c)
        self.cve_info = {}
        for _, r in df.drop_duplicates("CVE ID").iterrows():
            score = pd.to_numeric(r.get("baseScore", ""), errors="coerce")
            self.cve_info[_clean(r["CVE ID"])] = {
                "score": None if pd.isna(score) else float(score),
                "vector": _clean(r.get("attackVector", "")).upper(),
                "complexity": _clean(r.get("attackComplexity", "")).upper(),
                "privileges": _clean(r.get("privilegesRequired", "")).upper(),
                "interaction": _clean(r.get("userInteraction", "")).upper()}
        wk, tk, pk, ck = kc["cwe_key"], kc["technique_key"], kc["parent_technique_key"], kc["capec_key"]
        self.cve_cwe = {(_clean(v), _clean(w)) for v, w in zip(df["CVE ID"], df[wk]) if _clean(w)}
        self.cwe_name, self.step_name, self.capec_name = {}, {}, {}
        self.support = defaultdict(set)       # leaf (w, k, s, c, t) -> {CVE}
        for _, r in P.iterrows():
            w, k, s, c, t = r[wk], r[pk], r[tk], r[ck], r["tactics"]
            self.support[(w, k, s, c, t)].add(_clean(r["CVE ID"]))
            self.cwe_name.setdefault(w, _clean(r.get("cwe_Name", "")))
            self.capec_name.setdefault(c, _clean(r.get("capec_Name", "")))
            name, sub = _clean(r.get("technique_name", "")), _clean(r.get("subtechnique_name", ""))
            full = sub if (sub and (not name or sub.startswith(name))) else (f"{name}: {sub}" if sub else name)
            self.step_name.setdefault(s, full)
        self.leaves = sorted(self.support, key=lambda l: tuple(map(str, l)))
        self.tactics = _order({l[4] for l in self.leaves})
        self.summary = {}
        if summary_path and Path(summary_path).is_file():
            try:
                self.summary = json.loads(Path(summary_path).read_text(encoding="utf-8"))
            except (OSError, ValueError):
                self.summary = {}
        funnel = ((self.summary.get("stages", {}) or {}).get("merge", {}) or {}).get("coverage_funnel", {}) or {}
        n_fetched = funnel.get("cves_fetched_or_selected")
        # the dataset omits CVEs that have no CWE row at all, so the run summary has the full count
        self.n_cves = max(len(self.cves_in_scope), n_fetched if isinstance(n_fetched, int) else 0)

    # naming
    def cwe(self, w) -> str:
        return f"{self.cwe_name.get(w) or w} ({w})"

    def step(self, s, id_first=False) -> str:
        name = self.step_name.get(s) or s
        return f"{s}  {name}" if id_first else f"{name} ({s})"

    # views
    def leaves_in(self, tactic) -> list:
        return [l for l in self.leaves if l[4] == tactic]

    def cves_in(self, leaves) -> set:
        return set().union(*[self.support[l] for l in leaves]) if leaves else set()

    @property
    def cves_in_paths(self) -> set:
        return self.cves_in(self.leaves)


# the insights
def _weakness_across_stages(m: _Model):
    tree_cwes = {l[0] for l in m.leaves}
    by_cwe = defaultdict(set)
    for v, w in m.cve_cwe:
        if w in tree_cwes:
            by_cwe[w].add(v)

    def tactics_of(w):
        return {l[4] for l in m.leaves if l[0] == w}
    w = max(by_cwe, key=lambda x: (len(by_cwe[x]), len(tactics_of(x)), str(x)))
    cves, tactics = sorted(by_cwe[w]), _order(tactics_of(w))
    n_all, n_tac = m.n_cves, len(m.tactics)
    if len(cves) < 2:
        return Insight("weakness", "One weakness, many stages",
                       f"No weakness is shared: each of the {n_all} CVEs maps to its own weakness, "
                       "so a per-CVE view loses nothing here.")
    info = [(v, m.cve_info.get(v, {})) for v in cves]
    scored = sorted((i["score"], v, i["vector"]) for v, i in info if i.get("score") is not None)
    facts = [("CVEs", f"{len(cves)} of {n_all} in scope"),
             ("Tactic subtrees", f"{len(tactics)} of {n_tac} ({_join(tactics)})")]
    note = ""
    if scored:
        lo, hi = scored[0], scored[-1]
        facts.append(("CVSS base scores", f"{lo[0]} to {hi[0]}" if lo[0] != hi[0] else f"all {lo[0]}"))
        if lo[0] != hi[0]:
            facts.append(("Lowest-scoring", f"{lo[1]} ({lo[0]}{', ' + lo[2] if lo[2] else ''})"))
        if hi[0] - lo[0] >= 2:
            note = (f"{lo[1]} scores {lo[0]} and would rank low by severity alone, "
                    "yet it feeds the same weakness-centred progression as the others.")
    shared = [f"{label} {vals.pop()}" for label, vals in
              ((lab, {i.get(f) for _, i in info if i.get(f)}) for lab, f in
               (("attack complexity", "complexity"), ("privileges required", "privileges"),
                ("user interaction", "interaction"))) if len(vals) == 1]
    if shared:
        facts.append(("Same for all of them", _join(shared)))
    vec = Counter(i.get("vector") for _, i in info if i.get("vector"))
    if len(vec) > 1:
        facts.append(("Attack vector", _join(f"{k} x{n}" for k, n in sorted(vec.items()))))
    bars = [(t, sum(1 for l in m.leaves_in(t) if l[0] == w), "") for t in m.tactics]
    return Insight("weakness", "One weakness, many stages",
                   f"{m.cwe(w)} underlies {len(cves)} of {n_all} CVEs and reaches {len(tactics)} of "
                   f"{n_tac} tactic subtrees. Ranked one by one they read as separate findings; "
                   "the tree groups them under one recurring weakness.",
                   facts, "Paths of this weakness per tactic", bars, note=note)


def _path_count_vs_cves(m: _Model):
    rows = [(t, len(m.cves_in(m.leaves_in(t))), len(m.leaves_in(t))) for t in m.tactics]
    bars = [(t, p, f"from {_plural(c, 'CVE')}") for t, c, p in rows]
    title = "Paths per tactic"
    if len(rows) < 2:
        return Insight("path_count", "Path count is not CVE count",
                       f"Only one tactic is reached ({rows[0][0]}), so there is nothing to compare.",
                       bars_title=title, bars=bars)
    widest = max(rows, key=lambda r: (r[2], -r[1]))
    narrow = max((r for r in rows if r is not widest), key=lambda r: (r[1] / r[2], -r[2]))
    rho = _spearman([r[1] for r in rows], [r[2] for r in rows])
    facts = [("Widest tactic", f"{widest[0]}: {_plural(widest[2], 'path')} from {_plural(widest[1], 'CVE')}"),
             ("Narrowest per CVE", f"{narrow[0]}: {_plural(narrow[2], 'path')} from {_plural(narrow[1], 'CVE')}")]
    wl = m.leaves_in(widest[0])
    excl = Counter(next(iter(m.support[l])) for l in wl if len(m.support[l]) == 1)
    if excl:
        cve, n = max(sorted(excl.items()), key=lambda kv: kv[1])
        if 2 * n >= len(wl):
            mine = [l for l in wl if m.support[l] == {cve}]
            facts.append(("Dominant CVE there", f"{cve} alone gives {n} of {len(wl)} paths, "
                          f"through {_plural(len({l[1] for l in mine}), 'technique')} and "
                          f"{_plural(len({l[3] for l in mine}), 'CAPEC pattern')}"))
    nl = m.leaves_in(narrow[0])
    if len(nl) == 1 and narrow[1] > 1:
        facts.append(("Collapse", f"all {narrow[1]} CVEs lead to one step: {m.step(nl[0][2])}"))
    if rho is not None:
        facts.append(("Rank correlation, CVEs vs paths", f"{rho:.2f} across {len(rows)} tactics"))
    if rho is None:
        verdict = "CVE count says little about how many paths a tactic opens."
    elif rho >= 0.8:
        verdict = "Here CVE count tracks path count closely, so it is a fair proxy."
    elif rho >= 0.5:
        verdict = "CVE count is only a rough guide to how many paths a tactic opens."
    else:
        verdict = "CVE count is a poor guide to how many paths a tactic opens."
    return Insight("path_count", "Path count is not CVE count",
                   f"{widest[0]} has {_plural(widest[2], 'path')} from {_plural(widest[1], 'CVE')}, while "
                   f"{narrow[0]} has {_plural(narrow[2], 'path')} from {_plural(narrow[1], 'CVE')}. {verdict}",
                   facts, title, bars)


def _redundancy(m: _Model):
    raw_capec = sum(len({l[3] for l in m.leaves_in(t)}) for t in m.tactics)
    raw_tech = sum(len({l[1] for l in m.leaves_in(t)}) for t in m.tactics)
    capecs, techs = {l[3] for l in m.leaves}, {l[1] for l in m.leaves}
    by_step = defaultdict(lambda: (set(), 0))
    for l in m.leaves:
        ts, n = by_step[l[2]]
        by_step[l[2]] = (ts | {l[4]}, n + 1)
    ranked = sorted(by_step.items(), key=lambda kv: (-len(kv[1][0]), -kv[1][1], str(kv[0])))
    shared = [(s, ts, n) for s, (ts, n) in ranked if len(ts) >= 2][:TOP]
    facts = [("CAPEC references over all tactics", raw_capec),
             ("Distinct CAPEC patterns", len(capecs)),
             ("ATT&CK techniques over all tactics", raw_tech),
             ("Distinct ATT&CK techniques", len(techs))]
    bars = [(m.step(s, id_first=True), len(ts), _join(_order(ts))) for s, ts, n in shared]
    if raw_capec > len(capecs):
        head = (f"{raw_capec} CAPEC references collapse to {len(capecs)} distinct patterns "
                f"({_pct(raw_capec - len(capecs), raw_capec)} repeat one already used in another tactic). "
                "The same mechanisms recur across stages, so one control can cut paths in several of them.")
    else:
        head = "No CAPEC pattern is reused across tactics, so each tactic subtree needs its own controls."
    note = ""
    if shared:
        s, ts, _ = shared[0]
        note = f"A control aimed at {m.step(s)} would reach paths under {_join(_order(ts))}."
    return Insight("redundancy", "Redundancy shows where one control helps twice", head, facts,
                   "Steps that appear under the most tactics (number of tactics)", bars, note=note)


def _best_removal(m: _Model, k: int):
    """CVE set of size k that removes the most paths; exact when small, greedy otherwise."""
    cves = sorted(m.cves_in_paths)
    k = min(k, len(cves))
    supports = [m.support[l] for l in m.leaves]

    def removed(chosen):
        return sum(1 for s in supports if s <= chosen)
    if comb(len(cves), k) <= EXHAUSTIVE_LIMIT:
        scored = [(removed(set(c)), c) for c in combinations(cves, k)]
        top = max(n for n, _ in scored)
        return list(next(c for n, c in scored if n == top)), top
    chosen = set()
    for _ in range(k):
        pick = max((v for v in cves if v not in chosen),
                   key=lambda v: (removed(chosen | {v}), sum(1 for s in supports if v in s), v))
        chosen.add(pick)
    return sorted(chosen), removed(chosen)


def _fix_leverage(m: _Model):
    n, supports = len(m.leaves), [m.support[l] for l in m.leaves]
    single = sum(1 for s in supports if len(s) == 1)
    facts = [("Paths resting on one CVE", f"{single} of {n} ({_pct(single, n)})")]
    rows = []
    for k in (1, 2, 3):
        if k > len(m.cves_in_paths):
            break
        chosen, gone = _best_removal(m, k)
        rows.append([k, _join(chosen), gone, _pct(gone, n)])
    if not rows or rows[0][2] == 0:
        return Insight("leverage", "Where a fix removes the most paths",
                       "No single CVE fix removes a path: every path is supported by at least two CVEs.",
                       facts, note="A path is removed only when every CVE supporting it is fixed.")
    first = rows[0]
    cve = first[1]
    scores = [i["score"] for v, i in m.cve_info.items() if v in m.cves_in_paths and i["score"] is not None]
    mine = m.cve_info.get(cve, {}).get("score")
    rank = 1 + sum(1 for s in scores if s > mine) if (mine is not None and scores) else None
    if rank:
        facts.append((f"CVSS rank of {cve}", f"#{rank} of {len(scores)} by base score ({mine})"))
    tail = ("" if rank is None else
            " It also has the highest base score." if rank == 1 else
            f" Its base score ranks only #{rank} of {len(scores)}, so severity alone would not point to it.")
    return Insight("leverage", "Where a fix removes the most paths",
                   f"Fixing {cve} alone removes {first[2]} of {n} paths ({first[3]}), "
                   f"the most of any single CVE.{tail}",
                   facts, table={"columns": ["Fixes", "CVEs fixed", "Paths removed", "Share"], "rows": rows},
                   note="A path is removed only when every CVE supporting it is fixed. Sets are the best "
                        "of all combinations of that size (greedy for very large devices).")


def _exposure(m: _Model):
    def easiest(leaf):
        return min((_VECTOR_RANK.get(m.cve_info.get(v, {}).get("vector", ""), 4) for v in m.support[leaf]))
    names = {0: "Network", 1: "Adjacent", 2: "Local", 3: "Physical", 4: "Unknown"}
    dist = Counter(easiest(l) for l in m.leaves)
    if dist.get(4, 0) == len(m.leaves):
        return None

    def open_route(leaf):
        return any(m.cve_info.get(v, {}).get("vector") == "NETWORK"
                   and m.cve_info.get(v, {}).get("privileges") == "NONE"
                   and m.cve_info.get(v, {}).get("interaction") == "NONE" for v in m.support[leaf])
    n, free = len(m.leaves), sum(1 for l in m.leaves if open_route(l))
    bars = [(names[r], dist[r], _pct(dist[r], n)) for r in sorted(dist)]
    facts = [("Remote, no privileges, no interaction", f"{free} of {n} ({_pct(free, n)})"),
             ("Physical access is the only route", f"{dist.get(3, 0)} of {n}")]
    if free:
        head = (f"{free} of {n} paths ({_pct(free, n)}) can be driven remotely: at least one supporting CVE is "
                "reachable over the network with no privileges and no user interaction.")
    else:
        head = "No path has a supporting CVE that is network-reachable with no privileges and no interaction."
    return Insight("exposure", "How easily the paths can be reached", head, facts,
                   "Easiest attack vector among each path's supporting CVEs", bars,
                   note="Taken from each CVE's CVSS metrics; a path counts at the easiest of its CVEs.")


def _concentration(m: _Model):
    n = len(m.leaves)
    paths = Counter(l[0] for l in m.leaves)
    cves = {w: {v for v, x in m.cve_cwe if x == w} for w in paths}
    ranked = sorted(paths.items(), key=lambda kv: (-kv[1], str(kv[0])))
    bars = [(m.cwe(w), p, f"{_pct(p, n)}, from {_plural(len(cves[w]), 'CVE')}") for w, p in ranked[:TOP + 2]]
    w, p = ranked[0]
    top_cve = max(cves, key=lambda x: (len(cves[x]), -paths[x], str(x)))
    note = ""
    if top_cve != w and len(cves[top_cve]) > len(cves[w]):
        note = (f"{m.cwe(top_cve)} has more CVEs ({len(cves[top_cve])}) but fewer paths ({paths[top_cve]}): "
                "CVE counts and path counts rank the weaknesses differently.")
    return Insight("concentration", "Which weakness feeds the most paths",
                   f"{m.cwe(w)} supports {p} of {n} paths ({_pct(p, n)}) from {_plural(len(cves[w]), 'CVE')}.",
                   [("Weaknesses in the tree", len(paths))], "Paths per weakness", bars, note=note)


def _coverage(m: _Model):
    every = atl.MITRE_TACTIC_ORDER
    missing = [t for t in every if t not in m.tactics]
    funnel = (m.summary.get("stages", {}).get("merge", {}) or {}).get("coverage_funnel", {}) or {}
    reasons = funnel.get("chain_break_reasons") or {}
    facts = [("Tactics reached", f"{len(m.tactics)} of {len(every)}"),
             ("Not reached", _join(missing) or "none"),
             ("CVEs with a complete chain", f"{len(m.cves_in_paths)} of {m.n_cves}")]
    bars = [(_BREAK_LABELS.get(r, r), n, "") for r, n in sorted(reasons.items(), key=lambda kv: (-kv[1], kv[0]))]
    head = f"The paths reach {len(m.tactics)} of {len(every)} ATT&CK tactics."
    if bars:
        top, total = bars[0], sum(n for _, n, _ in bars)
        head += f" Most dropped chain rows ({top[1]} of {total}) are lost at one step: {top[0]}."
    return Insight("coverage", "Where public mappings run out", head, facts,
                   "Dropped chain rows by reason" if bars else "", bars,
                   note="Tactics not reached show gaps in public cross-references, "
                        "not evidence that the device is safe from them.")


def build_report(dataset_path, summary_path=None, device: str = "") -> Report:
    m = _Model(dataset_path, summary_path)
    rep = Report(device=device or Path(dataset_path).resolve().parent.name)
    paths = len(m.leaves)
    rep.overview = [("CVEs in scope", m.n_cves), ("CVEs reaching a tactic", len(m.cves_in_paths)),
                    ("Weaknesses", len({l[0] for l in m.leaves})), ("CAPEC patterns", len({l[3] for l in m.leaves})),
                    ("Techniques", len({l[1] for l in m.leaves})), ("Tactics", len(m.tactics)),
                    ("Paths", paths)]
    if not paths:
        return rep
    rep.core = [_weakness_across_stages(m), _path_count_vs_cves(m), _redundancy(m)]
    rep.additional = [x for x in (_fix_leverage(m), _exposure(m), _concentration(m), _coverage(m)) if x]
    return rep


# terminal output
class _Style:
    def __init__(self, color: bool, unicode: bool, width: int):
        self.color, self.unicode, self.width = color, unicode, width
        self.full, self.rule, self.bar_char = ("█", "━", "█") if unicode else ("#", "=", "#")

    def _w(self, code, s):
        return f"\033[{code}m{s}\033[0m" if self.color else s

    def bold(self, s): return self._w("1", s)
    def dim(self, s): return self._w("2", s)
    def accent(self, s): return self._w("1;36", s)
    def warm(self, s): return self._w("33", s)


def _use_color(force=None) -> bool:
    if force is not None:
        return force
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR") and os.environ.get("TERM") != "dumb"


def _use_unicode() -> bool:
    try:
        "█━".encode(getattr(sys.stdout, "encoding", None) or "ascii")
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def render_terminal(rep: Report, color=None, width=None) -> str:
    if sys.platform == "win32":
        os.system("")                                  # lets the Windows console read ANSI codes
    width = width or min(shutil.get_terminal_size((100, 20)).columns, 100)
    st = _Style(_use_color(color), _use_unicode(), max(width, 60))
    inner, out = st.width - 4, []

    def wrap(text, indent="    ", style=lambda s: s, first=None):
        lines = textwrap.wrap(str(text), st.width - len(indent) - 2) or [""]
        for i, line in enumerate(lines):
            out.append((first if (i == 0 and first is not None) else indent) + style(line))

    out.append(st.accent(st.rule * st.width))
    out.append(st.accent("  CVE2AT insights") + st.dim(f"  ·  {rep.device}"))
    out.append(st.accent(st.rule * st.width))
    if rep.overview:
        wrap(" · ".join(f"{label} {value}" for label, value in rep.overview), "  ", st.dim)
    if rep.empty:
        out.append("")
        out.append("  No complete chains in this dataset, so there is nothing to report.")
        return "\n".join(out)
    n = 0
    for heading, items in (("CORE INSIGHTS", rep.core), ("ADDITIONAL INSIGHTS", rep.additional)):
        if not items:
            continue
        out.append("")
        out.append(st.bold(f"  {heading}"))
        out.append("  " + st.dim(st.rule * (st.width - 4)))
        for ins in items:
            n += 1
            out.append("")
            out.append("  " + st.accent(f"{n:02d}") + "  " + st.bold(ins.title))
            wrap(ins.headline, "      ", st.bold)
            if ins.facts:
                out.append("")
                lab = min(max(len(str(a)) for a, _ in ins.facts), max(st.width // 3, 16))
                for a, b in ins.facts:
                    wrap(b, " " * (6 + lab + 2), first="      " + st.dim(str(a).ljust(lab)) + "  ")
            if ins.table:
                out.append("")
                cols, rows = ins.table["columns"], ins.table["rows"]
                widths = [max(len(str(c)), *(len(str(r[i])) for r in rows)) for i, c in enumerate(cols)]
                room = st.width - 6 - 2 * (len(cols) - 1)
                while sum(widths) > room and max(widths) > 12:
                    widths[widths.index(max(widths))] -= 1

                def cell(v, w):
                    v = str(v)
                    return (v if len(v) <= w else v[:w - 1] + "…").ljust(w)
                out.append("      " + "  ".join(st.dim(cell(c, w)) for c, w in zip(cols, widths)))
                for r in rows:
                    out.append("      " + "  ".join(cell(v, w) for v, w in zip(r, widths)))
            if ins.bars:
                out.append("")
                out.append("      " + st.dim(ins.bars_title))
                top = max(max(v for _, v, _ in ins.bars), 1)
                lab = min(max(len(str(a)) for a, _, _ in ins.bars), max(st.width // 3, 16))
                span = max(min(st.width - lab - 24, 28), 8)
                for a, v, note in ins.bars:
                    cells = int(round(v / top * span)) if v else 0
                    bar = st.warm(st.bar_char * cells) if cells else ""
                    text = str(a) if len(str(a)) <= lab else str(a)[:lab - 1] + "…"
                    line = "      " + text.ljust(lab) + "  " + bar + " " * (span - cells) + f" {v}"
                    if note and len(line) + len(note) + 3 <= st.width:
                        out.append(line + st.dim(f"  {note}"))
                    else:
                        out.append(line)
                        if note:
                            wrap(note, " " * (6 + lab + 2), st.dim)
            if ins.note:
                out.append("")
                wrap(ins.note, "      ", st.dim)
    out.append("")
    return "\n".join(out)


# markdown and html
def _md_bar(v, top, span=20) -> str:
    return "█" * int(round(v / top * span)) if v else ""


def render_markdown(rep: Report) -> str:
    L = [f"# Insights: {rep.device}", ""]
    if rep.overview:
        L += [" · ".join(f"{a} **{b}**" for a, b in rep.overview), ""]
    if rep.empty:
        return "\n".join(L + ["No complete chains in this dataset, so there is nothing to report.", ""])
    n = 0
    for heading, items in (("Core insights", rep.core), ("Additional insights", rep.additional)):
        if not items:
            continue
        L += [f"## {heading}", ""]
        for ins in items:
            n += 1
            L += [f"### {n}. {ins.title}", "", f"**{ins.headline}**", ""]
            if ins.facts:
                L += [f"- {a}: {b}" for a, b in ins.facts] + [""]
            if ins.table:
                cols = ins.table["columns"]
                L += ["| " + " | ".join(map(str, cols)) + " |", "|" + "---|" * len(cols)]
                L += ["| " + " | ".join(map(str, r)) + " |" for r in ins.table["rows"]] + [""]
            if ins.bars:
                top = max(max(v for _, v, _ in ins.bars), 1)
                L += [f"_{ins.bars_title}_", "", "| Item | Count | Bar | Detail |", "|---|---|---|---|"]
                L += [f"| {a} | {v} | {_md_bar(v, top)} | {c} |" for a, v, c in ins.bars] + [""]
            if ins.note:
                L += [f"> {ins.note}", ""]
    return "\n".join(L)


_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1c2430;--mute:#667085;--line:#e4e7ec;--acc:#0e7490;--bar:#f59e0b;--chip:#ecfeff}
@media (prefers-color-scheme:dark){:root{--bg:#10151c;--card:#171e28;--ink:#e6eaf0;--mute:#98a2b3;--line:#2a3340;--acc:#22d3ee;--bar:#fbbf24;--chip:#12303a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:900px;margin:0 auto;padding:32px 20px 56px}h1{font-size:26px;margin:0 0 4px}.dev{color:var(--mute);margin:0 0 18px}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:8px}.chip{background:var(--chip);border:1px solid var(--line);border-radius:999px;padding:4px 12px;font-size:13px}.chip b{color:var(--acc)}
h2{font-size:13px;letter-spacing:.12em;text-transform:uppercase;color:var(--mute);margin:34px 0 12px;border-bottom:1px solid var(--line);padding-bottom:6px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:20px 22px;margin:0 0 16px}
.card h3{margin:0 0 6px;font-size:17px}.num{display:inline-block;min-width:28px;color:var(--acc);font-weight:700}.lead{font-weight:600;margin:0 0 12px}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:0 0 12px;font-size:14px}dt{color:var(--mute)}dd{margin:0}
.bt{color:var(--mute);font-size:13px;margin:12px 0 6px}.row{display:grid;grid-template-columns:minmax(120px,260px) 1fr;gap:12px;align-items:center;margin:4px 0;font-size:14px}
.track{display:flex;align-items:center;gap:8px}.fill{height:12px;border-radius:6px;background:var(--bar);min-width:2px}.val{font-weight:600}.det{color:var(--mute);font-size:13px}
table{border-collapse:collapse;width:100%;font-size:14px;margin:8px 0}th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line)}th{color:var(--mute);font-weight:500}
.note{color:var(--mute);font-size:13px;margin:12px 0 0;border-left:3px solid var(--line);padding-left:10px}
"""


def render_html(rep: Report) -> str:
    e = _html.escape
    parts = [f"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
             f"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
             f"<title>Insights: {e(rep.device)}</title><style>{_CSS}</style></head><body><main>",
             f"<h1>Insights</h1><p class=\"dev\">{e(rep.device)}</p><div class=\"chips\">"
             + "".join(f"<span class=\"chip\">{e(str(a))} <b>{e(str(b))}</b></span>" for a, b in rep.overview)
             + "</div>"]
    if rep.empty:
        parts.append("<p>No complete chains in this dataset, so there is nothing to report.</p>")
    n = 0
    for heading, items in (("Core insights", rep.core), ("Additional insights", rep.additional)):
        if not items:
            continue
        parts.append(f"<h2>{e(heading)}</h2>")
        for ins in items:
            n += 1
            parts.append(f"<section class=\"card\"><h3><span class=\"num\">{n:02d}</span>{e(ins.title)}</h3>"
                         f"<p class=\"lead\">{e(ins.headline)}</p>")
            if ins.facts:
                parts.append("<dl>" + "".join(f"<dt>{e(str(a))}</dt><dd>{e(str(b))}</dd>" for a, b in ins.facts) + "</dl>")
            if ins.table:
                parts.append("<table><tr>" + "".join(f"<th>{e(str(c))}</th>" for c in ins.table["columns"]) + "</tr>"
                             + "".join("<tr>" + "".join(f"<td>{e(str(v))}</td>" for v in r) + "</tr>"
                                       for r in ins.table["rows"]) + "</table>")
            if ins.bars:
                top = max(max(v for _, v, _ in ins.bars), 1)
                parts.append(f"<div class=\"bt\">{e(ins.bars_title)}</div>")
                for a, v, c in ins.bars:
                    parts.append(f"<div class=\"row\"><span>{e(str(a))}</span><span class=\"track\">"
                                 f"<span class=\"fill\" style=\"width:{100.0 * v / top * 0.6:.1f}%\"></span>"
                                 f"<span class=\"val\">{e(str(v))}</span><span class=\"det\">{e(str(c))}</span></span></div>")
            if ins.note:
                parts.append(f"<p class=\"note\">{e(ins.note)}</p>")
            parts.append("</section>")
    parts.append("</main></body></html>")
    return "".join(parts)


def write_files(rep: Report, out_dir) -> list:
    """Write insights.md, insights.html and insights.json; return the paths."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    files = {"insights.md": render_markdown(rep), "insights.html": render_html(rep),
             "insights.json": json.dumps(rep.to_dict(), indent=2, ensure_ascii=False)}
    for name, text in files.items():
        (out / name).write_text(text, encoding="utf-8")
    return [out / n for n in files]