"""CTI provenance figure: how a device's CVEs propagate through the CVE2AT chain.

    CVE -> CWE -> CAPEC -> ATT&CK technique -> ATT&CK sub-technique -> ATT&CK tactic

The figure is drawn from the same curated data as the attack trees. Nothing is typed in by
hand and no mapping logic is repeated here. It calls these library functions:

    atl.load_dataset()              read device_compromise_dataset.xlsx
    atl.resolve_key_columns()       identity columns
    atl.build_curated_relation()    P, the complete chains
    atl.mitre_order()               kill-chain order of the tactic row
    atl.build_leaf_index()          only to cross-check the figure against the trees

Entry point: generate_cti_chain_figure(dataset_path, output_path, ...) -> CtiFigureResult.
It is also available as `cve2at cti-figure`.

Reading the figure
* solid edge: relation supported by a complete chain (a row of P)
* dotted edge: technique -> tactic directly, because that chain has no sub-technique
  (no sub-technique node is invented)
* dashed edge, hollow node or end cap: a relation that exists in the data but does not
  complete the chain, so the chain stops at that layer
* "+k CAPEC" stub: the CWE has k CAPEC patterns, for the CVEs shown, that never reach a
  complete technique and tactic mapping. They are merged in the drawing for readability and
  listed in the *_edges.csv and *_nodes.csv files.
"""
from __future__ import annotations

import bisect
import json
import random
import re
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

from . import attack_tree_lib as atl
from . import console
from .errors import ConfigError, DatasetError, PipelineError

# constants
LAYERS = ("cve", "cwe", "capec", "tech", "sub", "tactic")          # row 0 .. row 5
LAYER_TITLES = ("CVE", "CWE", "CAPEC", "ATT&CK technique", "ATT&CK sub-technique", "ATT&CK tactic")
BREAK_CODES = ("NO_TECHNIQUE_OR_TACTIC", "NO_CAPEC", "NO_CWE")      # round-robin order when picking CVEs
DEFAULT_FORMATS = ("png", "pdf", "svg")


# helpers
def _nat(s: str) -> list:
    """Natural sort key: CVE-2018-7844 < CVE-2018-10000, T1033 < T1036.001."""
    return [int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", str(s))]


def _clean(v) -> str:
    return atl._s(v)          # same trimming rule the library uses ('' for NaN/None)


def _norm_cwe_token(tok: str) -> str:
    tok = tok.strip()
    return f"CWE-{tok}" if tok.isdigit() else tok


# result and model containers
@dataclass
class CtiFigureResult:
    files: dict                 # {"png": Path, "pdf": Path, "svg": Path, "dot": Path, "nodes_csv": ..., ...}
    stats: dict                 # the summary printed to the console (full-data numbers)
    nodes: pd.DataFrame
    edges: pd.DataFrame
    cves: pd.DataFrame          # every CVE, its status, and whether it was drawn
    checks: pd.DataFrame        # the validation report (check, ok, detail)


@dataclass
class _Model:
    nodes: dict = field(default_factory=dict)       # nid -> dict(kind, layer, label, name, style, terminal)
    edges: dict = field(default_factory=dict)       # (src, dst) -> dict(kind, support)
    displayed_cves: list = field(default_factory=list)
    displayed_chain_cves: list = field(default_factory=list)
    omitted_cves: list = field(default_factory=list)
    omitted_chain_cves: list = field(default_factory=list)
    cve_class: dict = field(default_factory=dict)   # cve -> "CHAIN" | break code


# loading (through the library) and the CVE->CWE relation of the source tables
def _load_curated(dataset_path):
    df = atl.load_dataset(str(dataset_path))
    if "CVE ID" not in df.columns:
        raise DatasetError("The dataset has no 'CVE ID' column - cannot trace chains back to CVEs.")
    key_cols = atl.resolve_key_columns(df)
    P, dropped = atl.build_curated_relation(df, key_cols)
    if P.empty:
        raise PipelineError("No complete CVE->CWE->CAPEC->technique->tactic chains in the dataset - "
                            "there is no chain to draw.")
    for frame in (P, dropped):
        frame["CVE ID"] = frame["CVE ID"].map(_clean)
    df["CVE ID"] = df["CVE ID"].map(_clean)
    return df, key_cols, P, dropped


def _read_cve_table(path: Path | None):
    """cve_data.xlsx -> {cve: [cwe tokens]}, splitting the Weaknesses cell the way merge.py does.

    Returns (relation, available). A CVE with no weakness gets an empty list.
    """
    if path is None or not Path(path).is_file():
        return {}, False
    t = pd.read_excel(path)
    if "CVE ID" not in t.columns or "Weaknesses" not in t.columns:
        raise DatasetError(f"{Path(path).name} needs 'CVE ID' and 'Weaknesses' columns.")
    rel = {}
    for cve, cell in zip(t["CVE ID"], t["Weaknesses"]):
        cve = _clean(cve)
        if not cve:
            continue
        cell = "" if pd.isna(cell) else str(cell)
        toks = [_norm_cwe_token(x) for x in cell.split("; ") if x.strip()]
        rel.setdefault(cve, [])
        for tok in toks:
            if tok not in rel[cve]:
                rel[cve].append(tok)
    return rel, True


def _read_summary(path: Path | None) -> dict:
    if path is None or not Path(path).is_file():
        return {}
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


# chains of P, as plain tuples (the one place that knows the column names)
def _chain_table(P: pd.DataFrame, key_cols: dict) -> pd.DataFrame:
    """One row per row of P: cve, cwe, capec, parent (k), leaf (s), sub ('' if none), tactic and names.

    A chain has a sub-technique exactly when its sub-technique name is non-empty, as in
    build_leaf_index. The leaf key s is then the sub-technique id; otherwise there is no
    sub-technique node.
    """
    sl = key_cols["subtechnique_label"]
    has_sl = bool(sl) and sl in P.columns
    rows = []
    for _, r in P.iterrows():
        leaf = _clean(r[key_cols["technique_key"]])
        sub_name = _clean(r[sl]) if has_sl else ""
        rows.append({
            "cve": r["CVE ID"],
            "cwe": _clean(r[key_cols["cwe_key"]]),
            "capec": _clean(r[key_cols["capec_key"]]),
            "parent": _clean(r[key_cols["parent_technique_key"]]),
            "leaf": leaf,
            "sub": leaf if sub_name else "",
            "tactic": _clean(r["tactics"]),
            "cwe_name": _clean(r[key_cols["cwe_label"]]),
            "capec_name": _clean(r[key_cols["capec_label"]]),
            "parent_name": _clean(r[key_cols["parent_technique_label"]]),
            "sub_name": sub_name,
        })
    return pd.DataFrame(rows)


# choosing which CVEs are drawn
def _classify_cves(universe, cve_cwes, chain_cves, df_cves):
    cls = {}
    for cve in universe:
        if cve in chain_cves:
            cls[cve] = "CHAIN"
        elif not cve_cwes.get(cve):
            cls[cve] = "NO_CWE"
        elif cve in df_cves:
            cls[cve] = "NO_TECHNIQUE_OR_TACTIC"      # reached CAPEC level, no complete technique+tactic
        else:
            cls[cve] = "NO_CAPEC"                     # has a CWE, no usable CAPEC
    return cls


def _select_cves(cve_class, chains: pd.DataFrame, max_cves: int, min_noncarrying: int = 2):
    """Pick at most max_cves CVEs to draw.

    Every CVE that carries a chain is drawn if it fits (ranked by number of chain rows, then ID,
    only when they have to be truncated). The remaining slots go to CVEs without chains,
    round-robin over the break types so each kind of early stop appears, in ID order within a
    type. If such CVEs exist, at least min_noncarrying slots are reserved for them so the figure
    shows that some CVEs stop early.
    """
    n_rows = chains.groupby("cve").size().to_dict()
    chain = sorted([c for c, k in cve_class.items() if k == "CHAIN"], key=lambda c: (-n_rows.get(c, 0), _nat(c)))
    non = {code: sorted([c for c, k in cve_class.items() if k == code], key=_nat) for code in BREAK_CODES}
    n_non_total = sum(len(v) for v in non.values())

    n_non_show = min(n_non_total, max(max_cves - len(chain), min(min_noncarrying, max_cves)))
    n_chain_show = min(len(chain), max_cves - n_non_show)

    shown_chain = chain[:n_chain_show]
    shown_non, queues = [], {k: list(v) for k, v in non.items()}
    while len(shown_non) < n_non_show:
        progressed = False
        for code in BREAK_CODES:
            if queues[code] and len(shown_non) < n_non_show:
                shown_non.append(queues[code].pop(0))
                progressed = True
        if not progressed:
            break
    omitted_chain = [c for c in chain if c not in shown_chain]
    omitted = omitted_chain + [c for k in BREAK_CODES for c in non[k] if c not in shown_non]
    return shown_chain, shown_non, omitted, omitted_chain


# node and edge model
def _add_node(m: _Model, kind, key, label=None, name="", style="chain", **extra):
    nid = f"{kind}:{key}"
    if nid not in m.nodes:
        layer = LAYERS.index(kind) if kind in LAYERS else extra.pop("layer")
        extra.pop("layer", None)
        m.nodes[nid] = {"kind": kind, "layer": layer,
                        "label": label if label is not None else key, "key": key, "name": name,
                        "style": style, "terminal": False, **extra}
    elif style == "chain":                      # a node supported by a complete chain stays "chain"
        m.nodes[nid]["style"] = "chain"
        if name and not m.nodes[nid]["name"]:
            m.nodes[nid]["name"] = name
    return nid


def _add_edge(m: _Model, src, dst, kind, support=1):
    e = m.edges.setdefault((src, dst), {"kind": kind, "support": 0})
    e["support"] += support
    if kind == "chain" and e["kind"] == "terminated":     # never let a solid fact be downgraded
        e["kind"] = "chain"
    return e


def _build_model(chains: pd.DataFrame, dropped: pd.DataFrame, key_cols: dict, cve_cwes: dict,
                 universe: list, df_cves: set, max_cves: int, expand_incomplete: bool) -> _Model:
    m = _Model()
    chain_cves = set(chains["cve"])
    m.cve_class = _classify_cves(universe, cve_cwes, chain_cves, df_cves)
    shown_chain, shown_non, omitted, omitted_chain = _select_cves(m.cve_class, chains, max_cves)
    m.displayed_chain_cves, m.displayed_cves = shown_chain, shown_chain + shown_non
    m.omitted_cves, m.omitted_chain_cves = omitted, omitted_chain

    # CVE row
    for cve in shown_chain:
        _add_node(m, "cve", cve, style="chain")
    for cve in shown_non:
        _add_node(m, "cve", cve, style="incomplete", break_code=m.cve_class[cve])

    # solid structure: only rows of P that belong to a drawn, chain-carrying CVE
    PD = chains[chains["cve"].isin(shown_chain)]
    for r in PD.itertuples(index=False):
        a = _add_node(m, "cve", r.cve, style="chain")
        b = _add_node(m, "cwe", r.cwe, name=r.cwe_name)
        c = _add_node(m, "capec", r.capec, name=r.capec_name)
        k = _add_node(m, "tech", r.parent, name=r.parent_name)
        t = _add_node(m, "tactic", r.tactic, name=r.tactic)
        _add_edge(m, a, b, "chain")
        _add_edge(m, b, c, "chain")
        _add_edge(m, c, k, "chain")
        if r.sub:
            s = _add_node(m, "sub", r.sub, name=r.sub_name)
            _add_edge(m, k, s, "chain")
            _add_edge(m, s, t, "chain")
        else:
            _add_edge(m, k, t, "direct")          # no sub-technique node is invented

    # terminated branches (relations that exist but do not complete the chain)
    drawn_cves = set(m.displayed_cves)
    chain_pairs_cve_cwe = set(zip(PD["cve"], PD["cwe"]))
    chain_pairs_cwe_capec = set(zip(PD["cwe"], PD["capec"]))
    dr = dropped[dropped["CVE ID"].isin(drawn_cves)]
    cwe_k, capec_k = key_cols["cwe_key"], key_cols["capec_key"]
    dropped_pairs = {}                                        # cwe -> {capec: n_rows}
    dropped_cve_cwe = set()
    for r in dr[["CVE ID", cwe_k, capec_k]].itertuples(index=False):
        cve, cwe, capec = r[0], _clean(r[1]), _clean(r[2])
        if cwe:
            dropped_cve_cwe.add((cve, cwe))
            if capec:
                dropped_pairs.setdefault(cwe, {})
                dropped_pairs[cwe][capec] = dropped_pairs[cwe].get(capec, 0) + 1

    if expand_incomplete:
        for cve in m.displayed_cves:
            cwes = list(cve_cwes.get(cve, []))
            for (c2, w2) in sorted(dropped_cve_cwe, key=lambda x: (_nat(x[0]), _nat(x[1]))):
                if c2 == cve and w2 not in cwes:
                    cwes.append(w2)
            for cwe in cwes:
                if (cve, cwe) in chain_pairs_cve_cwe:
                    continue
                w = _add_node(m, "cwe", cwe, style="terminated")
                _add_edge(m, f"cve:{cve}", w, "terminated")
        for cwe, capecs in sorted(dropped_pairs.items(), key=lambda kv: _nat(kv[0])):
            wid = f"cwe:{cwe}"
            if wid not in m.nodes:
                continue
            pending = {c: n for c, n in capecs.items() if (cwe, c) not in chain_pairs_cwe_capec}
            if pending:
                sid = _add_node(m, "stub", cwe, label=f"+{len(pending)} CAPEC", style="terminated",
                                layer=2, members=sorted(pending, key=_nat))
                _add_edge(m, wid, sid, "terminated", support=sum(pending.values()))

    # long edges: technique -> tactic skips the sub-technique row via a dummy waypoint
    for (src, dst), e in list(m.edges.items()):
        if e["kind"] == "direct":
            did = f"dummy:{src}>{dst}"
            m.nodes[did] = {"kind": "dummy", "layer": 4, "label": "", "key": did, "name": "",
                            "style": "chain", "terminal": False}
            del m.edges[(src, dst)]
            m.edges[(src, did)] = {"kind": "direct", "support": e["support"]}
            m.edges[(did, dst)] = {"kind": "direct", "support": e["support"]}

    # end caps: drawn nodes that are not chain-complete and lead nowhere
    out_deg = {}
    for (s, _d) in m.edges:
        out_deg[s] = out_deg.get(s, 0) + 1
    for nid, n in m.nodes.items():
        if n["style"] in ("incomplete", "terminated") and out_deg.get(nid, 0) == 0 and n["kind"] != "dummy":
            n["terminal"] = True
    return m


# statistics (full data, not only what is drawn)
def _stats(chains, universe, cve_cwes, cves_available, cve_class, m: _Model, max_cves, leaf_total):
    n_total = len(universe)
    usable = sum(1 for c in universe if cve_cwes.get(c))
    subs = {s for s in chains["sub"] if s}
    st = {
        "total_cves": n_total,
        "cves_with_usable_cwe": usable,
        "cves_reaching_curated_relation": int(chains["cve"].nunique()),
        "unique_cwes": int(chains["cwe"].nunique()),
        "unique_capecs": int(chains["capec"].nunique()),
        "unique_techniques": int(chains["parent"].nunique()),
        "unique_subtechniques": len(subs),
        "unique_tactics": int(chains["tactic"].nunique()),
        "curated_rows": int(len(chains)),
        "leaf_paths_per_tactic": int(leaf_total),
        "cve_table_available": bool(cves_available),
        "cves_displayed": len(m.displayed_cves),
        "chain_cves_displayed": len(m.displayed_chain_cves),
        "chain_cves_omitted": len(m.omitted_chain_cves),
        "cves_omitted": len(m.omitted_cves),
        "max_cves": max_cves,
        "break_counts": {k: sum(1 for v in cve_class.values() if v == k) for k in BREAK_CODES},
    }
    return st


def _layer_split(df, key_cols, chains, universe, cve_cwes, summary) -> dict:
    """Per row of the figure: (total in the device's data, carried forward to a tactic).

    total   = distinct entries of that layer found in the data for the device, including those that
              stop early (CVEs fetched, CWEs named by the CVEs, CAPEC patterns and ATT&CK entries in
              the merged dataset, tactics of the ATT&CK matrix).
    carried = distinct entries on a complete chain, i.e. in the curated relation P.
    total is None when it cannot be known (no run_summary.json for the tactic total).
    """
    def distinct(series):
        return len({_clean(v) for v in series} - {""})

    cwe_total = ({w for ws in cve_cwes.values() for w in ws} |
                 {_clean(v) for v in df[key_cols["cwe_key"]]}) - {""}
    sl = key_cols["subtechnique_label"]
    sub_total = 0
    if sl and sl in df.columns:
        has_sub = df[sl].map(_clean) != ""
        sub_total = distinct(df.loc[has_sub, key_cols["technique_key"]])
    n_tactics = ((((summary.get("stages") or {}).get("merge") or {}).get("attack_matrix")) or {}).get("tactics")
    carried = {"cve": int(chains["cve"].nunique()), "cwe": int(chains["cwe"].nunique()),
               "capec": int(chains["capec"].nunique()), "tech": int(chains["parent"].nunique()),
               "sub": len({s for s in chains["sub"] if s}), "tactic": int(chains["tactic"].nunique())}
    total = {"cve": len(universe), "cwe": len(cwe_total), "capec": distinct(df[key_cols["capec_key"]]),
             "tech": distinct(df[key_cols["parent_technique_key"]]), "sub": sub_total,
             "tactic": int(n_tactics) if n_tactics else None}
    return {k: (total[k], carried[k]) for k in LAYERS}


# validation (runs before anything is written)
def _validate(m: _Model, df, key_cols, P, chains, dropped, cve_cwes, universe, cves_available,
              summary, stats, max_cves, ordered_tactics):
    checks = []

    def ok(name, cond, detail=""):
        checks.append({"check": name, "ok": bool(cond), "detail": detail})

    nodes = lambda kind: {n["key"] for n in m.nodes.values() if n["kind"] == kind}  # noqa: E731
    src_cves = set(universe) | set(df["CVE ID"])
    src_cwes = {w for ws in cve_cwes.values() for w in ws} | {_clean(v) for v in df[key_cols["cwe_key"]]}
    src_capec = {_clean(v) for v in df[key_cols["capec_key"]]}

    ok("every displayed CVE exists in the source data", nodes("cve") <= src_cves,
       str(sorted(nodes("cve") - src_cves)))
    ok("every displayed CWE exists in the source data", nodes("cwe") <= src_cwes,
       str(sorted(nodes("cwe") - src_cwes)))
    ok("every displayed CAPEC exists in the source data", nodes("capec") <= src_capec,
       str(sorted(nodes("capec") - src_capec)))
    ok("every displayed technique exists in the curated relation", nodes("tech") <= set(chains["parent"]),
       str(sorted(nodes("tech") - set(chains["parent"]))))
    ok("every displayed sub-technique exists in the curated relation",
       nodes("sub") <= {s for s in chains["sub"] if s}, "")
    ok("every displayed tactic exists in the curated relation", nodes("tactic") <= set(chains["tactic"]), "")
    ok("displayed CVE count <= max_cves", len(m.displayed_cves) <= max_cves,
       f"{len(m.displayed_cves)} <= {max_cves}")

    # every solid edge, re-derived independently with pandas set operations
    PD = chains[chains["cve"].isin(m.displayed_chain_cves)]
    exp = set()
    exp |= {(f"cve:{a}", f"cwe:{b}") for a, b in PD[["cve", "cwe"]].drop_duplicates().itertuples(index=False)}
    exp |= {(f"cwe:{a}", f"capec:{b}") for a, b in PD[["cwe", "capec"]].drop_duplicates().itertuples(index=False)}
    exp |= {(f"capec:{a}", f"tech:{b}") for a, b in PD[["capec", "parent"]].drop_duplicates().itertuples(index=False)}
    withsub = PD[PD["sub"] != ""]
    nosub = PD[PD["sub"] == ""]
    exp |= {(f"tech:{a}", f"sub:{b}") for a, b in withsub[["parent", "sub"]].drop_duplicates().itertuples(index=False)}
    exp |= {(f"sub:{a}", f"tactic:{b}") for a, b in withsub[["sub", "tactic"]].drop_duplicates().itertuples(index=False)}
    direct_expected = {(f"tech:{a}", f"tactic:{b}") for a, b in nosub[["parent", "tactic"]].drop_duplicates().itertuples(index=False)}

    # fold dummy waypoints back into the long edge they represent
    drawn_solid, drawn_direct = set(), set()
    for (s, d), e in m.edges.items():
        if e["kind"] == "chain":
            drawn_solid.add((s, d))
        elif e["kind"] == "direct" and d.startswith("dummy:"):
            drawn_direct.add((s, d.split(">", 1)[1]))
    ok("every solid edge is a row-supported relation of P", drawn_solid <= exp,
       str(sorted(drawn_solid - exp)[:5]))
    ok("no supported relation of the drawn chain CVEs is missing", exp <= drawn_solid,
       str(sorted(exp - drawn_solid)[:5]))
    ok("technique->tactic shortcuts exist only for chains without a sub-technique",
       drawn_direct == direct_expected, str(sorted(drawn_direct ^ direct_expected)[:5]))

    # terminated edges: supported by source rows AND not a complete chain
    src_cve_cwe = {(c, w) for c, ws in cve_cwes.items() for w in ws}
    src_cve_cwe |= set(zip(df["CVE ID"], (_clean(v) for v in df[key_cols["cwe_key"]])))
    complete_cve_cwe = set(zip(chains["cve"], chains["cwe"]))
    complete_cwe_capec = set(zip(chains["cwe"], chains["capec"]))
    bad_support, bad_complete = [], []
    drow = set(zip(dropped["CVE ID"], (_clean(v) for v in dropped[key_cols["cwe_key"]]),
                   (_clean(v) for v in dropped[key_cols["capec_key"]])))
    for (s, d), e in m.edges.items():
        if e["kind"] != "terminated":
            continue
        if s.startswith("cve:"):
            pair = (s[4:], d[4:])
            if pair not in src_cve_cwe:
                bad_support.append(pair)
            if pair in complete_cve_cwe and pair[0] in m.displayed_chain_cves:
                bad_complete.append(pair)
        elif s.startswith("cwe:") and d.startswith("stub:"):
            cwe, members = s[4:], m.nodes[d]["members"]
            for capec in members:
                if not any((cv, cwe, capec) in drow for cv in m.displayed_cves):
                    bad_support.append((cwe, capec))
                if (cwe, capec) in complete_cwe_capec and any(
                        (cwe, capec) in set(zip(PD["cwe"], PD["capec"])) for _ in [0]):
                    bad_complete.append((cwe, capec))
    ok("every terminated edge is supported by a source row", not bad_support, str(bad_support[:5]))
    ok("no terminated edge hides a complete chain", not bad_complete, str(bad_complete[:5]))
    ok("incomplete chains are not artificially continued",
       all(not (n["style"] in ("terminated", "incomplete") and
                any(e["kind"] in ("chain", "direct") for (s, _d), e in m.edges.items() if s == nid))
           for nid, n in m.nodes.items()), "")

    # the figure agrees with the attack-tree pipeline
    ordered = ordered_tactics
    leaf_index = atl.build_leaf_index(P, key_cols, ordered, mode="per_tactic")
    lib_ids = set()
    for tac, by_cwe in leaf_index.leaves_by_tactic.items():
        for recs in by_cwe.values():
            for r in recs:
                lib_ids.add((r.cwe_key, r.parent_technique_key, r.technique_key, r.capec_key, tac))
    mine = set()
    for r in chains.itertuples(index=False):
        mine.add((r.cwe, r.parent, r.leaf, r.capec, r.tactic))
    ok("figure chains == chains the tree pipeline builds (build_leaf_index)", mine == lib_ids,
       f"figure {len(mine)} vs library {len(lib_ids)}")
    ok("subtechnique nodes are leaf ids distinct from their parent",
       all(r.sub != r.parent for r in chains.itertuples(index=False) if r.sub), "")

    split = stats.get("layer_split") or {}
    ok("row totals are at least the counts carried forward",
       all(t is None or t >= c for t, c in split.values()), str(split))
    ok("chain-carrying CVEs == CVEs of P", stats["cves_reaching_curated_relation"] == P["CVE ID"].nunique(),
       str(stats["cves_reaching_curated_relation"]))
    ok("drawn chain CVEs + omitted chain CVEs == all chain-carrying CVEs",
       len(m.displayed_chain_cves) + len(m.omitted_chain_cves) == stats["cves_reaching_curated_relation"], "")
    has_edge = {s for (s, _d) in m.edges} | {d for (_s, d) in m.edges}
    ok("omitted-CVE marker carries no edges", "ellipsis" not in has_edge, "")

    # agreement with run_summary.json (strict)
    tt = (summary.get("stages") or {}).get("tactic_trees") or {}
    if tt:
        for ours, theirs in (("cves_reaching_curated_relation", "cves_in_P"), ("unique_cwes", "unique_cwes"),
                             ("unique_capecs", "unique_capecs"), ("unique_techniques", "unique_techniques"),
                             ("leaf_paths_per_tactic", "total_paths"), ("unique_tactics", "tactics")):
            if theirs in tt and tt[theirs] is not None:
                ok(f"{ours} == run_summary.tactic_trees.{theirs}", stats[ours] == tt[theirs],
                   f"figure {stats[ours]} vs pipeline {tt[theirs]}")
    return checks


def _soft_notes(summary, stats):
    """Non-fatal comparisons (a --target-cve run legitimately has fewer in-scope CVEs)."""
    notes = []
    fun = (((summary.get("stages") or {}).get("merge") or {}).get("coverage_funnel")) or {}
    if fun:
        if fun.get("cves_fetched_or_selected") not in (None, stats["total_cves"]):
            notes.append(f"CVEs fetched: figure {stats['total_cves']} vs pipeline "
                         f"{fun['cves_fetched_or_selected']} (a --target-cve run?)")
        if fun.get("cves_with_usable_cwe") not in (None, stats["cves_with_usable_cwe"]):
            notes.append(f"CVEs with usable CWE: figure {stats['cves_with_usable_cwe']} vs pipeline "
                         f"{fun['cves_with_usable_cwe']}")
    return notes


# layout: crossing-reduced order and x/y positions in inches (no matplotlib needed)
def _crossings(order, adj_edges):
    total = 0
    for li, edges in adj_edges.items():
        pos_u = {n: i for i, n in enumerate(order[li])}
        pos_v = {n: i for i, n in enumerate(order[li + 1])}
        pairs = sorted((pos_u[u], pos_v[v]) for (u, v) in edges if u in pos_u and v in pos_v)
        seen = []
        for _pu, pv in pairs:
            total += len(seen) - bisect.bisect_right(seen, pv)
            bisect.insort(seen, pv)
    return total


def _bary_sort(nodes, nbrs, pos, n_neighbor_layer):
    cur = {n: (i + 0.5) / max(len(nodes), 1) for i, n in enumerate(nodes)}
    key = {}
    for n in nodes:
        ps = [(pos[x] + 0.5) / max(n_neighbor_layer, 1) for x in nbrs.get(n, ()) if x in pos]
        key[n] = (sum(ps) / len(ps)) if ps else cur[n]
    return sorted(nodes, key=lambda n: (key[n], cur[n], _nat(n)))


def _order_block(layers, edges, fixed_layers=(), restarts=8, sweeps=24, seed=7):
    """Barycentre sweeps with random restarts; deterministic (fixed seed)."""
    L = len(layers)
    up, down, adj = {}, {}, {}
    inblock = {n for lay in layers for n in lay}
    layer_of = {n: li for li, lay in enumerate(layers) for n in lay}
    for (u, v) in edges:
        if u in inblock and v in inblock:
            up.setdefault(v, []).append(u)
            down.setdefault(u, []).append(v)
            adj.setdefault(layer_of[u], []).append((u, v))
    rnd = random.Random(seed)
    best, best_c = None, None
    for r in range(restarts):
        order = [sorted(lay, key=_nat) if r == 0 or li in fixed_layers else rnd.sample(sorted(lay, key=_nat), len(lay))
                 for li, lay in enumerate(layers)]
        local_best, local_c = [list(o) for o in order], _crossings(order, adj)
        for _ in range(sweeps):
            for li in range(1, L):
                if li not in fixed_layers and order[li]:
                    pos = {n: i for i, n in enumerate(order[li - 1])}
                    order[li] = _bary_sort(order[li], up, pos, len(order[li - 1]))
            for li in range(L - 2, -1, -1):
                if li not in fixed_layers and order[li]:
                    pos = {n: i for i, n in enumerate(order[li + 1])}
                    order[li] = _bary_sort(order[li], down, pos, len(order[li + 1]))
            c = _crossings(order, adj)
            if c < local_c:
                local_best, local_c = [list(o) for o in order], c
        if best_c is None or local_c < best_c:
            best, best_c = local_best, local_c
        if best_c == 0:
            break
    return best, best_c


def _pav(targets, weights):
    blocks = []
    for t, w in zip(targets, weights):
        blocks.append([t * w, w, 1])
        while len(blocks) > 1 and blocks[-2][0] / blocks[-2][1] > blocks[-1][0] / blocks[-1][1]:
            b = blocks.pop()
            blocks[-1][0] += b[0]
            blocks[-1][1] += b[1]
            blocks[-1][2] += b[2]
    out = []
    for sw, w, c in blocks:
        out += [sw / w] * c
    return out


@dataclass
class _Layout:
    order: list                  # per layer: node ids left->right
    x: dict                      # nid -> centre x (inches)
    width: dict                  # nid -> node width (inches)
    row_y: list                  # per layer: top y of the row band's node area
    row_h: list                  # per layer: node height
    total_w: float
    total_h: float
    crossings: int
    left_margin: float
    top_margin: float
    gap_y: float


def _measure(text, size, bold=False):
    from matplotlib.font_manager import FontProperties
    from matplotlib.textpath import TextPath
    if not text:
        return 0.0
    fp = FontProperties(family="DejaVu Sans", weight="bold" if bold else "normal")
    return TextPath((0, 0), text, size=size, prop=fp).get_extents().width / 72.0


def _layout(m: _Model, ordered_tactics, font_size, cap_w=0.19, gap=0.075, block_gap=0.5,
            gap_y=1.0, left_margin=2.35, top_margin=1.65, tactic_w=None) -> _Layout:
    nodes = m.nodes
    L = len(LAYERS)
    by_layer = [[] for _ in range(L)]
    for nid, n in nodes.items():
        by_layer[n["layer"]].append(nid)

    # connected components; every component touching a tactic is the "chain block"
    parent = {n: n for n in nodes}

    def find(a):
        while parent[a] != a:
            parent[a] = parent[parent[a]]
            a = parent[a]
        return a
    for (u, v) in m.edges:
        parent[find(u)] = find(v)
    comps = {}
    for n in nodes:
        comps.setdefault(find(n), []).append(n)
    chain_block, other = [], []
    for members in comps.values():
        (chain_block if any(nodes[x]["kind"] == "tactic" for x in members) else other).append(members)
    blocks = []
    if chain_block:
        blocks.append([x for mem in chain_block for x in mem])
    other.sort(key=lambda mem: min((_nat(nodes[x]["key"]) for x in mem if nodes[x]["kind"] == "cve"), default=[]))
    blocks += other

    tactic_rank = {t: i for i, t in enumerate(ordered_tactics)}
    adj_all = [(u, v) for (u, v) in m.edges]
    final = [[] for _ in range(L)]
    total_cross = 0
    for bi, block in enumerate(blocks):
        bset = set(block)
        layers = [[n for n in by_layer[li] if n in bset] for li in range(L)]
        fixed = ()
        if bi == 0 and chain_block:
            layers[5] = sorted(layers[5], key=lambda n: tactic_rank.get(nodes[n]["key"], 999))
            fixed = (5,)
        order, c = _order_block(layers, adj_all, fixed_layers=fixed)
        total_cross += c
        for li in range(L):
            final[li] += order[li]
    block_of = {n: bi for bi, blk in enumerate(blocks) for n in blk}

    # node widths
    width = {}
    for nid, n in nodes.items():
        if n["kind"] == "dummy":
            width[nid] = 0.07
        elif n["kind"] == "tactic":
            width[nid] = tactic_w if tactic_w else _measure(n["label"], font_size * 1.05, bold=True) + 0.55
        else:
            width[nid] = cap_w

    # x coordinates: balanced by neighbours, order preserved (isotonic regression)
    up, down = {}, {}
    for (u, v) in m.edges:
        up.setdefault(v, []).append(u)
        down.setdefault(u, []).append(v)

    def offsets(lay):
        off, acc = [], 0.0
        for i, n in enumerate(lay):
            if i:
                p = lay[i - 1]
                g = block_gap if block_of[p] != block_of[n] else gap
                acc += (width[p] + width[n]) / 2 + g
            off.append(acc)
        return off

    x = {}
    packed = [(offsets(lay)[-1] + (width[lay[0]] + width[lay[-1]]) / 2) if lay else 0 for lay in final]
    W0 = max(packed + [1.0])
    for li, lay in enumerate(final):
        if not lay:
            continue
        off = offsets(lay)
        start = (W0 - packed[li]) / 2 + width[lay[0]] / 2
        for n, o in zip(lay, off):
            x[n] = start + o

    def sweep(li, nbrs):
        lay = final[li]
        if not lay:
            return
        off = offsets(lay)
        tg, wt = [], []
        for n, o in zip(lay, off):
            ps = [x[q] for q in nbrs.get(n, ()) if q in x]
            if ps:
                tg.append(sum(ps) / len(ps) - o)
                wt.append(float(len(ps)))
            else:
                tg.append(x[n] - o)
                wt.append(0.01)
        for n, o, y in zip(lay, off, _pav(tg, wt)):
            x[n] = y + o

    for _ in range(14):
        for li in range(1, L):
            sweep(li, up)
        for li in range(L - 2, -1, -1):
            sweep(li, down)
    for li in range(L):                                   # settle with both neighbour sets
        both = {n: up.get(n, []) + down.get(n, []) for n in final[li]}
        sweep(li, both)

    # reserve room for the omitted-CVE marker at the right end of row 1
    n_extra = 0.0
    if m.omitted_cves:
        n_extra = cap_w + 1.0
    min_x = min(x[n] - width[n] / 2 for lay in final for n in lay) if x else 0
    shift = left_margin - min_x
    for n in x:
        x[n] += shift
    right = max((x[n] + width[n] / 2 for n in x), default=left_margin)
    if m.omitted_cves and final[0]:
        right = max(right, max(x[n] + width[n] / 2 for n in final[0]) + n_extra)
    total_w = right + 0.5

    # row heights from the longest vertical label of each row
    row_h = []
    for li in range(L):
        if li == 5:
            row_h.append(0.34)
            continue
        longest = max((_measure(nodes[n]["label"], font_size) for n in final[li]), default=0.3)
        row_h.append(max(longest + 0.34, 0.8))
    row_y, y = [], top_margin
    for li in range(L):
        row_y.append(y)
        y += row_h[li] + gap_y
    total_h = y - gap_y + 4.1                            # room for legend + statistics
    return _Layout(final, x, width, row_y, row_h, total_w, total_h, total_cross, left_margin, top_margin, gap_y)


# rendering (matplotlib, imported lazily)
_FILL = {   # grayscale-safe: every type differs in fill, hatch AND marker shape, not only colour
    "cve_chain":  dict(fc="#1f1f1f", hatch=None,   tc="white", ls="-",  marker="circle",   mfill=True),
    "cve_incomp": dict(fc="white",   hatch=None,   tc="#555555", ls="--", marker="circle", mfill=False),
    "cwe":        dict(fc="#d0d0d0", hatch=None,   tc="black", ls="-",  marker="square",   mfill=True),
    "capec":      dict(fc="white",   hatch="//////", tc="black", ls="-", marker="diamond",  mfill=True),
    "tech":       dict(fc="#b5b5b5", hatch=None,   tc="black", ls="-",  marker="triangle", mfill=True),
    "sub":        dict(fc="white",   hatch="......", tc="black", ls="-", marker="pentagon", mfill=True),
    "tactic":     dict(fc="white",   hatch=None,   tc="black", ls="-",  marker="hexagon",  mfill=True),
    "term":       dict(fc="white",   hatch=None,   tc="#555555", ls="--", marker=None,     mfill=False),
}


def _style_key(n):
    k, s = n["kind"], n["style"]
    if k == "cve":
        return "cve_chain" if s == "chain" else "cve_incomp"
    if s == "terminated" or k == "stub":
        return "term"
    return k


def _marker(ax, kind, cx, cy, r, filled, color):
    from matplotlib.patches import Circle, Rectangle, RegularPolygon
    kw = dict(edgecolor=color, linewidth=0.6, facecolor=color if filled else "white", zorder=6)
    if kind == "circle":
        ax.add_patch(Circle((cx, cy), r, **kw))
    elif kind == "square":
        ax.add_patch(Rectangle((cx - r * 0.85, cy - r * 0.85), r * 1.7, r * 1.7, **kw))
    elif kind == "diamond":
        ax.add_patch(RegularPolygon((cx, cy), 4, radius=r * 1.25, **kw))
    elif kind == "triangle":
        ax.add_patch(RegularPolygon((cx, cy + r * 0.1), 3, radius=r * 1.25, orientation=3.14159, **kw))
    elif kind == "pentagon":
        ax.add_patch(RegularPolygon((cx, cy), 5, radius=r * 1.15, orientation=3.14159, **kw))
    elif kind == "hexagon":
        ax.add_patch(RegularPolygon((cx, cy), 6, radius=r * 1.15, **kw))


def _draw_node(ax, n, cx, ytop, w, h, fs, s):
    from matplotlib.patches import FancyBboxPatch
    st = _FILL[_style_key(n)]
    horizontal = n["kind"] == "tactic"
    rr = min(w, h) / 2 * 0.85
    box = f"round,pad=0,rounding_size={rr}"
    edge_col = "#555555" if st["ls"] == "--" else "black"
    if st["hatch"]:
        ax.add_patch(FancyBboxPatch((cx - w / 2, ytop), w, h, boxstyle=box, facecolor=st["fc"],
                                    edgecolor="#8a8a8a", linewidth=0, hatch=st["hatch"], zorder=3))
    else:
        ax.add_patch(FancyBboxPatch((cx - w / 2, ytop), w, h, boxstyle=box, facecolor=st["fc"],
                                    edgecolor="none", linewidth=0, zorder=3))
    ax.add_patch(FancyBboxPatch((cx - w / 2, ytop), w, h, boxstyle=box, fill=False, edgecolor=edge_col,
                                linewidth=0.8 * s, linestyle=(0, (3, 1.6)) if st["ls"] == "--" else "-", zorder=4))
    if n["kind"] == "tactic":                                   # double outline = tactic
        ins = 0.035
        ax.add_patch(FancyBboxPatch((cx - w / 2 + ins, ytop + ins), w - 2 * ins, h - 2 * ins,
                                    boxstyle=f"round,pad=0,rounding_size={rr * 0.8}", fill=False,
                                    edgecolor="black", linewidth=0.6 * s, zorder=4))
    mcol = "white" if st["fc"] == "#1f1f1f" else ("#555555" if st["ls"] == "--" else "black")
    bbox = dict(boxstyle="round,pad=0.06", fc="white", ec="none", alpha=0.88) if st["hatch"] else None
    if horizontal:
        _marker(ax, st["marker"], cx - w / 2 + 0.2, ytop + h / 2, 0.055, st["mfill"], mcol)
        ax.text(cx + 0.1, ytop + h / 2, n["label"], ha="center", va="center", fontsize=fs * 1.05,
                fontweight="bold", color=st["tc"], zorder=7)
    else:
        if st["marker"]:
            _marker(ax, st["marker"], cx, ytop + 0.12, 0.05, st["mfill"], mcol)
        top_text = ytop + (0.24 if st["marker"] else 0.08)
        ax.text(cx, top_text + (ytop + h - 0.07 - top_text) / 2, n["label"], rotation=90, ha="center",
                va="center", fontsize=fs, color=st["tc"], bbox=bbox, zorder=7)


def _edge_style(kind, s):
    if kind == "chain":
        return dict(color="#454545", lw=0.55 * s, ls="-", alpha=0.85)
    if kind == "direct":
        return dict(color="#454545", lw=0.8 * s, ls=(0, (1, 1.6)), alpha=0.95)
    return dict(color="#6e6e6e", lw=0.8 * s, ls=(0, (3.2, 2)), alpha=0.95)


def _bezier(ax, x1, y1, x2, y2, style, arrow=True):
    from matplotlib.patches import PathPatch, Polygon
    from matplotlib.path import Path as MPath
    ym = (y1 + y2) / 2
    verts = [(x1, y1), (x1, ym), (x2, ym), (x2, y2)]
    ax.add_patch(PathPatch(MPath(verts, [MPath.MOVETO, MPath.CURVE4, MPath.CURVE4, MPath.CURVE4]),
                           fill=False, capstyle="butt", zorder=2, edgecolor=style["color"],
                           linewidth=style["lw"], linestyle=style["ls"], alpha=style["alpha"]))
    if arrow:
        a = 0.045
        ax.add_patch(Polygon([(x2, y2), (x2 - a * 0.7, y2 - a * 1.7), (x2 + a * 0.7, y2 - a * 1.7)],
                             closed=True, facecolor=style["color"], edgecolor="none", zorder=2))


def _render(m: _Model, lay: _Layout, stats, title, subtitle, figsize, dpi, font_size, out_base, formats,
            device_note):
    from matplotlib import rc_context
    from matplotlib.figure import Figure
    from matplotlib.patches import FancyBboxPatch, Rectangle

    W, H = lay.total_w, lay.total_h
    if figsize:
        fw, fh = figsize
        s = min(fw / W, fh / H)
    else:
        fw, fh, s = W, H, 1.0
    fs = font_size * s
    files = {}
    with rc_context({"pdf.fonttype": 42, "ps.fonttype": 42, "hatch.linewidth": 0.35 * max(s, 0.4),
                     "font.family": "DejaVu Sans"}):
        fig = Figure(figsize=(fw, fh), dpi=dpi)
        ax = fig.add_axes([0, 0, 1, 1])
        vw, vh = fw / s, fh / s
        ax.set_xlim(-(vw - W) / 2, W + (vw - W) / 2)
        ax.set_ylim(H + (vh - H) / 2, -(vh - H) / 2)
        ax.set_aspect("equal")
        ax.axis("off")
        nodes, x = m.nodes, lay.x

        # row bands + labels
        for li in range(len(LAYERS)):
            y0, h = lay.row_y[li], lay.row_h[li]
            ax.add_patch(Rectangle((0.15, y0 - 0.14), W - 0.3, h + 0.28, facecolor="#f2f2f2" if li % 2 == 0 else "#fafafa",
                                   edgecolor="#cfcfcf", linewidth=0.5 * s, zorder=0))
            n_draw = sum(1 for n in lay.order[li] if nodes[n]["kind"] not in ("dummy",))
            ax.text(0.3, y0 + h / 2 - 0.1, f"Row {li + 1}", fontsize=fs * 1.0, color="#666666", ha="left", va="center", zorder=7)
            ax.text(0.3, y0 + h / 2 + 0.1, LAYER_TITLES[li], fontsize=fs * 1.35, fontweight="bold", ha="left", va="center", zorder=7)
            tot = {0: stats["total_cves"], 1: stats["unique_cwes"], 2: stats["unique_capecs"],
                   3: stats["unique_techniques"], 4: stats["unique_subtechniques"], 5: stats["unique_tactics"]}[li]
            if li == 0:
                sub = f"{n_draw} drawn of {tot} fetched"
            else:
                full = sum(1 for n in lay.order[li] if nodes[n]["style"] == "chain" and nodes[n]["kind"] != "dummy")
                extra = n_draw - full
                sub = f"{full} shown of {tot} in curated relation" if full != tot else f"{full} (all, curated relation)"
                if extra:
                    sub += f"\n+ {extra} terminated"
            ax.text(0.3, y0 + h / 2 + 0.36, sub, fontsize=fs * 0.95, color="#444444", ha="left", va="center", zorder=7)

        # edges
        row_bottom = lambda li: lay.row_y[li] + lay.row_h[li]    # noqa: E731
        for (u, v), e in sorted(m.edges.items(), key=lambda kv: (kv[1]["kind"] != "terminated", kv[0])):
            nu, nv = nodes[u], nodes[v]
            x1, y1 = x[u], row_bottom(nu["layer"]) if nu["kind"] != "dummy" else lay.row_y[4] + lay.row_h[4] / 2
            x2 = x[v]
            y2 = lay.row_y[nv["layer"]] if nv["kind"] != "dummy" else lay.row_y[4] + lay.row_h[4] / 2
            _bezier(ax, x1, y1, x2, y2, _edge_style(e["kind"], s), arrow=(nv["kind"] != "dummy"))

        # nodes
        for nid, n in nodes.items():
            if n["kind"] == "dummy":
                continue
            li, w, h = n["layer"], lay.width[nid], lay.row_h[n["layer"]]
            _draw_node(ax, n, x[nid], lay.row_y[li], w, h, fs, s)
            if n["terminal"]:                                   # end cap: the chain stops here
                yb = lay.row_y[li] + h + 0.1
                ax.plot([x[nid] - 0.09, x[nid] + 0.09], [yb, yb], color="#333333", lw=1.4 * s, zorder=5, solid_capstyle="butt")
                ax.plot([x[nid], x[nid]], [yb - 0.1, yb], color="#333333", lw=0.8 * s, zorder=5)

        # omitted-CVE marker (never has edges)
        if m.omitted_cves and lay.order[0]:
            last = lay.order[0][-1]
            cx = x[last] + lay.width[last] / 2 + 0.5
            h = lay.row_h[0]
            ax.add_patch(FancyBboxPatch((cx - 0.095, lay.row_y[0]), 0.19, h, boxstyle="round,pad=0,rounding_size=0.08",
                                        fill=False, edgecolor="#777777", linewidth=0.8 * s, linestyle=(0, (1, 2)), zorder=4))
            n_om, n_omc = len(m.omitted_cves), len(m.omitted_chain_cves)
            ax.text(cx, lay.row_y[0] + h / 2, f"... + {n_om} more CVEs", rotation=90, ha="center", va="center",
                    fontsize=fs, color="#444444", zorder=7)
            note = ("none reach a\ncomplete chain" if n_omc == 0 else
                    f"{n_omc} of these carry\ncomplete chains\n(not drawn)")
            ax.text(cx + 0.2, lay.row_y[0] + h / 2, note, rotation=90, ha="left", va="center", fontsize=fs * 0.85,
                    color="#555555", style="italic", linespacing=1.1, zorder=7)

        # brackets above row 1: which CVEs carry chains and which do not
        by_style = {"chain": [], "incomplete": []}
        for n in lay.order[0]:
            by_style[nodes[n]["style"]].append(n)
        yb = lay.row_y[0] - 0.42
        n_carry = stats["cves_reaching_curated_relation"]
        carry_txt = (f"{len(by_style['chain'])} CVEs reach the complete chain" if len(by_style["chain"]) == n_carry
                     else f"{len(by_style['chain'])} of {n_carry} chain-carrying CVEs drawn")
        for st_name, txt in (("chain", carry_txt),
                             ("incomplete", f"{len(by_style['incomplete'])} CVEs stop early (examples)")):
            grp = by_style[st_name]
            if not grp:
                continue
            xa = min(x[n] - lay.width[n] / 2 for n in grp)
            xb = max(x[n] + lay.width[n] / 2 for n in grp)
            ax.plot([xa, xa, xb, xb], [yb + 0.1, yb, yb, yb + 0.1], color="#333333", lw=0.8 * s, zorder=5)
            ax.text((xa + xb) / 2, yb - 0.1, txt, ha="center", va="bottom", fontsize=fs * 1.1, fontweight="bold", zorder=7)

        # title
        ax.text(0.3, 0.38, title, fontsize=fs * 2.0, fontweight="bold", ha="left", va="center")
        ax.text(0.3, 0.72, subtitle, fontsize=fs * 1.15, color="#444444", ha="left", va="center")

        _legend_and_stats(ax, lay, stats, device_note, fs, s, W, m)

        for ext in formats:
            p = Path(f"{out_base}.{ext}")
            kw = {"dpi": dpi} if ext == "png" else {}
            fig.savefig(p, **kw)
            files[ext] = p
    return files


def _legend_and_stats(ax, lay, stats, note, fs, s, W, m):
    from matplotlib.patches import FancyBboxPatch
    y = lay.row_y[5] + lay.row_h[5] + 0.65
    ax.text(0.3, y - 0.2, "Legend", fontsize=fs * 1.25, fontweight="bold", va="center")
    items = [("cve_chain", "CVE: reaches complete chain", "cve"), ("cve_incomp", "CVE: no complete chain", "cve"),
             ("cwe", "CWE", "cwe"), ("capec", "CAPEC", "capec"), ("tech", "ATT&CK technique", "tech"),
             ("sub", "ATT&CK sub-technique", "sub"), ("tactic", "ATT&CK tactic", "tactic"),
             ("term", "terminated branch / stub", "stub")]
    cx, cy, rowh = 0.45, y + 0.2, 0.62
    for key, text, kind in items:
        n = {"kind": kind, "style": "chain" if key not in ("cve_incomp", "term") else "terminated", "label": "",
             "terminal": False}
        if key == "cve_incomp":
            n["style"] = "incomplete"
        w = 0.19 if key != "tactic" else 0.5
        h = 0.34 if key != "tactic" else 0.24
        _draw_node(ax, {**n, "label": ""}, cx + w / 2, cy - h / 2, w, h, fs, s)
        tw = _measure(text, fs / s) + 0.1
        ax.text(cx + w + 0.08, cy, text, fontsize=fs, va="center", ha="left")
        cx += w + 0.08 + tw + 0.3
    # edge samples
    cx, cy2 = 0.45, y + 0.2 + rowh
    for kind, text in (("chain", "relation supported by a complete curated chain"),
                       ("direct", "technique -> tactic directly (chain has no sub-technique)"),
                       ("terminated", "relation exists but the chain does not complete here")):
        st = _edge_style(kind, s)
        ax.plot([cx, cx + 0.45], [cy2, cy2], color=st["color"], lw=st["lw"] * 1.6, ls=st["ls"], alpha=1.0)
        ax.text(cx + 0.55, cy2, text, fontsize=fs, va="center", ha="left")
        cx += 0.55 + _measure(text, fs / s) + 0.35
    ax.plot([cx, cx + 0.18], [cy2 + 0.08, cy2 + 0.08], color="#333333", lw=1.4 * s, solid_capstyle="butt")
    ax.plot([cx + 0.09, cx + 0.09], [cy2 - 0.02, cy2 + 0.08], color="#333333", lw=0.8 * s)
    ax.text(cx + 0.28, cy2, "end cap: chain stops at this node", fontsize=fs, va="center", ha="left")

    # statistics block (full data)
    st = stats
    lines = [("Total CVEs", st["total_cves"] if st["cve_table_available"] else f"{st['total_cves']} (in dataset only)"),
             ("CVEs with usable CWE", st["cves_with_usable_cwe"]),
             ("CVEs reaching curated relation", st["cves_reaching_curated_relation"]),
             ("Unique CWEs / CAPECs", f"{st['unique_cwes']} / {st['unique_capecs']}"),
             ("Unique techniques / sub-techniques", f"{st['unique_techniques']} / {st['unique_subtechniques']}"),
             ("Unique tactics", st["unique_tactics"])]
    sy = cy2 + 0.5
    ax.text(0.45, sy, "Coverage (computed from the curated data)", fontsize=fs * 1.15, fontweight="bold", va="center")
    for i, (a, b) in enumerate(lines):
        ax.text(0.45, sy + 0.26 * (i + 1), a, fontsize=fs, va="center", ha="left")
        ax.text(3.6, sy + 0.26 * (i + 1), str(b), fontsize=fs, va="center", ha="left", fontweight="bold")
    ax.text(5.4, sy + 0.26, note, fontsize=fs * 0.95, va="top", ha="left", color="#444444", linespacing=1.5)


# tables and DOT
def _frames(m: _Model, chains, cve_class, universe):
    nrow = []
    for nid, n in m.nodes.items():
        if n["kind"] == "dummy":
            continue
        nrow.append({"node_id": nid, "row": n["layer"] + 1, "layer": LAYER_TITLES[n["layer"]], "id": n["label"] if n["kind"] != "stub" else n["key"],
                     "name": n["name"], "status": ("complete_chain" if n["style"] == "chain" else
                                                   "terminated" if n["kind"] != "cve" else "no_complete_chain"),
                     "stub_members": "; ".join(n.get("members", [])) if n["kind"] == "stub" else "",
                     "break_code": n.get("break_code", "") })
    nrow.sort(key=lambda r: (r["row"], _nat(r["node_id"])))
    nodes = pd.DataFrame(nrow)
    erow = []
    for (u, v), e in m.edges.items():
        if u.startswith("dummy:") or v.startswith("dummy:"):
            continue
        erow.append({"source": u, "target": v, "source_row": m.nodes[u]["layer"] + 1,
                     "target_row": m.nodes[v]["layer"] + 1, "kind": e["kind"], "supporting_rows": e["support"]})
    for (u, v), e in m.edges.items():                     # fold shortcut edges back into one row
        if v.startswith("dummy:"):
            dst = v.split(">", 1)[1]
            erow.append({"source": u, "target": dst, "source_row": 4, "target_row": 6,
                         "kind": "direct (no sub-technique)", "supporting_rows": e["support"]})
    edges = pd.DataFrame(erow)
    drawn = set(m.displayed_cves)
    cves = pd.DataFrame([{"cve": c, "status": ("complete_chain" if cve_class[c] == "CHAIN" else cve_class[c]),
                          "drawn": c in drawn} for c in sorted(universe, key=_nat)])
    return nodes, edges, cves


def _dot_source(m: _Model, name="cti_chain") -> str:
    from graphviz import Digraph
    g = Digraph(name, graph_attr={"rankdir": "TB", "splines": "spline", "nodesep": "0.12", "ranksep": "0.9"},
                node_attr={"fontsize": "9", "height": "0.25"})
    shape = {"cve": "ellipse", "cwe": "box", "capec": "diamond", "tech": "triangle", "sub": "pentagon",
             "tactic": "hexagon", "stub": "box"}
    for li in range(len(LAYERS)):
        with g.subgraph() as sg:
            sg.attr(rank="same")
            for nid, n in m.nodes.items():
                if n["layer"] == li and n["kind"] != "dummy":
                    sg.node(nid, label=n["label"], shape=shape.get(n["kind"], "box"),
                            style="filled" if n["style"] == "chain" else "dashed",
                            fillcolor="#bbbbbb" if n["style"] == "chain" else "white")
    for (u, v), e in m.edges.items():
        if u.startswith("dummy:"):
            continue
        if v.startswith("dummy:"):
            g.edge(u, v.split(">", 1)[1], style="dotted")
        else:
            g.edge(u, v, style="dashed" if e["kind"] == "terminated" else "solid")
    return g.source


# public entry point
def generate_cti_chain_figure(dataset_path, output_path, *, cve_table_path=None, summary_path=None,
                              max_cves: int = 15, figsize=None, dpi: int = 300,
                              formats=DEFAULT_FORMATS, title: str | None = None,
                              expand_incomplete: bool = True, font_size: float = 6.0,
                              compact: bool = True, tactic_labels: bool = True,
                              write_tables: bool = True, write_dot: bool = True,
                              strict: bool = True, verbose: bool = True) -> CtiFigureResult:
    """Draw the CVE -> CWE -> CAPEC -> technique -> sub-technique -> tactic provenance figure.

        dataset_path       device_compromise_dataset.xlsx of one workspace (merge-stage output)
        output_path        base path; PNG, PDF and SVG (plus DOT, *_nodes.csv, *_edges.csv and
                           *_cves.csv) are written next to it. A trailing .png/.pdf/.svg is removed.
        cve_table_path     cve_data.xlsx with all fetched CVEs (default: next to dataset_path).
                           Needed for the total-CVE and usable-CWE numbers and for the CVEs that
                           stop before the dataset.
        summary_path       run_summary.json for the cross-check (default: next to dataset_path)
        max_cves           most CVE nodes drawn in row 1 (default 15)
        figsize, dpi       figure size in inches (default: natural size of the layout) and PNG
                           resolution
        expand_incomplete  True: CVEs that stop early are drawn with their terminated (dashed)
                           branches; False: they are drawn as end-capped nodes only
        strict             True: a failed validation check raises PipelineError and nothing is saved
    """
    try:
        import matplotlib  # noqa: F401  (imported lazily so the rest of the package does not need it)
    except ImportError as e:
        raise ConfigError("The CTI figure needs matplotlib:  pip install matplotlib") from e
    dataset_path = Path(dataset_path)
    ws_dir = dataset_path.parent
    cve_table_path = Path(cve_table_path) if cve_table_path else ws_dir / "cve_data.xlsx"
    summary_path = Path(summary_path) if summary_path else ws_dir / "run_summary.json"
    base = Path(output_path)
    formats = tuple(dict.fromkeys(f.lower().lstrip(".") for f in formats))
    if base.suffix.lower() in (".png", ".pdf", ".svg"):
        if base.suffix.lower().lstrip(".") not in formats:
            formats += (base.suffix.lower().lstrip("."),)
        base = base.with_suffix("")
    base.parent.mkdir(parents=True, exist_ok=True)
    if max_cves < 1:
        raise PipelineError("max_cves must be >= 1")

    # data, via the existing library
    df, key_cols, P, dropped = _load_curated(dataset_path)
    ordered_tactics = atl.mitre_order(P["tactics"].unique())
    chains = _chain_table(P, key_cols)
    cve_cwes, cves_available = _read_cve_table(cve_table_path)
    df_cwe = df[["CVE ID", key_cols["cwe_key"]]]
    if not cves_available:
        console.warn(f"'{cve_table_path}' not found: only CVEs that reached the merged dataset can be shown, "
                     "'Total CVEs' / 'usable CWE' are therefore NOT the fetched numbers.")
        for cve, cwe in zip(df_cwe["CVE ID"], df_cwe[key_cols["cwe_key"]]):
            if _clean(cwe):
                cve_cwes.setdefault(cve, [])
                if _clean(cwe) not in cve_cwes[cve]:
                    cve_cwes[cve].append(_clean(cwe))
    universe = sorted(set(cve_cwes) | set(df["CVE ID"]) | set(chains["cve"]), key=_nat)
    df_cves = set(df["CVE ID"])
    summary = _read_summary(summary_path)
    pipeline_breaks = {}
    inc = ws_dir / "incomplete_chains.csv"
    if inc.is_file():
        try:
            pipeline_breaks = {str(k): int(v) for k, v in pd.read_csv(inc)["chain_break"].value_counts().items()}
        except (OSError, KeyError, ValueError):
            pipeline_breaks = {}

    # model, stats, validation
    m = _build_model(chains, dropped, key_cols, cve_cwes, universe, df_cves, max_cves, expand_incomplete)
    leaf_index = atl.build_leaf_index(P, key_cols, ordered_tactics, mode="per_tactic")
    stats = _stats(chains, universe, cve_cwes, cves_available, m.cve_class, m, max_cves, atl.total_paths(leaf_index))
    stats["merge_stage_chain_breaks"] = pipeline_breaks
    stats["layer_split"] = _layer_split(df, key_cols, chains, universe, cve_cwes, summary)
    checks = _validate(m, df, key_cols, P, chains, dropped, cve_cwes, universe, cves_available, summary, stats,
                       max_cves, ordered_tactics)
    notes = _soft_notes(summary, stats)

    if verbose:
        console.section("CTI chain figure - coverage summary")
        console.headline("Total CVEs", stats["total_cves"] if cves_available else f"{stats['total_cves']} (cve_data.xlsx missing)")
        console.headline("CVEs with usable CWE", stats["cves_with_usable_cwe"])
        console.headline("CVEs reaching curated relation", stats["cves_reaching_curated_relation"])
        console.headline("Unique CWEs", stats["unique_cwes"])
        console.headline("Unique CAPECs", stats["unique_capecs"])
        console.headline("Unique techniques", stats["unique_techniques"])
        console.headline("Unique sub-techniques", stats["unique_subtechniques"])
        console.headline("Unique tactics", stats["unique_tactics"])
        console.info("Row numerals (total in data -> carried forward): " + ", ".join(
            f"{k} {'?' if t is None else t}->{c}" for k, (t, c) in stats["layer_split"].items()))
        console.info(f"CVEs drawn in row 1: {stats['cves_displayed']} (max {max_cves}); "
                     f"chain-carrying drawn: {stats['chain_cves_displayed']}; omitted: {stats['cves_omitted']}")
        console.info("CVEs that stop early: " + ", ".join(f"{k}={v}" for k, v in stats["break_counts"].items()))
        if pipeline_breaks:
            console.info("Chain breaks recorded by the merge stage (incomplete_chains.csv, not drawable): "
                         + ", ".join(f"{k}={v}" for k, v in pipeline_breaks.items()))
        for n_ in notes:
            console.warn(n_)
        bad = [c for c in checks if not c["ok"]]
        console.info(f"Validation: {len(checks) - len(bad)}/{len(checks)} checks passed")
        for c in bad:
            console.warn(f"FAILED: {c['check']}  {c['detail']}")
    failed = [c for c in checks if not c["ok"]]
    if failed and strict:
        raise PipelineError("CTI figure validation failed - nothing was saved:\n  " +
                            "\n  ".join(f"{c['check']} ({c['detail']})" for c in failed))

    # layout + render
    if compact:
        from .cti_figure_compact import compact_layout, render_compact
        lay = compact_layout(m, ordered_tactics, font_size, tactic_labels)
    else:
        lay = _layout(m, ordered_tactics, font_size)
    device = ws_dir.name
    title = title or f"CVE2AT CTI provenance: {device}"
    subtitle = (f"{stats['cves_reaching_curated_relation']} of {stats['total_cves']} CVEs reach a complete "
                f"CVE -> CWE -> CAPEC -> technique -> tactic chain; {stats['cves_with_usable_cwe']} have a usable CWE")
    omit_note = ("Showing at most {0} CVEs. Only CVEs contributing to complete chains are expanded below"
                 .format(max_cves)) if not expand_incomplete else (
                 f"Showing at most {max_cves} CVEs; omitted CVEs are summarised, never connected.")
    note = omit_note + ".\nEdges are projections of the curated chains (rows of P); shared entities are single nodes.\n" \
        "Names/descriptions: see the accompanying *_nodes.csv."
    if compact:
        files = render_compact(m, lay, figsize, dpi, font_size, base, formats, tactic_labels,
                               split=stats["layer_split"])
    else:
        files = _render(m, lay, stats, title, subtitle, figsize, dpi, font_size, base, formats, note)

    nodes_df, edges_df, cves_df = _frames(m, chains, m.cve_class, universe)
    if write_tables:
        for tag, frame in (("nodes", nodes_df), ("edges", edges_df), ("cves", cves_df)):
            p = Path(f"{base}_{tag}.csv")
            frame.to_csv(p, index=False)
            files[f"{tag}_csv"] = p
        p = Path(f"{base}_checks.csv")
        pd.DataFrame(checks).to_csv(p, index=False)
        files["checks_csv"] = p
    if write_dot:
        p = Path(f"{base}.dot")
        p.write_text(_dot_source(m, base.name), encoding="utf-8")
        files["dot"] = p
    if verbose:
        for k, v in files.items():
            console.info(f"wrote {k}: {v}")
    return CtiFigureResult(files=files, stats=stats, nodes=nodes_df, edges=edges_df, cves=cves_df,
                           checks=pd.DataFrame(checks))