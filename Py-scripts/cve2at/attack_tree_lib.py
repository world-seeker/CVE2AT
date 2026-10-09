"""Shared library for the CVE2AT attack-tree stages.

The tactic-level and comprehensive tree stages (trees.py) both call the functions here, so
loading, curation, deduplication and graph construction have one implementation.

Steps
1. load_dataset            read the merged CVE -> CWE -> CAPEC -> ATT&CK workbook
2. resolve_key_columns     choose the identity columns (stable IDs if present, else names)
3. build_curated_relation  P: one row per complete (CVE, CWE, CAPEC, technique, tactic) chain
4. build_leaf_index        deduplicate P into leaves, in one of two modes:
                             per_tactic       collapse exact duplicates within a tactic only
                             earliest_tactic  keep a (w, k, s, c) chain once, under the earliest
                                              tactic (MITRE order) where it appears
5. build_tactic_graph      one tree per tactic, using only OR and AND gates
   build_comprehensive_graph  the combined view: a virtual root and one OR gate over the
                             tactic roots (presentation only, not part of the model)
6. export_tree             write .dot, .svg, .html, .json and .png
7. validate_tree           structural checks on the finished trees

Needs pandas, openpyxl and graphviz, plus the Graphviz `dot` program on PATH.
"""

from __future__ import annotations

import os
import re
import json
import html as html_lib
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Optional

import pandas as pd
import xml.etree.ElementTree as ET
from graphviz import Digraph

from . import console

# config

MITRE_TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]

COLORS = {
    "root":    "#FFD700",
    "tactic":  "#98FB98",
    "cwe":     "#ADD8E6",
    "tech":    "#90EE90",
    "subtech": "#FFFACD",
    "capec":   "#FFB6C1",
    "gate":    "#FFCCCB",
}

ROOT_GATE_LABEL = "OR"  # gate under the virtual root in the combined view (presentation only)
LEAF_GATE_LABEL = "AND"   # gate joining (sub-)technique + CAPEC at each leaf (the only place AND is used)

# candidate ID columns, used only when all three primary ones are present
_ID_CWE_COL   = "CWE ID"
# "Technique_ID_Only" is the leaf-level id s: the sub-technique id when the row has one,
# else the parent technique id. It is not a count of distinct techniques.
_ID_LEAF_TECH_COL = "Technique_ID_Only"
# "technique" is the parent technique id k; use it to count techniques
_ID_PARENT_TECH_COL = "technique"
_ID_CAPEC_COL = "CAPEC_ID"
_ID_SUBTECH_CANDIDATES = ["subtechnique_id", "Subtechnique_ID_Only", "Subtechnique_ID"]

# label columns present in the merged dataset
_NAME_CWE_COL    = "cwe_Name"
_NAME_TECH_COL   = "technique_name"
_NAME_SUBTECH_COL = "subtechnique_name"
_NAME_CAPEC_COL  = "capec_Name"
_TACTIC_COL      = "tactics"


# data structures

@dataclass
class LeafRecord:
    """One surviving (weakness, technique, sub-technique, CAPEC, tactic) chain."""
    cwe_key: str
    cwe_name: str
    technique_key: str        # leaf-level s (Technique_ID_Only): sub-technique
                               # if one exists, else same as parent_technique_key
    technique_name: str
    parent_technique_key: str  # parent technique k (count techniques with this)
    parent_technique_name: str
    subtechnique_key: str    # "" if the chain has no sub-technique
    subtechnique_name: str
    capec_key: str
    capec_name: str
    tactic: str


@dataclass
class LeafIndex:
    mode: str                              # "per_tactic" | "earliest_tactic"
    ordered_tactics: list
    leaves_by_tactic: dict = field(default_factory=dict)   # tactic -> {cwe_key: [LeafRecord,...]}
    pruned: list = field(default_factory=list)             # only populated for "earliest_tactic"


@dataclass
class TreeResult:
    name: str
    dot: "Digraph"
    nodes_data: list
    edges_data: list
    node_html: dict
    leaf_count: int
    node_count: int = 0
    edge_count: int = 0
    root_id: str = "root"    # a tactic tree's root is its tactic node, not a shared "Compromise Device"


# loading

def load_dataset(path: str) -> pd.DataFrame:
    """Load the merged CVE->CWE->CAPEC->ATT&CK Excel dataset."""
    df = pd.read_excel(path, index_col=False)
    if _TACTIC_COL not in df.columns:
        raise KeyError(f"Expected a '{_TACTIC_COL}' column in the dataset.")
    df = df.fillna("")
    df[_TACTIC_COL] = df[_TACTIC_COL].astype(str).str.strip()
    return df


def mitre_order(tactics_iterable) -> list:
    """Order a collection of tactic names by MITRE ATT&CK's canonical
    kill-chain order, appending any unrecognised tactic names at the end.
    """
    present = [t for t in tactics_iterable if t]
    ordered = [t for t in MITRE_TACTIC_ORDER if t in present]
    for t in present:
        if t not in ordered:
            ordered.append(t)
    return ordered


# identity columns

def resolve_key_columns(df: pd.DataFrame) -> dict:
    """Choose the identity columns for CWE, technique, sub-technique and CAPEC.

    Identity columns drive deduplication and row filtering; label columns only supply the text
    shown on nodes. Stable ID columns are preferred when all three primary ones exist, because
    matching on names can merge entries that are worded differently or miss a name collision
    between an unrelated CWE and CAPEC. If the ID columns are missing, the _Name columns are used
    and the fallback is reported.
    """
    cols = set(df.columns)
    has_ids = {_ID_CWE_COL, _ID_LEAF_TECH_COL, _ID_CAPEC_COL}.issubset(cols)
    has_parent_tech = _ID_PARENT_TECH_COL in cols
    subtech_id_col = next((c for c in _ID_SUBTECH_CANDIDATES if c in cols), None)

    if has_ids:
        return {
            "cwe_key": _ID_CWE_COL,          "cwe_label": _NAME_CWE_COL,
            # leaf-level (sub-)technique id s: used for the (s AND c) leaf and in the dedup identity.
            # Not for counting techniques.
            "technique_key": _ID_LEAF_TECH_COL, "technique_label": _NAME_TECH_COL,
            # parent technique id k: the other part of the dedup identity, and the column to use when
            # counting distinct techniques

            "parent_technique_key": _ID_PARENT_TECH_COL if has_parent_tech else _ID_LEAF_TECH_COL,
            "parent_technique_label": _NAME_TECH_COL,
            "subtechnique_key": subtech_id_col, "subtechnique_label": _NAME_SUBTECH_COL,
            "capec_key": _ID_CAPEC_COL,      "capec_label": _NAME_CAPEC_COL,
            "used_ids": True,
        }
    return {
        "cwe_key": _NAME_CWE_COL,          "cwe_label": _NAME_CWE_COL,
        "technique_key": _NAME_TECH_COL,   "technique_label": _NAME_TECH_COL,
        "parent_technique_key": _NAME_TECH_COL, "parent_technique_label": _NAME_TECH_COL,
        "subtechnique_key": _NAME_SUBTECH_COL, "subtechnique_label": _NAME_SUBTECH_COL,
        "capec_key": _NAME_CAPEC_COL,      "capec_label": _NAME_CAPEC_COL,
        "used_ids": False,
    }


def _s(v) -> str:
    """Trim/normalise a cell value to a plain string ('' if empty/NaN)."""
    v = "" if v is None else v
    s = str(v).strip()
    return "" if s.lower() == "nan" else s


# curated relation P


def build_curated_relation(df: pd.DataFrame, key_cols: dict):
    """Return (P, dropped).

    P has one row per complete (CVE, CWE, CAPEC, technique, tactic) chain; the sub-technique is
    optional. Rows missing a required column go to `dropped` so they can be audited. They never
    appear as placeholder leaves.
    """
    required = [key_cols["cwe_key"], key_cols["technique_key"],
                key_cols["capec_key"], _TACTIC_COL]
    touch = set(required)
    if key_cols["subtechnique_key"]:
        touch.add(key_cols["subtechnique_key"])

    work = df.copy()
    for c in touch:
        if c in work.columns:
            work[c] = work[c].map(_s)

    mask = pd.Series(True, index=work.index)
    for c in required:
        mask &= work[c].astype(bool)

    P = work[mask].copy()
    dropped = work[~mask].copy()
    return P, dropped


# deduplication

def build_leaf_index(P: pd.DataFrame, key_cols: dict, ordered_tactics: list,
                      mode: str = "per_tactic") -> LeafIndex:
    """Deduplicate P into leaf records, grouped by tactic and CWE.

    mode="per_tactic": the key is (cwe, technique, subtechnique, capec, tactic). Only exact
    duplicates inside one tactic are collapsed, so a chain that occurs under several tactics is
    kept once for each. This gives the per-tactic path counts.

    mode="earliest_tactic": the key has no tactic. Rows are read in MITRE tactic order and each
    key is kept once, under the first tactic where it occurs. Later repeats under other tactics
    are pruned and listed in `.pruned`.

    Both modes use this one function, so the per-tactic table and the comprehensive total
    cannot drift apart.
    """
    if mode not in ("per_tactic", "earliest_tactic"):
        raise ValueError("mode must be 'per_tactic' or 'earliest_tactic'")

    ck, tk, sk, pk = (key_cols["cwe_key"], key_cols["technique_key"],
                      key_cols["subtechnique_key"], key_cols["capec_key"])
    cl, tl, sl, pl = (key_cols["cwe_label"], key_cols["technique_label"],
                      key_cols["subtechnique_label"], key_cols["capec_label"])
    ptk, ptl = key_cols["parent_technique_key"], key_cols["parent_technique_label"]

    leaves_by_tactic = {t: {} for t in ordered_tactics}
    pruned = []
    seen_local = set()          # per_tactic mode: (identity, tactic)
    first_tactic_of = {}        # earliest_tactic mode: identity -> tactic

    for tactic in ordered_tactics:
        t_rows = P[P[_TACTIC_COL] == tactic]
        for _, row in t_rows.iterrows():
            cwe_key, cwe_name = row[ck], row[cl]
            tech_key, tech_name = row[tk], row[tl]              # leaf s
            parent_tech_key, parent_tech_name = row[ptk], row[ptl]  # k
            sub_name = _s(row[sl]) if sl else ""
            sub_key = tech_key if sub_name else ""
            capec_key, capec_name = row[pk], row[pl]

            # identity is the (w, k, s, c) key: the parent technique k and the leaf s both take part, so
            # sub-techniques of one technique that land under different weaknesses or CAPECs still dedup
            # correctly, and techniques can be counted by grouping on parent_technique_key.
            identity = (cwe_key, parent_tech_key, tech_key, capec_key)

            if mode == "per_tactic":
                local_key = identity + (tactic,)
                if local_key in seen_local:
                    continue
                seen_local.add(local_key)
            else:  # earliest_tactic
                if identity in first_tactic_of:
                    pruned.append({
                        "cwe": cwe_name, "technique": parent_tech_name,
                        "subtechnique": sub_name, "capec": capec_name,
                        "seen_in_tactic": tactic,
                        "kept_under_tactic": first_tactic_of[identity],
                    })
                    continue
                first_tactic_of[identity] = tactic

            rec = LeafRecord(cwe_key, cwe_name, tech_key, tech_name,
                              parent_tech_key, parent_tech_name,
                              sub_key, sub_name, capec_key, capec_name, tactic)
            leaves_by_tactic[tactic].setdefault(cwe_key, []).append(rec)

    return LeafIndex(mode=mode, ordered_tactics=ordered_tactics,
                      leaves_by_tactic=leaves_by_tactic, pruned=pruned)


def total_paths(leaf_index: LeafIndex) -> int:
    return sum(len(v) for tac in leaf_index.leaves_by_tactic.values() for v in tac.values())


def leaf_summary_table(leaf_index: LeafIndex) -> pd.DataFrame:
    """Per-tactic counts of paths, CWEs, techniques and CAPECs, plus a TOTAL row.

    TOTAL counts globally distinct items, not the sum of the per-tactic counts, because the same
    technique, CWE or CAPEC can occur under more than one tactic. Techniques are counted on
    parent_technique_key; counting the leaf-level technique_key would count a parent technique
    once per sub-technique.
    """
    rows = []
    all_cwes, all_techs, all_capecs = set(), set(), set()
    for tactic in leaf_index.ordered_tactics:
        cwes = leaf_index.leaves_by_tactic.get(tactic, {})
        n_paths = sum(len(v) for v in cwes.values())
        techs, capecs = set(), set()
        for cwe_key, recs in cwes.items():
            all_cwes.add(cwe_key)
            for r in recs:
                techs.add(r.parent_technique_key); all_techs.add(r.parent_technique_key)
                capecs.add(r.capec_key); all_capecs.add(r.capec_key)
        rows.append({"tactic": tactic, "paths": n_paths, "unique_cwes": len(cwes),
                     "unique_techniques": len(techs), "unique_capecs": len(capecs)})
    out = pd.DataFrame(rows).set_index("tactic")
    out.loc["TOTAL"] = [out["paths"].sum(), len(all_cwes), len(all_techs), len(all_capecs)]
    return out


def pruned_report(leaf_index: LeafIndex) -> pd.DataFrame:
    """Every chain pruned under earliest_tactic mode: which tactic it was
    seen in vs. which tactic actually keeps it. Empty for per_tactic mode."""
    cols = ["cwe", "technique", "subtechnique", "capec", "seen_in_tactic", "kept_under_tactic"]
    if not leaf_index.pruned:
        return pd.DataFrame(columns=cols)
    return pd.DataFrame(leaf_index.pruned)[cols]


# node metadata

def _norm(s) -> str:
    return re.sub(r"[^0-9a-z]", "", str(s).lower())


_META_KEY_GROUPS = {
    "cwe": [
        "CVE ID", "Description", "cwe_Name", "cwe_Abstraction", "cwe_Structure", "cwe_Status",
        "cwe_Description", "cwe_Extended_Description", "cwe_Related_Weaknesses",
        "cwe_Weakness_Ordinality", "cwe_Modes_Of_Introduction", "cwe_Likelihood_Of_Exploit",
        "cwe_Common_Consequences", "cwe_Detection_Methods", "cwe_Potential_Mitigations",
        "attackVector", "baseScore", "baseSeverity", "attackComplexity",
        "privilegesRequired", "userInteraction", "confidentialityImpact",
        "availabilityImpact", "exploitabilityScore", "exposure_tags",
    ],
    "capec": [
        "CVE ID", "capec_Name", "capec_Mitre_Techniques", "capec_Abstraction", "capec_Status",
        "capec_Description", "capec_Extended_Description", "capec_Likelihood_Of_Attack",
        "capec_Typical_Severity", "capec_Execution_Flow", "capec_Prerequisites",
        "capec_Skills_Required", "capec_Resources_Required", "capec_Consequences",
        "capec_Mitigations", "capec_Related_Weaknesses", "attackVector", "exposure_tags",
    ],
    "tech": [
        "CVE ID", "Description", "tech_description", "technique_name", "subtechnique_name",
        "tactics", "detection", "platforms", "data sources", "defenses bypassed",
        "permissions required", "impact type", "effective permissions",
        "attackVector", "baseScore", "baseSeverity", "attackComplexity",
        "privilegesRequired", "userInteraction", "exposure_tags",
    ],
    "subtech": [
        "subtechnique_name", "technique_name", "tactics", "detection", "platforms", "data sources",
    ],
}


def extract_node_metadata(df_subset: pd.DataFrame, node_type: str) -> dict:
    """Aggregate unique non-empty column values for a node, tolerant to
    case/spacing/underscore variation in column names."""
    cols_map = {_norm(c): c for c in df_subset.columns}
    keys = _META_KEY_GROUPS.get(node_type, list(df_subset.columns))

    meta = {}
    for k in keys:
        col = cols_map.get(_norm(k))
        if not col or col not in df_subset.columns:
            continue
        vals = [v for v in df_subset[col].astype(str).str.strip().tolist()
                if v and v.lower() != "nan"]
        uniq = list(dict.fromkeys(vals))
        if uniq:
            meta[k] = " | ".join(uniq)
    return meta


def meta_to_html(meta: dict) -> str:
    if not meta:
        return "<div class='meta-empty'>No metadata available.</div>"
    preferred = ["cwe_Name", "capec_Name", "technique_name", "subtechnique_name",
                 "CVE ID", "baseScore", "baseSeverity", "attackVector"]
    ordered_keys = [k for k in preferred if k in meta]
    ordered_keys += [k for k in meta if k not in ordered_keys]
    rows = []
    for k in ordered_keys:
        rows.append(f"<tr><th>{html_lib.escape(str(k))}</th>"
                     f"<td>{html_lib.escape(str(meta[k]))}</td></tr>")
    return "<table class='meta-table'>" + "".join(rows) + "</table>"


# graph building (shared by both renderers)

def _add_node(dot, nid, label, ntype, nodes_data, metadata=None):
    shape = "note" if ntype == "cwe" else "ellipse" if ntype == "gate" else "box"
    color = COLORS.get(ntype, "#FFFFFF")
    dot.node(nid, label=label, shape=shape, fillcolor=color, style="filled", fontname="Helvetica")
    entry = {"id": nid, "label": label, "type": ntype}
    if metadata:
        entry["metadata"] = metadata
    nodes_data.append(entry)


def _add_edge(dot, src, dst, edges_data):
    dot.edge(src, dst)
    edges_data.append({"from": src, "to": dst})


def nary_gate(dot, parent_id, child_ids, gate_id, label, nodes_data, edges_data):
    """Connect parent to all children through one n-ary gate (no nesting).

    With a single child the gate is skipped and the edge goes straight to it; with none, nothing
    is added.
    """
    if not child_ids:
        return
    if len(child_ids) == 1:
        _add_edge(dot, parent_id, child_ids[0], edges_data)
        return
    _add_node(dot, gate_id, label, "gate", nodes_data)
    _add_edge(dot, parent_id, gate_id, edges_data)
    for c in child_ids:
        _add_edge(dot, gate_id, c, edges_data)


def _build_leaf_and_gate(dot, rec: LeafRecord, df_subset: pd.DataFrame, key_cols: dict,
                          id_prefix: str, n: int, nodes_data, edges_data, node_html) -> str:
    """Build the nodes for one LeafRecord: a sub-technique (or technique) node, a CAPEC node
    and the AND gate that joins them. Returns the gate's node id.

    Both renderers create leaves here, so a technique x CAPEC cross product is never formed.
    Rows without a complete pair were already dropped in build_curated_relation.
    """
    tk, pk = key_cols["technique_key"], key_cols["capec_key"]

    tech_mask = df_subset[tk].astype(str).str.strip() == rec.technique_key
    leaf_rows = df_subset[tech_mask]

    if rec.subtechnique_key:
        sub_id = f"{id_prefix}_sub_{n}"
        sub_meta = extract_node_metadata(leaf_rows, "subtech")
        _add_node(dot, sub_id, rec.subtechnique_name, "subtech", nodes_data, metadata=sub_meta)
        node_html[sub_id] = meta_to_html(sub_meta)
        pair_id = sub_id
    else:
        tech_id = f"{id_prefix}_tech_{n}"
        tech_meta = extract_node_metadata(leaf_rows, "tech")
        _add_node(dot, tech_id, rec.technique_name, "tech", nodes_data, metadata=tech_meta)
        node_html[tech_id] = meta_to_html(tech_meta)
        pair_id = tech_id

    capec_mask = tech_mask & (df_subset[pk].astype(str).str.strip() == rec.capec_key)

    cap_rows = df_subset[capec_mask]
    cap_id = f"{id_prefix}_cap_{n}"
    cap_meta = extract_node_metadata(cap_rows, "capec")
    _add_node(dot, cap_id, rec.capec_name, "capec", nodes_data, metadata=cap_meta)
    node_html[cap_id] = meta_to_html(cap_meta)

    and_id = f"{id_prefix}_and_{n}"
    _add_node(dot, and_id, LEAF_GATE_LABEL, "gate", nodes_data)
    _add_edge(dot, and_id, pair_id, edges_data)
    _add_edge(dot, and_id, cap_id, edges_data)
    return and_id


def _build_cwe_subtree(dot, cwe_key: str, records: list, df_subset: pd.DataFrame, key_cols: dict,
                        id_prefix: str, ci: int, counter: list, nodes_data, edges_data, node_html) -> str:
    """Build one CWE node, the AND-gate leaves under it and the OR gate that joins them (left
    out when there is a single leaf). Used by both renderers.
    """
    cwe_name = records[0].cwe_name
    cwe_id = f"{id_prefix}_cwe_{ci}"
    cwe_rows = df_subset[df_subset[key_cols["cwe_key"]].astype(str).str.strip() == cwe_key]
    cwe_meta = extract_node_metadata(cwe_rows, "cwe")
    _add_node(dot, cwe_id, cwe_name, "cwe", nodes_data, metadata=cwe_meta)
    node_html[cwe_id] = meta_to_html(cwe_meta)

    and_ids = []
    for rec in records:
        n = counter[0]
        counter[0] += 1
        and_id = _build_leaf_and_gate(dot, rec, cwe_rows, key_cols, f"{id_prefix}_{ci}", n,
                                       nodes_data, edges_data, node_html)
        and_ids.append(and_id)

    nary_gate(dot, cwe_id, and_ids, f"{id_prefix}_cwe{ci}_or", "OR", nodes_data, edges_data)
    return cwe_id


# tactic-level renderer

def build_tactic_graph(tactic: str, leaf_index: LeafIndex, df: pd.DataFrame,
                        key_cols: dict, tactic_index: int) -> TreeResult:
    """Build one tactic's tree. The tactic node is the root; one OR gate fans out to the CWE
    nodes (left out when there is only one), and each CWE joins its AND leaves through one OR
    gate (left out for a single leaf).
    """
    dot = Digraph()
    dot.attr("graph", rankdir="TB", splines="ortho", nodesep="0.5", ranksep="0.8")
    dot.attr("node", fontname="Helvetica", fontsize="12")

    nodes_data, edges_data, node_html = [], [], {}
    counter = [0]
    prefix = f"t{tactic_index}"

    tactic_id = f"{prefix}_tactic"
    _add_node(dot, tactic_id, tactic, "tactic", nodes_data, metadata={"tactic": tactic})
    node_html[tactic_id] = meta_to_html({"tactic": tactic})

    tactic_df = df[df[_TACTIC_COL] == tactic]
    cwes = leaf_index.leaves_by_tactic.get(tactic, {})

    cwe_ids = []
    for ci, (cwe_key, records) in enumerate(cwes.items()):
        if not records:
            continue
        cwe_id = _build_cwe_subtree(dot, cwe_key, records, tactic_df, key_cols,
                                     prefix, ci, counter, nodes_data, edges_data, node_html)
        cwe_ids.append(cwe_id)

    nary_gate(dot, tactic_id, cwe_ids, f"{prefix}_tac_or", "OR", nodes_data, edges_data)

    leaf_count = sum(len(v) for v in cwes.values())
    return TreeResult(tactic, dot, nodes_data, edges_data, node_html, leaf_count,
                       len(nodes_data), len(edges_data), root_id=tactic_id)


# comprehensive renderer

def build_comprehensive_graph(leaf_index: LeafIndex, df: pd.DataFrame, key_cols: dict) -> TreeResult:
    """Build the combined view: a virtual "Compromise(Device)" root above one OR gate (left out
    for a single tactic) that spans the tactic roots.

    This only shows the tactic trees in one picture. The model itself is the set of per-tactic trees
    from build_tactic_graph. OR adds no constraint between the trees it joins, so each tactic
    tree keeps its own meaning.
    """
    dot = Digraph(name="comprehensive_attack_tree", format="svg")
    # Left to right: the leaves stack downwards, so the picture is tall instead of tens of
    # thousands of points wide. Straight-segment edges keep every edge traceable (ortho merges them).
    dot.attr("graph", rankdir="LR", splines="polyline", nodesep="0.3", ranksep="1.0")
    dot.attr("node", fontname="Helvetica", fontsize="13")

    nodes_data, edges_data, node_html = [], [], {}
    counter = [0]

    ordered_tactics = [t for t in leaf_index.ordered_tactics if leaf_index.leaves_by_tactic.get(t)]

    root_id = "root"
    _add_node(dot, root_id, "Compromise(Device)", "root", nodes_data)
    node_html[root_id] = meta_to_html({"label": "Compromise(Device)",
                                        "note": "Virtual root of the combined view; presentation only."})

    tactic_ids = []
    for i, tactic in enumerate(ordered_tactics):
        tid = f"tactic_{i}"
        _add_node(dot, tid, tactic, "tactic", nodes_data, metadata={"tactic": tactic})
        node_html[tid] = meta_to_html({"tactic": tactic})
        tactic_ids.append(tid)

    # one n-ary OR gate from the root to every tactic root (omitted for a single tactic)
    nary_gate(dot, root_id, tactic_ids, "root_or", ROOT_GATE_LABEL, nodes_data, edges_data)

    for i, tactic in enumerate(ordered_tactics):
        tid = f"tactic_{i}"
        tactic_df = df[df[_TACTIC_COL] == tactic]
        cwes = leaf_index.leaves_by_tactic[tactic]
        cwe_ids = []
        for ci, (cwe_key, records) in enumerate(cwes.items()):
            cwe_id = _build_cwe_subtree(dot, cwe_key, records, tactic_df, key_cols,
                                         f"c{i}", ci, counter, nodes_data, edges_data, node_html)
            cwe_ids.append(cwe_id)
        nary_gate(dot, tid, cwe_ids, f"tac{i}_or", "OR", nodes_data, edges_data)

    leaf_count = total_paths(leaf_index)
    return TreeResult("combined_view", dot, nodes_data, edges_data, node_html, leaf_count,
                       len(nodes_data), len(edges_data), root_id=root_id)


# export

def inject_node_ids(svg_path: str) -> str:
    """Parse the Graphviz SVG, set data-node-id on each node <g>, and
    replace its <title> with the plain label (cleaner hover tooltip)."""
    NS = "http://www.w3.org/2000/svg"
    ET.register_namespace("", NS)
    ET.register_namespace("xlink", "http://www.w3.org/1999/xlink")
    tree = ET.parse(svg_path)
    root = tree.getroot()
    for g in root.findall(f".//{{{NS}}}g"):
        title_el = g.find(f"{{{NS}}}title")
        if title_el is None or not title_el.text:
            continue
        node_id = title_el.text.strip()
        g.set("data-node-id", node_id)
        text_el = g.find(f".//{{{NS}}}text")
        if text_el is not None and text_el.text:
            title_el.text = text_el.text.strip()
    return ET.tostring(root, encoding="unicode", xml_declaration=False)


_HTML_TEMPLATE = """\
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>Attack Tree  {title}</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; }}
    html, body {{ height: 100%; margin: 0; padding: 0; background: #f4f4f4;
                  font-family: Arial, Helvetica, sans-serif; font-size: 15px; }}
    .app {{ display: flex; height: 100vh; gap: 0; overflow: hidden; }}
    .graph-col {{ flex: 1 1 auto; display: flex; flex-direction: column;
                  overflow: hidden; background: #fff; border-right: 2px solid #d0d0d0; }}
    .graph-header {{ padding: 10px 16px 8px; border-bottom: 1px solid #e0e0e0; background: #fff; }}
    .graph-header h1 {{ margin: 0 0 6px; font-size: 20px; }}
    .legend {{ display: flex; flex-wrap: wrap; gap: 6px; margin-top: 4px; }}
    .legend-item {{ padding: 3px 10px; border-radius: 4px; font-size: 13px;
                     border: 1px solid rgba(0,0,0,.12); }}
    .svg-scroll {{ flex: 1 1 auto; overflow: auto; padding: 12px; background: #fafafa; }}
    .svg-scroll svg {{ width: auto; height: auto; display: block; cursor: default; }}
    .svg-scroll [data-node-id] {{ cursor: pointer; }}
    .svg-scroll [data-node-id]:hover ellipse,
    .svg-scroll [data-node-id]:hover polygon,
    .svg-scroll [data-node-id]:hover path {{ filter: brightness(0.88); }}
    .selected-node ellipse, .selected-node polygon, .selected-node path {{
      stroke: #1a6fc4 !important; stroke-width: 3px !important; }}
    .graph-footer {{ padding: 6px 16px; font-size: 13px; color: #666;
                      border-top: 1px solid #e0e0e0; background: #fff; }}
    .panel-col {{ flex: 0 0 400px; display: flex; flex-direction: column;
                   background: #fff; overflow: hidden; transition: flex-basis .2s; }}
    .panel-col.hidden {{ flex: 0 0 0; overflow: hidden; }}
    .panel-header {{ display: flex; align-items: center; justify-content: space-between;
                      padding: 10px 14px; border-bottom: 1px solid #e0e0e0; background: #f8f8f8; }}
    .panel-header h2 {{ margin: 0; font-size: 16px; }}
    .close-btn {{ border: none; background: transparent; font-size: 22px; cursor: pointer;
                   line-height: 1; padding: 0 4px; color: #555; }}
    .close-btn:hover {{ color: #000; }}
    .panel-body {{ flex: 1 1 auto; overflow-y: auto; padding: 14px; }}
    .panel-placeholder {{ color: #888; font-style: italic; margin-top: 20px; text-align: center; }}
    .node-label-heading {{ font-size: 17px; font-weight: 700; margin: 0 0 4px; word-break: break-word; }}
    .node-type-badge {{ display: inline-block; padding: 2px 8px; border-radius: 20px;
                         font-size: 12px; font-weight: 600; margin-bottom: 10px; }}
    .meta-table {{ width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 14px; }}
    .meta-table th {{ text-align: left; padding: 6px 8px; background: #f3f3f3;
                       border-bottom: 1px solid #e0e0e0; font-weight: 600; width: 36%;
                       vertical-align: top; word-break: break-word; }}
    .meta-table td {{ padding: 6px 8px; border-bottom: 1px solid #eee;
                       vertical-align: top; word-break: break-word; }}
    .meta-empty {{ color: #888; font-style: italic; }}
    .badge-root    {{ background: #FFD700; color: #5a4200; }}
    .badge-tactic  {{ background: #98FB98; color: #1a5c1a; }}
    .badge-cwe     {{ background: #ADD8E6; color: #1a3a5c; }}
    .badge-tech    {{ background: #90EE90; color: #1a5c1a; }}
    .badge-subtech {{ background: #FFFACD; color: #5c5000; }}
    .badge-capec   {{ background: #FFB6C1; color: #6b0a1e; }}
    .badge-gate    {{ background: #FFCCCB; color: #7a1a00; }}
  </style>
</head>
<body>
<div class="app">
  <div class="graph-col">
    <div class="graph-header">
      <h1>Attack Tree  {title}</h1>
      <div class="legend">
        <span class="legend-item" style="background:{c_root}">Compromise Device (root)</span>
        <span class="legend-item" style="background:{c_tactic}">Tactic</span>
        <span class="legend-item" style="background:{c_cwe}">CWE</span>
        <span class="legend-item" style="background:{c_tech}">Technique</span>
        <span class="legend-item" style="background:{c_subtech}">Subtechnique</span>
        <span class="legend-item" style="background:{c_capec}">CAPEC</span>
        <span class="legend-item" style="background:{c_gate}">OR / AND gates</span>
      </div>
    </div>
    <div class="svg-scroll" id="svg-scroll">
      {svg_content}
    </div>
    <div class="graph-footer">
      {note} &nbsp;|&nbsp; Click any node to view its metadata in the right-hand panel. &nbsp;|&nbsp;
      Scroll / drag to navigate. &nbsp;|&nbsp; Press <kbd>Esc</kbd> to close the panel.
    </div>
  </div>
  <div class="panel-col hidden" id="panel-col">
    <div class="panel-header">
      <h2 id="panel-title">Node metadata</h2>
      <button class="close-btn" id="close-btn" title="Close panel">&times;</button>
    </div>
    <div class="panel-body" id="panel-body">
      <div class="panel-placeholder">Click a node in the graph to see details here.</div>
    </div>
  </div>
</div>
<script>
var NODE_HTML  = {node_html_json};
var NODES_DATA = {nodes_data_json};
var nodeInfo = {{}};
NODES_DATA.forEach(function(n) {{ nodeInfo[n.id] = n; }});
var panelCol  = document.getElementById('panel-col');
var panelBody = document.getElementById('panel-body');
var panelTitle= document.getElementById('panel-title');
var closeBtn  = document.getElementById('close-btn');
var svgScroll = document.getElementById('svg-scroll');
var selectedGroup = null;
function showPanel(nodeId) {{
  var info = nodeInfo[nodeId] || {{}};
  var label = info.label || nodeId;
  var ntype = info.type || 'unknown';
  var htmlTbl = NODE_HTML[nodeId] || '<div class="meta-empty">No metadata recorded for this node.</div>';
  panelTitle.textContent = 'Node metadata';
  var badgeClass = 'badge-' + ntype;
  panelBody.innerHTML = '<p class="node-label-heading">' + escHtml(label) + '</p>' +
    '<span class="node-type-badge ' + badgeClass + '">' + escHtml(ntype) + '</span>' + htmlTbl;
  panelCol.classList.remove('hidden');
}}
function closePanel() {{
  panelCol.classList.add('hidden');
  if (selectedGroup) {{ selectedGroup.classList.remove('selected-node'); selectedGroup = null; }}
}}
function escHtml(s) {{
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}}
document.addEventListener('DOMContentLoaded', function() {{
  var groups = svgScroll.querySelectorAll('[data-node-id]');
  groups.forEach(function(g) {{
    g.addEventListener('click', function(ev) {{
      ev.stopPropagation();
      var nodeId = g.getAttribute('data-node-id');
      if (selectedGroup && selectedGroup !== g) {{ selectedGroup.classList.remove('selected-node'); }}
      if (selectedGroup === g) {{ closePanel(); return; }}
      selectedGroup = g; g.classList.add('selected-node'); showPanel(nodeId);
    }});
  }});
  svgScroll.addEventListener('click', function() {{ closePanel(); }});
  closeBtn.addEventListener('click', closePanel);
  document.addEventListener('keydown', function(e) {{ if (e.key === 'Escape') closePanel(); }});
}});
</script>
</body>
</html>
"""


def build_interactive_html(title: str, note: str, svg_str: str, node_html: dict, nodes_data: list) -> str:
    return _HTML_TEMPLATE.format(
        title=html_lib.escape(title), note=html_lib.escape(note), svg_content=svg_str,
        node_html_json=json.dumps(node_html), nodes_data_json=json.dumps(nodes_data),
        c_root=COLORS["root"], c_tactic=COLORS["tactic"], c_cwe=COLORS["cwe"],
        c_tech=COLORS["tech"], c_subtech=COLORS["subtech"], c_capec=COLORS["capec"], c_gate=COLORS["gate"],
    )


def _clean_for_json(obj):
    if isinstance(obj, dict):
        return {k: _clean_for_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean_for_json(v) for v in obj]
    try:
        if pd.isna(obj):
            return "NaN"
    except Exception:
        pass
    return obj


def export_tree(tree_result: TreeResult, base_path: str, note: str = "", png: bool = True) -> dict:
    """Write the .dot, .svg, .html, .json and .png files for a tree_result.

    All of these files are written here, so the JSON counts and the rendered SVG come from the
    same data.
    """
    out_dir = os.path.dirname(base_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    dot_path = base_path + ".dot"
    tree_result.dot.save(dot_path)

    tree_result.dot.render(base_path, format="svg", cleanup=True)
    svg_path = base_path + ".svg"
    svg_str = inject_node_ids(svg_path)
    with open(svg_path, "w", encoding="utf-8") as f:
        f.write(svg_str)

    html_str = build_interactive_html(tree_result.name, note, svg_str,
                                       tree_result.node_html, tree_result.nodes_data)
    html_path = base_path + ".html"
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_str)

    json_path = base_path + ".json"
    json_data = {
        "name": tree_result.name,
        "leaf_count": tree_result.leaf_count,
        "node_count": tree_result.node_count,
        "edge_count": tree_result.edge_count,
        "nodes": _clean_for_json(tree_result.nodes_data),
        "edges": _clean_for_json(tree_result.edges_data),
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=2)

    paths = {"dot": dot_path, "svg": svg_path, "html": html_path, "json": json_path}
    if png:
        try:
            dpi = _png_dpi(svg_path)
            if dpi < _PNG_DPI:
                tree_result.dot.graph_attr["dpi"] = str(dpi)
            tree_result.dot.render(base_path, format="png", cleanup=True)
            paths["png"] = base_path + ".png"
        except Exception as e:                     # Graphviz missing the png renderer, or out of memory
            console.warn(f"PNG not written for {os.path.basename(base_path)}: {e}")
    return paths


_PNG_DPI = 96                  # Graphviz default
_PNG_MAX_PX = 30000            # cairo / most viewers fail beyond ~32k pixels per side


def _png_dpi(svg_path: str) -> int:
    """Resolution at which the rendered SVG stays within _PNG_MAX_PX pixels on its longest side."""
    with open(svg_path, encoding="utf-8") as f:
        head = f.read(4000)
    m = re.search(r'<svg[^>]*\swidth="([\d.]+)pt"[^>]*\sheight="([\d.]+)pt"', head)
    if not m:
        return _PNG_DPI
    longest_pt = max(float(m.group(1)), float(m.group(2)))
    return max(10, min(_PNG_DPI, int(_PNG_MAX_PX * 72 / longest_pt)))


def export_all(tree_results: dict, out_dir: str, png: bool = True) -> list:
    """tree_results: {name: TreeResult}. Returns a list of dicts (one per
    tree) suitable for pd.DataFrame(...) display."""
    rows = []
    for name, tr in tree_results.items():
        safe = re.sub(r"[^0-9A-Za-z]+", "_", name).strip("_")
        base = os.path.join(out_dir, safe)
        paths = export_tree(tr, base, png=png)
        sizes = {k: os.path.getsize(v) for k, v in paths.items()}
        rows.append({"name": name, "leaf_count": tr.leaf_count,
                     "nodes": tr.node_count, "edges": tr.edge_count, **paths, **{f"{k}_bytes": v for k, v in sizes.items()}})
    return rows


# validation

def validate_tree(tree_result: TreeResult, expected_leaf_count: Optional[int] = None) -> dict:
    """Check the structure of a tree (not whether any path is true).

    Checks: every node is reachable from the tree's own root_id; every non-root node has exactly
    one parent; every AND gate has two children, one technique or sub-technique node and one
    CAPEC node; every OR gate has at least two children; the AND-gate count equals the leaf
    count.
    """
    root_id = tree_result.root_id
    adj = {}
    for e in tree_result.edges_data:
        adj.setdefault(e["from"], []).append(e["to"])
    all_ids = {n["id"] for n in tree_result.nodes_data}
    by_id = {n["id"]: n for n in tree_result.nodes_data}

    seen, queue = {root_id}, [root_id]
    while queue:
        cur = queue.pop()
        for nb in adj.get(cur, []):
            if nb not in seen:
                seen.add(nb)
                queue.append(nb)
    unreachable = sorted(all_ids - seen)

    parents = {}
    for e in tree_result.edges_data:
        parents.setdefault(e["to"], []).append(e["from"])
    multi_parent = sorted(n for n, ps in parents.items() if len(ps) > 1)
    missing_parent = sorted(all_ids - {root_id} - set(parents))
    tree_condition_ok = not multi_parent and not missing_parent

    and_gate_count = 0
    bad_and_gates, bad_or_gates = [], []
    for n in tree_result.nodes_data:
        if n["type"] != "gate":
            continue
        kids = adj.get(n["id"], [])
        if n["label"] == LEAF_GATE_LABEL:
            and_gate_count += 1
            kid_types = sorted(by_id[k]["type"] for k in kids if k in by_id)
            if len(kids) != 2 or kid_types != sorted(["tech", "capec"]) and kid_types != sorted(["subtech", "capec"]):
                bad_and_gates.append(n["id"])
        elif n["label"] == "OR":
            if len(kids) < 2:
                bad_or_gates.append(n["id"])

    checks = {
        "reachable_from_root": len(unreachable) == 0,
        "unreachable_nodes": unreachable,
        "tree_condition_ok": tree_condition_ok,
        "nodes_with_multiple_parents": multi_parent,
        "nodes_with_no_parent": missing_parent,
        "and_gate_count": and_gate_count,
        "leaf_count": tree_result.leaf_count,
        "and_gate_count_matches_leaf_count": and_gate_count == tree_result.leaf_count,
        "and_gates_well_formed": len(bad_and_gates) == 0,
        "malformed_and_gates": bad_and_gates,
        "or_gates_well_formed": len(bad_or_gates) == 0,
        "malformed_or_gates": bad_or_gates,
    }
    if expected_leaf_count is not None:
        checks["expected_leaf_count"] = expected_leaf_count
        checks["matches_expected_total"] = tree_result.leaf_count == expected_leaf_count
    checks["ok"] = (checks["reachable_from_root"]
                     and checks["tree_condition_ok"]
                     and checks["and_gate_count_matches_leaf_count"]
                     and checks["and_gates_well_formed"]
                     and checks["or_gates_well_formed"]
                     and checks.get("matches_expected_total", True))
    return checks


_VALIDATE_LIST_FIELDS = {"unreachable_nodes", "nodes_with_multiple_parents",
                          "nodes_with_no_parent", "malformed_and_gates", "malformed_or_gates"}


def validate_tree_set(tree_results: dict, expected_counts: Optional[dict] = None) -> SimpleNamespace:
    rows = []
    ok = True
    for name, tr in tree_results.items():
        expected = expected_counts.get(name) if expected_counts else None
        c = validate_tree(tr, expected)
        rows.append({"name": name, **{k: v for k, v in c.items() if k not in _VALIDATE_LIST_FIELDS}})
        if not c["ok"]:
            ok = False
    details = pd.DataFrame(rows).set_index("name")
    return SimpleNamespace(ok=ok, details=details)


# terminal display helpers

def headline(label: str, value) -> None:
    """The one-line 'main point' of a step, printed so it stands out."""
    print(f"  >> {label}: {value}")


def highlight_table(df: pd.DataFrame, bold_rows: Optional[list] = None):
    """Print a dataframe to the terminal (bold_rows kept for API compatibility)."""
    print(df.to_string())
    return df