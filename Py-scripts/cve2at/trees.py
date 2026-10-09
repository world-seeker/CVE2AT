"""Stages 4 and 5: attack-tree construction, built on attack_tree_lib.

    run_tactic_trees(...)        one tree per tactic
    run_comprehensive_tree(...)  the single combined tree

Both read device_compromise_dataset.xlsx and use the same library functions.
"""
from __future__ import annotations

import os

import pandas as pd

from . import attack_tree_lib as atl
from . import console
from .errors import PipelineError

DEDUP_MODES = ("earliest_tactic", "per_tactic")


def _load_curated(dataset_path):
    """Load + resolve identity keys + curated relation P + MITRE tactic order (shared by both stages)."""
    df = atl.load_dataset(str(dataset_path))
    key_cols = atl.resolve_key_columns(df)
    P, dropped = atl.build_curated_relation(df, key_cols)
    if P.empty:
        raise PipelineError(
            "No complete CVE->CWE->CAPEC->technique->tactic chains in the dataset - no tree can be built.")
    ordered_tactics = atl.mitre_order(P["tactics"].unique())
    return df, key_cols, P, dropped, ordered_tactics


# one tree per tactic, deduplicated within each tactic

def run_tactic_trees(dataset_path, out_dir, png: bool = True) -> dict:
    os.makedirs(out_dir, exist_ok=True)

    console.step("1. Load the dataset")
    df, key_cols, P, dropped, ordered_tactics = _load_curated(dataset_path)
    atl.headline("Rows loaded", len(df))

    console.step("2. Resolve identity keys")
    atl.headline("Using ID columns for identity", key_cols["used_ids"])

    console.step("3. Curated relation P (Eq. 1): drop incomplete chains")
    atl.headline("Complete rows kept", f"{len(P)} / {len(df)}")
    atl.headline("Rows dropped (incomplete CWE/Technique/CAPEC/Tactic chain)", len(dropped))
    if len(dropped):
        cols = [c for c in ["CVE ID", key_cols["cwe_label"], key_cols["technique_label"],
                            key_cols["capec_label"], "tactics"] if c in dropped.columns]
        console.table(dropped[cols])

    console.step("4. Tactic ordering (MITRE ATT&CK kill-chain order)")
    atl.headline("Tactics present", len(ordered_tactics))
    console.info(", ".join(ordered_tactics))

    console.step("5. Per-tactic deduplication + leaf counts")
    leaf_index = atl.build_leaf_index(P, key_cols, ordered_tactics, mode="per_tactic")
    summary = atl.leaf_summary_table(leaf_index)
    atl.headline("TOTAL PATHS (per-tactic dedup)", int(summary.loc["TOTAL", "paths"]))
    console.table(summary)

    console.step("6. Build each tactic's graph")
    tactic_trees = {}
    for i, tactic in enumerate(ordered_tactics):
        tree = atl.build_tactic_graph(tactic, leaf_index, P, key_cols, i)
        tactic_trees[tactic] = tree
        atl.headline(f"[{i + 1}/{len(ordered_tactics)}] {tactic}",
                     f"{tree.leaf_count} paths, {tree.node_count} nodes, {tree.edge_count} edges")

    console.step("7. Export SVG / HTML / JSON / DOT" + (" / PNG" if png else "") + " for every tactic")
    exported = atl.export_all(tactic_trees, str(out_dir), png=png)
    n_files = sum(1 for row in exported for k in ("dot", "svg", "html", "json", "png") if k in row)
    atl.headline("Files written", n_files)
    console.table(pd.DataFrame(exported)[["name", "leaf_count", "nodes", "edges"]])

    console.step("8. Validation: reachability, no orphans, AND-gate count == leaf count per tactic")
    report = atl.validate_tree_set(tactic_trees)
    atl.headline("Validation", "PASSED" if report.ok else "FAILED")
    console.table(report.details)

    summary.to_csv(os.path.join(out_dir, "tactic_summary.csv"))

    # last two funnel numbers: CVEs and CWEs that actually reach P. The earlier funnel
    # stages are reported by merge.build_device_dataset.
    cves_in_final = int(df["CVE ID"].nunique()) if "CVE ID" in df.columns else None
    cves_in_P = int(P["CVE ID"].nunique()) if "CVE ID" in P.columns else None
    cwes_in_P = int(P[key_cols["cwe_key"]].nunique())

    if len(dropped):
        reason_cols = [c for c in ["CVE ID", "CWE ID", "chain_break", "tactics"] if c in dropped.columns]
        dropped[reason_cols].to_csv(os.path.join(out_dir, "incomplete_chains_at_tree_stage.csv"), index=False)

    return {
        "dedup_mode": "per_tactic",
        "rows_loaded": int(len(df)),
        "rows_kept": int(len(P)),
        "rows_dropped": int(len(dropped)),
        "cves_in_final_dataset": cves_in_final,
        "cves_in_P": cves_in_P,
        "cwes_in_P": cwes_in_P,
        "tactics": len(ordered_tactics),
        "total_paths": int(summary.loc["TOTAL", "paths"]),
        "unique_cwes": int(summary.loc["TOTAL", "unique_cwes"]),
        "unique_techniques": int(summary.loc["TOTAL", "unique_techniques"]),
        "unique_capecs": int(summary.loc["TOTAL", "unique_capecs"]),
        "validation_ok": bool(report.ok),
        "output_dir": str(out_dir),
    }


# the combined tree; the dedup mode is a run option (per_tactic by default)

def run_comprehensive_tree(dataset_path, out_dir, dedup_mode: str = "per_tactic",
                           png: bool = True) -> dict:
    if dedup_mode not in DEDUP_MODES:
        raise PipelineError(f"dedup mode must be one of {DEDUP_MODES}, got '{dedup_mode}'")
    os.makedirs(out_dir, exist_ok=True)

    console.step("1. Load + curate")
    df, key_cols, P, dropped, ordered_tactics = _load_curated(dataset_path)
    atl.headline("Curated rows", f"{len(P)} / {len(df)}")
    atl.headline("Using ID columns for identity", key_cols["used_ids"])

    console.step("2. Both dedup readings, side by side")
    leaf_index_local = atl.build_leaf_index(P, key_cols, ordered_tactics, mode="per_tactic")
    leaf_index_earliest = atl.build_leaf_index(P, key_cols, ordered_tactics, mode="earliest_tactic")
    atl.headline("Per-tactic-local total", atl.total_paths(leaf_index_local))
    atl.headline("Earliest-tactic total", atl.total_paths(leaf_index_earliest))
    n_local = atl.total_paths(leaf_index_local)
    n_earliest = atl.total_paths(leaf_index_earliest)
    # leaves removed by the earliest-tactic rule (0 when the comprehensive tree is built per-tactic)
    leaves_removed = (n_local - n_earliest) if dedup_mode == "earliest_tactic" else 0
    console.step("3. Reconciliation report")
    pruned_df = atl.pruned_report(leaf_index_earliest)
    cross_tactic = pruned_df[pruned_df["seen_in_tactic"] != pruned_df["kept_under_tactic"]]
    within_tactic = pruned_df[pruned_df["seen_in_tactic"] == pruned_df["kept_under_tactic"]]
    atl.headline("Leaves removed by cross-tactic dedup", leaves_removed)
    atl.headline("Pruned report rows (cross-tactic / within-tactic)",
                 f"{len(cross_tactic)} / {len(within_tactic)}")
    if len(cross_tactic):
        console.table(cross_tactic)

    console.step("4. Per-tactic comparison: where the two readings diverge")
    local_summary = atl.leaf_summary_table(leaf_index_local)["paths"]
    earliest_summary = atl.leaf_summary_table(leaf_index_earliest)["paths"]
    comparison = pd.DataFrame({"per_tactic_count": local_summary,
                               "earliest_tactic_count": earliest_summary}).fillna(0).astype(int)
    comparison["difference"] = comparison["per_tactic_count"] - comparison["earliest_tactic_count"]
    console.table(comparison)

    console.step("5. Dedup mode used for the comprehensive tree")
    leaf_index = {"per_tactic": leaf_index_local, "earliest_tactic": leaf_index_earliest}[dedup_mode]
    atl.headline("Comprehensive tree built with", dedup_mode)

    console.step("6. Build the combined view of the tactic trees (virtual root, single OR gate over tactics)")
    comprehensive = atl.build_comprehensive_graph(leaf_index, P, key_cols)
    atl.headline("Combined view total paths", comprehensive.leaf_count)
    atl.headline("Nodes / Edges", f"{comprehensive.node_count} / {comprehensive.edge_count}")

    console.step("7. Export the tree")
    base = os.path.join(str(out_dir), "comprehensive_attack_tree")
    if dedup_mode == "per_tactic":
        note = ("Combined view of the tactic trees (presentation only): "
                 "a tactic-level attack path may legitimately recur under several tactics, because the "
                 "same weakness/technique/CAPEC step serves a different objective in each tactic.")
    else:
        note = (f"Combined view built with DEDUP_MODE={dedup_mode} (analysis flag, not the default): "
                 "each (weakness, technique, CAPEC) chain is shown once, under the earliest MITRE-ordered "
                 "tactic it appears in.")
    paths = atl.export_tree(comprehensive, base, png=png, note=note)
    console.table(pd.DataFrame([{"file": k, "path": v, "bytes": os.path.getsize(v)}
                                for k, v in paths.items()]))

    console.step("8. Cross-check: comprehensive tree vs the sum of its own tactic subtrees")
    tactic_trees_same_mode = {
        t: atl.build_tactic_graph(t, leaf_index, P, key_cols, i)
        for i, t in enumerate(leaf_index.ordered_tactics) if leaf_index.leaves_by_tactic.get(t)}
    sum_of_subtrees = sum(tr.leaf_count for tr in tactic_trees_same_mode.values())
    match = sum_of_subtrees == comprehensive.leaf_count
    atl.headline("Comprehensive == sum of its own tactic subtrees?",
                 "MATCH" if match else f"MISMATCH ({sum_of_subtrees} != {comprehensive.leaf_count})")

    console.step("9. Validation")
    report = atl.validate_tree_set({"comprehensive": comprehensive},
                                   expected_counts={"comprehensive": sum_of_subtrees})
    atl.headline("Validation", "PASSED" if report.ok else "FAILED")
    console.table(report.details)

    final = pd.DataFrame([{
        "dedup_mode": dedup_mode,
        "total_paths": comprehensive.leaf_count,
        "total_nodes": comprehensive.node_count,
        "total_edges": comprehensive.edge_count,
        "cross_tactic_duplicates_removed": int(leaves_removed),
        "pruned_rows_cross_tactic": int(len(cross_tactic)),
        "pruned_rows_within_tactic": int(len(within_tactic)),
        "tactics_represented": len(tactic_trees_same_mode),
    }])
    console.step("10. Final numeric summary")
    console.table(final)

    comparison.to_csv(os.path.join(out_dir, "dedup_comparison.csv"))
    pruned_df.to_csv(os.path.join(out_dir, "pruned_duplicates.csv"), index=False)
    final.to_csv(os.path.join(out_dir, "summary.csv"), index=False)
    return {
        "dedup_mode": dedup_mode,
        "total_paths": int(comprehensive.leaf_count),
        "total_nodes": int(comprehensive.node_count),
        "total_edges": int(comprehensive.edge_count),
        "per_tactic_total": int(atl.total_paths(leaf_index_local)),
        "earliest_tactic_total": int(atl.total_paths(leaf_index_earliest)),
        "cross_tactic_duplicates_removed": int(leaves_removed),
        "pruned_rows_cross_tactic": int(len(cross_tactic)),
        "pruned_rows_within_tactic": int(len(within_tactic)),
        "tactics_represented": len(tactic_trees_same_mode),
        "subtree_sum_matches": bool(match),
        "validation_ok": bool(report.ok and match),
        "output_dir": str(out_dir),
    }