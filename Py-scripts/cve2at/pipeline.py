"""Runs the stages in order and writes run_summary.json."""
from __future__ import annotations

import json
import platform
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, console
from .config import Workspace, check_reference_files
from .errors import ConfigError, PipelineError
from .excel_report import build_formatted_workbook
from .fetch import DEFAULT_DELAY, DEFAULT_DELAY_WITH_KEY, process_and_save_cves, sweep_rejected
from .merge import build_device_dataset
from .tabulate import tabulate_cves
from .trees import run_comprehensive_tree, run_tactic_trees


@dataclass
class RunOptions:
    datasets_dir: Path
    skip_fetch: bool = False
    api_key: str | None = None
    delay: float | None = None
    target_cve_ids: list = field(default_factory=list)
    dedup_mode: str = "per_tactic"
    png: bool = True


def resolve_delay(delay, api_key) -> float:
    if delay is not None:
        return delay
    return DEFAULT_DELAY_WITH_KEY if api_key else DEFAULT_DELAY


def check_graphviz() -> str:
    """The attack-tree stages render with the Graphviz `dot` program."""
    exe = shutil.which("dot")
    if not exe:
        hints = {"Windows": "winget install Graphviz.Graphviz   (or https://graphviz.org/download/)",
                 "Darwin": "brew install graphviz",
                 "Linux": "sudo apt install graphviz   (or your distro's package manager)"}
        raise ConfigError("Graphviz's `dot` program was not found on PATH (needed to draw the attack trees).\n"
                          f"  Install it: {hints.get(platform.system(), 'https://graphviz.org/download/')}")
    return exe


def preflight(datasets_dir) -> None:
    check_reference_files(datasets_dir)
    check_graphviz()


# individual stages (each is also a CLI command)
def stage_fetch(cpe: str, ws: Workspace, opts: RunOptions) -> dict:
    console.section("STAGE 1/5  Fetch CVEs from NVD")
    result = process_and_save_cves(cpe, ws, delay=resolve_delay(opts.delay, opts.api_key),
                                   api_key=opts.api_key)
    if result["total"] == 0:
        raise PipelineError("NVD returned no CVEs for this CPE, so there is nothing to analyse.")
    if result["accepted"] == 0:
        raise PipelineError("Every CVE for this CPE is marked Rejected, so there is nothing to analyse.")
    return result


def stage_tabulate(ws: Workspace) -> dict:
    console.section("STAGE 2/5  Tabulate CVEs (cve_data.xlsx + review workbook)")
    console.step("Move any Rejected CVEs out of cve_data/")
    swept = sweep_rejected(ws)
    console.step("Tabulate CVEs for curation")
    df = tabulate_cves(ws)
    console.step("Formatted review workbook")
    workbook = build_formatted_workbook(ws)
    return {"cves": int(len(df)), "swept_rejected": swept["moved"], "workbook": workbook}


def stage_merge(ws: Workspace, opts: RunOptions) -> dict:
    console.section("STAGE 3/5  Merge CVE -> CWE -> CAPEC -> ATT&CK")
    return build_device_dataset(ws, opts.datasets_dir, opts.target_cve_ids or None)


def stage_tactic_trees(ws: Workspace, opts: RunOptions) -> dict:
    console.section("STAGE 4/5  Tactic-level attack trees")
    return run_tactic_trees(ws.compromise_dataset_xlsx, ws.tactic_tree_dir, png=opts.png)


def stage_comprehensive_tree(ws: Workspace, opts: RunOptions) -> dict:
    console.section("STAGE 5/5  Comprehensive attack tree")
    return run_comprehensive_tree(ws.compromise_dataset_xlsx, ws.comprehensive_tree_dir,
                                  dedup_mode=opts.dedup_mode, png=opts.png)


def _timed(timings: dict, name: str, func, *args):
    """Call func(*args) and record how long it took, in seconds, under timings[name]."""
    start = time.perf_counter()
    result = func(*args)
    timings[name] = round(time.perf_counter() - start, 2)
    return result


def scale_summary(stages: dict) -> dict:
    """Sizes that the run time depends on: the ATT&CK matrix, P, and the finished trees."""
    return {
        "attack_matrix": stages["merge"].get("attack_matrix"),
        "chains_in_P": stages["tactic_trees"]["rows_kept"],
        "paths": stages["tactic_trees"]["total_paths"],
        "tree_nodes": stages["comprehensive_tree"]["total_nodes"],
        "tree_edges": stages["comprehensive_tree"]["total_edges"],
    }


def write_summary(ws: Workspace, payload: dict) -> None:
    ws.ensure()
    with open(ws.summary_json, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)


# full run
def run_pipeline(cpe: str, ws: Workspace, opts: RunOptions) -> int:
    t0 = time.time()
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")

    console.section(f"CVE2AT {__version__}  |  {cpe}")
    preflight(opts.datasets_dir)          # fail fast, before any folders or slow network work
    ws.ensure()
    console.info(f"Workspace: {ws.root}")

    summary = {"cpe": cpe, "started": started, "workspace": str(ws.root),
               "dedup_mode": opts.dedup_mode, "stages": {}}

    timings = {"fetch": None}      # stays None when --skip-fetch is used
    if opts.skip_fetch:
        console.section("STAGE 1/5  Fetch CVEs from NVD  (skipped: using existing cve_data/)")
        if not ws.cve_dir.is_dir() or not any(ws.cve_dir.glob("*.json")):
            raise PipelineError(f"--skip-fetch was given but '{ws.cve_dir}' has no CVE json files.")
    else:
        summary["stages"]["fetch"] = _timed(timings, "fetch", stage_fetch, cpe, ws, opts)

    summary["stages"]["tabulate"] = _timed(timings, "tabulate", stage_tabulate, ws)
    summary["stages"]["merge"] = _timed(timings, "merge", stage_merge, ws, opts)
    summary["stages"]["tactic_trees"] = _timed(timings, "tactic_trees", stage_tactic_trees, ws, opts)
    summary["stages"]["comprehensive_tree"] = _timed(timings, "comprehensive_tree",
                                                     stage_comprehensive_tree, ws, opts)

    ok = (summary["stages"]["tactic_trees"]["validation_ok"]
          and summary["stages"]["comprehensive_tree"]["validation_ok"])
    summary["finished"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    summary["elapsed_seconds"] = round(time.time() - t0, 1)     # whole run, including the NVD fetch
    timings["total"] = summary["elapsed_seconds"]
    summary["timing_seconds"] = timings
    summary["scale"] = scale_summary(summary["stages"])
    summary["validation_ok"] = bool(ok)
    write_summary(ws, summary)

    console.section("DONE" if ok else "DONE - but tree VALIDATION FAILED (see the stage output above)")
    tac, comp = summary["stages"]["tactic_trees"], summary["stages"]["comprehensive_tree"]
    console.headline("Per-tactic paths", tac["total_paths"])
    console.headline(f"Comprehensive tree paths ({comp['dedup_mode']})", comp["total_paths"])
    fetch_note = "skipped" if timings["fetch"] is None else f"{timings['fetch']} s"
    console.info(f"Run time: {summary['elapsed_seconds']} s (NVD fetch: {fetch_note})")
    console.info(f"Everything is in: {ws.root}")
    console.info(f"  Open the interactive trees:  {ws.comprehensive_tree_dir / 'comprehensive_attack_tree.html'}")
    console.info(f"                               {ws.tactic_tree_dir / '*.html'}")
    console.info(f"  Run summary:                 {ws.summary_json}")
    return 0 if ok else 2