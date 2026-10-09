"""Command-line interface.

    cve2at run "cpe:2.3:h:baxter:sigma_spectrum_infusion_system:-:*:*:*:*:*:*:*"
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__, console
from .config import Workspace, check_reference_files, resolve_datasets_dir, validate_cpe, workspace_for
from .errors import ConfigError, Cve2atError
from .pipeline import (RunOptions, check_graphviz, run_pipeline, stage_comprehensive_tree, stage_fetch,
                       stage_merge, stage_tabulate, stage_tactic_trees)
from .trees import DEDUP_MODES

EXAMPLE_CPE = "cpe:2.3:h:baxter:sigma_spectrum_infusion_system:-:*:*:*:*:*:*:*"

# the two case-study devices
CASE_STUDY_CPES = (
    "cpe:2.3:h:baxter:sigma_spectrum_infusion_system:-:*:*:*:*:*:*:*",
    "cpe:2.3:h:schneider-electric:modicon_m580:-:*:*:*:*:*:*:*",
)


# argument groups
def _target_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("cpe", nargs="?", metavar="CPE",
                   help=f"CPE 2.3 name of the device, e.g. {EXAMPLE_CPE}")
    p.add_argument("-o", "--output-dir", default="output",
                   help="parent folder for run workspaces (default: ./output). "
                        "Each device gets its own sub-folder.")
    p.add_argument("-w", "--workspace", help="use this exact folder instead of <output-dir>/<device>")


def _datasets_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument("-d", "--datasets-dir",
                   help="folder holding cwe_data.xlsx, capec_data.xlsx, techniques.xlsx "
                        "(default: $CVE2AT_DATASETS_DIR, else ./datasets)")


def _nvd_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--api-key", default=None,
                   help="NVD API key (or set NVD_API_KEY). Makes fetching ~10x faster.")
    p.add_argument("--delay", type=float, default=None,
                   help="seconds between NVD page requests (default 6, or 0.6 with an API key)")


def _tree_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--dedup-mode", choices=DEDUP_MODES, default="per_tactic",
                   help="how the combined view de-duplicates chains (default: per_tactic, no "
                        "cross-tactic dedup; 'earliest_tactic' "
                        "is kept only as an analysis flag for the distinct-steps statistic)")
    p.add_argument("--no-png", action="store_true",
                   help="skip PNG export (SVG/HTML/JSON/DOT are still written); much faster on big trees")


def _target_cves(p: argparse.ArgumentParser) -> None:
    p.add_argument("--target-cve", action="append", default=[], metavar="CVE-ID",
                   help="restrict the analysis to these CVE IDs (repeatable). Default: all fetched CVEs.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cve2at",
        description="Give a device's CPE name; get its CVEs, the CVE->CWE->CAPEC->ATT&CK dataset, "
                    "and the attack trees.")
    parser.add_argument("--version", action="version", version=f"cve2at {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p = sub.add_parser("run", help="run the whole pipeline for a CPE (fetch -> tabulate -> merge -> trees)")
    _target_args(p); _datasets_arg(p); _nvd_args(p); _tree_args(p); _target_cves(p)
    p.add_argument("--skip-fetch", action="store_true",
                   help="reuse the CVE files already in the workspace's cve_data/ instead of querying NVD")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("fetch", help="stage 1 only: download the CVEs for a CPE from NVD")
    _target_args(p); _nvd_args(p)
    p.set_defaults(func=cmd_fetch)

    p = sub.add_parser("tabulate", help="stage 2 only: build cve_data.xlsx and the review workbook")
    _target_args(p)
    p.set_defaults(func=cmd_tabulate)

    p = sub.add_parser("merge", help="stage 3 only: merge CVEs with CWE / CAPEC / ATT&CK")
    _target_args(p); _datasets_arg(p); _target_cves(p)
    p.set_defaults(func=cmd_merge)

    p = sub.add_parser("trees", help="stages 4-5 only: build the attack trees from device_compromise_dataset.xlsx")
    _target_args(p); _tree_args(p)
    p.add_argument("--only", choices=("tactic", "comprehensive", "both"), default="both",
                   help="which trees to build (default: both)")
    p.set_defaults(func=cmd_trees)

    p = sub.add_parser("sensitivity",
                       help="robustness of the attack trees to missing CTI links (Monte-Carlo, reads "
                            "device_compromise_dataset.xlsx; not part of `run`)")
    _target_args(p)
    p.add_argument("--reps", type=int, default=500, help="replicates per (link type, p) cell (default 500)")
    p.add_argument("--seed", type=int, default=2026, help="random seed, recorded in the output (default 2026)")
    p.add_argument("--levels", type=float, nargs="+", default=None, metavar="P",
                   help="removal probabilities (default: 0.1 0.2 0.3 0.4 0.5)")
    p.add_argument("--ci-method", choices=("bootstrap", "normal"), default="bootstrap",
                   help="95%% CI for the mean over replicates (default: percentile bootstrap)")
    p.add_argument("--top", type=int, default=5, help="critical links to list per link type (default 5)")
    p.add_argument("--convergence", action="store_true",
                   help="also write sensitivity_convergence.csv (retention mean vs R = 50, 200, 1000)")
    p.set_defaults(func=cmd_sensitivity)

    p = sub.add_parser("tables", help="build the CVE, CWE and CAPEC tables (CSV + workbook) from "
    "cve_data.xlsx + the reference datasets; not part of `run`")
    _target_args(p); _datasets_arg(p)
    p.set_defaults(func=cmd_tables)
    p = sub.add_parser("validate",
                       help="build validation_paths.xlsx (paths + supporting CVEs + advisory refs, "
                            "cross-tactic repeats colour-coded); reads the existing workspace, does "
                            "not rebuild the trees; not part of `run`")
    _target_args(p)
    p.set_defaults(func=cmd_validate)
    p = sub.add_parser("insight",
                       help="plain-language findings from a finished run (terminal view plus "
                            "insights.md/.html/.json); reads the existing workspace; not part of `run`")
    _target_args(p)
    p.add_argument("--no-color", action="store_true", help="plain terminal output without colours")
    p.add_argument("--no-files", action="store_true", help="print only; do not write the report files")
    p.set_defaults(func=cmd_insight)
    p = sub.add_parser("reproduce",
                       help="fetch the CVEs and run every step (trees, tables, sensitivity, chain-share figures, insights) for the two case-study devices, or for the CPEs given")
    _datasets_arg(p); _nvd_args(p)
    p.add_argument("cpe", nargs="*", metavar="CPE",
                   help="CPE names to process (default: the two case-study devices)")
    p.add_argument("-o", "--output-dir", default="output",
                   help="folder holding one sub-folder per device (default: ./output)")
    p.add_argument("--skip-fetch", action="store_true",
                   help="reuse the CVE files already in each device's cve_data/ folder instead of querying NVD")
    p.add_argument("--no-png", action="store_true", help="skip PNG export of the trees")
    p.set_defaults(func=cmd_reproduce)

    p = sub.add_parser("doctor", help="check that Graphviz and the reference datasets are in place")
    _datasets_arg(p)
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("cti-figure",
                       help="layered CVE -> CWE -> CAPEC -> technique -> sub-technique -> tactic provenance "
                            "figure (PNG/PDF/SVG + node/edge CSVs); reads an existing workspace; not part of `run`")
    _target_args(p)
    p.add_argument("--max-cves", type=int, default=15, help="max CVE nodes drawn in row 1 (default 15)")
    p.add_argument("--figsize", type=float, nargs=2, metavar=("W", "H"), default=None,
                   help="figure size in inches (default: natural size of the layout)")
    p.add_argument("--dpi", type=int, default=300, help="PNG resolution (default 300)")
    p.add_argument("--formats", nargs="+", choices=("png", "pdf", "svg"), default=["png", "pdf", "svg"],
                   help="image formats to write (default: png pdf svg)")
    p.add_argument("--out", default=None, metavar="BASE",
                   help="output base path without extension (default: <workspace>/outputs/figures/cti_chain_figure)")
    p.add_argument("--title", default=None, help="figure title (default: derived from the workspace name)")
    p.add_argument("--no-expand-incomplete", action="store_true",
                   help="draw CVEs that stop early as end-capped nodes only, without their terminated branches")
    p.add_argument("--detailed", action="store_true", help="old large figure with titles, names and statistics")
    p.add_argument("--font-size", type=float, default=None, help="base font size (default 6.0 compact, 6.5 detailed)")
    p.add_argument("--no-tactic-labels", action="store_true", help="omit the tactic names")
    p.set_defaults(func=cmd_cti_figure)

    p = sub.add_parser("cti-summary",
                       help="two-panel summary of the CVE -> tactic chain (where it breaks, and which weaknesses feed "
                            "which tactics). Give one CPE for that device, or two CPEs to also get the combined "
                            "panel (a), first device on top; reads existing workspaces; not part of `run`")
    p.add_argument("cpe", nargs="*", metavar="CPE", help="one or two CPE 2.3 names")
    p.add_argument("-o", "--output-dir", default="output",
                   help="parent folder for run workspaces (default: ./output)")
    p.add_argument("-w", "--workspace", action="append", metavar="DIR",
                   help="use this exact workspace folder instead of <output-dir>/<device>; give it once or twice")
    p.add_argument("--formats", nargs="+", choices=("png", "pdf", "svg"), default=["pdf", "svg", "png"],
                   help="image formats to write (default: pdf svg png)")
    p.add_argument("--out", default=None, metavar="BASE",
                   help="output base path without extension. One device: default <workspace>/outputs/figures/"
                        "cti_chain_summary. Two devices: it names the combined figure, default "
                        "<output-dir>/figures/cti_chain_share_combined")
    p.add_argument("--combined-only", action="store_true",
                   help="two devices only: write the combined figure and skip the per-device figures")
    p.set_defaults(func=cmd_cti_summary)
    return parser


# commands
def _ws(args):
    return workspace_for(args.cpe, args.output_dir, args.workspace)


def _opts(args, **extra) -> RunOptions:
    api_key = getattr(args, "api_key", None) or os.environ.get("NVD_API_KEY")
    return RunOptions(
        datasets_dir=resolve_datasets_dir(getattr(args, "datasets_dir", None)),
        skip_fetch=getattr(args, "skip_fetch", False),
        api_key=api_key,
        delay=getattr(args, "delay", None),
        target_cve_ids=list(getattr(args, "target_cve", []) or []),
        dedup_mode=getattr(args, "dedup_mode", "per_tactic"),
        png=not getattr(args, "no_png", False),
        **extra)


def cmd_run(args) -> int:
    cpe = validate_cpe(args.cpe) if args.cpe else None
    if not cpe and not args.skip_fetch:
        raise Cve2atError("Give a CPE name, e.g.\n  cve2at run \"" + EXAMPLE_CPE + "\"")
    ws = _ws(args)
    return run_pipeline(cpe or "(existing workspace)", ws, _opts(args))


def cmd_fetch(args) -> int:
    cpe = validate_cpe(args.cpe) if args.cpe else None
    if not cpe:
        raise Cve2atError("fetch needs a CPE name.")
    stage_fetch(cpe, _ws(args), _opts(args))
    return 0


def cmd_tabulate(args) -> int:
    stage_tabulate(_ws(args))
    return 0


def cmd_merge(args) -> int:
    opts = _opts(args)
    check_reference_files(opts.datasets_dir)
    stage_merge(_ws(args), opts)
    return 0


def cmd_trees(args) -> int:
    check_graphviz()
    ws, opts = _ws(args), _opts(args)
    if not ws.compromise_dataset_xlsx.is_file():
        raise Cve2atError(f"'{ws.compromise_dataset_xlsx}' not found. Run the merge stage first.")
    ok = True
    if args.only in ("tactic", "both"):
        ok &= stage_tactic_trees(ws, opts)["validation_ok"]
    if args.only in ("comprehensive", "both"):
        ok &= stage_comprehensive_tree(ws, opts)["validation_ok"]
    return 0 if ok else 2

def cmd_sensitivity(args) -> int:
    from . import sensitivity as sens          # lazy: numpy/pandas only needed by this command
    ws = _ws(args)
    if not ws.compromise_dataset_xlsx.is_file():
        raise Cve2atError(f"'{ws.compromise_dataset_xlsx}' not found. Run the merge stage first.")
    kwargs = {"levels": tuple(args.levels)} if args.levels else {}
    try:
        res = sens.run_sensitivity(ws.compromise_dataset_xlsx, reps=args.reps, seed=args.seed,
                                   ci_method=args.ci_method, top_critical=args.top, **kwargs)
    except ValueError as e:
        raise Cve2atError(str(e))
    out_dir = ws.compromise_dataset_xlsx.parent
    df = res.to_frame()
    df.to_csv(out_dir / "sensitivity.csv", index=False)
    res.critical_frame().to_csv(out_dir / "sensitivity_critical_links.csv", index=False)

    console.section(f"Sensitivity: path retention, mean [95% CI]  (R={res.reps}, seed={res.seed}, "
                    f"CI={res.ci_method}, {res.n_leaves} paths)")
    if not res.n_leaves:
        console.warn("No complete chains in the dataset: every metric is undefined (NaN).")
    r = df[df["metric"] == "retention"].copy()
    r["cell"] = [f"{m:.3f} [{lo:.3f}, {hi:.3f}]" for m, lo, hi in zip(r["mean"], r["ci_lo"], r["ci_hi"])]
    table = r.pivot(index="link", columns="p", values="cell").reindex(list(res.link_types))
    for line in table.to_string().splitlines():
        console.info(line)
    chk = sens.verify_against_analytic(res, strict=False)
    console.info(f"Closed-form check: {int(chk['ok'].sum())}/{len(chk)} cells within 4 x SEM of the analytic mean.")
    console.info(f"Wrote {out_dir / 'sensitivity.csv'} and {out_dir / 'sensitivity_critical_links.csv'}")
    if args.convergence:
        conv = res.convergence_check()
        conv.to_csv(out_dir / "sensitivity_convergence.csv", index=False)
        for line in conv.groupby("R")[["sem", "abs_err"]].max().to_string().splitlines():
            console.info(line)
        console.info(f"Wrote {out_dir / 'sensitivity_convergence.csv'}")
    return 0 if chk["ok"].all() else 2

def cmd_tables(args) -> int:
    from . import tables                  # lazy: keeps `cve2at --help` snappy
    opts = _opts(args)
    check_reference_files(opts.datasets_dir)
    tables.build_tables(_ws(args), opts.datasets_dir)
    return 0

def cmd_validate(args) -> int:
    from . import validate_report      # lazy: keeps `cve2at --help` snappy
    ws = _ws(args)
    validate_report.build_validation_workbook(ws)
    return 0
def cmd_cti_figure(args) -> int:
    from . import cti_figure              # lazy: matplotlib is only needed by this command
    ws = _ws(args)
    if not ws.compromise_dataset_xlsx.is_file():
        raise Cve2atError(f"'{ws.compromise_dataset_xlsx}' not found. Run the merge stage first.")
    ws.figures_dir.mkdir(parents=True, exist_ok=True)
    cti_figure.generate_cti_chain_figure(
        ws.compromise_dataset_xlsx, args.out or ws.figures_dir / "cti_chain_figure",
        cve_table_path=ws.cve_xlsx, summary_path=ws.summary_json,
        max_cves=args.max_cves, figsize=tuple(args.figsize) if args.figsize else None, dpi=args.dpi,
        formats=tuple(args.formats), title=args.title, expand_incomplete=not args.no_expand_incomplete,
        compact=not args.detailed, font_size=args.font_size or (6.5 if args.detailed else 6.0),
        tactic_labels=not args.no_tactic_labels)
    return 0


def cmd_cti_summary(args) -> int:
    from . import cti_funnel_figure as cs     # lazy: matplotlib is only needed by this command
    if args.workspace:
        wss = [Workspace(Path(w)) for w in args.workspace]
    else:
        wss = [workspace_for(c, args.output_dir, None) for c in args.cpe]
    if not 1 <= len(wss) <= 2:
        raise ConfigError("Give one CPE (figure for that device) or two (both devices plus the combined figure, "
                          "first one on top).")
    if args.combined_only and len(wss) != 2:
        raise ConfigError("--combined-only needs two devices.")
    formats = tuple(args.formats)
    if not args.combined_only:
        for ws in wss:
            out = args.out if len(wss) == 1 else None
            for path in cs.generate_summary_figure(ws, out, formats=formats).values():
                console.info(f"Wrote {path}")
    if len(wss) == 2:
        for path in cs.generate_combined_figure(wss[0], wss[1], args.out, formats=formats).values():
            console.info(f"Wrote {path}")
    return 0


def cmd_insight(args) -> int:
    from . import insight                 # lazy: keeps `cve2at --help` snappy
    ws = _ws(args)
    if not ws.compromise_dataset_xlsx.is_file():
        raise Cve2atError(f"'{ws.compromise_dataset_xlsx}' not found. Run the merge stage first.")
    rep = insight.build_report(ws.compromise_dataset_xlsx, ws.summary_json, device=ws.root.name)
    print(insight.render_terminal(rep, color=False if args.no_color else None))
    if rep.empty:
        console.warn("No complete chains in the dataset: no insights to write.")
        return 0
    if not args.no_files:
        for path in insight.write_files(rep, ws.insights_dir):
            console.info(f"Wrote {path}")
    return 0


def cmd_reproduce(args) -> int:
    import json
    cpes = [validate_cpe(c) for c in args.cpe] if args.cpe else list(CASE_STUDY_CPES)
    common = ["-o", args.output_dir]
    datasets = ["-d", args.datasets_dir] if args.datasets_dir else []
    nvd = (["--api-key", args.api_key] if args.api_key else []) + \
          (["--delay", str(args.delay)] if args.delay is not None else [])
    run_extra = (["--no-png"] if args.no_png else []) + (["--skip-fetch"] if args.skip_fetch else nvd)
    steps = (
        ("run", lambda c: ["run", c, *common, *datasets, *run_extra]),
        ("tables", lambda c: ["tables", c, *common, *datasets]),
        ("sensitivity", lambda c: ["sensitivity", c, *common]),
        ("cti-figure", lambda c: ["cti-figure", c, *common]),
        ("cti-summary", lambda c: ["cti-summary", c, *common]),
        ("insight", lambda c: ["insight", c, *common, "--no-color"]),
    )
    parser = build_parser()
    failed, report = [], []
    for cpe in cpes:
        console.section(f"Device {cpe}")
        for name, make_argv in steps:
            console.step(name)
            sub_args = parser.parse_args(make_argv(cpe))
            try:
                code = sub_args.func(sub_args)
            except Cve2atError as e:
                console.warn(str(e))
                code = 1
            if code:
                failed.append(f"{name} ({cpe})")
        summary = workspace_for(cpe, args.output_dir, None).summary_json
        if summary.is_file():
            tree = json.loads(summary.read_text(encoding="utf-8"))["stages"]["comprehensive_tree"]
            report.append((cpe, tree["total_paths"], tree["total_nodes"]))

    if len(cpes) == 2:                    # both devices: the combined panel (a), first CPE on top
        console.section("Both devices")
        console.step("cti-summary (combined)")
        sub_args = parser.parse_args(["cti-summary", *cpes, *common, "--combined-only"])
        try:
            code = sub_args.func(sub_args)
        except Cve2atError as e:
            console.warn(str(e))
            code = 1
        if code:
            failed.append("cti-summary (combined)")

    console.section("Summary")
    for cpe, paths, nodes in report:
        console.info(f"{cpe}: {paths} attack paths, {nodes} tree nodes")
    for item in failed:
        console.warn(f"step failed: {item}")
    return 0 if not failed else 2


def cmd_doctor(args) -> int:
    problems = 0
    datasets = resolve_datasets_dir(args.datasets_dir)
    console.section("cve2at doctor")
    try:
        console.info(f"Graphviz dot : {check_graphviz()}")
    except Cve2atError as e:
        problems += 1
        console.warn(str(e))
    try:
        check_reference_files(datasets)
        console.info(f"Datasets     : OK ({datasets})")
    except Cve2atError as e:
        problems += 1
        console.warn(str(e))
    console.info("Everything looks good." if not problems else f"{problems} problem(s) found.")
    return 0 if not problems else 1


# entry point
def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0].lower().startswith("cpe:"):     # `cve2at "cpe:2.3:..."` == `cve2at run "cpe:2.3:..."`
        argv.insert(0, "run")

    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    try:
        return args.func(args)
    except Cve2atError as e:
        print(f"\nerror: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130