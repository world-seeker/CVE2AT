"""CTI chain figure, two panels, drawn only from the files a run already writes.

(a) Where the chain breaks. One bar per layer, left to right: CVE, CWE, CAPEC, technique, tactic.
    Each bar is split into the items that continue to the next layer (blue) and the items that
    stop, hatched by the missing link. The links between bars carry the relation names
    M_VW, M_WC, M_CK, M_KT (CVE-CWE, CWE-CAPEC, CAPEC-technique, technique-tactic). Bar height is the share of the layer;
    the absolute count is printed in the header (n=...).
(b) Which weaknesses feed which tactics. One row per tactic, one column per CWE that reaches a
    tactic, cell = number of tactic-level attack paths. The row and column sums are the path counts in tactic_summary.csv, so the two can be checked against each other.

Inputs (all inside the workspace written by `cve2at run`):
    cve_data.xlsx, device_compromise_dataset.xlsx, incomplete_chains.csv, run_summary.json

Commands:
    cve2at cti-summary "<CPE>"            two-panel figure for one device
    cve2at cti-summary "<CPE1>" "<CPE2>"  the same for both, plus the combined panel (a), first device on top
Both are also run by `cve2at reproduce`.
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from . import attack_tree_lib as L
from .config import Workspace
from .errors import Cve2atError, PipelineError

TEXT_W = 4.8                       # text width of the target template (inches); the figure is made at this size
FS = 6.4                           # body font (pt), no scaling afterwards
FS_SMALL = 5.8
BLUE = "#0072B2"
# Which link is missing is shown by a hatch pattern on a white fill, so the bars stay readable in print and
# in black and white. "Not reached" is a white bar with a dashed outline.
HATCH = {"cwe": "////", "capec": "xxxx", "technique": "....", "c": None, "x": None}
EDGE = "#333333"
N_ATTACK_TACTICS = 14

# Short CWE names for the column headers.
SHORT_CWE = {
    "CWE-74": "Injection", "CWE-125": "Out-of-\nbounds read", "CWE-200": "Info.\nexposure",
    "CWE-287": "Improper\nauth.", "CWE-290": "Spoofing\nauth. bypass",
    "CWE-306": "Missing\nauth.", "CWE-312": "Cleartext\nstorage",
    "CWE-319": "Cleartext\ntransmission", "CWE-330": "Weak\nrandomness",
    "CWE-538": "Info. in\nfile/dir.", "CWE-732": "Incorrect\npermissions",
    "CWE-798": "Hard-coded\ncredentials",
}


# data
def collect(ws: Workspace) -> dict:
    """Everything the figure shows, computed from the workspace files."""
    for f in (ws.compromise_dataset_xlsx, ws.cve_xlsx):
        if not f.is_file():
            raise Cve2atError(f"'{f}' not found. Run `cve2at run` for this device first.")
    df = L.load_dataset(str(ws.compromise_dataset_xlsx))
    kc = L.resolve_key_columns(df)
    P, _ = L.build_curated_relation(df, kc)
    if P.empty:
        raise PipelineError(f"{ws.root.name}: no complete CVE-to-tactic chain, nothing to draw.")
    tactics = L.mitre_order(P["tactics"].unique())
    leaf = L.build_leaf_index(P, kc, tactics, mode="per_tactic")
    inc_file = ws.root / "incomplete_chains.csv"          # absent when every chain was complete
    inc = pd.read_csv(inc_file) if inc_file.is_file() else pd.DataFrame(columns=["CVE ID", "chain_break", "CWE ID"])
    all_cves = pd.read_excel(ws.cve_xlsx)["CVE ID"].astype(str).tolist()

    # CVE layer: furthest link reached
    in_P, in_df = set(P["CVE ID"]), set(df["CVE ID"])
    only_no_cwe = {c for c, g in inc.groupby("CVE ID") if set(g["chain_break"]) == {"NO_CWE"}}
    cve = {"continue": 0, "cwe": 0, "capec": 0, "technique": 0}
    for c in all_cves:
        if c in in_P:
            cve["continue"] += 1
        elif c in in_df:
            cve["technique"] += 1
        elif c in only_no_cwe:
            cve["cwe"] += 1
        else:
            cve["capec"] += 1

    # CWE layer: every CWE that a usable CVE points to
    inc_cwes = {f"CWE-{int(x)}" for x in inc["CWE ID"].dropna()}
    cwe_all = set(df["CWE ID"]) | inc_cwes
    cwe_P, cwe_df = set(P["CWE ID"]), set(df["CWE ID"])
    cwe = {"continue": len(cwe_P), "technique": len(cwe_df - cwe_P), "capec": len(cwe_all - cwe_df)}

    # CAPEC and technique layers
    capec = {"continue": P["CAPEC_ID"].nunique(), "technique": df["CAPEC_ID"].nunique() - P["CAPEC_ID"].nunique()}
    pt = kc["parent_technique_key"]
    tech_df = df.loc[df[pt] != "", pt].nunique()
    tech = {"continue": P[pt].nunique(), "tactic": tech_df - P[pt].nunique()}
    n_sub = int(P["subtechnique"].replace("", pd.NA).nunique()) if "subtechnique" in P.columns else 0

    # matrix
    rows = {}
    for t, by_cwe in leaf.leaves_by_tactic.items():
        for w, recs in by_cwe.items():
            rows.setdefault(w, {})[t] = len(recs)
    order = sorted(rows, key=lambda w: (-sum(rows[w].values()), w))
    cves_of = {w: P.loc[P["CWE ID"] == w, "CVE ID"].nunique() for w in order}

    summary = json.loads(ws.summary_json.read_text()) if ws.summary_json.is_file() else {}
    return dict(cve=cve, cwe=cwe, capec=capec, tech=tech, n_sub=n_sub,
                n_cve=len(all_cves), n_cwe=len(cwe_all), n_capec=df["CAPEC_ID"].nunique(),
                n_tech=int(tech_df), n_tactic=N_ATTACK_TACTICS, n_reached=len(tactics),
                tactics=tactics, order=order, rows=rows, cves_of=cves_of,
                n_paths=L.total_paths(leaf), n_cves_P=len(in_P),
                device=summary.get("cpe", ws.root.name))


def checks(d: dict) -> list:
    """Internal consistency checks; the figure is not written if one fails."""
    out = []
    out.append(("CVE bar adds up", sum(d["cve"].values()) == d["n_cve"]))
    out.append(("CWE bar adds up", sum(d["cwe"].values()) == d["n_cwe"]))
    out.append(("CAPEC bar adds up", sum(d["capec"].values()) == d["n_capec"]))
    out.append(("technique bar adds up", sum(d["tech"].values()) == d["n_tech"]))
    out.append(("matrix sums to path count", sum(sum(r.values()) for r in d["rows"].values()) == d["n_paths"]))
    out.append(("CVEs reaching a tactic match", d["cve"]["continue"] == d["n_cves_P"]))
    out.append(("CWE rows match CWE bar", len(d["order"]) == d["cwe"]["continue"]))
    return out


# drawing
def _seg_text(ax, x, y0, y1, w, n, fs, color, backing=False):
    box = dict(boxstyle="square,pad=0.12", fc="white", ec="none") if backing else None
    ax.text(x, (y0 + y1) / 2, str(n), ha="center", va="center", fontsize=fs, color=color, zorder=5, bbox=box)


def _bar(ax, x, ybot, h, w, parts):
    """parts: list of (count, colour, line style or None, key); key picks the hatch. Stacked from the top."""
    from matplotlib.patches import Rectangle
    total = sum(p[0] for p in parts)
    y = ybot + h
    placed = []
    for n, colour, ls, key in parts:
        if n <= 0:
            continue
        seg = h * n / total
        ax.add_patch(Rectangle((x - w / 2, y - seg), w, seg, facecolor=colour, edgecolor=EDGE, linewidth=0.5,
                               linestyle=ls or "-", hatch=HATCH.get(key), zorder=3))
        placed.append((n, y - seg, y, colour, key))
        y -= seg
    return placed


def _bar_parts(d: dict) -> list:
    """Stacked parts of the five bars: (count, colour, line style, key); 'continues' first."""
    return [
        [(d["cve"]["continue"], BLUE, None, "c"), (d["cve"]["cwe"], "#ffffff", None, "cwe"),
         (d["cve"]["capec"], "#ffffff", None, "capec"), (d["cve"]["technique"], "#ffffff", None, "technique")],
        [(d["cwe"]["continue"], BLUE, None, "c"), (d["cwe"]["capec"], "#ffffff", None, "capec"),
         (d["cwe"]["technique"], "#ffffff", None, "technique")],
        [(d["capec"]["continue"], BLUE, None, "c"), (d["capec"]["technique"], "#ffffff", None, "technique")],
        [(d["tech"]["continue"], BLUE, None, "c"), (d["tech"]["tactic"], "#ffffff", "--", "x")],
        [(d["n_reached"], BLUE, None, "c"), (d["n_tactic"] - d["n_reached"], "#ffffff", "--", "x")],
    ]


def _draw_bars(ax, xs, y_bar0, h, bw, d):
    """The five stacked bars with their counts; counts of thin segments go to the right with a leader."""
    for x, parts in zip(xs, _bar_parts(d)):
        placed = _bar(ax, x, y_bar0, h, bw, parts)
        outside = []
        for n, ya, yb, colour, key in placed:
            if (yb - ya) >= 0.115:
                _seg_text(ax, x, ya, yb, bw, n, FS, "white" if colour == BLUE else "black",
                          backing=HATCH.get(key) is not None)
            else:
                outside.append(((ya + yb) / 2, n))
        last = -9
        for ym, n in sorted(outside):
            yl = max(ym, last + 0.11)
            ax.plot([x + bw / 2, x + bw / 2 + 0.06], [ym, yl], color="#555555", lw=0.4, zorder=4)
            ax.text(x + bw / 2 + 0.08, yl, str(n), ha="left", va="center", fontsize=FS_SMALL)
            last = yl


def _draw_legend(ax, ly):
    from matplotlib.patches import Rectangle
    items = [(BLUE, None, None, "continues"), ("#ffffff", None, HATCH["cwe"], "no CWE"),
             ("#ffffff", None, HATCH["capec"], "no CAPEC"), ("#ffffff", None, HATCH["technique"], "no technique"),
             ("#ffffff", "--", None, "not reached")]
    lx = 0.06
    widths = [0.62, 0.55, 0.62, 0.78, 0.72]
    for (c, ls, h, t), wd in zip(items, widths):
        ax.add_patch(Rectangle((lx, ly - 0.045), 0.13, 0.09, facecolor=c, edgecolor=EDGE, linewidth=0.5,
                               linestyle=ls or "-", hatch=h))
        ax.text(lx + 0.17, ly, t, fontsize=FS_SMALL, va="center")
        lx += 0.17 + wd


def _draw_relations(ax, xs, y_bar0):
    rel = [r"$M_{VW}$", r"$M_{WC}$", r"$M_{CK}$", r"$M_{KT}$"]
    for i, r in enumerate(rel):
        xm = (xs[i] + xs[i + 1]) / 2
        ax.annotate("", xy=(xm + 0.16, y_bar0 - 0.05), xytext=(xm - 0.16, y_bar0 - 0.05),
                    arrowprops=dict(arrowstyle="-|>", lw=0.5, color="#555555", mutation_scale=5))
        ax.text(xm, y_bar0 - 0.13, r, ha="center", va="center", fontsize=FS_SMALL)


def draw(d: dict, out_base: Path, title: str = "", formats=("pdf", "svg", "png")) -> dict:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.patches import Rectangle

    plt.rcParams.update({"font.family": "DejaVu Sans", "svg.fonttype": "none", "pdf.fonttype": 42,
                         "hatch.linewidth": 0.4})
    ntac_rows = len(d["tactics"])

    # vertical plan (inches, measured from the top)
    pa_head, pa_bar, pa_leg = 0.56, 1.05, 0.28
    pb_head, row_h, pb_foot = 0.38, 0.185, 0.42
    gap = 0.18
    H = 0.16 + pa_head + pa_bar + pa_leg + gap + 0.16 + pb_head + ntac_rows * row_h + pb_foot + 0.04
    fig = plt.figure(figsize=(TEXT_W, H))
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, TEXT_W)
    ax.set_ylim(H, 0)                       # y grows downward
    ax.axis("off")

    # panel (a)
    y = 0.02
    ax.text(0.02, y + 0.09, "(a)", fontsize=FS + 0.6, fontweight="bold", va="center")
    ax.text(0.22, y + 0.09, "Share of each layer that continues to the next", fontsize=FS, va="center")
    y_head = y + 0.2
    y_bar0 = y_head + pa_head
    cx0, dx, bw = 0.52, 0.94, 0.42
    xs = [cx0 + i * dx for i in range(5)]
    stages = [
        ("CVE", d["n_cve"], ""), ("CWE", d["n_cwe"], ""), ("CAPEC", d["n_capec"], ""),
        ("Technique", d["n_tech"], f"+{d['n_sub']} sub-tech." if d["n_sub"] else ""),
        ("Tactic", d["n_tactic"], ""),
    ]
    for x, (name, n, extra) in zip(xs, stages):
        ax.text(x, y_head + 0.06, name, ha="center", va="center", fontsize=FS, fontweight="bold")
        ax.text(x, y_head + 0.20, f"n={n}", ha="center", va="center", fontsize=FS_SMALL)
        if extra:
            ax.text(x, y_head + 0.32, extra, ha="center", va="center", fontsize=FS_SMALL - 0.4, color="#444444")
    _draw_relations(ax, xs, y_bar0)
    _draw_bars(ax, xs, y_bar0, pa_bar, bw, d)
    ly = y_bar0 + pa_bar + 0.17
    _draw_legend(ax, ly)

    # panel (b): rows = tactics in ATT&CK order, columns = weaknesses (most paths first)
    yb0 = ly + 0.17 + gap
    ax.plot([0.02, TEXT_W - 0.02], [yb0 - 0.04, yb0 - 0.04], color="#bbbbbb", lw=0.5)
    ax.text(0.02, yb0 + 0.09, "(b)", fontsize=FS + 0.6, fontweight="bold", va="center")
    ax.text(0.22, yb0 + 0.09, "Attack paths by tactic and weakness", fontsize=FS, va="center")
    ncwe, ntac = len(d["order"]), len(d["tactics"])
    gx0, right = 1.02, 0.46
    cw = (TEXT_W - 0.04 - right - gx0) / ncwe
    y_mat0 = yb0 + 0.16 + pb_head
    xr = gx0 + ncwe * cw + right / 2                     # centre of the Paths column
    for j, w in enumerate(d["order"]):
        xc = gx0 + (j + 0.5) * cw
        ax.text(xc, y_mat0 - 0.20, w.replace("CWE-", ""), ha="center", va="bottom", fontsize=FS, fontweight="bold")
        ax.text(xc, y_mat0 - 0.04, SHORT_CWE.get(w, ""), ha="center", va="bottom", fontsize=FS_SMALL - 0.3,
                linespacing=0.95)
    ax.text(0.02, y_mat0 - 0.04, "Tactic", fontsize=FS_SMALL, fontweight="bold", va="bottom")
    ax.text(xr, y_mat0 - 0.04, "Paths", fontsize=FS_SMALL, fontweight="bold", va="bottom", ha="center")
    ax.text(gx0 - 0.04, y_mat0 - 0.20, "CWE", fontsize=FS_SMALL, fontweight="bold", va="bottom", ha="right")
    vmax = max(max(r.values()) for r in d["rows"].values())
    cmap = matplotlib.colormaps["Blues"]
    for i, t in enumerate(d["tactics"]):
        yy = y_mat0 + i * row_h
        ax.text(0.02, yy + row_h / 2, t, fontsize=FS, va="center")
        for j, w in enumerate(d["order"]):
            n = d["rows"][w].get(t, 0)
            xx = gx0 + j * cw
            if n:
                col = cmap(0.12 + 0.78 * (n / vmax) ** 0.8)
                ax.add_patch(Rectangle((xx + 0.015, yy + 0.015), cw - 0.03, row_h - 0.03, facecolor=col,
                                       edgecolor="none", zorder=2))
                lum = 0.299 * col[0] + 0.587 * col[1] + 0.114 * col[2]
                ax.text(xx + cw / 2, yy + row_h / 2, str(n), ha="center", va="center", fontsize=FS,
                        color="white" if lum < 0.55 else "black", zorder=3)
            else:
                ax.text(xx + cw / 2, yy + row_h / 2, "·", ha="center", va="center", fontsize=FS, color="#aaaaaa")
        ax.text(xr, yy + row_h / 2, str(sum(d["rows"][w].get(t, 0) for w in d["order"])), fontsize=FS,
                va="center", ha="center", fontweight="bold")
    yt = y_mat0 + ntac * row_h
    ax.plot([0.02, TEXT_W - 0.02], [yt + 0.01, yt + 0.01], color=EDGE, lw=0.5)
    ax.text(0.02, yt + 0.12, "Paths", fontsize=FS, fontweight="bold", va="center")
    ax.text(0.02, yt + 0.30, "CVEs", fontsize=FS, va="center")
    for j, w in enumerate(d["order"]):
        xc = gx0 + (j + 0.5) * cw
        ax.text(xc, yt + 0.12, str(sum(d["rows"][w].values())), ha="center", va="center", fontsize=FS,
                fontweight="bold")
        ax.text(xc, yt + 0.30, str(d["cves_of"][w]), ha="center", va="center", fontsize=FS)
    ax.text(xr, yt + 0.12, str(d["n_paths"]), fontsize=FS, va="center", ha="center", fontweight="bold")
    ax.text(xr, yt + 0.30, str(d["n_cves_P"]), fontsize=FS, va="center", ha="center")

    return _save(fig, out_base, formats)


def draw_combined(top: dict, bottom: dict, labels, out_base: Path, formats=("pdf", "svg", "png")) -> dict:
    """Panel (a) of both devices in one figure: `top` above `bottom`, one shared header and legend."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update({"font.family": "DejaVu Sans", "svg.fonttype": "none", "pdf.fonttype": 42,
                         "hatch.linewidth": 0.4})
    bar_h, block_h = 0.82, 1.30
    head_h = 0.36
    H = head_h + 2 * block_h + 0.40
    fig = plt.figure(figsize=(TEXT_W, H))
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, TEXT_W)
    ax.set_ylim(H, 0)
    ax.axis("off")
    cx0, dx, bw = 0.52, 0.94, 0.42
    xs = [cx0 + i * dx for i in range(5)]
    for x, name in zip(xs, ("CVE", "CWE", "CAPEC", "Technique", "Tactic")):
        ax.text(x, 0.10, name, ha="center", va="center", fontsize=FS, fontweight="bold")
    for k, (d, lab) in enumerate(((top, labels[0]), (bottom, labels[1]))):
        y0 = head_h + k * block_h                       # top of this block
        ax.plot([0.02, TEXT_W - 0.02], [y0 - 0.02, y0 - 0.02], color="#bbbbbb", lw=0.5)
        ax.text(0.02, y0 + 0.07, lab, fontsize=FS + 0.6, fontweight="bold", va="center")
        ns = [d["n_cve"], d["n_cwe"], d["n_capec"], d["n_tech"], d["n_tactic"]]
        for x, n in zip(xs, ns):
            ax.text(x, y0 + 0.07, f"n={n}", ha="center", va="center", fontsize=FS_SMALL)
        y_bar0 = y0 + 0.40
        _draw_relations(ax, xs, y_bar0)
        _draw_bars(ax, xs, y_bar0, bar_h, bw, d)
    _draw_legend(ax, head_h + 2 * block_h + 0.17)
    return _save(fig, out_base, formats)


def _save(fig, out_base: Path, formats) -> dict:
    import matplotlib.pyplot as plt
    out_base = Path(out_base)
    out_base.parent.mkdir(parents=True, exist_ok=True)
    files = {}
    for ext in formats:
        p = out_base.with_suffix("." + ext)
        fig.savefig(p, dpi=300) if ext == "png" else fig.savefig(p)
        files[ext] = p
    plt.close(fig)
    return files


# entry points used by the CLI
def device_label(ws: Workspace) -> str:
    n = ws.root.name.lower()
    return "SSIP" if "baxter" in n else "M580" if "m580" in n else ws.root.name


def _checked(ws: Workspace) -> dict:
    d = collect(ws)
    bad = [name for name, ok in checks(d) if not ok]
    if bad:
        raise PipelineError(f"{ws.root.name}: summary figure not drawn, failed checks: " + ", ".join(bad))
    return d


def generate_summary_figure(ws: Workspace, out_base: Path | None = None, formats=("pdf", "svg", "png")) -> dict:
    """Two-panel figure for one device -> {ext: path}. Default base: <workspace>/outputs/figures/cti_chain_summary."""
    return draw(_checked(ws), Path(out_base) if out_base else ws.figures_dir / "cti_chain_summary", formats=formats)


def generate_combined_figure(top: Workspace, bottom: Workspace, out_base: Path | None = None, labels=None,
                             formats=("pdf", "svg", "png")) -> dict:
    """Panel (a) of two devices in one figure, `top` above `bottom` -> {ext: path}."""
    out_base = Path(out_base) if out_base else top.root.parent / "figures" / "cti_chain_share_combined"
    labels = labels or (device_label(top), device_label(bottom))
    return draw_combined(_checked(top), _checked(bottom), labels, out_base, formats=formats)
