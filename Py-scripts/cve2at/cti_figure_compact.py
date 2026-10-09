"""Compact CTI provenance figure, laid out for print.

What the figure encodes
  * one row per layer (CVE, CWE, CAPEC, technique, sub-technique, tactic); the shaded left panel gives every
    row its name and two numerals, "total -> carried forward" (a CVE row of "40 -> 11" means 40 CVEs fetched,
    11 on a complete chain to a tactic). The nodes drawn are only a sample (--max-cves)
  * every link is coloured by the CWE it descends from (grey = shared by several CWEs); all links and glyphs
    have the same size
  * dashed grey link = a relation that never completes the chain ("missing link"); the end cap under a hollow
    node = "chain ends"
  * labels are horizontal, set in a serif face, each on a small white tag so no link runs through the text:
    every coloured CWE, every tactic (names wrapped on two lines) and only the few most important nodes of
    the technique / sub-technique rows (LABEL_LIMIT). CAPEC nodes carry no label (there are too many to print
    legibly); every ID is in the *_nodes.csv
  * a row that has more entries in the data than are drawn ends in "..." (aligned with its nodes); the legend
    (link types, chain end, "...") fits on one line

Layout: node order and crossing reduction come from cti_figure._layout. Here the CWE row and the tactic row
are then spread at equal distances across the figure, the other rows are pulled towards them (order of every
row preserved, so no new crossings) and everything is packed as tightly as the glyphs and the labels allow.

Tip: HIGHLIGHT_CVE = "CVE-xxxx-yyyy" draws only that CVE's chain in colour (rest fades to grey).
"""
from __future__ import annotations

from math import sqrt
from pathlib import Path

from . import cti_figure as cf
from . import console

SHORT_TITLES = ("CVE", "CWE", "CAPEC", "Technique", "Sub-tech.", "Tactic")
_SHAPE = {"cve": "circle", "cwe": "square", "capec": "diamond", "tech": "triangle",
          "sub": "hexagon", "tactic": "hexagon", "stub": "square"}
_SHAPE_W = {"circle": 2.0, "square": 1.9, "diamond": 2.6, "triangle": 2.6, "pentagon": 2.3, "hexagon": 2.4}
_BOTTOM = {"cve": 1.0, "cwe": 0.9, "capec": 1.3, "tech": 0.65, "sub": 1.2, "stub": 0.9}   # glyph extent below its centre / r
_TONE = {"cve": "#111111", "capec": "#a8a8a8", "tech": "#2b2b2b", "sub": "#ffffff",
         "tactic": "#ffffff", "cwe": "#ffffff"}
_CWE_COLORS = ("#0072B2", "#D55E00", "#009E73", "#CC79A7", "#E69F00", "#56B4E9",
               "#6A3D9A", "#8C564B", "#117733")                 # colour-blind-safe
_NEUTRAL = "#6f6f6f"          # link shared by several CWEs
_FADED = "#d2d2d2"
_R = 0.045                    # base glyph radius (inches, design units)
_RMIN, _RMAX = 1.0, 1.0       # glyph size is uniform ...
TACTIC_SCALE = 1.5            # ... except the tactic glyph, which is drawn larger
MIN_FS = 6.0                  # smallest font after scaling (pt)
MIN_LW = 0.5                  # thinnest line after scaling (pt)
TEXT_W = 4.8                  # text width of the target template (in)
HUB_DEGREE = 3                # a technique / sub-technique needs >= this many links to be labelled
LABEL_LIMIT = {"capec": 0, "tech": 2, "sub": 2}   # most labels of the "most important" nodes per row (0: none)
STUB_MIN_LABEL = 3            # "+n" labels of dead-end stubs, printed only when LABEL_STUBS is True
LABEL_STUBS = False           # the end cap alone says "chain ends"; True also prints the "+n" count
LABEL_CVES = False            # print CVE IDs above row 1 (the highlighted CVE is always printed)
ID_PREFIX = True              # label IDs as "CWE-287" / "CAPEC-21" (False: bare numbers)
HIGHLIGHT_CVE = None          # e.g. "CVE-2020-12041"
PACK_GAP = 0.02               # clear space between neighbouring glyphs (inches)
FONT_FAMILY = ("Times New Roman", "Liberation Serif", "Nimbus Roman", "FreeSerif", "DejaVu Serif")
ID_FS = 1.2                   # ID, tactic and legend text size, times the base font
LEG_FS = 1.15                 # legend text size, times the base font
HEAD_FS = 1.9                 # row title size, times the base font
NUM_FS = 1.6                  # row numerals size, times the base font
HEAD_H = 0.34                 # height of the row header block (inches); sets the minimum row pitch
HEAD_GAP = 0.08               # clear space between the title and the numerals (inches)
HEAD_X0 = 0.10                # left edge of the row header text (inches)
HEAD_BAR = False              # also draw the carried/total bar under the numerals
LABEL_LEVELS = 2              # a label that must be drawn (CWE, CVE ID, ...) may drop up to this many lines to avoid a neighbour
LEVEL_STEP = 1.5              # distance between two label lines, times the text line height
LABEL_SIDE = 0.0              # a label that cannot be centred ends / starts this far past its node (inches)
LABEL_PAD = 0.06              # least clear space between two labels (inches)
HUB_PAD = 0.14                # least clear space between two "most important node" labels (inches)
LABEL_BOX = 0.14              # white tag behind a label: padding as a fraction of the font size (0: no tag)
CELL_PAD = 0.08               # clear space between two labels of an evenly spaced row (CWE, tactic) (inches)
ROW_GAP = 0.36                # least clear space between two rows of nodes (inches)
EDGE_MARGIN = 0.20            # clear space between the left panel and the first node (inches)
CVE_STEP = 0.35               # most distance between a hollow CVE and the node before it in row 1 (inches)
MORE_R = 0.019                # radius of one dot of a "..." (inches)
MORE_STEP = 0.060             # distance between two dots of a "..." (inches)
MORE_GAP = 0.07               # clear space between the last node of a row and its "..." (inches)

_LEGEND = [("edge", "chain", "", "Origin CWE"),
           ("edge", "shared", "", "Shared"),
           ("edge", "missing", "", "Missing link"),
           ("cap", "", "", "Chain ends"),
           ("more", "", "", "More entries")]


# text measuring (same serif face as the drawing)
_FONT = None


def _font():
    """First installed face of FONT_FAMILY (DejaVu Serif ships with matplotlib, so there is always one)."""
    global _FONT
    if _FONT is None:
        from matplotlib.font_manager import FontProperties, findfont
        _FONT = "DejaVu Serif"
        for name in FONT_FAMILY:
            try:
                findfont(FontProperties(family=name), fallback_to_default=False)
            except ValueError:
                continue
            _FONT = name
            break
    return _FONT


def _tw(text, size, bold=False):
    """Width in inches of `text` set at `size` pt."""
    from matplotlib.font_manager import FontProperties
    from matplotlib.textpath import TextPath
    if not text:
        return 0.0
    fp = FontProperties(family=_font(), weight="bold" if bold else "normal")
    return TextPath((0, 0), text, size=size, prop=fp).get_extents().width / 72.0


def _lh(size):
    """Line height in inches of text set at `size` pt."""
    return 1.2 * size / 72.0


def _block(depth, lh):
    """Height of `depth` label lines."""
    return 0.0 if depth <= 0 else lh + (depth - 1) * LEVEL_STEP * lh


def _wrap(label):
    """Tactic name on one or two balanced lines."""
    words = label.split()
    if len(words) < 2:
        return [label]
    best = None
    for i in range(1, len(words)):
        a, b = " ".join(words[:i]), " ".join(words[i:])
        if best is None or max(len(a), len(b)) < best[0]:
            best = (max(len(a), len(b)), [a, b])
    return best[1]


# labels, flow, colours
def _short(n):
    k, key = n["kind"], str(n["key"])
    if k == "cwe":
        return key if ID_PREFIX else key.replace("CWE-", "")
    if k == "capec":
        return key if ID_PREFIX else key.replace("CAPEC-", "")
    if k == "cve":
        return key.replace("CVE-", "")
    if k == "tactic":
        return n["label"]
    if k == "stub":
        return n["label"].split()[0]
    return key


def _degrees(m):
    deg = {}
    for (u, v), e in m.edges.items():
        if e["kind"] == "terminated":
            continue
        for q in (u, v):
            deg[q] = deg.get(q, 0) + 1
    return deg


def _flow(m):
    """nid -> number of curated chains through the node (max of in-flow and out-flow, dummies excluded)."""
    fin, fout = {}, {}
    for (u, v), e in m.edges.items():
        if e["kind"] == "terminated":
            continue
        fout[u] = fout.get(u, 0) + e["support"]
        fin[v] = fin.get(v, 0) + e["support"]
    return {n: max(fin.get(n, 0), fout.get(n, 0)) for n in m.nodes}


def _radii(m):
    flow = _flow(m)
    top = {}
    for nid, n in m.nodes.items():
        if n["kind"] not in ("dummy", "stub"):
            top[n["layer"]] = max(top.get(n["layer"], 0), flow.get(nid, 0))
    r = {}
    for nid, n in m.nodes.items():
        if n["kind"] == "dummy":
            r[nid] = 0.0
        elif n["style"] != "chain" or n["kind"] == "stub":
            r[nid] = _R
        else:
            share = flow.get(nid, 0) / max(top.get(n["layer"], 1), 1)
            r[nid] = _R * (_RMIN + (_RMAX - _RMIN) * sqrt(min(share, 1.0)))
        if n["kind"] == "tactic":
            r[nid] = _R * TACTIC_SCALE
    return r


def _find_spot(xc, w, placed, maxlev, xmin, sides=True, pad=LABEL_PAD):
    """Free place for a label of width w under a node at xc: centred on the first line, else (sides=True) hanging
    to the left of the node (the text ends at it), else to the right of it (the text starts at it); then the same
    one line further out, and so on up to maxlev. None if all places are taken."""
    spots = (("center", xc - w / 2), ("right", xc + LABEL_SIDE - w), ("left", xc - LABEL_SIDE))
    for lev in range(maxlev + 1):
        for ha, x0 in spots if sides else spots[:1]:
            if x0 < xmin:
                continue
            x1 = x0 + w
            if any(l == lev and x0 < b1 + pad and a0 < x1 + pad for a0, b1, l in placed):
                continue
            xt = xc if ha == "center" else (xc + LABEL_SIDE if ha == "right" else xc - LABEL_SIDE)
            return ha, xt, lev, x0, x1
    return None


def _place_labels(m, lay, font_size, max_labels):
    """Choose and place the horizontal labels (one line under the node). Returns (labels, place, depth, x_right):
    labels: nid -> text, place: nid -> (ha, x of the text anchor, line number), depth: layer -> number of label
    lines the layer needs below it (layer 0: above it), x_right: right-most label edge.
    Labelled: every coloured CWE, plus the LABEL_LIMIT[kind] most important nodes of the technique / sub-technique /
    CAPEC rows (importance = chains through the node, then number of links)."""
    nodes, x = m.nodes, lay.x
    size = font_size * ID_FS
    deg = _degrees(m)
    flow = _flow(m)
    labels, place = {}, {}
    depth = [0] * len(cf.LAYERS)
    x_right = 0.0
    for li, row in enumerate(lay.order):
        if li == len(cf.LAYERS) - 1:                          # tactic names are handled with the tactic row
            continue
        must, hubs = [], []
        for nid in row:
            n = nodes[nid]
            k = n["kind"]
            if k == "cve" and (LABEL_CVES or (HIGHLIGHT_CVE and n["key"] == HIGHLIGHT_CVE)):
                must.append(nid)
            elif k == "cwe" and n["style"] == "chain":
                must.append(nid)
            elif k == "stub" and LABEL_STUBS and len(n.get("members", [])) >= STUB_MIN_LABEL:
                must.append(nid)
            elif k in ("capec", "tech", "sub") and n["style"] == "chain" and deg.get(nid, 0) >= HUB_DEGREE:
                hubs.append(nid)
        hubs.sort(key=lambda q: (-flow.get(q, 0), -deg[q], cf._nat(q)))
        limit = {"capec": 0, "tech": 0, "sub": 0}
        limit.update(LABEL_LIMIT)
        placed, n_hub = [], 0
        for nid, mandatory in [(q, True) for q in must] + [(q, False) for q in hubs]:
            if not mandatory:
                cap = limit.get(nodes[nid]["kind"], 0) if max_labels is None else max_labels
                if n_hub >= cap:
                    break
            text = _short(nodes[nid])
            w = _tw(text, size) + 0.02
            # a hub label stays centred under its node: if it does not fit there, the next node is tried
            spot = (_find_spot(x[nid], w, placed, LABEL_LEVELS, lay.label_xmin) if mandatory else
                    _find_spot(x[nid], w, placed, 0, lay.label_xmin, sides=False, pad=HUB_PAD))
            if spot is None:
                if not mandatory:
                    continue
                spot = ("center", x[nid], 0, x[nid] - w / 2, x[nid] + w / 2)    # nothing free: keep it anyway
            ha, xt, lev, x0, x1 = spot
            placed.append((x0, x1, lev))
            labels[nid] = text
            place[nid] = (ha, xt, lev)
            depth[li] = max(depth[li], lev + 1)
            x_right = max(x_right, x1)
            if not mandatory:
                n_hub += 1
    return labels, place, depth, x_right


def _edge_colours(m):
    nodes = m.nodes
    cwes = [n for n, d in nodes.items() if d["kind"] == "cwe" and d["style"] == "chain"]
    deg = _degrees(m)
    cwes.sort(key=lambda q: (-deg.get(q, 0), cf._nat(q)))
    colour = {c: _CWE_COLORS[i] for i, c in enumerate(cwes) if i < len(_CWE_COLORS)}
    up = {n: set() for n in nodes}
    for c in cwes:
        up[c].add(c)
    live = [(u, v) for (u, v), e in m.edges.items() if e["kind"] != "terminated"]
    for li in range(2, 6):
        for (u, v) in live:
            if nodes[v]["layer"] == li:
                up[v] |= up[u]
    for _ in range(2):
        for (u, v) in live:
            if nodes[v]["kind"] != "cve":
                up[v] |= up[u]
    out = {}
    for (u, v) in live:
        if nodes[u]["kind"] == "cve":
            owner = {v} if nodes[v]["kind"] == "cwe" else set()
        else:
            owner = up[u]
        out[(u, v)] = colour.get(next(iter(owner))) if len(owner) == 1 else None
    return out, colour


def _descendants(m, start):
    seen, stack = {start}, [start]
    while stack:
        a = stack.pop()
        for (u, v), e in m.edges.items():
            if u == a and e["kind"] != "terminated" and v not in seen:
                seen.add(v)
                stack.append(v)
    return seen


def _edge_lw(support):
    """Printed width (pt, before scaling) of a link carrying `support` chains."""
    return 1.1                                    # uniform: width carries no information


# horizontal packing
def _pack_x(m, lay, radius, min_w=None):
    """Squeeze the columns together. Every node keeps its place in the left-to-right order of its
    row and the global x-order of all nodes is preserved (no new crossings); gaps that no row needs
    are removed. Longest-path solution of: q[j] - q[i] >= needed spacing for neighbours i, j.
    min_w: nid -> least width the node must be given (the width of a tactic name)."""
    nodes, x = m.nodes, lay.x
    wid = {}
    for nid, n in nodes.items():
        wid[nid] = 0.03 if n["kind"] == "dummy" else _SHAPE_W[_SHAPE[n["kind"]]] * radius[nid]
        if min_w and nid in min_w:
            wid[nid] = max(wid[nid], min_w[nid])
    xs = sorted({round(v, 6) for v in x.values()})
    idx = {v: i for i, v in enumerate(xs)}
    need = {}
    for row in lay.order:
        for a, b in zip(row, row[1:]):
            i, j = idx[round(x[a], 6)], idx[round(x[b], 6)]
            if i < j:
                need.setdefault(j, []).append((i, (wid[a] + wid[b]) / 2 + PACK_GAP))
    q = [0.0] * len(xs)
    for k in range(1, len(xs)):
        q[k] = q[k - 1]
        for i, sep in need.get(k, ()):
            q[k] = max(q[k], q[i] + sep)
    new = {nid: q[idx[round(x[nid], 6)]] for nid in x}
    return new, wid


def _spread_x(m, lay, x0, wid, cell_min, even_rows=(1, 5), ref_rows=None, bound_rows=(0, 2), sweeps=40,
              rounds=12):
    """Spread the CWE row and the tactic row at equal distances, then pull the other rows towards them.

    Every row in even_rows gets equal cells (cell >= cell_min[row], the width of its widest label) across the
    span of its reference rows (ref_rows[row]: the rows it has to look in line with, default all the other rows).
    Every other row is moved towards the mean x of the nodes it is linked to, keeping its left-to-right order and
    the least spacing of its glyphs (weighted isotonic regression, as in cti_figure._layout), so no crossing is
    added. The spans are re-measured after each round, so the figure ends up as narrow as its widest row allows;
    all even rows are centred on the axis of the bound_rows (the widest rows), so the picture does not drift.
    Returns the new x of every node."""
    rows = lay.order
    free = [li for li in range(len(rows)) if li not in even_rows and rows[li]]
    ref_rows = ref_rows or {}
    ref = {li: [r for r in ref_rows.get(li, free) if rows[r]] or free for li in even_rows}
    nbrs = {}
    for (u, v) in m.edges:
        nbrs.setdefault(u, []).append(v)
        nbrs.setdefault(v, []).append(u)
    x = dict(x0)

    def offsets(row):
        off, acc = [], 0.0
        for k, nid in enumerate(row):
            if k:
                acc += (wid[row[k - 1]] + wid[nid]) / 2 + PACK_GAP
            off.append(acc)
        return off

    def sweep(li):
        row = rows[li]
        off = offsets(row)
        tg, wt = [], []
        for nid, o in zip(row, off):
            ps = [x[q] for q in nbrs.get(nid, ()) if q in x]
            tg.append((sum(ps) / len(ps) if ps else x[nid]) - o)
            wt.append(float(len(ps)) if ps else 0.01)
        for nid, o, y in zip(row, off, cf._pav(tg, wt)):
            x[nid] = y + o

    def extent(rs):
        a = min(x[n] - wid[n] / 2 for li in rs for n in rows[li])
        b = max(x[n] + wid[n] / 2 for li in rs for n in rows[li])
        return a, b

    g0, g1 = extent([r for r in bound_rows if rows[r]] or free)
    c0 = (g0 + g1) / 2                    # all even rows are centred on the same vertical axis: no drift

    def lay_even(spans):
        for li in even_rows:
            row = rows[li]
            if not row:
                continue
            a, b = spans[li]
            span = max(b - a, len(row) * cell_min.get(li, 0.0))
            c = c0
            for k, nid in enumerate(row):
                x[nid] = c - span / 2 + (k + 0.5) * span / len(row)

    spans = {li: extent(ref[li]) for li in even_rows if rows[li]}
    for _ in range(rounds):
        lay_even(spans)
        for _ in range(sweeps):
            for li in free:
                sweep(li)
        new = {li: extent(ref[li]) for li in spans}
        done = all(abs(new[li][0] - spans[li][0]) < 1e-3 and abs(new[li][1] - spans[li][1]) < 1e-3 for li in spans)
        spans = new
        if done:
            break
    lay_even(spans)
    return x


# legend: one line (a line that is still too long wraps)
LEG_STEP = 0.22               # distance between legend lines (inches)
LEG_PADV = 0.07               # clear space above the first and below the last legend line (inches)
LEG_GAP = 0.26                # clear space between two legend items (inches)


def _legend_layout(W, font_size):
    """Returns (items, nlines, height): items = [(index in _LEGEND, x of the glyph slot, line, slot width)].
    Each line is centred in the frame."""
    fsz = font_size * LEG_FS
    iw = lambda it: 0.30 if it[0] == "edge" else 0.16                             # noqa: E731
    wid = [iw(it) + 0.06 + _tw(it[3], fsz) for it in _LEGEND]
    avail = W - 0.06 - 0.24
    all_idx = list(range(len(_LEGEND)))
    width_of = lambda ids: sum(wid[i] for i in ids) + LEG_GAP * (len(ids) - 1)    # noqa: E731
    out, wrapped = [], []
    for ids in [all_idx]:                                                              # a line that is still too long wraps
        cur = []
        for i in ids:
            if cur and width_of(cur + [i]) > avail:
                wrapped.append(cur)
                cur = []
            cur.append(i)
        wrapped.append(cur)
    for ln, ids in enumerate(wrapped):
        x = (W - width_of(ids)) / 2
        for i in ids:
            out.append((i, x, ln, iw(_LEGEND[i])))
            x += wid[i] + LEG_GAP
    n = len(wrapped)
    return out, n, 2 * LEG_PADV + LEG_STEP * n


def _gutter_w(font_size):
    """Width of the text block in the left panel: the widest title, or 'total -> carried' of up to 3 digits each."""
    hfs, nfs = font_size * HEAD_FS, font_size * NUM_FS
    title = max(_tw(t, hfs, bold=True) for t in SHORT_TITLES)
    table = _tw("000", nfs) + 0.02 + 0.06 + 0.11 + 0.06 + _tw("000", nfs, bold=True)
    return max(title, table)


def _pull_hollow_cves(m, lay, x, wid):
    """Move each hollow CVE of row 1 towards the node before it (at most CVE_STEP away); the order is kept."""
    row = lay.order[0]
    for a, b in zip(row, row[1:]):
        if m.nodes[b]["style"] == "incomplete":
            lim = max(x[a] + CVE_STEP, x[a] + (wid[a] + wid[b]) / 2 + PACK_GAP)
            x[b] = min(x[b], lim)


def _more_marks(m, lay, split):
    """Rows with more entries than are drawn: {row: x of the middle of the row's "..."}. All of them share
    one column, right of everything drawn. The technique, sub-technique and tactic rows always have more
    (the ATT&CK matrix is larger than the chains)."""
    marks = {}
    xm = lay.total_w - 0.10 + MORE_GAP + MORE_STEP + MORE_R
    for li, row in enumerate(lay.order):
        ids = [n for n in row if m.nodes[n]["kind"] != "dummy"]
        if not ids:
            continue
        shown = {m.nodes[n]["key"] for n in ids if m.nodes[n]["kind"] != "stub"}
        for n in ids:
            if m.nodes[n]["kind"] == "stub":
                shown |= set(m.nodes[n].get("members", []))
        total = (split or {}).get(cf.LAYERS[li], (None, None))[0]
        if li >= 3 or (li == 0 and m.omitted_cves) or (total is not None and len(shown) < total):
            marks[li] = xm
    return marks


def _more_dots(ax, cx, cy, z=6):
    from matplotlib.patches import Circle
    for k in (-1, 0, 1):
        ax.add_patch(Circle((cx + k * MORE_STEP, cy), MORE_R, facecolor="#5a5a5a", edgecolor="none", zorder=z))


# layout
def compact_layout(m, ordered_tactics, font_size, tactic_labels=True, cap_w=0.105, gap=0.025,
                   block_gap=0.22, left_margin=1.10, gap_min=ROW_GAP, max_labels=None, **_ignored):
    """x order from cti_figure._layout (crossing-reduced), then packed; y geometry built around the labels."""
    lay = cf._layout(m, ordered_tactics, font_size, cap_w=cap_w, gap=gap, block_gap=block_gap,
                     gap_y=0.3, left_margin=left_margin, top_margin=0.15, tactic_w=cap_w)
    L = len(cf.LAYERS)
    lsize = font_size * ID_FS
    lh = _lh(lsize)
    lay.radius = _radii(m)

    # left panel and the room the labels may use
    lay.gutter_r = HEAD_X0 + _gutter_w(font_size) + 0.12
    left_margin = max(left_margin, lay.gutter_r + EDGE_MARGIN)
    lay.label_xmin = lay.gutter_r + 0.04

    # tactic names: horizontal, on up to two lines; they set the least spacing of the tactic row
    tact = {n: _wrap(m.nodes[n]["label"]) for n in lay.order[5]} if tactic_labels else {}
    tact_w = {n: max(_tw(s, lsize) for s in lines) + 0.07 for n, lines in tact.items()}
    lay.tactic_lines = tact
    packed, wid = _pack_x(m, lay, lay.radius, tact_w)
    # CWE row and tactic row: equal cells, each as wide as its widest label needs; the rows between follow them
    lab_w = {n: _tw(_short(m.nodes[n]), lsize) for n in lay.order[1] if m.nodes[n]["style"] == "chain"}
    lab_w.update({n: w - 0.07 for n, w in tact_w.items()})
    cell_min = {}
    for li in (1, 5):                  # least cell: two neighbouring labels (or glyphs) must clear each other
        w = {n: max(lab_w.get(n, 0.0), wid[n]) for n in lay.order[li]}
        row = lay.order[li]
        cell_min[li] = max([(w[a] + w[b]) / 2 + CELL_PAD for a, b in zip(row, row[1:])] + [max(w.values(), default=0.0)])
    packed = _spread_x(m, lay, packed, wid, cell_min, ref_rows={1: (0, 2), 5: (3, 4)})
    _pull_hollow_cves(m, lay, packed, wid)
    shift = left_margin - min(packed[n] - wid[n] / 2 for n in packed)
    lay.x = {n: v + shift for n, v in packed.items()}
    lay.width = wid
    lay.labels, lay.label_place, depth, lab_right = _place_labels(
        m, lay, font_size, None if max_labels is None else max(0, int(max_labels)))

    rmax = _R * max(_RMAX, TACTIC_SCALE)
    up = _block(depth[0], lh)
    cy = [max(0.1 + (up + 0.06 if up else 0.0) + rmax, 0.03 + HEAD_H / 2 + 0.06)]
    for li in range(1, L):
        below = _block(depth[li - 1], lh) + 0.03 if li - 1 >= 1 and depth[li - 1] else 0.0
        need = rmax * 1.3 + 0.06 + below + 0.22
        cy.append(cy[-1] + max(2 * rmax + gap_min, need, HEAD_H + 0.08))
    lay.cy = cy
    lay.row_h = [2 * rmax] * L
    lay.row_y = [c - rmax for c in cy]
    lay.depth = depth
    lay.lh = lh
    nlines = max((len(s) for s in tact.values()), default=0)
    lay.label_h = 0.07 + nlines * lh + 0.03 if tactic_labels and nlines else 0.0
    right = max((lay.x[n] + lay.width[n] / 2 for n in lay.x), default=left_margin)
    right = max(right, lab_right)
    lay.total_w = max(right + 0.10, 3.0)
    _items, nleg, leg_h = _legend_layout(lay.total_w, font_size)
    lay.legend_lines = nleg
    lay.legend_h = leg_h
    lay.band_end = cy[5] + rmax + lay.label_h + 0.04           # bottom of the last row band
    lay.legend_top = lay.band_end + 0.10
    lay.total_h = lay.legend_top + leg_h + 0.04
    return lay


# drawing
def _glyph(ax, shape, cx, cy, r, fc, ec, lw, ls="-", z=5):
    from matplotlib.patches import Circle, Rectangle, RegularPolygon
    kw = dict(facecolor=fc, edgecolor=ec, linewidth=lw, linestyle=ls, zorder=z)
    if shape == "circle":
        ax.add_patch(Circle((cx, cy), r, **kw))
    elif shape == "square":
        ax.add_patch(Rectangle((cx - r * 0.9, cy - r * 0.9), r * 1.8, r * 1.8, **kw))
    elif shape == "diamond":
        ax.add_patch(RegularPolygon((cx, cy), 4, radius=r * 1.3, **kw))
    elif shape == "triangle":
        ax.add_patch(RegularPolygon((cx, cy), 3, radius=r * 1.3, orientation=3.14159, **kw))
    elif shape == "pentagon":
        ax.add_patch(RegularPolygon((cx, cy), 5, radius=r * 1.15, orientation=3.14159, **kw))
    elif shape == "hexagon":
        ax.add_patch(RegularPolygon((cx, cy), 6, radius=r * 1.2, **kw))


def _node_style(n, cwe_colour=None):
    k = n["kind"]
    if (k == "cve" and n["style"] == "incomplete") or k == "stub" or n["style"] == "terminated":
        return dict(fc="white", ec="#444444", ls=(0, (2, 1.2)))
    if k == "cwe" and cwe_colour:
        return dict(fc=cwe_colour, ec="black", ls="-")
    return dict(fc=_TONE[k], ec="black", ls="-")


def _row_header(ax, title, cy, split, fs, s, lw, cols, gw):
    """Left panel of one row: the title, then 'total -> carried' numerals under it.

    The block is centred on the row's node line and the clear space between its lines is the same on every
    row. The totals are right-aligned in one column, the arrows sit in one column and the carried numerals are
    left-aligned in one column, so the numerals read as a table down the panel.
    """
    from matplotlib.patches import Polygon, Rectangle
    wt, wc = cols
    x0 = HEAD_X0
    total, carried = split if split else (None, None)
    hfs, nfs = fs * HEAD_FS, fs * NUM_FS
    ct = 0.67 * hfs / 72.0 / s                     # cap height of the title / digit height, in design inches
    cn = 0.68 * nfs / 72.0 / s
    bh = 0.035
    has_nums = carried is not None
    block = ct + (HEAD_GAP + cn if has_nums else 0.0) + (HEAD_GAP + bh if has_nums and HEAD_BAR else 0.0)
    top = cy - block / 2
    ax.text(x0, top + ct, title, fontsize=hfs, fontweight="bold", ha="left", va="baseline", zorder=7)
    if not has_nums:
        return
    yn = top + ct + HEAD_GAP + cn                   # baseline of the numerals
    ym = yn - cn / 2                                # vertical middle of the numerals (for the arrow)
    if total is None:                               # total unknown: carried count only
        ax.text(x0, yn, str(carried), fontsize=nfs, fontweight="bold", ha="left", va="baseline", zorder=7)
        return
    ax.text(x0, yn, str(total), fontsize=nfs, color="#333333", ha="left", va="baseline", zorder=7)
    xa = x0 + wt + 0.06                             # arrow column
    ax.plot([xa, xa + 0.07], [ym, ym], color="#222222", lw=lw(0.9), solid_capstyle="butt", zorder=7)
    ax.add_patch(Polygon([(xa + 0.105, ym), (xa + 0.065, ym - 0.028), (xa + 0.065, ym + 0.028)], closed=True,
                         facecolor="#222222", edgecolor="none", zorder=7))
    ax.text(xa + 0.11 + 0.06, yn, str(carried), fontsize=nfs, fontweight="bold", ha="left", va="baseline",
            zorder=7)                               # carried column
    if HEAD_BAR:
        yb = yn + HEAD_GAP
        share = min(max(carried / total, 0.0), 1.0) if total else 0.0
        ax.add_patch(Rectangle((x0, yb), gw, bh, facecolor="white", edgecolor="#444444", linewidth=lw(0.5),
                               linestyle=(0, (2, 1.2)), zorder=6))
        if share > 0:
            ax.add_patch(Rectangle((x0, yb), gw * share, bh, facecolor="#222222", edgecolor="#222222",
                                   linewidth=lw(0.5), zorder=7))


def render_compact(m, lay, figsize, dpi, font_size, out_base, formats, tactic_labels=True, split=None,
                   **_ignored):
    from matplotlib import rc_context
    from matplotlib.figure import Figure
    from matplotlib.patches import Rectangle

    marks = _more_marks(m, lay, split)
    W, H = max(lay.total_w, max(marks.values(), default=0.0) + MORE_STEP + MORE_R + 0.10), lay.total_h
    if figsize:
        fw, fh = figsize
        s = min(fw / W, fh / H)
    else:
        fw, fh, s = W, H, 1.0
    fs = max(font_size * s, MIN_FS)
    lw = lambda v: max(v * s, MIN_LW)                                   # noqa: E731
    if fs > font_size * s + 1e-6:
        console.warn(f"Scaled to {s:.2f}x: font raised to the {MIN_FS:g} pt floor, labels may touch. "
                     "Use fewer CVEs (--max-cves) or a larger --figsize.")
    if not figsize and W > TEXT_W + 0.05:
        console.warn(f"Natural size {W:.1f} x {H:.1f} in is wider than the {TEXT_W:g} in text width: in a document "
                     f"the {font_size * ID_FS:.1f} pt labels shrink to {font_size * ID_FS * TEXT_W / W:.1f} pt. "
                     f"Reduce --max-cves or use sidewaysfigure.")
    console.info(f"CTI figure size {fw:.2f} x {fh:.2f} in, text {fs * ID_FS:.1f} pt. "
                 f"Include with width={min(fw, TEXT_W):.2f}in and no extra scaling.")

    nodes, x, cy, rad = m.nodes, lay.x, lay.cy, lay.radius
    edge_col, cwe_col = _edge_colours(m)
    hl = None
    if HIGHLIGHT_CVE and f"cve:{HIGHLIGHT_CVE}" in nodes:
        hl = _descendants(m, f"cve:{HIGHLIGHT_CVE}")
    rc = {"pdf.fonttype": 42, "ps.fonttype": 42, "svg.fonttype": "none", "font.family": _font()}
    rmax = _R * max(_RMAX, TACTIC_SCALE)
    lsz = fs * ID_FS                                                    # ID / tactic text size
    lh = lay.lh
    cap = 0.70 * lsz / 72.0 / s                                         # cap height of that text, in design inches
    padn = LABEL_BOX * lsz / 72.0 / s                                   # tag padding, in design inches
    tag = dict(boxstyle=f"square,pad={LABEL_BOX}", facecolor="white", edgecolor="none",
               ) if LABEL_BOX else None                                 # white tag: no link runs through a label
    files = {}
    with rc_context(rc):
        fig = Figure(figsize=(fw, fh), dpi=dpi)
        ax = fig.add_axes([0, 0, 1, 1])
        vw, vh = fw / s, fh / s
        ax.set_xlim(-(vw - W) / 2, W + (vw - W) / 2)
        ax.set_ylim(H + (vh - H) / 2, -(vh - H) / 2)
        ax.set_aspect("equal")
        ax.axis("off")

        # frame, shaded left panel, dashed row dividers, row titles
        bounds = [0.03] + [(cy[i] + rmax + cy[i + 1] - rmax) / 2 for i in range(5)] + [lay.band_end]
        gx = lay.gutter_r
        ax.add_patch(Rectangle((0.03, bounds[0]), gx - 0.03, bounds[6] - bounds[0], facecolor="#ececec",
                               edgecolor="none", zorder=0))
        for b in bounds[1:6]:
            ax.plot([0.03, W - 0.03], [b, b], color="#a8a8a8", lw=lw(0.5), ls=(0, (3, 2)), zorder=1)
        ax.plot([gx, gx], [bounds[0], bounds[6]], color="#b0b0b0", lw=lw(0.5), zorder=1)
        ax.add_patch(Rectangle((0.03, bounds[0]), W - 0.06, bounds[6] - bounds[0], fill=False,
                               edgecolor="#8c8c8c", linewidth=lw(0.6), zorder=2))
        splits = [(split or {}).get(cf.LAYERS[li]) for li in range(6)]
        nfs_d = fs * NUM_FS / s
        wt = max((_tw(str(t), nfs_d) for t, c in (p for p in splits if p) if t is not None), default=0.0)
        wt += 0.02 if wt else 0.0                                       # side bearings of the right-aligned digits
        wc = max((_tw(str(c), nfs_d, bold=True) for t, c in (p for p in splits if p) if c is not None), default=0.0)
        gw = gx - HEAD_X0 - 0.12
        for li in range(6):
            _row_header(ax, SHORT_TITLES[li], cy[li], splits[li], fs, s, lw, (wt, wc), gw)

        # edges: dead ends first, then shared, then coloured; thick trunks first so thin twigs stay visible
        def _key(kv):
            (u, v), e = kv
            rank = 0 if e["kind"] == "terminated" else (1 if edge_col.get((u, v)) is None else 2)
            return (rank, -e["support"], kv[0])
        for (u, v), e in sorted(m.edges.items(), key=_key):
            nu, nv = nodes[u], nodes[v]
            y1 = cy[nu["layer"]] + (0 if nu["kind"] == "dummy" else rad[u] * 1.25)
            y2 = cy[nv["layer"]] - (0 if nv["kind"] == "dummy" else rad[v] * 1.25)
            if e["kind"] == "terminated":
                st = dict(color="#9a9a9a", lw=lw(0.6), ls=(0, (3, 2)), alpha=0.9)
            else:
                col = edge_col.get((u, v)) or _NEUTRAL
                width = _edge_lw(e["support"])
                if hl is not None and not (u in hl and v in hl):
                    col, width = _FADED, 0.4
                st = dict(color=col, lw=lw(width), ls="-", alpha=0.88)
            cf._bezier(ax, x[u], y1, x[v], y2, st, arrow=False)

        # nodes and labels
        for nid, n in nodes.items():
            if n["kind"] == "dummy":
                continue
            li, k, r = n["layer"], n["kind"], rad[nid]
            st = _node_style(n, cwe_col.get(nid))
            _glyph(ax, _SHAPE[k], x[nid], cy[li], r, st["fc"], st["ec"], lw(0.7), st["ls"])
            if k == "tactic":
                _glyph(ax, "hexagon", x[nid], cy[li], r * 0.55, "none", "black", lw(0.5), "-", z=6)
                if tactic_labels:                                       # one text per line, common baselines
                    for ln, line in enumerate(lay.tactic_lines[nid]):
                        ax.text(x[nid], cy[li] + r * 1.25 + 0.07 + cap + ln * lh, line, ha="center",
                                va="baseline", fontsize=lsz, zorder=7)
            elif nid in lay.labels:
                ha, xt, lev = lay.label_place[nid]
                off = lev * LEVEL_STEP * lh                             # a label on a further line
                if k == "cve":
                    yl = cy[li] - r * 1.1 - 0.005 - off
                    ax.text(xt, yl - padn, lay.labels[nid], ha=ha, va="bottom", fontsize=lsz, zorder=8, bbox=tag)
                    if lev:
                        ax.plot([x[nid], x[nid]], [cy[li] - r * 1.1, yl], color="#444444", lw=lw(0.5), zorder=6)
                else:                                                   # tag touches the node: no stub of a link shows
                    yl = cy[li] + r * _BOTTOM.get(k, 1.0) + (0.12 if n["terminal"] else 0.0) + 0.005 + off
                    ax.text(xt, yl + padn, lay.labels[nid], ha=ha, va="top", fontsize=lsz, zorder=8, bbox=tag)
                    if lev:
                        ax.plot([x[nid], x[nid]], [cy[li] + r * _BOTTOM.get(k, 1.0), yl], color="#444444", lw=lw(0.5),
                                zorder=6)
            if n["terminal"]:
                yb = cy[li] + r + 0.075
                ax.plot([x[nid], x[nid]], [cy[li] + r, yb], color="#222222", lw=lw(0.7), zorder=6)
                ax.plot([x[nid] - 0.055, x[nid] + 0.055], [yb, yb], color="#222222", lw=lw(1.3),
                        solid_capstyle="butt", zorder=6)

        # "..." at the end of every row that has more entries than are drawn
        for li, mx in marks.items():
            _more_dots(ax, mx, cy[li])

        # legend, in a frame of its own
        items, nleg, leg_h = _legend_layout(W, font_size)
        ax.add_patch(Rectangle((0.03, lay.legend_top), W - 0.06, leg_h, facecolor="white", edgecolor="#8c8c8c",
                               linewidth=lw(0.6), zorder=1))
        for idx, lx, line, iw in items:
            kind, key, style, text = _LEGEND[idx]
            ly = lay.legend_top + LEG_PADV + LEG_STEP * (line + 0.5)
            if kind == "node":
                st = _node_style({"kind": key, "style": style}, _CWE_COLORS[0] if key == "cwe" else None)
                r0 = 0.05 * (TACTIC_SCALE if key == "tactic" else 1.0)
                _glyph(ax, _SHAPE[key], lx + iw / 2, ly, r0, st["fc"], st["ec"], lw(0.6), st["ls"])
                if key == "tactic":
                    _glyph(ax, "hexagon", lx + iw / 2, ly, r0 * 0.55, "none", "black", lw(0.5), "-", z=6)
            elif kind == "edge":
                if key == "chain":
                    for i, c in enumerate(_CWE_COLORS[:3]):
                        ax.plot([lx + 0.1 * i, lx + 0.1 * i + 0.09], [ly, ly], color=c, lw=lw(1.6), solid_capstyle="butt")
                elif key == "shared":
                    ax.plot([lx, lx + 0.3], [ly, ly], color=_NEUTRAL, lw=lw(1.6))
                else:
                    ax.plot([lx, lx + 0.3], [ly, ly], color="#9a9a9a", lw=lw(0.9), ls=(0, (3, 2)))
            elif kind == "more":
                _more_dots(ax, lx + iw / 2, ly, z=5)
            elif kind == "cap":
                ax.plot([lx + iw / 2, lx + iw / 2], [ly - 0.065, ly + 0.02], color="#222222", lw=lw(0.7))
                ax.plot([lx + iw / 2 - 0.06, lx + iw / 2 + 0.06], [ly + 0.02, ly + 0.02], color="#222222", lw=lw(1.3),
                        solid_capstyle="butt")
            ax.text(lx + iw + 0.06, ly, text, fontsize=fs * LEG_FS, ha="left", va="center_baseline")

        for ext in formats:
            p = Path(f"{out_base}.{ext}")
            fig.savefig(p, **({"dpi": dpi} if ext == "png" else {}))
            files[ext] = p
    return files
