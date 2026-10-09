"""Validation workbook (not part of `run`).

Reads the already-built device_compromise_dataset.xlsx and the CVE json files from the fetch
stage. It does not call or change the other stages. The output, validation/validation_paths.xlsx,
supports a consensus workflow: two annotators label every path on their own, then agree one
final label together. There is no third person who decides. Six sheets, in this order:

1. Consensus
   One row per attack path. Columns A to J:
     A Path ID, B Tactic, C A1 Validation, D A2 Validation, E A1 Rationale, F A2 Rationale,
     G Consensus Label, H Consensus Rationale, I Path Key, J Status.
   C to F are formulas that copy what each annotator wrote on their own sheet, so nobody types
   there. G and H are filled in automatically when A1 and A2 gave the same label ("Both
   annotators agree."). Where they differ, J says Discuss, the two annotators talk it through
   and type the label and the reason they both accept into G and H. J then says Resolved.
   Status is one of Pending (an annotator has not labelled the path yet), Agree, Discuss,
   Resolved.

2. Results
   Formulas over the Consensus sheet, nothing to type. The table of consensus labels per tactic
   starts at A1. Below it: percent agreement and Cohen's kappa between A1 and A2 (all paths,
   and each Path Key counted once), a cross-tab of A1 against A2, and how the disputed keys
   ended up.

3. A1_annotation and 4. A2_annotation
   The same form twice, one row per (w, k, s, c, t) attack path: identity columns, supporting
   CVEs, a Cross-Tactic Repeat flag (paths with the same (w, k, s, c) key share a highlight
   colour) and the three columns the annotator fills in: Validation, Validation Rationale,
   Notes. There is no per-path document column: an annotator cites documents in the rationale by
   Doc ID, as many as the path needs, and looks them up on Reference_Documents.

5. Reference_Documents
   One row per distinct Reference URL across the whole dataset: Doc ID, Advisory Tag,
   Reference URL. Advisory Tag is the union of the tags the citing CVEs' NVD reference objects
   carry for that URL, so it comes from the data, not from a person. An annotator who finds a
   document that is not listed adds a row with Reference URL (and Advisory Tag) filled in and
   Doc ID left blank; the next run gives it a permanent D####. Use a temporary NEW-<initials>-N
   tag instead if the copy will not be run back through `cve2at validate`.
   Two more columns: Alternate URLs (other addresses of the same document, one per line; filled
   in by the script, and you may add to it) and Paths Citing (a formula: how many paths have the
   Doc ID in a rationale; nothing to type).

6. Labeling_Guide
   The label definitions and the consensus steps, stored in the workbook so they travel with it.

Formulas have no stored results until a spreadsheet program calculates them. The workbook is
flagged to recalculate when opened, so Excel and LibreOffice show every value at once. A
program that only reads the file (pandas, for example) sees empty cells for formulas until the
file has been opened and saved once.

Re-running

`cve2at validate` on a workspace that already has validation_paths.xlsx merges instead of
overwriting. It keeps everything people typed: both annotators' Validation, Validation Rationale
and Notes, any Consensus Label or Consensus Rationale that was typed (not the automatic ones,
which are rebuilt), and every Reference_Documents row, including rows added by hand. A row typed
in with a Reference URL but no Doc ID gets the next free D####. A workbook with the old single
"Validation Paths" sheet is not migrated, because it does not say which annotator wrote the
labels; its documents are kept and the script says so.

Documents are identified by Doc ID, not by URL, because rationales cite D####. A publisher may
rename or move a page (the CISA advisories moved from us-cert.gov to cisa.gov) while NVD keeps
citing the old address. The script therefore matches a cited URL to an existing row by exact
Reference URL, then Alternate URLs, then _url_fingerprint (the CISA advisory number, or the
address without scheme, "www." and trailing slash). A match through another address is written
into that row's Alternate URLs, so the Doc ID the annotators cited stays the one row for that
document. Only a URL that matches nothing gets a new D####, and the script warns when that happens
on top of a workbook that already has documents. If an earlier run already made a second row for
one document, the higher-numbered row is folded into the lower one (unless a rationale cites it).
When the workbook is replaced, the old file is first copied to validation/backups/ (newest 10
kept), and any D#### written in a rationale or note that has no row on Reference_Documents is
reported. To record a renamed document by hand, put the new address in the row's Reference URL
(or Alternate URLs) and keep its Doc ID.

Typed values are kept only if Path ID P00N still refers to the same (Tactic, CWE, Technique,
CAPEC) chain as when they were typed. Path IDs come from enumeration order, so a different row
order (a new CVE, a CWE/CAPEC/ATT&CK refresh, a re-fetch whose reference order changed) can make
P00N point at a different path. Each sheet carries a Path Key (the content identity behind
Cross-Tactic Repeat). On every merge the recorded (Path Key, Tactic) for a Path ID is compared
with what that ID computes to now. If they differ, the old values are not attached to the new
path; they are reported through console.warn instead. See _build_tables.

Annotation rounds

Once the workbook has been handed to the annotators, do not re-run `cve2at validate` on that
workspace until the round closes: a re-run can shift Path IDs and produce a workbook that the
annotators' copies no longer match. Each annotator fills only their own sheet in their own copy.
The coordinator then pastes columns M to O of each returned sheet into the same sheet of the
master workbook (the rows are in the same order). This script reconciles only its own previous
file; it does not read returned copies.
"""
from __future__ import annotations

import os
import re
import shutil
from datetime import datetime
from urllib.parse import urlsplit

import pandas as pd
from openpyxl import Workbook, load_workbook
from openpyxl.comments import Comment
from openpyxl.formatting.rule import FormulaRule
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
from openpyxl.workbook.properties import CalcProperties
from openpyxl.worksheet.datavalidation import DataValidation

from . import attack_tree_lib as atl
from . import console
from .config import Workspace
from .cve_parse import cve_json_files, load_cve
from .errors import PipelineError

C_HEADER_BG, C_HEADER_FG, C_BORDER = "1A2B4A", "FFFFFF", "C8D0DC"
C_AUTO_BG = "F2F2F2"       # filled by a formula, do not type
C_INPUT_BG = "FFF8DC"      # typed by the annotators (consensus label and reason)
C_DISCUSS_BG, C_RESOLVED_BG = "F8CBAD", "C6E0B4"
# small pastel palette, cycled across distinct repeated path-keys
REPEAT_PALETTE = ["FFE8B3", "C9E4DE", "F6C6C6", "D6E4F0", "E3D5F5", "FBE4D8", "D0F0C0"]

_thin = Side(border_style="thin", color=C_BORDER)
_border = Border(left=_thin, right=_thin, top=_thin, bottom=_thin)

CONSENSUS_SHEET = "Consensus"
RESULTS_SHEET = "Results"
ANNOTATORS = ("A1", "A2")
ANNOTATION_SHEETS = {"A1": "A1_annotation", "A2": "A2_annotation"}
DOC_SHEET_NAME = "Reference_Documents"
GUIDE_SHEET_NAME = "Labeling_Guide"
LEGACY_PATH_SHEET = "Validation Paths"        # single-annotator workbook of earlier versions
LEGACY_DOC_SHEET = "Reference Documents"

PATH_COLS = ["Path ID", "Tactic", "CWE ID", "CWE Name", "Technique", "Technique Name",
             "Sub-technique", "CAPEC ID", "CAPEC Name", "CVE(s)", "Path Key",
             "Cross-Tactic Repeat",
             "Validation", "Validation Rationale", "Notes"]
# columns an annotator fills in on an annotation sheet; kept across re-runs, keyed by Path ID
JUDGMENT_COLS = ["Validation", "Validation Rationale", "Notes"]
JUDGMENT_LETTERS = [get_column_letter(PATH_COLS.index(c) + 1) for c in JUDGMENT_COLS]   # N, O, P

CONSENSUS_COLS = ["Path ID", "Tactic", "A1 Validation", "A2 Validation", "A1 Rationale",
                  "A2 Rationale", "Consensus Label", "Consensus Rationale", "Path Key", "Status"]
CONSENSUS_TYPED = ["Consensus Label", "Consensus Rationale"]     # the only typed columns here
SOURCES = ANNOTATORS + (CONSENSUS_SHEET,)

DOC_COLS = ["Doc ID", "Advisory Tag", "Reference URL", "Alternate URLs"]
# Written to the sheet but never read back: a formula counting the paths whose rationale cites the Doc ID.
DOC_SHEET_COLS = DOC_COLS + ["Paths Citing"]
# The Doc ID is the identity of a document, because rationales cite it by ID. A URL is only how that
# document is currently reachable: publishers move and rename pages (us-cert.gov -> cisa.gov), and NVD may
# keep citing the old address. Reference URL is what the people want to see; Alternate URLs holds every
# other address of the same document (one per line), so the next run still recognises it.
DOC_ID_RE = re.compile(r"\bD\d{4}\b")
_CISA_ADVISORY_RE = re.compile(r"(icsm?a-\d{2}-\d{3}-\d{2}[a-z]?)", re.I)
_CISA_HOSTS = ("cisa.gov", "us-cert.gov")
BACKUP_KEEP = 10                # how many timestamped copies of the old workbook to keep

VALIDATION_CHOICES = ["Confirmed", "Plausible", "No supporting evidence found"]
AGREE_TEXT = "Both annotators agree."


def _letters(cols, name):
    return get_column_letter(cols.index(name) + 1)


def _norm_header(h):
    # "Consensus  Rationale" (two spaces) and "Consensus Rationale" are the same column
    return " ".join(str(h).split()) if h is not None else ""


def _find_sheet(wb, *names):
    lower = {s.lower(): s for s in wb.sheetnames}
    for n in names:
        if n.lower() in lower:
            return wb[lower[n.lower()]]
    return None


def _coding_guide(n_last_tactic_row):
    v, r, nt = JUDGMENT_LETTERS
    return [
        ("Validation (A1_annotation and A2_annotation sheets)", ""),
        ("Confirmed",
         "Strong evidence that the weakness-technique-attack pattern combination was explicitly "
         "described for this device in at least one of the documents. Tactic placement is not assessed."),
        ("Plausible",
         "The exact path is not directly documented, but credible evidence supports the underlying "
         "attack behaviour, for example from an analogous device in the same product category or "
         "from underlying technical documentation."),
        ("No supporting evidence found",
         "No suitable supporting evidence was identified within the predefined search scope. This "
         "does NOT establish that the path is impossible or has never occurred, only that the "
         "manual search did not find documentation of it."),
        ("Validation Rationale",
         "One or two sentences explaining why this label was chosen. Cite the Doc ID(s) from the "
         "Reference_Documents sheet and the section of the document where useful."),
        ("Notes", "Anything else worth recording about how this path was validated."),
        ("", ""),
        ("Working independently", ""),
        ("Your own sheet only",
         f"Each annotator fills columns {v}, {r} and {nt} (Validation, Validation Rationale, Notes) "
         "of their own sheet, A1_annotation or A2_annotation, and does not read the other "
         "annotator's sheet until both have finished."),
        ("Same Path Key",
         "Rows that share a highlight colour have the same Path Key (Cross-Tactic Repeat = Yes). "
         "They describe the same weakness, technique and CAPEC pattern under different tactics and "
         "should normally carry the same label and rationale."),
        ("", ""),
        ("Reaching consensus (Consensus sheet)", ""),
        ("A1 / A2 Validation and Rationale (C to F)",
         "Copied automatically from the two annotation sheets. Do not type in them."),
        ("Status (J)",
         "Pending: an annotator has not labelled the path yet. Agree: both gave the same label. "
         "Discuss: the labels differ and no consensus label has been entered. Resolved: the labels "
         "differed and a consensus label has been entered."),
        ("Consensus Label (G)",
         "Filled in automatically when both annotators gave the same label. On a Discuss row the "
         "two annotators talk it through and type the label they both accept, using the dropdown. "
         "No third person decides. The row stays Discuss until the two annotators agree."),
        ("Consensus Rationale (H)",
         "Filled in automatically as \"Both annotators agree.\" when the labels match. On a "
         "discussed row, type one or two sentences giving the reason both annotators accept, citing "
         "the Doc ID and the section of the document."),
        ("", ""),
        ("Results sheet", ""),
        ("Label table and agreement",
         f"Every cell is a formula over the Consensus sheet; do not type there. The label table starts at "
         f"A1 and ends at the Percent of all paths row (A1:E{n_last_tactic_row}). Only paths with a "
         "consensus label are counted."),
        ("", ""),
        (DOC_SHEET_NAME + " (sheet)", ""),
        ("Doc ID / Advisory Tag / Reference URL",
         "One row per distinct source document referenced anywhere in this dataset, not one row "
         "per path and not one row per citing CVE. Advisory Tag is whatever tag NVD's own "
         "reference data carries for that URL (for example Vendor Advisory or Patch); it describes "
         "the document itself, not any one path."),
        ("Adding a document you found yourself",
         "Add a row with Reference URL and Advisory Tag filled in and Doc ID left blank. "
         "Re-running `cve2at validate` assigns it a permanent D#### ID. If this copy will not be "
         "run back through the tool (for example a frozen annotation round), write a temporary ID "
         "instead, such as NEW-<your initials>-1, so your additions can be told apart from the "
         "other annotator's when the copies are combined."),
        ("Renamed or moved documents",
         "The Doc ID is what identifies a document, and rationales cite it. If a publisher moves a "
         "page, keep the Doc ID and put the new address in Reference URL; the old one goes under "
         "Alternate URLs. Do not delete the row and add a new one, or the Doc ID in the rationales "
         "will point at nothing. Alternate URLs is filled in automatically when a re-run recognises "
         "the same document under a different address."),
        ("Paths Citing",
         "A formula: the number of paths whose A1 or A2 rationale contains this Doc ID. Nothing to "
         "type."),
    ]


# data loading (curated relation)
def _load_curated(dataset_path):
    """Same three calls as trees._load_curated, repeated here rather than imported so this
    module does not depend on trees.py internals.
    """
    df = atl.load_dataset(str(dataset_path))
    key_cols = atl.resolve_key_columns(df)
    P, dropped = atl.build_curated_relation(df, key_cols)
    if P.empty:
        raise PipelineError(
            "No complete CVE->CWE->CAPEC->technique->tactic chains in the dataset - nothing to validate.")
    ordered_tactics = atl.mitre_order(P["tactics"].unique())
    return df, key_cols, P, ordered_tactics


def _supporting_cves(P: pd.DataFrame, key_cols: dict, rec, tactic: str) -> list:
    """CVE IDs in P whose row produced this exact (w,k,s,c) chain under this tactic."""
    ck, tk, pk = key_cols["cwe_key"], key_cols["technique_key"], key_cols["capec_key"]
    ptk = key_cols["parent_technique_key"]
    mask = ((P["tactics"] == tactic) & (P[ck].astype(str).str.strip() == rec.cwe_key)
            & (P[tk].astype(str).str.strip() == rec.technique_key)
            & (P[ptk].astype(str).str.strip() == rec.parent_technique_key)
            & (P[pk].astype(str).str.strip() == rec.capec_key))
    if "CVE ID" not in P.columns:
        return []
    return sorted(P.loc[mask, "CVE ID"].dropna().astype(str).unique().tolist())


def _load_cve_references(ws: Workspace) -> dict:
    """{CVE ID: [(url, tags_str), ...]} from the CVE json already in ws.cve_dir. No network
    access and no tag filtering: every reference is a candidate document, and a person decides
    which are relevant.
    """
    out = {}
    for path in cve_json_files(ws.cve_dir):
        data = load_cve(path)
        cve_id = data.get("id", path.stem)
        seen, rows = set(), []
        for ref in data.get("references", []):
            url = ref.get("url", "")
            if not url or url in seen:
                continue
            seen.add(url)
            tags = ", ".join(ref.get("tags", []) or [])
            rows.append((url, tags))
        out[cve_id] = rows
    return out


# reading back an existing workbook, for merge-on-rerun
def _typed(value):
    # a cell that still holds an automatic formula is not something a person typed
    if value is None:
        return ""
    if isinstance(value, str) and value.startswith("="):
        return ""
    return value


def _read_judgments(sheet, cols):
    """({Path ID: {col: typed value}}, {Path ID: (Path Key, Tactic)}) from one sheet, reading the
    file's own header so a reordered or renamed column does not break the rest."""
    header = [_norm_header(c.value) for c in sheet[1]]
    if "Path ID" not in header:
        return {}, {}
    idx = {name: i for i, name in enumerate(header)}
    judgments, identity = {}, {}
    for row in sheet.iter_rows(min_row=2, values_only=True):
        pid = row[idx["Path ID"]]
        if not pid:
            continue
        judgments[pid] = {c: _typed(row[idx[c]]) for c in cols if c in idx}
        identity[pid] = (row[idx["Path Key"]] if "Path Key" in idx else None,
                         row[idx["Tactic"]] if "Tactic" in idx else None)
    return judgments, identity


def _load_existing_workbook(out_path) -> dict:
    """Return {} if no workbook exists at out_path (or it cannot be read). Otherwise return

      {"docs_by_url": {Reference URL: {col: value, ...}},
       "leftover_docs": [rows that do not key cleanly by Reference URL, e.g. a duplicate URL
                         or a malformed hand-added row],
       "max_doc_n": int,
       "judgments": {"A1": {Path ID: {col: value}}, "A2": {...},
                     "Consensus": {Path ID: {"Consensus Label": ..., "Consensus Rationale": ...}}},
       "identity": {"A1": {Path ID: (Path Key, Tactic)}, "A2": {...}, "Consensus": {...}}}

    identity records what each Path ID meant on each sheet last time, so a re-run can check
    whether Pn now means something else before trusting the values filed under it (see
    _build_tables). Sheet names are matched without regard to case.

    The Reference_Documents sheet is reconciled only if it already has a "Doc ID" column. A
    "Tag" header counts as "Advisory Tag". A workbook that has no such column starts the
    document list fresh, while the typed labels are still recovered.
    """
    if not os.path.isfile(out_path):
        return {}
    try:
        wb = load_workbook(out_path, data_only=False)
    except Exception as e:                                  # corrupt/locked file: start fresh
        console.warn(f"Could not read existing '{out_path}' ({e}); it will be regenerated from scratch.")
        return {}

    sheets = {a: _find_sheet(wb, ANNOTATION_SHEETS[a]) for a in ANNOTATORS}
    consensus_ws = _find_sheet(wb, CONSENSUS_SHEET)
    legacy_ws = _find_sheet(wb, LEGACY_PATH_SHEET)
    doc_ws = _find_sheet(wb, DOC_SHEET_NAME, LEGACY_DOC_SHEET)
    if not any(sheets.values()) and consensus_ws is None and legacy_ws is None:
        return {}
    if legacy_ws is not None and not any(sheets.values()):
        console.warn(f"'{out_path}' has the old single '{LEGACY_PATH_SHEET}' sheet. It does not say "
                     "which annotator wrote the labels, so they are NOT carried over. Paste them "
                     f"into {ANNOTATION_SHEETS['A1']} or {ANNOTATION_SHEETS['A2']} "
                     f"(columns {JUDGMENT_LETTERS[0]} to {JUDGMENT_LETTERS[-1]}) after this run. "
                     "The reference documents are kept.")

    judgments = {s: {} for s in SOURCES}
    identity = {s: {} for s in SOURCES}
    for a in ANNOTATORS:
        if sheets[a] is not None:
            judgments[a], identity[a] = _read_judgments(sheets[a], JUDGMENT_COLS)
    if consensus_ws is not None:
        judgments[CONSENSUS_SHEET], identity[CONSENSUS_SHEET] = _read_judgments(
            consensus_ws, CONSENSUS_TYPED)

    docs_by_url, leftover_docs, max_n = {}, [], 0
    if doc_ws is not None:
        existing_header = [_norm_header(c.value) for c in doc_ws[1]]
        if "Tag" in existing_header and "Advisory Tag" not in existing_header:
            existing_header = ["Advisory Tag" if h == "Tag" else h for h in existing_header]
        # rows are read with the file's own header order and mapped onto DOC_COLS by column name, not
        # position, so a column renamed, removed or reordered in Excel does not discard every row
        if "Doc ID" not in existing_header:
            console.warn(f"'{doc_ws.title}' header in the existing workbook has no 'Doc ID' "
                         "column to identify rows by; starting the document list fresh (typed "
                         "labels are still kept).")
        else:
            # rows typed in by hand with a URL but no Doc ID are held back and given IDs after the main pass,
            # once max_n reflects every existing D#### in the sheet
            pending_new_id = []
            for raw_row in doc_ws.iter_rows(min_row=2, values_only=True):
                raw = dict(zip(existing_header, raw_row))
                if not raw.get("Reference URL"):
                    if any(v for v in raw.values() if v not in (None, "")):
                        leftover_docs.append({c: raw.get(c, "") for c in DOC_COLS})
                    continue  # a genuinely blank row, nothing to keep
                rec = {c: raw.get(c, "") for c in DOC_COLS}
                rec["Alternate URLs"] = str(rec["Alternate URLs"] or "")
                did = raw.get("Doc ID")
                if not did:
                    pending_new_id.append(rec)
                    continue
                did = str(did)
                rec["Doc ID"] = did
                if did.startswith("D") and did[1:].isdigit():
                    max_n = max(max_n, int(did[1:]))
                url = rec["Reference URL"]
                if url not in docs_by_url:
                    docs_by_url[url] = rec
                else:
                    leftover_docs.append(rec)  # duplicate URL, keep verbatim rather than merge

            for rec in pending_new_id:
                max_n += 1
                rec["Doc ID"] = f"D{max_n:04d}"
                url = rec["Reference URL"]
                if url not in docs_by_url:
                    docs_by_url[url] = rec
                else:
                    leftover_docs.append(rec)

    return {"docs_by_url": docs_by_url, "leftover_docs": leftover_docs,
            "max_doc_n": max_n, "judgments": judgments, "identity": identity}


def _doc_sort_key(doc_id):
    # a tuple starting with an int keeps every key comparable, so a hand-typed ID that does not
    # follow the D#### pattern (e.g. NEW-SK-1) sorts after the well-formed ones instead of raising
    doc_id = str(doc_id)
    if doc_id.startswith("D") and doc_id[1:].isdigit():
        return (0, int(doc_id[1:]))
    return (1, doc_id)


# document identity
def _url_fingerprint(url) -> str:
    """A string that is the same for every address of one document, as far as can be told from the
    address alone. Two rules:

    * CISA ICS advisories keep their number (ICSA-15-181-01, ICSMA-20-170-04) through every site move,
      so cisa.gov and us-cert.gov addresses naming the same number are the same advisory. Only those
      two hosts count: a vendor PDF that merely has an advisory number in its file name is not the
      CISA advisory.
    * Any other address is compared after dropping the scheme, "www.", a trailing slash and the
      fragment, and ignoring case in the host.
    """
    url = str(url or "").strip()
    parts = urlsplit(url if "//" in url else "//" + url)
    host = (parts.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    if any(host == h or host.endswith("." + h) for h in _CISA_HOSTS):
        m = _CISA_ADVISORY_RE.search(parts.path)
        if m:
            return "cisa-advisory:" + m.group(1).lower()
    path = parts.path.rstrip("/")
    return f"url:{host}{path}" + (f"?{parts.query}" if parts.query else "")


def _split_alts(text) -> list:
    return [u.strip() for u in re.split(r"[\n;]+", str(text or "")) if u.strip()]


def _cited_doc_ids(judgments: dict) -> set:
    """Every D#### that appears in anything a person typed (rationales, notes, consensus text)."""
    out = set()
    for per_sheet in judgments.values():
        for cols in per_sheet.values():
            for v in cols.values():
                out.update(DOC_ID_RE.findall(str(v or "")))
    return out


def _merge_tags(*tag_strings) -> str:
    seen = []
    for t in tag_strings:
        for tag in str(t or "").split(", "):
            if tag and tag not in seen:
                seen.append(tag)
    return ", ".join(seen)


def _reconcile_documents(docs_by_url: dict, leftover_docs: list, tags_by_url_seen: dict,
                         next_n: int, cited_ids: set = frozenset()):
    """Decide the Reference_Documents rows. Returns (doc_rows, doc_id_of_url, next_n, report).

    Doc IDs are never reassigned and never reused. A URL cited by the CVE data is matched to an
    existing row in this order: exact Reference URL, an Alternate URL, then the same fingerprint
    (_url_fingerprint). A match through an address the row did not list yet is recorded in that row's
    Alternate URLs, so the link survives the next run too. Only a URL that matches nothing gets a new
    D####.

    Healing: a workbook that already holds two rows for one document (for example D0008 created by an
    earlier run for the old address of D0001) is folded into the row with the lower number, and the
    other row's URLs become Alternate URLs, unless the higher ID is cited in typed text, in which case
    both rows stay and the report says so.

    report = {"new": [(Doc ID, URL)], "aliased": [(Doc ID, URL)], "merged": [(kept, absorbed)],
              "kept_apart": [(kept, other)], "unlinked": [Doc ID, ...]}
    where "unlinked" are existing documents that no CVE cites by any known address.
    """
    report = {"new": [], "aliased": [], "merged": [], "kept_apart": [], "unlinked": []}
    existing = [dict(rec) for rec in docs_by_url.values()]
    for rec in existing:
        rec["_alts"] = [u for u in _split_alts(rec.get("Alternate URLs")) if u != rec["Reference URL"]]

    def fps(rec):
        return {_url_fingerprint(u) for u in [rec["Reference URL"]] + rec["_alts"]}

    # 1. fold duplicate rows of one document into the lowest-numbered one
    by_id = sorted(existing, key=lambda r: _doc_sort_key(r["Doc ID"]))
    keepers, absorbed_ids = [], set()
    for rec in by_id:
        twin = next((k for k in keepers if fps(k) & fps(rec)), None)
        if twin is None:
            keepers.append(rec)
        elif rec["Doc ID"] in cited_ids:
            report["kept_apart"].append((twin["Doc ID"], rec["Doc ID"]))
            keepers.append(rec)
        else:
            for u in [rec["Reference URL"]] + rec["_alts"]:
                if u != twin["Reference URL"] and u not in twin["_alts"]:
                    twin["_alts"].append(u)
            twin["Advisory Tag"] = _merge_tags(twin.get("Advisory Tag"), rec.get("Advisory Tag"))
            absorbed_ids.add(rec["Doc ID"])
            report["merged"].append((twin["Doc ID"], rec["Doc ID"]))
    existing = [r for r in existing if r["Doc ID"] not in absorbed_ids]    # keeps the sheet's own order

    # 2. link each URL the CVE data cites to an existing row, or give it a new ID
    def find(url):
        for rec in existing:
            if url == rec["Reference URL"] or url in rec["_alts"]:
                return rec, False
        fp = _url_fingerprint(url)
        for rec in existing:
            if fp in fps(rec):
                return rec, True
        return None, False

    doc_id_of_url, matched_ids, new_rows = {}, set(), []
    for url, tags in tags_by_url_seen.items():
        rec, via_fingerprint = find(url)
        if rec is not None:
            matched_ids.add(rec["Doc ID"])
            doc_id_of_url[url] = rec["Doc ID"]
            if via_fingerprint:
                rec["_alts"].append(url)
                report["aliased"].append((rec["Doc ID"], url))
            continue
        did = f"D{next_n:04d}"
        next_n += 1
        doc_id_of_url[url] = did
        new_rows.append({"Doc ID": did, "Advisory Tag": ", ".join(sorted(tags)),
                         "Reference URL": url, "Alternate URLs": ""})
        report["new"].append((did, url))

    # 3. same row order as before: documents the data cites, then new ones, then everything else
    def out(rec):
        row = {c: rec.get(c, "") for c in DOC_COLS}
        row["Alternate URLs"] = "\n".join(rec.get("_alts", _split_alts(rec.get("Alternate URLs"))))
        return row

    doc_rows = [out(r) for r in existing if r["Doc ID"] in matched_ids]
    doc_rows += new_rows
    for r in existing:
        if r["Doc ID"] not in matched_ids:
            report["unlinked"].append(r["Doc ID"])
            doc_rows.append(out(r))
    doc_rows += [out(rec) for rec in leftover_docs]
    return doc_rows, doc_id_of_url, next_n, report


# path + document tables, merged against any existing workbook
def _build_tables(P: pd.DataFrame, key_cols: dict, ordered_tactics: list, cve_refs: dict,
                   existing: dict):
    leaf_index = atl.build_leaf_index(P, key_cols, ordered_tactics, mode="per_tactic")

    docs_by_url = existing.get("docs_by_url", {})
    leftover_docs = list(existing.get("leftover_docs", []))
    next_n = existing.get("max_doc_n", 0) + 1
    old_judgments = existing.get("judgments", {s: {} for s in SOURCES})
    old_identity = existing.get("identity", {s: {} for s in SOURCES})
    drifted = []            # [{"path_id", "sheet", "old_identity", "new_identity", "old_judgment"}, ...]

    path_rows, key_count = [], {}
    # Reference URL -> tags seen this run, in first-seen order. The first path that cites a URL fixes
    # its row position on the documents sheet, which keeps a from-scratch rebuild identical from run to run.
    tags_by_url_seen = {}
    path_n = 0

    for tactic in ordered_tactics:
        cwes = leaf_index.leaves_by_tactic.get(tactic, {})
        for cwe_key, records in cwes.items():
            for rec in records:
                path_key = (rec.cwe_key, rec.parent_technique_key, rec.technique_key, rec.capec_key)
                key_count[path_key] = key_count.get(path_key, 0) + 1

                path_n += 1
                path_id = f"P{path_n:03d}"
                cves = _supporting_cves(P, key_cols, rec, tactic)
                new_identity = ("|".join(path_key), tactic)

                # every reference URL cited by this path's supporting CVEs feeds the document list. Several
                # CVEs often cite the same advisory; it is one document, tracked once in tags_by_url_seen.
                for cve_id in cves:
                    for url, tags in cve_refs.get(cve_id, []):
                        tags_by_url_seen.setdefault(url, set()).update(
                            t for t in tags.split(", ") if t)

                row = {
                    "Path ID": path_id, "Tactic": tactic,
                    "CWE ID": rec.cwe_key, "CWE Name": rec.cwe_name,
                    "Technique": rec.parent_technique_key, "Technique Name": rec.parent_technique_name,
                    "Sub-technique": rec.subtechnique_name,
                    "CAPEC ID": rec.capec_key, "CAPEC Name": rec.capec_name,
                    "CVE(s)": ", ".join(cves),
                    "Path Key": "|".join(path_key),
                    "_path_key": path_key,          # internal, dropped before writing
                    "Cross-Tactic Repeat": "",       # filled in below once counts are known
                }
                # a Path ID that now points at a different path: compare what it meant last time (Path
                # Key + Tactic on that sheet) with what it computes to now. If they differ, what was
                # typed under it describes another path and is not carried over.
                for src in SOURCES:
                    prev_identity = old_identity.get(src, {}).get(path_id)
                    prev = old_judgments.get(src, {}).get(path_id, {})
                    stale = prev_identity is not None and prev_identity != new_identity
                    if stale and any(v not in ("", None) for v in prev.values()):
                        drifted.append({"path_id": path_id, "sheet": src,
                                        "old_identity": prev_identity, "new_identity": new_identity,
                                        "old_judgment": prev})
                    keep = {} if stale else prev
                    if src in ANNOTATORS:
                        for c in JUDGMENT_COLS:
                            row[f"{src} {c}"] = keep.get(c, "")
                    else:
                        for c in CONSENSUS_TYPED:
                            row[c] = keep.get(c, "")
                path_rows.append(row)

    # resolve the global document list (see _reconcile_documents): a document keeps its Doc ID and row
    # even when its URL was renamed, a URL that matches nothing gets the next D####, and rows nothing
    # cites any more (hand-added, or no longer in the CVE data) stay at the end instead of being dropped.
    doc_rows, _, next_n, doc_report = _reconcile_documents(
        docs_by_url, leftover_docs, tags_by_url_seen, next_n, _cited_doc_ids(old_judgments))

    for row in path_rows:
        row["Cross-Tactic Repeat"] = "Yes" if key_count[row["_path_key"]] > 1 else "No"

    path_df = pd.DataFrame(path_rows)
    path_df.attrs["key_count"] = key_count
    path_df.attrs["drifted"] = drifted
    path_df.attrs["doc_report"] = doc_report

    doc_df = pd.DataFrame(doc_rows, columns=DOC_COLS)
    return path_df, doc_df


# excel styling (same conventions as excel_report.py)
def _style_header(cell):
    cell.font = Font(bold=True, color=C_HEADER_FG, name="Calibri", size=10)
    cell.fill = PatternFill("solid", fgColor=C_HEADER_BG)
    cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
    cell.border = _border


def _style_data(cell):
    cell.font = Font(name="Calibri", size=10)
    cell.alignment = Alignment(vertical="top", wrap_text=True)
    cell.border = _border


def _autofit(ws, min_w=10, max_w=60):
    for col in ws.columns:
        length = max((len(str(c.value or "")) for c in col), default=0)
        ws.column_dimensions[get_column_letter(col[0].column)].width = min(max(length + 2, min_w), max_w)


def _add_dropdown(ws, col_index: int, n_rows: int, choices: list):
    formula = '"' + ",".join(choices) + '"'
    dv = DataValidation(type="list", formula1=formula, allow_blank=True)
    ws.add_data_validation(dv)
    col = get_column_letter(col_index)
    dv.add(f"{col}2:{col}{n_rows + 1}")


def _write_annotation_sheet(sheet, annotator, path_df, color_of):
    for ci, h in enumerate(PATH_COLS, 1):
        _style_header(sheet.cell(row=1, column=ci, value=h))
    for ri, row in enumerate(path_df.to_dict("records"), 2):
        path_key = row["_path_key"]
        fill = PatternFill("solid", fgColor=color_of[path_key]) if path_key in color_of else None
        for ci, col in enumerate(PATH_COLS, 1):
            value = row[f"{annotator} {col}"] if col in JUDGMENT_COLS else row[col]
            cell = sheet.cell(row=ri, column=ci, value=value)
            _style_data(cell)
            if fill and col not in JUDGMENT_COLS:
                cell.fill = fill
    sheet.freeze_panes = "A2"
    sheet.auto_filter.ref = sheet.dimensions
    sheet.row_dimensions[1].height = 26
    _autofit(sheet)
    for letter, width in zip(JUDGMENT_LETTERS, (28, 60, 40)):
        sheet.column_dimensions[letter].width = width
    _add_dropdown(sheet, PATH_COLS.index("Validation") + 1, len(path_df), VALIDATION_CHOICES)


def _write_consensus_sheet(sheet, path_df, color_of):
    n = len(path_df)
    last = n + 1
    col = {name: get_column_letter(i + 1) for i, name in enumerate(CONSENSUS_COLS)}
    val_letter, rat_letter = JUDGMENT_LETTERS[0], JUDGMENT_LETTERS[1]

    def pull(annotator, source_letter, r):
        s = ANNOTATION_SHEETS[annotator]
        ids = f"{s}!$A$2:$A${last}"
        src = f"{s}!${source_letter}$2:${source_letter}${last}"
        return f'=IFERROR(INDEX({src},MATCH($A{r},{ids},0))&"","")'

    for ci, h in enumerate(CONSENSUS_COLS, 1):
        _style_header(sheet.cell(row=1, column=ci, value=h))
    sheet[f"{col['Consensus Label']}1"].comment = Comment(
        "Filled in automatically when A1 and A2 gave the same label. On a Discuss row, type the "
        "label both annotators agree on.", "cve2at")
    sheet[f"{col['Consensus Rationale']}1"].comment = Comment(
        "Filled in automatically when the labels match. On a Discuss row, type the reason both "
        "annotators accept.", "cve2at")

    cL, cR, cS = col["Consensus Label"], col["Consensus Rationale"], col["Status"]
    for ri, row in enumerate(path_df.to_dict("records"), 2):
        a1, a2 = col["A1 Validation"], col["A2 Validation"]
        values = {
            "Path ID": row["Path ID"], "Tactic": row["Tactic"], "Path Key": row["Path Key"],
            "A1 Validation": pull("A1", val_letter, ri), "A2 Validation": pull("A2", val_letter, ri),
            "A1 Rationale": pull("A1", rat_letter, ri), "A2 Rationale": pull("A2", rat_letter, ri),
            "Consensus Label": row["Consensus Label"] or f'=IF(AND({a1}{ri}<>"",{a1}{ri}={a2}{ri}),{a1}{ri},"")',
            "Consensus Rationale": row["Consensus Rationale"] or f'=IF({cS}{ri}="Agree","{AGREE_TEXT}","")',
            "Status": (f'=IF(OR({a1}{ri}="",{a2}{ri}=""),"Pending",IF({a1}{ri}={a2}{ri},"Agree",'
                       f'IF({cL}{ri}="","Discuss","Resolved")))'),
        }
        fill = PatternFill("solid", fgColor=color_of[row["_path_key"]]) if row["_path_key"] in color_of else None
        for ci, name in enumerate(CONSENSUS_COLS, 1):
            cell = sheet.cell(row=ri, column=ci, value=values[name])
            _style_data(cell)
            if name in ("Path ID", "Tactic", "Path Key") and fill:
                cell.fill = fill
            elif name in CONSENSUS_TYPED:
                cell.fill = PatternFill("solid", fgColor=C_INPUT_BG)
            elif name not in ("Path ID", "Tactic", "Path Key"):
                cell.fill = PatternFill("solid", fgColor=C_AUTO_BG)

    status_rng = f"{cL}2:{cR}{last}"
    sheet.conditional_formatting.add(status_rng, FormulaRule(
        formula=[f'${cS}2="Discuss"'], fill=PatternFill("solid", bgColor=C_DISCUSS_BG)))
    sheet.conditional_formatting.add(f"{cS}2:{cS}{last}", FormulaRule(
        formula=[f'${cS}2="Discuss"'], fill=PatternFill("solid", bgColor=C_DISCUSS_BG)))
    sheet.conditional_formatting.add(f"{cS}2:{cS}{last}", FormulaRule(
        formula=[f'${cS}2="Resolved"'], fill=PatternFill("solid", bgColor=C_RESOLVED_BG)))
    sheet.freeze_panes = "C2"
    sheet.auto_filter.ref = sheet.dimensions
    sheet.row_dimensions[1].height = 26
    for name, width in zip(CONSENSUS_COLS, (10, 22, 28, 28, 60, 60, 28, 60, 35, 12)):
        sheet.column_dimensions[col[name]].width = width
    _add_dropdown(sheet, CONSENSUS_COLS.index("Consensus Label") + 1, n, VALIDATION_CHOICES)


def _write_results_sheet(sheet, n_paths, ordered_tactics):
    """The label table and the agreement statistics, all as formulas over the Consensus sheet.
    Returns the last row of the label table (the Percent of all paths row)."""
    last = n_paths + 1
    col = {name: get_column_letter(i + 1) for i, name in enumerate(CONSENSUS_COLS)}

    def rng(name):
        return f"{CONSENSUS_SHEET}!${col[name]}$2:${col[name]}${last}"

    tac, a1, a2, cons, key = rng("Tactic"), rng("A1 Validation"), rng("A2 Validation"), \
        rng("Consensus Label"), rng("Path Key")
    w = f"COUNTIF({key},{key})"          # each Path Key counts once, however many tactics repeat it
    labels = VALIDATION_CHOICES

    def put(ref, value, bold=False, fmt=None, header=False, wrap=False):
        c = sheet[ref]
        c.value = value
        if header:
            _style_header(c)
            return c
        c.font = Font(name="Calibri", size=10, bold=bold)
        c.border = _border
        c.alignment = Alignment(vertical="top", wrap_text=wrap)
        if fmt:
            c.number_format = fmt
        return c

    def title(row, text):
        sheet[f"A{row}"].value = text
        sheet[f"A{row}"].font = Font(name="Calibri", size=11, bold=True)

    # label table: consensus labels per tactic
    title(1, f"Validation of the {n_paths} paths (consensus labels)")
    for ci, h in enumerate(["Tactic"] + labels + ["Total"]):
        put(f"{get_column_letter(ci + 1)}2", h, header=True)
    first = 3
    for i, tactic in enumerate(ordered_tactics):
        r = first + i
        put(f"A{r}", tactic)
        for L in "BCD":
            put(f"{L}{r}", f"=COUNTIFS({tac},$A{r},{cons},{L}$2)")
        put(f"E{r}", f"=SUM(B{r}:D{r})")
    tot = first + len(ordered_tactics)
    pct = tot + 1
    put(f"A{tot}", "Total", bold=True)
    for L in "BCDE":
        put(f"{L}{tot}", f"=SUM({L}{first}:{L}{tot - 1})", bold=True)
    put(f"A{pct}", "Percent of all paths", bold=True)
    for L in "BCD":
        put(f"{L}{pct}", f'=IF($E${tot}=0,"",{L}{tot}/$E${tot})', fmt="0.0%")
    put(f"E{pct}", f'=IF($E${tot}=0,"",SUM(B{pct}:D{pct}))', fmt="0.0%")
    put(f"A{pct + 1}", "Paths without a consensus label yet")
    put(f"B{pct + 1}", f"={n_paths}-E{tot}")

    # agreement between the two annotators, before consensus
    s = pct + 3
    title(s, "Inter-annotator agreement between the two annotators, A1 and A2")
    put(f"A{s + 1}", "What the two annotators said", header=True)
    put(f"B{s + 1}", f"Paths (all {n_paths})", header=True)
    put(f"C{s + 1}", "Unique path keys", header=True)
    r_both = {lab: s + 2 + i for i, lab in enumerate(labels)}
    r_diff, r_tot, r_agree, r_pct, r_chance, r_kappa = (s + 5, s + 6, s + 7, s + 8, s + 9, s + 10)

    for lab, r in r_both.items():
        put(f"A{r}", f"Both said {lab}")
        put(f"B{r}", f'=COUNTIFS({a1},"{lab}",{a2},"{lab}")')
        put(f"C{r}", f'=ROUND(SUMPRODUCT(({a1}="{lab}")*({a2}="{lab}")/{w}),6)')
    put(f"A{r_diff}", "Different labels")
    put(f"A{r_tot}", "Paths labelled by both annotators", bold=True)
    put(f"A{r_agree}", "Number where A1 and A2 agree")
    put(f"A{r_pct}", "Percent agreement")
    put(f"A{r_chance}", "Agreement expected by chance")
    put(f"A{r_kappa}", "Cohen's kappa", bold=True)
    put(f"B{r_tot}", f'=SUMPRODUCT(({a1}<>"")*({a2}<>""))', bold=True)
    put(f"C{r_tot}", f'=ROUND(SUMPRODUCT(({a1}<>"")*({a2}<>"")/{w}),6)', bold=True)
    chance_paths = "+".join(
        f'SUMPRODUCT(({a1}="{lab}")*({a2}<>""))*SUMPRODUCT(({a2}="{lab}")*({a1}<>""))' for lab in labels)
    chance_keys = "+".join(
        f'SUMPRODUCT(({a1}="{lab}")*({a2}<>"")/{w})*SUMPRODUCT(({a2}="{lab}")*({a1}<>"")/{w})'
        for lab in labels)
    for L, chance in (("B", chance_paths), ("C", chance_keys)):
        put(f"{L}{r_diff}", f"={L}{r_tot}-{L}{r_agree}")
        put(f"{L}{r_agree}", f"=SUM({L}{r_both[labels[0]]}:{L}{r_both[labels[-1]]})")
        put(f"{L}{r_pct}", f'=IFERROR({L}{r_agree}/{L}{r_tot},"")', fmt="0.0%")
        put(f"{L}{r_chance}", f'=IFERROR(({chance})/{L}{r_tot}^2,"")', fmt="0.000")
        put(f"{L}{r_kappa}", f'=IFERROR(({L}{r_pct}-{L}{r_chance})/(1-{L}{r_chance}),"")',
            bold=True, fmt="0.000")
    put(f"A{r_kappa + 1}", "Unique path keys count each Path Key once, however many tactics repeat it.")
    sheet[f"A{r_kappa + 1}"].font = Font(name="Calibri", size=9, italic=True)
    sheet[f"A{r_kappa + 1}"].border = Border()

    # cross-tab of A1 against A2
    x = r_kappa + 3
    title(x, "A1 (rows) against A2 (columns), all paths")
    put(f"A{x + 1}", "A1 \\ A2", header=True)
    for ci, lab in enumerate(labels):
        put(f"{get_column_letter(ci + 2)}{x + 1}", lab, header=True)
    put(f"E{x + 1}", "Total", header=True)
    for i, lab in enumerate(labels):
        r = x + 2 + i
        put(f"A{r}", lab)
        for L in "BCD":
            put(f"{L}{r}", f"=COUNTIFS({a1},$A{r},{a2},{L}${x + 1})")
        put(f"E{r}", f"=SUM(B{r}:D{r})")
    xt = x + 2 + len(labels)
    put(f"A{xt}", "Total", bold=True)
    for L in "BCDE":
        put(f"{L}{xt}", f"=SUM({L}{x + 2}:{L}{xt - 1})", bold=True)

    # how the disagreements ended
    d = xt + 3
    title(d, "Consensus outcome on disputed keys")
    put(f"A{d + 1}", "", header=True)
    put(f"B{d + 1}", "Unique path keys", header=True)
    put(f"C{d + 1}", "Paths", header=True)
    disputed = f'({a1}<>"")*({a2}<>"")*({a1}<>{a2})'
    rows = [("Keys where A1 and A2 disagreed", "")] + \
           [(f"Consensus label: {lab}", f'*({cons}="{lab}")') for lab in labels] + \
           [("Disagreed, no consensus label yet", f'*({cons}="")')]
    for i, (text, extra) in enumerate(rows):
        r = d + 2 + i
        put(f"A{r}", text)
        put(f"B{r}", f"=ROUND(SUMPRODUCT({disputed}{extra}/{w}),6)")
        put(f"C{r}", f"=SUMPRODUCT({disputed}{extra})")

    sheet.column_dimensions["A"].width = 52
    for L in "BCDE":
        sheet.column_dimensions[L].width = 24
    sheet.row_dimensions[2].height = 30
    return pct


def _dangling_citations(path_df: pd.DataFrame, doc_df: pd.DataFrame) -> list:
    """[(sheet, Path ID, Doc ID)] for every D#### written in a rationale or note that has no row on the
    Reference_Documents sheet. Catches a document that was renumbered, removed or never added."""
    known = set(doc_df["Doc ID"].astype(str))
    fields = {"A1": ["A1 Validation Rationale", "A1 Notes"], "A2": ["A2 Validation Rationale", "A2 Notes"],
              CONSENSUS_SHEET: ["Consensus Rationale"]}
    out = []
    for row in path_df.to_dict("records"):
        for sheet, cols in fields.items():
            ids = set()
            for c in cols:
                ids.update(DOC_ID_RE.findall(str(row.get(c, "") or "")))
            out += [(sheet, row["Path ID"], d) for d in sorted(ids - known)]
    return out


def _report_documents(doc_report: dict, had_existing: bool):
    for kept, other in doc_report["merged"]:
        console.info(f"Reference_Documents: {other} was a second row for the same document as {kept}; "
                     f"folded into {kept} (its address is now under Alternate URLs).")
    for kept, other in doc_report["kept_apart"]:
        console.warn(f"Reference_Documents: {other} looks like the same document as {kept}, but {other} is "
                     "cited in a rationale or note, so both rows were kept. Merge them by hand if you "
                     "want one.")
    for did, url in doc_report["aliased"]:
        console.info(f"Reference_Documents: the CVE data cites {url}, recognised as {did} under another "
                     "address; recorded under Alternate URLs.")
    if had_existing and doc_report["new"]:
        orphans = ", ".join(doc_report["unlinked"]) or "none"
        for did, url in doc_report["new"]:
            console.warn(f"Reference_Documents: new document {did} created for {url}. If this is a renamed "
                         "or moved copy of a document you already have, add the address to that row's "
                         f"Alternate URLs and re-run. Existing rows no CVE cites by any known address: "
                         f"{orphans}.")


def _backup_existing(out_path):
    """Copy the workbook about to be replaced into validation/backups/ and keep the newest few."""
    if not os.path.isfile(out_path):
        return None
    folder = os.path.join(os.path.dirname(out_path), "backups")
    os.makedirs(folder, exist_ok=True)
    stem = os.path.splitext(os.path.basename(out_path))[0]
    dest = os.path.join(folder, f"{stem}.{datetime.now():%Y%m%d-%H%M%S}.xlsx")
    shutil.copy2(out_path, dest)
    mine = sorted(f for f in os.listdir(folder) if f.startswith(stem + ".") and f.endswith(".xlsx"))
    for old in mine[:-BACKUP_KEEP]:
        os.remove(os.path.join(folder, old))
    return dest


def build_validation_workbook(ws: Workspace, out_path=None) -> dict:
    if not ws.compromise_dataset_xlsx.is_file():
        raise PipelineError(f"'{ws.compromise_dataset_xlsx}' not found. Run the merge stage first.")

    out_path = out_path or (ws.root / "validation" / "validation_paths.xlsx")

    console.step("Load curated relation P")
    _, key_cols, P, ordered_tactics = _load_curated(ws.compromise_dataset_xlsx)

    console.step("Load CVE references already downloaded by the fetch stage")
    cve_refs = _load_cve_references(ws)

    console.step("Check for an existing validation_paths.xlsx to merge against")
    existing = _load_existing_workbook(out_path)
    kept = {s: sum(1 for j in existing.get("judgments", {}).get(s, {}).values()
                   if any(v not in ("", None) for v in j.values())) for s in SOURCES}
    if existing:
        n_docs = len(existing["docs_by_url"]) + len(existing["leftover_docs"])
        console.info(f"Found existing workbook: preserving {n_docs} document(s), "
                     f"{kept['A1']} A1 and {kept['A2']} A2 coded path(s) and "
                     f"{kept[CONSENSUS_SHEET]} typed consensus row(s).")

    console.step("Build one row per (w,k,s,c,t) attack path, and the deduplicated document list")
    path_df, doc_df = _build_tables(P, key_cols, ordered_tactics, cve_refs, existing)
    key_count = path_df.attrs["key_count"]
    repeated_keys = [k for k, n in key_count.items() if n > 1]
    color_of = {k: REPEAT_PALETTE[i % len(REPEAT_PALETTE)] for i, k in enumerate(repeated_keys)}

    drifted = path_df.attrs.get("drifted", [])
    if drifted:
        console.warn(f"{len(drifted)} entry(ies) were filed under a Path ID that now refers to a "
                     "different exploitation chain (the dataset's enumeration order shifted, e.g. "
                     "a new CVE or an updated CTI dataset). They were NOT carried over. Re-enter these:")
        for d in drifted:
            old_key, old_tactic = d["old_identity"]
            new_key, new_tactic = d["new_identity"]
            console.warn(f"  {d['path_id']} on {d['sheet']}: was [{old_tactic}] {old_key}  ->  now "
                         f"[{new_tactic}] {new_key}  (lost: {d['old_judgment']})")

    _report_documents(path_df.attrs["doc_report"], bool(existing))
    dangling = _dangling_citations(path_df, doc_df)
    if dangling:
        console.warn(f"{len(dangling)} rationale/note citation(s) name a Doc ID that is not on the "
                     f"{DOC_SHEET_NAME} sheet:")
        for sheet, pid, did in dangling:
            console.warn(f"  {did} cited on {sheet} {pid}")

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    n_paths = len(path_df)

    wb = Workbook()
    wb.calculation = CalcProperties(fullCalcOnLoad=True)

    # Sheets 1 and 2: Consensus and Results
    ws_cons = wb.active
    ws_cons.title = CONSENSUS_SHEET
    _write_consensus_sheet(ws_cons, path_df, color_of)
    ws_res = wb.create_sheet(RESULTS_SHEET)
    label_table_last_row = _write_results_sheet(ws_res, n_paths, ordered_tactics)

    # Sheets 3 and 4: one annotation form per annotator
    for a in ANNOTATORS:
        _write_annotation_sheet(wb.create_sheet(ANNOTATION_SHEETS[a]), a, path_df, color_of)

    # Sheet 5: Reference_Documents
    ws2 = wb.create_sheet(DOC_SHEET_NAME)
    for ci, h in enumerate(DOC_SHEET_COLS, 1):
        _style_header(ws2.cell(row=1, column=ci, value=h))
    rat = JUDGMENT_LETTERS[1]                                  # Validation Rationale column (O)
    last_path_row = n_paths + 1
    for ri, row in enumerate(doc_df.to_dict("records"), 2):
        for ci, col in enumerate(DOC_COLS, 1):
            _style_data(ws2.cell(row=ri, column=ci, value=row[col]))
        # Paths Citing: how many paths have this Doc ID written in either annotator's rationale. A formula
        # keyed on the Doc ID, so it stays right when a URL is renamed and is never typed over.
        cites = "+".join(
            f"ISNUMBER(SEARCH($A{ri},'{ANNOTATION_SHEETS[a]}'!${rat}$2:${rat}${last_path_row}))"
            for a in ANNOTATORS)
        cell = ws2.cell(row=ri, column=len(DOC_COLS) + 1,
                        value=f'=IF($A{ri}="","",SUMPRODUCT(--(({cites})>0)))' if row["Doc ID"] else "")
        _style_data(cell)
        cell.fill = PatternFill("solid", fgColor=C_AUTO_BG)
    ws2.freeze_panes = "A2"
    ws2.auto_filter.ref = ws2.dimensions
    _autofit(ws2)
    ws2.column_dimensions[get_column_letter(len(DOC_COLS) + 1)].width = 14
    n_docs = len(doc_df)

    # Sheet 6: Labeling_Guide (static definitions, travels with the workbook)
    ws3 = wb.create_sheet(GUIDE_SHEET_NAME)
    for ci, h in enumerate(("Term", "Definition"), 1):
        c = ws3.cell(row=1, column=ci, value=h)
        c.fill = PatternFill("solid", fgColor=C_HEADER_BG)
        c.font = Font(bold=True, color=C_HEADER_FG, name="Calibri", size=11)
    for ri, (term, definition) in enumerate(_coding_guide(label_table_last_row), 2):
        term_cell = ws3.cell(row=ri, column=1, value=term)
        ws3.cell(row=ri, column=2, value=definition)
        if term and not definition:  # section heading row
            term_cell.font = Font(bold=True, name="Calibri", size=10)
            term_cell.fill = PatternFill("solid", fgColor="E8EDF3")
        else:
            term_cell.font = Font(bold=bool(term), name="Calibri", size=10)
        term_cell.alignment = Alignment(wrap_text=True, vertical="top")
        ws3.cell(row=ri, column=2).alignment = Alignment(wrap_text=True, vertical="top")
    ws3.column_dimensions["A"].width = 40
    ws3.column_dimensions["B"].width = 100

    backup = _backup_existing(out_path)
    wb.save(out_path)
    if backup:
        console.info(f"Previous workbook copied to: {backup}")
    n_repeat = int(sum(1 for k in path_df["_path_key"] if k in color_of))
    console.info(f"Saved: {out_path}")
    console.headline("Total paths", n_paths)
    console.headline("Paths that recur across tactics (colored)", n_repeat)
    console.headline("Reference documents", n_docs)
    console.info(f"Annotators fill {ANNOTATION_SHEETS['A1']} / {ANNOTATION_SHEETS['A2']}, columns "
                 f"{JUDGMENT_LETTERS[0]} to {JUDGMENT_LETTERS[-1]}. The {CONSENSUS_SHEET} sheet fills itself; "
                 f"type a label only where its Status says Discuss.")
    console.info(f"The label table is {RESULTS_SHEET}!A1:E{label_table_last_row}.")

    return {
        "total_paths": int(n_paths),
        "cross_tactic_repeat_paths": n_repeat,
        "distinct_repeated_keys": len(repeated_keys),
        "reference_document_rows": int(n_docs),
        "output_path": str(out_path),
        "label_table_range": f"A1:E{label_table_last_row}",
        "stale_path_ids": drifted,
        "document_changes": path_df.attrs["doc_report"],
        "dangling_doc_citations": dangling,
        "backup_path": backup,
    }