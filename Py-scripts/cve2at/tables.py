"""CVE, CWE and CAPEC tables built from the pipeline output.

    cves.csv    CVE records: CVE ID, CVSS vector, CWE, base score, exploitability, affected components
    cwes.csv    CWE classes the CVEs reference, with a Retained flag
    capecs.csv  CAPEC patterns reachable from the retained CWEs

Only the tabulate stage has to have run. The CVE table reads cve_data.xlsx and cve_data_formated.xlsx,
the CWE table reads cve_data.xlsx and cwe_data.xlsx, and the CAPEC table reads the CWE table and
capec_data.xlsx. Nothing here changes another stage's output.

The CWE table also lists CWEs that the merge stage later drops (deprecated, no related CAPEC, or
missing from the reference set). "Retained" is True for the ones that continue the
CVE -> CWE -> CAPEC chain. The CAPEC table uses retained CWEs only, so it can list more CAPEC patterns
than reach the trees: the CAPEC -> ATT&CK step can still drop patterns.

"Affected Components" is rebuilt from every CPE match NVD attaches to the CVE, grouped by
product and version.
"""
from __future__ import annotations

import pandas as pd

from . import console
from .config import Workspace, check_reference_files
from .errors import DatasetError, PipelineError

EM_DASH = "\u2014"


def _require(df: pd.DataFrame, columns, where: str) -> None:
    missing = [c for c in columns if c not in df.columns]
    if missing:
        raise DatasetError(f"{where} is missing required column(s): {', '.join(missing)}")


def _format_affected_components(cfg_df: pd.DataFrame) -> pd.Series:
    """One 'Product (versions); Product (versions)' string per CVE, from every CPE match row and
    not only those flagged vulnerable: a WBM version counts as affected even when NVD marks it as
    the platform the vulnerable firmware runs on.
    """
    df = cfg_df.copy()
    df["Version"] = df["Version"].fillna("").astype(str).str.strip()

    def fmt(group: pd.DataFrame) -> str:
        parts = []
        for product, sub in group.groupby("Product / Component", sort=False):
            versions = sorted({v for v in sub["Version"] if v not in ("", "-", "*")})
            parts.append(f"{product} ({', '.join(versions)})" if versions else str(product))
        return "; ".join(dict.fromkeys(parts))   # de-dup, keep first-seen order

    if df.empty:
        return pd.Series(dtype=str)
    return df.groupby("CVE ID", sort=False).apply(fmt)


def build_cve_table(ws: Workspace) -> pd.DataFrame:
    """CVE table: CVE ID, CVSS Vector, CWE, Base, Expl., Affected Components."""
    if not ws.cve_xlsx.is_file() or not ws.formatted_xlsx.is_file():
        raise PipelineError(
            f"'{ws.cve_xlsx.name}' / '{ws.formatted_xlsx.name}' not found in '{ws.root}'. "
            "Run the tabulate stage first (`cve2at tabulate ...`).")

    cve = pd.read_excel(ws.cve_xlsx)
    _require(cve, ["CVE ID", "Weaknesses", "baseScore", "exploitabilityScore"], ws.cve_xlsx.name)
    main = pd.read_excel(ws.formatted_xlsx, sheet_name="CVE Summary")
    _require(main, ["CVE ID", "Vector String"], f"{ws.formatted_xlsx.name} [CVE Summary]")
    cfg = pd.read_excel(ws.formatted_xlsx, sheet_name="Affected Components")

    vector = (main.set_index("CVE ID")["Vector String"].astype(str)
              .str.replace(r"^CVSS:[\d.]+/", "", regex=True))
    components = _format_affected_components(cfg)

    df = pd.DataFrame({
        "CVE ID": cve["CVE ID"],
        "CVSS Vector": cve["CVE ID"].map(vector).fillna(""),
        "CWE": cve["Weaknesses"].fillna("").str.replace("; ", ", ", regex=False),
        "Base": cve["baseScore"],
        "Expl.": cve["exploitabilityScore"],
        "Affected Components": cve["CVE ID"].map(components).fillna(""),
    })
    return df.sort_values("CVE ID", ignore_index=True)


def build_cwe_table(ws: Workspace, datasets_dir) -> pd.DataFrame:
    """CWE table: CWE, Name, Abstraction, Status, Likelihood, #CVE, Related CAPEC, Retained."""
    if not ws.cve_xlsx.is_file():
        raise PipelineError(f"'{ws.cve_xlsx.name}' not found in '{ws.root}'. Run the tabulate stage first.")
    ref = check_reference_files(datasets_dir)
    cwe_ref = pd.read_excel(ref["cwe"])
    _require(cwe_ref, ["CWE_ID", "Name", "Abstraction", "Status",
                       "Likelihood_Of_Exploit", "Related_Attack_Patterns"], ref["cwe"].name)
    cwe_ref = cwe_ref.copy()
    cwe_ref["CWE_ID"] = cwe_ref["CWE_ID"].astype(str).str.strip()

    cve = pd.read_excel(ws.cve_xlsx)
    _require(cve, ["CVE ID", "Weaknesses"], ws.cve_xlsx.name)
    w = cve[["CVE ID", "Weaknesses"]].copy()
    w["Weaknesses"] = w["Weaknesses"].fillna("").str.split("; ")
    w = w.explode("Weaknesses")
    w["Weaknesses"] = w["Weaknesses"].str.replace("CWE-", "", regex=False).str.strip()
    w = w[w["Weaknesses"] != ""]
    if w.empty:
        raise PipelineError("No CVE in this workspace has a usable CWE mapping.")

    counts = w.groupby("Weaknesses")["CVE ID"].nunique().rename("num_cve").reset_index()
    merged = counts.merge(cwe_ref, left_on="Weaknesses", right_on="CWE_ID", how="left")

    def related_capec(v) -> str:
        if pd.isna(v) or not str(v).strip():
            return ""
        ids = sorted({int(x) for x in str(v).split(",") if x.strip()})
        return ", ".join(str(i) for i in ids)

    merged["Related CAPEC"] = merged["Related_Attack_Patterns"].apply(related_capec)
    in_reference = merged["CWE_ID"].notna()
    contributes = (in_reference
                   & (merged["Related CAPEC"] != "")
                   & (merged["Status"].astype(str).str.lower() != "deprecated"))

    out = pd.DataFrame({
        "CWE": "CWE-" + merged["Weaknesses"],
        "Name": merged["Name"].fillna("(not in reference dataset)"),
        "Abstraction": merged["Abstraction"].fillna(""),
        "Status": merged["Status"].fillna(""),
        "Likelihood": merged["Likelihood_Of_Exploit"].fillna(""),
        "#CVE": merged["num_cve"],
        "Related CAPEC": merged["Related CAPEC"].where(merged["Related CAPEC"] != "", EM_DASH),
        "Retained": contributes,  # reaches CAPEC; the ATT&CK mapping can still drop it later
    })
    out["_sort"] = merged["Weaknesses"].astype(int)
    return out.sort_values("_sort", ignore_index=True).drop(columns="_sort")


def build_capec_table(cwe_table: pd.DataFrame, datasets_dir) -> pd.DataFrame:
    """CAPEC table: CAPEC, Name, Abstraction, Likelihood, Severity - for every CAPEC pattern
    reachable from the CWEs where the CWE table's 'Retained' column is True."""
    if "Retained" not in cwe_table.columns:
        raise PipelineError("build_capec_table() needs the DataFrame returned by build_cwe_table().")
    ref = check_reference_files(datasets_dir)
    capec_ref = pd.read_excel(ref["capec"])
    _require(capec_ref, ["CAPEC_ID", "Name", "Abstraction", "Status",
                         "Likelihood_Of_Attack", "Typical_Severity"], ref["capec"].name)
    capec_ref = capec_ref.copy()
    capec_ref["CAPEC_ID"] = capec_ref["CAPEC_ID"].astype(str).str.strip()
    capec_ref = capec_ref[capec_ref["Status"].astype(str).str.lower() != "deprecated"]

    ids = set()
    for cell in cwe_table.loc[cwe_table["Retained"], "Related CAPEC"]:
        for part in str(cell).split(","):
            part = part.strip()
            if part and part != EM_DASH:
                ids.add(part)
    if not ids:
        raise PipelineError("None of the CWEs in the CWE table contribute a CAPEC pattern; the CAPEC table would be empty.")

    sub = capec_ref[capec_ref["CAPEC_ID"].isin(ids)].copy()
    missing = ids - set(sub["CAPEC_ID"])
    if missing:
        console.warn(f"CAPEC ID(s) referenced by a CWE but not found (or deprecated) in "
                     f"{ref['capec'].name}, skipped: {sorted(missing, key=int)}")

    out = pd.DataFrame({
        "CAPEC": "CAPEC-" + sub["CAPEC_ID"],
        "Name": sub["Name"],
        "Abstraction": sub["Abstraction"].fillna(""),
        "Likelihood": sub["Likelihood_Of_Attack"].fillna(EM_DASH),
        "Severity": sub["Typical_Severity"].fillna(EM_DASH),
    })
    out["_sort"] = sub["CAPEC_ID"].astype(int).values
    return out.sort_values("_sort", ignore_index=True).drop(columns="_sort")


def build_tables(ws: Workspace, datasets_dir) -> dict:
    """Builds the CVE, CWE and CAPEC tables, prints them, and writes CSVs + one workbook into ws.tables_dir."""
    console.section("Tables (CVEs, CWEs, CAPECs)")

    console.step("CVE records")
    t1 = build_cve_table(ws)
    console.table(t1)

    console.step("CWE weakness classes")
    t2 = build_cwe_table(ws, datasets_dir)
    console.table(t2.drop(columns=["Retained"]))
    excluded = t2.loc[~t2["Retained"], "CWE"].tolist()
    if excluded:
        console.info(f"Not retained past the CWE->CAPEC step (deprecated / no related CAPEC / "
                     f"not in {check_reference_files(datasets_dir)['cwe'].name}): {excluded}")

    console.step("CAPEC attack patterns")
    t3 = build_capec_table(t2, datasets_dir)
    console.table(t3)

    out_dir = ws.tables_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    t1.to_csv(out_dir / "cves.csv", index=False)
    t2.to_csv(out_dir / "cwes.csv", index=False)
    t3.to_csv(out_dir / "capecs.csv", index=False)
    xlsx_path = out_dir / "tables.xlsx"
    with pd.ExcelWriter(xlsx_path) as xw:
        t1.to_excel(xw, sheet_name="CVEs", index=False)
        t2.to_excel(xw, sheet_name="CWEs", index=False)
        t3.to_excel(xw, sheet_name="CAPECs", index=False)

    for name in ("cves.csv", "cwes.csv", "capecs.csv"):
        console.info(f"Saved: {out_dir / name}")
    console.info(f"Saved: {xlsx_path}")

    return {
        "cve_rows": int(len(t1)),
        "cwe_rows": int(len(t2)),
        "cwe_not_retained": excluded,
        "capec_rows": int(len(t3)),
        "output_dir": str(out_dir),
    }