"""Stage 3: merge the CVEs with CWE, CAPEC and MITRE ATT&CK.

    cve_data.xlsx  --(CWE ID)-->  cwe_data.xlsx  --(CAPEC IDs)-->  capec_data.xlsx
                   --(technique IDs)-->  techniques.xlsx  -->  one row per
                   (CVE, CWE, CAPEC, technique/sub-technique, tactic) chain

Writes Device_Attack_Pattern.xlsx and device_compromise_dataset.xlsx into the workspace.
"""
from __future__ import annotations

import pandas as pd

from . import console
from .config import REFERENCE_FILES as REF_NAME, Workspace, check_reference_files
from .errors import DatasetError, PipelineError

# columns of the final dataset
FINAL_COLUMNS = [
    "CVE ID", "CWE ID", "CAPEC_ID", "Technique_ID_Only", "technique", "subtechnique",
    "Description", "attackVector", "baseScore", "baseSeverity", "attackComplexity",
    "privilegesRequired", "userInteraction", "confidentialityImpact", "availabilityImpact",
    "integrityImpact", "exploitabilityScore", "exposure_tags",
    # CAPEC details
    "capec_Name", "capec_Mitre_Techniques", "capec_Abstraction", "capec_Status", "capec_Description",
    "capec_Extended_Description", "capec_Likelihood_Of_Attack", "capec_Typical_Severity",
    "capec_Execution_Flow", "capec_Prerequisites", "capec_Skills_Required", "capec_Resources_Required",
    "capec_Consequences", "capec_Mitigations", "capec_Example_Instances", "capec_Related_Weaknesses",
    "capec_Taxonomy_Mappings",
    # CWE details
    "cwe_Name", "cwe_Abstraction", "cwe_Structure", "cwe_Status", "cwe_Description",
    "cwe_Extended_Description", "cwe_Related_Weaknesses", "cwe_Weakness_Ordinality",
    "cwe_Language_Name", "cwe_Technology_Class", "cwe_Alternate_Terms",
    "cwe_Alternate_Terms_With_Descriptions", "cwe_Background_Details", "cwe_Modes_Of_Introduction",
    "cwe_Likelihood_Of_Exploit", "cwe_Common_Consequences", "cwe_Detection_Methods",
    "cwe_Potential_Mitigations", "cwe_Demonstrative_Examples", "cwe_Observed_Examples",
    # MITRE ATT&CK technique / sub-technique fields
    "technique_name", "tech_description", "subtechnique_name", "tactics", "detection", "platforms",
    "data sources", "defenses bypassed", "contributors", "permissions required", "supports remote",
    "system requirements", "impact type", "effective permissions",
]


def _require(df: pd.DataFrame, columns, where: str) -> None:
    missing = [c for c in columns if c not in df.columns]
    if missing:
        raise DatasetError(f"{where} is missing required column(s): {', '.join(missing)}")


def _text(series: pd.Series) -> pd.Series:
    """Missing -> '' *before* casting to str, so a gap never turns into the literal text 'nan'."""
    return series.astype(object).where(series.notna(), "").astype(str)


def _add_prefix(series: pd.Series, prefix: str) -> pd.Series:
    return series.apply(lambda v: f"{prefix}{v}" if pd.notna(v) else v)


def build_device_dataset(ws: Workspace, datasets_dir, target_cve_ids=None) -> dict:
    ref = check_reference_files(datasets_dir)
    if not ws.cve_xlsx.is_file():
        raise PipelineError(f"'{ws.cve_xlsx}' not found. Run the tabulate stage first.")

    # Load datasets and select in-scope CVEs
    console.step("Load datasets and select in-scope CVEs")
    cve_dataset = pd.read_excel(ws.cve_xlsx)
    cwe_dataset = pd.read_excel(ref["cwe"])
    console.info(f"cve_dataset: {cve_dataset.shape[0]} rows, {cve_dataset.shape[1]} columns")
    console.info(f"cwe_dataset: {cwe_dataset.shape[0]} rows, {cwe_dataset.shape[1]} columns")
    _require(cve_dataset, ["CVE ID", "Weaknesses"], ws.cve_xlsx.name)

    if target_cve_ids:
        device_vulnerabilities = cve_dataset[cve_dataset["CVE ID"].isin(target_cve_ids)].copy()
        if device_vulnerabilities.empty:
            raise PipelineError("None of the requested --target-cve IDs are present in the CVE table.")
    else:
        device_vulnerabilities = cve_dataset.copy()
    console.info(f"Selected {device_vulnerabilities.shape[0]} of {cve_dataset.shape[0]} CVEs for this run.")

    # CVE weakness (CWE) preprocessing
    console.step("CVE weakness (CWE) preprocessing for merge")
    device_vulnerabilities["Weaknesses"] = _text(device_vulnerabilities["Weaknesses"])
    # one row per CWE ID
    device_vulnerabilities["Weaknesses"] = device_vulnerabilities["Weaknesses"].str.split("; ")
    device_vulnerabilities = device_vulnerabilities.explode("Weaknesses", ignore_index=True)
    # strip the "CWE-" prefix so IDs merge cleanly with cwe_dataset
    device_vulnerabilities["Weaknesses"] = (
        device_vulnerabilities["Weaknesses"].str.replace("CWE-", "", regex=False).str.strip())
    no_cwe_mask = device_vulnerabilities["Weaknesses"] == ""
    no_cwe_mapping = int(no_cwe_mask.sum())
    dropped_chains = []
    if no_cwe_mapping:
        dropped_chains.append(
            device_vulnerabilities.loc[no_cwe_mask, ["CVE ID"]].assign(chain_break="NO_CWE"))
    device_vulnerabilities = device_vulnerabilities[~no_cwe_mask]
    console.info(f"{no_cwe_mapping} CVE row(s) had no CWE mapping and were dropped before the merge")
    console.info(f"{device_vulnerabilities.shape[0]} CVE-CWE rows remain after splitting multi-CWE mappings")
    n_cve_cwe_rows = int(len(device_vulnerabilities))
    if device_vulnerabilities.empty:
        raise PipelineError("None of the selected CVEs has a usable CWE, so there is nothing to map.")

    # CWE data preprocessing + merge
    console.step("Merge CVEs with CWE weaknesses")
    if not any(col.startswith("cwe_") for col in cwe_dataset.columns):   # safe to re-run
        cwe_dataset = cwe_dataset.add_prefix("cwe_")
    cwe_dataset = cwe_dataset.rename(columns={"cwe_CWE_ID": "Weaknesses"})
    _require(cwe_dataset, ["Weaknesses", "cwe_Name", "cwe_Related_Attack_Patterns"], REF_NAME["cwe"])
    cwe_dataset["Weaknesses"] = cwe_dataset["Weaknesses"].astype(str).str.strip()

    device_weaknesses = device_vulnerabilities.merge(cwe_dataset, on="Weaknesses", how="left")
    device_weaknesses = device_weaknesses.rename(columns={"Weaknesses": "CWE ID"})
    unmatched_cwe_mask = device_weaknesses["cwe_Name"].isnull()
    unmatched_cwe = sorted(device_weaknesses.loc[unmatched_cwe_mask, "CWE ID"].unique())
    console.info(f"CWE IDs with no matching record in {REF_NAME['cwe']}: {unmatched_cwe}")
    if unmatched_cwe_mask.any():
        dropped_chains.append(
            device_weaknesses.loc[unmatched_cwe_mask, ["CVE ID", "CWE ID"]].assign(chain_break="CWE_UNKNOWN"))
    device_weaknesses = device_weaknesses[~unmatched_cwe_mask].copy()

    # CAPEC data
    console.step("Load CAPEC data and preprocess for merge")
    capec_dataset = pd.read_excel(ref["capec"])
    console.info(f"capec_dataset: {capec_dataset.shape[0]} rows, {capec_dataset.shape[1]} columns")
    _require(capec_dataset, ["CAPEC_ID"], REF_NAME["capec"])

    capec_dataset["CAPEC_ID"] = capec_dataset["CAPEC_ID"].astype(str).str.strip()

    # Exclude deprecated CAPEC patterns from the mapping stage; keep the full set for audit.
    status_col = "capec_Status" if "capec_Status" in capec_dataset.columns else "Status"
    _require(capec_dataset, [status_col], REF_NAME["capec"])
    deprecated_mask = capec_dataset[status_col].astype(str).str.strip().str.lower() == "deprecated"
    capec_dataset_all = capec_dataset.copy()  # noqa: F841
    capec_dataset = capec_dataset[~deprecated_mask].copy()
    console.info(f"CAPEC patterns: {len(capec_dataset_all)} total, {int(deprecated_mask.sum())} deprecated "
                 f"(excluded), {capec_dataset.shape[0]} kept for mapping")

    capec_dataset.columns = [f"capec_{c}" if not c.startswith("capec_") else c for c in capec_dataset.columns]
    capec_dataset = capec_dataset.rename(columns={"capec_CAPEC_ID": "cwe_Related_Attack_Patterns"})
    _require(capec_dataset, ["capec_Name", "capec_Mitre_Techniques"], REF_NAME["capec"])

    # Device weaknesses -> CAPEC
    console.step("Merge device weaknesses with CAPEC attack patterns")
    device_weaknesses["cwe_Related_Attack_Patterns"] = _text(
        device_weaknesses["cwe_Related_Attack_Patterns"]).str.strip()
    # one row per CAPEC ID
    device_weaknesses["cwe_Related_Attack_Patterns"] = device_weaknesses["cwe_Related_Attack_Patterns"].str.split(",")
    device_weaknesses = device_weaknesses.explode("cwe_Related_Attack_Patterns")
    device_weaknesses["cwe_Related_Attack_Patterns"] = device_weaknesses["cwe_Related_Attack_Patterns"].str.strip()
    no_capec_mask = device_weaknesses["cwe_Related_Attack_Patterns"] == ""
    no_capec_mapping = int(no_capec_mask.sum())
    if no_capec_mapping:
        dropped_chains.append(
            device_weaknesses.loc[no_capec_mask, ["CVE ID", "CWE ID"]].assign(chain_break="NO_CAPEC"))
    device_weaknesses = device_weaknesses[~no_capec_mask]
    console.info(f"{no_capec_mapping} CVE-CWE row(s) had no CAPEC mapping and were dropped before the merge")
    console.info(f"{device_weaknesses.shape[0]} CVE-CWE-CAPEC rows remain after splitting multi-CAPEC mappings")
    if device_weaknesses.empty:
        raise PipelineError("None of the CWEs found for this device maps to a CAPEC pattern.")

    device_attack_patterns = device_weaknesses.merge(capec_dataset, on="cwe_Related_Attack_Patterns", how="left")
    device_attack_patterns = device_attack_patterns.rename(columns={"cwe_Related_Attack_Patterns": "CAPEC_ID"})
    missing_capec_mask = device_attack_patterns["capec_Name"].isnull()
    missing_capec = sorted(device_attack_patterns.loc[missing_capec_mask, "CAPEC_ID"].unique())
    console.info(f"CAPEC IDs with no matching non-deprecated record: {missing_capec}")
    if missing_capec_mask.any():
        dropped_chains.append(
            device_attack_patterns.loc[missing_capec_mask, ["CVE ID", "CWE ID"]].assign(chain_break="CAPEC_INACTIVE"))
    device_attack_patterns = device_attack_patterns[~missing_capec_mask].copy()
    device_attack_patterns = device_attack_patterns.loc[:, ~device_attack_patterns.columns.str.contains("^Unnamed")]

    # MITRE ATT&CK
    console.step("Load the MITRE ATT&CK dataset")
    mitre_df = pd.read_excel(ref["mitre"])
    _require(mitre_df, ["ID", "name", "description", "tactics", "supports remote", "impact type"], REF_NAME["mitre"])
    mitre_df["supports remote"] = mitre_df["supports remote"].fillna(0).astype(int).astype(bool)
    mitre_df["impact type"] = mitre_df["impact type"].astype("category")
    mitre_df = mitre_df.rename(columns={"description": "tech_description"})
    # numeric ID (drops the leading "T"); used to join against CAPEC's Mitre_Techniques column
    mitre_df["Technique_ID_Only"] = mitre_df["ID"].str.replace("T", "", regex=False)
    console.info(f"mitre_df: {mitre_df.shape[0]} techniques/sub-techniques")
    is_sub = mitre_df["ID"].str.contains(".", regex=False)
    tactic_names = {t.strip() for cell in mitre_df["tactics"].dropna() for t in str(cell).split(",")}
    attack_matrix = {"tactics": len(tactic_names),
                     "techniques": int((~is_sub).sum()),
                     "sub_techniques": int(is_sub.sum())}

    console.step("Merge device attack patterns with MITRE techniques and tactics")
    # a CAPEC entry can list several techniques -> one row each
    device_attack_patterns["capec_Mitre_Techniques"] = (
        device_attack_patterns["capec_Mitre_Techniques"].str.split(r"\s*\|\|\s*"))
    device_attack_patterns = device_attack_patterns.explode("capec_Mitre_Techniques")
    # numeric technique / sub-technique ID (everything before ' -')
    device_attack_patterns["Technique_ID_Only"] = (
        device_attack_patterns["capec_Mitre_Techniques"].str.extract(r"^([\d\.]+)", expand=False))
    no_technique_mask = device_attack_patterns["Technique_ID_Only"].isna()
    if no_technique_mask.any():
        dropped_chains.append(
            device_attack_patterns.loc[no_technique_mask, ["CVE ID", "CWE ID", "CAPEC_ID"]]
            .assign(chain_break="NO_TECHNIQUE"))
    device_attack_patterns = device_attack_patterns.merge(mitre_df, how="left", on="Technique_ID_Only")
    console.info(f"{device_attack_patterns.shape[0]} rows after mapping CAPEC patterns to ATT&CK techniques")

    technique_unknown_mask = device_attack_patterns["Technique_ID_Only"].notna() & device_attack_patterns["name"].isnull()
    if technique_unknown_mask.any():
        dropped_chains.append(
            device_attack_patterns.loc[technique_unknown_mask, ["CVE ID", "CWE ID", "CAPEC_ID", "Technique_ID_Only"]]
            .assign(chain_break="TECHNIQUE_UNKNOWN"))

    # split each ATT&CK ID into its parent technique and, where present, its sub-technique
    ids = device_attack_patterns["Technique_ID_Only"]
    device_attack_patterns["technique"] = ids.map(lambda v: None if pd.isna(v) else str(v).split(".")[0])
    device_attack_patterns["subtechnique"] = ids.map(lambda v: str(v) if (pd.notna(v) and "." in str(v)) else None)

    id_to_name = mitre_df.set_index("Technique_ID_Only")["name"].to_dict()
    id_to_tactics = mitre_df.set_index("Technique_ID_Only")["tactics"].to_dict()
    device_attack_patterns["technique_name"] = device_attack_patterns["technique"].map(id_to_name)
    device_attack_patterns["subtechnique_name"] = device_attack_patterns["subtechnique"].map(id_to_name)
    # tactics come from the exact technique / sub-technique ID, so a sub-technique keeps its own tactics
    device_attack_patterns["tactics"] = device_attack_patterns["Technique_ID_Only"].map(id_to_tactics)

    no_tactic_mask = (device_attack_patterns["name"].notna()
                       & device_attack_patterns["tactics"].isna())
    if no_tactic_mask.any():
        dropped_chains.append(
            device_attack_patterns.loc[no_tactic_mask, ["CVE ID", "CWE ID", "CAPEC_ID", "Technique_ID_Only"]]
            .assign(chain_break="NO_TACTIC"))

    # Restore the canonical "CWE-", "CAPEC-" and "T" prefixes now that every numeric lookup is done.
    # (Also stops Excel re-typing padded IDs like "1574.010" as the number 1574.01.)
    device_attack_patterns["CWE ID"] = _add_prefix(device_attack_patterns["CWE ID"], "CWE-")
    device_attack_patterns["CAPEC_ID"] = _add_prefix(device_attack_patterns["CAPEC_ID"], "CAPEC-")
    device_attack_patterns["Technique_ID_Only"] = _add_prefix(device_attack_patterns["Technique_ID_Only"], "T")
    device_attack_patterns["technique"] = _add_prefix(device_attack_patterns["technique"], "T")
    device_attack_patterns["subtechnique"] = _add_prefix(device_attack_patterns["subtechnique"], "T")

    # Final CVE -> CWE -> CAPEC -> ATT&CK dataset
    console.step("Build the final CVE -> CWE -> CAPEC -> ATT&CK dataset")
    missing_cols = [c for c in FINAL_COLUMNS if c not in device_attack_patterns.columns]
    if missing_cols:
        raise DatasetError(
            "The merged data lacks column(s) the attack-tree stage needs: " + ", ".join(missing_cols)
            + f"\n  They come from the CVE table and {', '.join(REF_NAME.values())}; check those files' headers.")
    final_df = device_attack_patterns[FINAL_COLUMNS].copy()

    # A technique can map to several tactics -> one row per (CVE, CWE, CAPEC, technique, tactic).
    final_df["tactics"] = final_df["tactics"].str.split(r"\s*,\s*")
    final_df = final_df.explode("tactics")
    console.info(f"Final dataset: {final_df.shape[0]} rows x {final_df.shape[1]} columns")

    device_attack_patterns.to_excel(ws.device_attack_pattern_xlsx, index=False)
    final_df.to_excel(ws.compromise_dataset_xlsx, index=False)
    console.info(f"Saved: {ws.device_attack_pattern_xlsx}")
    console.info(f"Saved: {ws.compromise_dataset_xlsx}")

    # Reason-coded incomplete-chain report + coverage funnel
    # every candidate row dropped in this function, with the reason; also feeds the coverage
    # funnel in run_summary.json
    reason_counts = {}
    if dropped_chains:
        incomplete = pd.concat(dropped_chains, ignore_index=True, sort=False)
        incomplete.to_csv(ws.root / "incomplete_chains.csv", index=False)
        reason_counts = {k: int(v) for k, v in incomplete["chain_break"].value_counts().items()}
        console.info(f"Saved: {ws.root / 'incomplete_chains.csv'} ({len(incomplete)} rows, "
                     f"reasons: {reason_counts})")

    funnel = {
        "cves_fetched_or_selected": int(cve_dataset["CVE ID"].nunique() if target_cve_ids is None
                                         else len(target_cve_ids)),
        "cves_with_usable_cwe": int(device_vulnerabilities["CVE ID"].nunique()),
        "cwe_rows": n_cve_cwe_rows,
        "cwe_ids_known": int(cwe_dataset["Weaknesses"].nunique()),
        "capec_rows_after_capec_merge": int(len(device_attack_patterns)),
        "distinct_cwe_ids_in_final": int(final_df["CWE ID"].nunique()) if "CWE ID" in final_df else None,
        "distinct_capec_ids_in_final": int(final_df["CAPEC_ID"].nunique()) if "CAPEC_ID" in final_df else None,
        "distinct_technique_ids_in_final": int(final_df["Technique_ID_Only"].nunique()) if "Technique_ID_Only" in final_df else None,
        "chain_break_reasons": reason_counts,
    }

    return {
        "cves_in_scope": int(device_vulnerabilities["CVE ID"].nunique()),
        "cve_cwe_rows": n_cve_cwe_rows,
        "unmatched_cwe": unmatched_cwe,
        "missing_capec": missing_capec,
        "final_rows": int(len(final_df)),
        "coverage_funnel": funnel,
        "attack_matrix": attack_matrix,
    }