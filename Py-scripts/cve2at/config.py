"""Paths, CPE validation and the per-run workspace layout."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from .errors import ConfigError, DatasetError

# reference workbooks the user supplies (see datasets/README.md)
REFERENCE_FILES = {
    "cwe": "cwe_data.xlsx",
    "capec": "capec_data.xlsx",
    "mitre": "techniques.xlsx",
}

_CPE_SPLIT = re.compile(r"(?<!\\):")   # split on ':' but not on an escaped '\:'


def split_cpe(cpe: str) -> list:
    return _CPE_SPLIT.split(cpe.strip())


def validate_cpe(cpe: str) -> str:
    """Accepts a CPE 2.3 formatted string, e.g.
    cpe:2.3:h:baxter:sigma_spectrum_infusion_system:-:*:*:*:*:*:*:*"""
    cpe = (cpe or "").strip()
    parts = split_cpe(cpe)
    if (len(parts) != 13 or parts[0].lower() != "cpe" or parts[1] != "2.3"
            or parts[2] not in ("a", "h", "o")):
        raise ConfigError(
            f"'{cpe}' is not a valid CPE 2.3 name.\n"
            "  Expected 13 colon-separated fields, e.g.\n"
            "  cpe:2.3:h:baxter:sigma_spectrum_infusion_system:-:*:*:*:*:*:*:*"
        )
    return cpe


def cpe_slug(cpe: str) -> str:
    """Folder-friendly name for a CPE: vendor_product[_version]."""
    parts = split_cpe(cpe)
    vendor, product, version = parts[3], parts[4], parts[5]
    slug = f"{vendor}_{product}"
    if version not in ("-", "*", ""):
        slug += f"_{version}"
    return re.sub(r"[^0-9A-Za-z._-]+", "_", slug).strip("_") or "device"


@dataclass(frozen=True)
class Workspace:
    """Everything one run reads/writes lives under `root` (one folder per device),
    so runs for different CPEs can never mix their CVE files."""
    root: Path

    @property
    def cve_dir(self) -> Path: return self.root / "cve_data"
    @property
    def rejected_dir(self) -> Path: return self.root / "rejected_cve_data"
    @property
    def cve_xlsx(self) -> Path: return self.root / "cve_data.xlsx"
    @property
    def formatted_xlsx(self) -> Path: return self.root / "cve_data_formated.xlsx"
    @property
    def device_attack_pattern_xlsx(self) -> Path: return self.root / "Device_Attack_Pattern.xlsx"
    @property
    def compromise_dataset_xlsx(self) -> Path: return self.root / "device_compromise_dataset.xlsx"
    @property
    def tactic_tree_dir(self) -> Path: return self.root / "outputs" / "tactic_trees"
    @property
    def comprehensive_tree_dir(self) -> Path: return self.root / "outputs" / "comprehensive_tree"
    @property
    def tables_dir(self) -> Path: return self.root / "outputs" / "tables"
    @property
    def figures_dir(self) -> Path: return self.root / "outputs" / "figures"
    @property
    def insights_dir(self) -> Path: return self.root / "outputs" / "insights"
    @property
    def summary_json(self) -> Path: return self.root / "run_summary.json"

    def ensure(self) -> "Workspace":
        self.root.mkdir(parents=True, exist_ok=True)
        return self


def workspace_for(cpe: str | None, output_dir: str | None, workspace: str | None) -> Workspace:
    """`--workspace` wins; otherwise <output_dir>/<slug-of-cpe>."""
    if workspace:
        return Workspace(Path(workspace))
    if not cpe:
        raise ConfigError("Give a CPE name, or --workspace pointing at an existing run folder.")
    return Workspace(Path(output_dir or "output") / cpe_slug(validate_cpe(cpe)))


def resolve_datasets_dir(arg: str | None = None) -> Path:
    """--datasets-dir, else $CVE2AT_DATASETS_DIR, else ./datasets (or ./Datasets)."""
    if arg:
        return Path(arg)
    env = os.environ.get("CVE2AT_DATASETS_DIR")
    if env:
        return Path(env)
    for cand in ("datasets", "Datasets"):
        if Path(cand).is_dir():
            return Path(cand)
    return Path("datasets")


def check_reference_files(datasets_dir: Path) -> dict:
    """Return {key: Path} for the three reference workbooks, or raise listing what's missing."""
    paths = {k: Path(datasets_dir) / fname for k, fname in REFERENCE_FILES.items()}
    missing = [p.name for p in paths.values() if not p.is_file()]
    if missing:
        raise DatasetError(
            f"Missing reference dataset(s) in '{datasets_dir}': {', '.join(missing)}\n"
            f"  Put {', '.join(REFERENCE_FILES.values())} there, or point to them with --datasets-dir."
        )
    return paths