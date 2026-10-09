## Reference datasets

The pipeline needs three reference workbooks in this folder (or in the folder
given by `--datasets-dir` or `$CVE2AT_DATASETS_DIR`). They are the same for
every device. `cve2at doctor` checks that they are found.

| File | What it holds | Columns the pipeline uses | Official source |
|---|---|---|---|
| `cwe_data.xlsx` | CWE catalogue | `CWE_ID`, `Name`, `Related_Attack_Patterns` (comma-separated CAPEC IDs) and other CWE detail columns | [CWE v4.16 Archive](https://cwe.mitre.org/data/archive/) |
| `capec_data.xlsx` | CAPEC catalogue | `CAPEC_ID`, `Name`, `Status`, `Mitre_Techniques` (`1574.010 - name \|\| 1190 - name`) and other CAPEC detail columns | [CAPEC v3.9 Archive](https://capec.mitre.org/data/archive.html) |
| `techniques.xlsx` | MITRE ATT&CK techniques | `ID`, `name`, `description`, `tactics`, `supports remote`, `impact type` and detection/platform columns | [MITRE ATT&CK Data & Tools](https://attack.mitre.org/resources/attack-data-and-tools/) |

### Versions used for the case-study results

| File | Source version | Source |
|---|---|---|
| `cwe_data.xlsx` | CWE v4.16 | [MITRE CWE v4.16 archive](https://cwe.mitre.org/data/archive/) |
| `capec_data.xlsx` | CAPEC v3.9 | [MITRE CAPEC v3.9 archive](https://capec.mitre.org/data/archive.html) |
| `techniques.xlsx` | ATT&CK Enterprise v16.1 | [MITRE ATT&CK Data & Tools](https://attack.mitre.org/resources/attack-data-and-tools/) |

Other versions can be used to update the reference datasets. However, the
case-study results (51 and 74 attack paths) reproduce only with the versions listed above.

Rows marked deprecated in CAPEC are left out of the CWE -> CAPEC mapping;
see `merge.py`.

## Data collection and extraction

The repository also includes the notebooks and source files used to collect
and extract the reference data used by the CVE2AT pipeline. These materials
are provided to make the dataset construction and preprocessing steps
traceable and reproducible.

| Directory | Purpose | Main source/input |
|---|---|---|
| `1.CVE-data-collection/` | Collect device-related CVEs from the NVD API using CPEs and inspect keyword-based CVE matches | NVD CVE API |
| `2.CWE-data_Extraction/` | Parse the CWE catalogue and extract CWE-to-CAPEC relationships | CWE v4.16 XML |
| `3.CAPEC-dataExtraction/` | Parse the CAPEC catalogue and extract CAPEC metadata and ATT&CK mappings | CAPEC v3.9 XML |
| `4.Mitre-Attack/` | Fetch and extract the current MITRE ATT&CK Enterprise technique data | MITRE ATT&CK STIX data |

The MITRE ATT&CK extraction notebook retrieves the `enterprise-attack` dataset
from the MITRE CTI repository when it is run. The `techniques.xlsx` included
with this release is the snapshot generated from that process on 4 April
2025, corresponding to ATT&CK Enterprise v16.1. Running the notebook again
may retrieve a newer ATT&CK version.

The raw source files and extraction notebooks are retained in the repository
so that the reference workbooks can be traced back to their source datasets.