# Insights: baxter_sigma_spectrum_infusion_system

CVEs in scope **10** · CVEs reaching a tactic **9** · Weaknesses **5** · CAPEC patterns **20** · Techniques **16** · Tactics **8** · Paths **51**

## Core insights

### 1. One weakness, many stages

**Use of Hard-coded Credentials (CWE-798) underlies 5 of 10 CVEs and reaches 5 of 8 tactic subtrees. Ranked one by one they read as separate findings; the tree groups them under one recurring weakness.**

- CVEs: 5 of 10 in scope
- Tactic subtrees: 5 of 8 (Initial Access, Persistence, Privilege Escalation, Defense Evasion, Credential Access)
- CVSS base scores: 2.4 to 9.8
- Lowest-scoring: CVE-2020-12039 (2.4, PHYSICAL)
- Same for all of them: attack complexity LOW, privileges required NONE, user interaction NONE
- Attack vector: NETWORK x3, PHYSICAL x2

_Paths of this weakness per tactic_

| Item | Count | Bar | Detail |
|---|---|---|---|
| Initial Access | 1 | ████████████████████ |  |
| Persistence | 1 | ████████████████████ |  |
| Privilege Escalation | 1 | ████████████████████ |  |
| Defense Evasion | 1 | ████████████████████ |  |
| Credential Access | 1 | ████████████████████ |  |
| Discovery | 0 |  |  |
| Lateral Movement | 0 |  |  |
| Collection | 0 |  |  |

> CVE-2020-12039 scores 2.4 and would rank low by severity alone, yet it feeds the same weakness-centred progression as the others.

### 2. Path count is not CVE count

**Defense Evasion has 14 paths from 7 CVEs, while Initial Access has 1 path from 5 CVEs. CVE count is only a rough guide to how many paths a tactic opens.**

- Widest tactic: Defense Evasion: 14 paths from 7 CVEs
- Narrowest per CVE: Initial Access: 1 path from 5 CVEs
- Dominant CVE there: CVE-2020-12041 alone gives 9 of 14 paths, through 5 techniques and 7 CAPEC patterns
- Collapse: all 5 CVEs lead to one step: Valid Accounts: Default Accounts (T1078.001)
- Rank correlation, CVEs vs paths: 0.66 across 8 tactics

_Paths per tactic_

| Item | Count | Bar | Detail |
|---|---|---|---|
| Initial Access | 1 | █ | from 5 CVEs |
| Persistence | 9 | █████████████ | from 7 CVEs |
| Privilege Escalation | 11 | ████████████████ | from 7 CVEs |
| Defense Evasion | 14 | ████████████████████ | from 7 CVEs |
| Credential Access | 6 | █████████ | from 8 CVEs |
| Discovery | 3 | ████ | from 3 CVEs |
| Lateral Movement | 3 | ████ | from 2 CVEs |
| Collection | 4 | ██████ | from 3 CVEs |

### 3. Redundancy shows where one control helps twice

**44 CAPEC references collapse to 20 distinct patterns (54.5% repeat one already used in another tactic). The same mechanisms recur across stages, so one control can cut paths in several of them.**

- CAPEC references over all tactics: 44
- Distinct CAPEC patterns: 20
- ATT&CK techniques over all tactics: 27
- Distinct ATT&CK techniques: 16

_Steps that appear under the most tactics (number of tactics)_

| Item | Count | Bar | Detail |
|---|---|---|---|
| T1078.001  Valid Accounts: Default Accounts | 4 | ████████████████████ | Initial Access, Persistence, Privilege Escalation, Defense Evasion |
| T1574.010  Hijack Execution Flow: Services File Permissions Weakness | 3 | ███████████████ | Persistence, Privilege Escalation, Defense Evasion |
| T1574.005  Hijack Execution Flow: Executable Installer File Permissions Weakness | 3 | ███████████████ | Persistence, Privilege Escalation, Defense Evasion |

> A control aimed at Valid Accounts: Default Accounts (T1078.001) would reach paths under Initial Access, Persistence, Privilege Escalation, Defense Evasion.

## Additional insights

### 4. Where a fix removes the most paths

**Fixing CVE-2020-12041 alone removes 25 of 51 paths (49.0%), the most of any single CVE. Its base score ranks only #7 of 9, so severity alone would not point to it.**

- Paths resting on one CVE: 46 of 51 (90.2%)
- CVSS rank of CVE-2020-12041: #7 of 9 by base score (9.4)

| Fixes | CVEs fixed | Paths removed | Share |
|---|---|---|---|
| 1 | CVE-2020-12041 | 25 | 49.0% |
| 2 | CVE-2014-5432, CVE-2020-12041 | 40 | 78.4% |
| 3 | CVE-2014-5432, CVE-2020-12040, CVE-2020-12041 | 44 | 86.3% |

> A path is removed only when every CVE supporting it is fixed. Sets are the best of all combinations of that size (greedy for very large devices).

### 5. How easily the paths can be reached

**51 of 51 paths (100.0%) can be driven remotely: at least one supporting CVE is reachable over the network with no privileges and no user interaction.**

- Remote, no privileges, no interaction: 51 of 51 (100.0%)
- Physical access is the only route: 0 of 51

_Easiest attack vector among each path's supporting CVEs_

| Item | Count | Bar | Detail |
|---|---|---|---|
| Network | 51 | ████████████████████ | 100.0% |

> Taken from each CVE's CVSS metrics; a path counts at the easiest of its CVEs.

### 6. Which weakness feeds the most paths

**Incorrect Permission Assignment for Critical Resource (CWE-732) supports 25 of 51 paths (49.0%) from 1 CVE.**

- Weaknesses in the tree: 5

_Paths per weakness_

| Item | Count | Bar | Detail |
|---|---|---|---|
| Incorrect Permission Assignment for Critical Resource (CWE-732) | 25 | ████████████████████ | 49.0%, from 1 CVE |
| Improper Authentication (CWE-287) | 15 | ████████████ | 29.4%, from 1 CVE |
| Use of Hard-coded Credentials (CWE-798) | 5 | ████ | 9.8%, from 5 CVEs |
| Cleartext Transmission of Sensitive Information (CWE-319) | 4 | ███ | 7.8%, from 1 CVE |
| Cleartext Storage of Sensitive Information (CWE-312) | 2 | ██ | 3.9%, from 1 CVE |

> Use of Hard-coded Credentials (CWE-798) has more CVEs (5) but fewer paths (5): CVE counts and path counts rank the weaknesses differently.

### 7. Where public mappings run out

**The paths reach 8 of 14 ATT&CK tactics. Most dropped chain rows (9 of 17) are lost at one step: CAPEC pattern has no ATT&CK technique.**

- Tactics reached: 8 of 14
- Not reached: Reconnaissance, Resource Development, Execution, Command and Control, Exfiltration, Impact
- CVEs with a complete chain: 9 of 10

_Dropped chain rows by reason_

| Item | Count | Bar | Detail |
|---|---|---|---|
| CAPEC pattern has no ATT&CK technique | 9 | ████████████████████ |  |
| CWE has no usable CAPEC pattern | 7 | ████████████████ |  |
| CWE not in the reference set | 1 | ██ |  |

> Tactics not reached show gaps in public cross-references, not evidence that the device is safe from them.
