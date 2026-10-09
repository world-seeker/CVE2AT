# Insights: schneider-electric_modicon_m580

CVEs in scope **40** · CVEs reaching a tactic **11** · Weaknesses **6** · CAPEC patterns **33** · Techniques **38** · Tactics **8** · Paths **74**

## Core insights

### 1. One weakness, many stages

**Exposure of Sensitive Information to an Unauthorized Actor (CWE-200) underlies 5 of 40 CVEs and reaches 7 of 8 tactic subtrees. Ranked one by one they read as separate findings; the tree groups them under one recurring weakness.**

- CVEs: 5 of 40 in scope
- Tactic subtrees: 7 of 8 (Reconnaissance, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement)
- CVSS base scores: all 7.5
- Same for all of them: attack complexity LOW, privileges required NONE, user interaction NONE

_Paths of this weakness per tactic_

| Item | Count | Bar | Detail |
|---|---|---|---|
| Reconnaissance | 3 | ████ |  |
| Persistence | 2 | ██ |  |
| Privilege Escalation | 3 | ████ |  |
| Defense Evasion | 6 | ███████ |  |
| Credential Access | 1 | █ |  |
| Discovery | 17 | ████████████████████ |  |
| Lateral Movement | 1 | █ |  |
| Collection | 0 |  |  |

### 2. Path count is not CVE count

**Defense Evasion has 19 paths from 8 CVEs, while Lateral Movement has 4 paths from 7 CVEs. Here CVE count tracks path count closely, so it is a fair proxy.**

- Widest tactic: Defense Evasion: 19 paths from 8 CVEs
- Narrowest per CVE: Lateral Movement: 4 paths from 7 CVEs
- Rank correlation, CVEs vs paths: 0.81 across 8 tactics

_Paths per tactic_

| Item | Count | Bar | Detail |
|---|---|---|---|
| Reconnaissance | 3 | ███ | from 5 CVEs |
| Persistence | 5 | █████ | from 7 CVEs |
| Privilege Escalation | 10 | ███████████ | from 8 CVEs |
| Defense Evasion | 19 | ████████████████████ | from 8 CVEs |
| Credential Access | 10 | ███████████ | from 10 CVEs |
| Discovery | 19 | ████████████████████ | from 8 CVEs |
| Lateral Movement | 4 | ████ | from 7 CVEs |
| Collection | 4 | ████ | from 4 CVEs |

### 3. Redundancy shows where one control helps twice

**50 CAPEC references collapse to 33 distinct patterns (34.0% repeat one already used in another tactic). The same mechanisms recur across stages, so one control can cut paths in several of them.**

- CAPEC references over all tactics: 50
- Distinct CAPEC patterns: 33
- ATT&CK techniques over all tactics: 46
- Distinct ATT&CK techniques: 38

_Steps that appear under the most tactics (number of tactics)_

| Item | Count | Bar | Detail |
|---|---|---|---|
| T1574.006  Hijack Execution Flow: Dynamic Linker Hijacking | 3 | ████████████████████ | Persistence, Privilege Escalation, Defense Evasion |
| T1574.007  Hijack Execution Flow: Path Interception by PATH Environment Variable | 3 | ████████████████████ | Persistence, Privilege Escalation, Defense Evasion |
| T1040  Network Sniffing | 2 | █████████████ | Credential Access, Discovery |

> A control aimed at Hijack Execution Flow: Dynamic Linker Hijacking (T1574.006) would reach paths under Persistence, Privilege Escalation, Defense Evasion.

## Additional insights

### 4. Where a fix removes the most paths

**Fixing CVE-2018-7847 alone removes 15 of 74 paths (20.3%), the most of any single CVE. It also has the highest base score.**

- Paths resting on one CVE: 37 of 74 (50.0%)
- CVSS rank of CVE-2018-7847: #1 of 11 by base score (9.8)

| Fixes | CVEs fixed | Paths removed | Share |
|---|---|---|---|
| 1 | CVE-2018-7847 | 15 | 20.3% |
| 2 | CVE-2018-7842, CVE-2018-7847 | 27 | 36.5% |
| 3 | CVE-2018-7842, CVE-2018-7847, CVE-2020-7475 | 35 | 47.3% |

> A path is removed only when every CVE supporting it is fixed. Sets are the best of all combinations of that size (greedy for very large devices).

### 5. How easily the paths can be reached

**74 of 74 paths (100.0%) can be driven remotely: at least one supporting CVE is reachable over the network with no privileges and no user interaction.**

- Remote, no privileges, no interaction: 74 of 74 (100.0%)
- Physical access is the only route: 0 of 74

_Easiest attack vector among each path's supporting CVEs_

| Item | Count | Bar | Detail |
|---|---|---|---|
| Network | 74 | ████████████████████ | 100.0% |

> Taken from each CVE's CVSS metrics; a path counts at the easiest of its CVEs.

### 6. Which weakness feeds the most paths

**Exposure of Sensitive Information to an Unauthorized Actor (CWE-200) supports 33 of 74 paths (44.6%) from 5 CVEs.**

- Weaknesses in the tree: 6

_Paths per weakness_

| Item | Count | Bar | Detail |
|---|---|---|---|
| Exposure of Sensitive Information to an Unauthorized Actor (CWE-200) | 33 | ████████████████████ | 44.6%, from 5 CVEs |
| Improper Authentication (CWE-287) | 15 | █████████ | 20.3%, from 1 CVE |
| Authentication Bypass by Spoofing (CWE-290) | 12 | ███████ | 16.2%, from 1 CVE |
| Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') (CWE-74) | 8 | █████ | 10.8%, from 1 CVE |
| Cleartext Transmission of Sensitive Information (CWE-319) | 4 | ██ | 5.4%, from 2 CVEs |

### 7. Where public mappings run out

**The paths reach 8 of 14 ATT&CK tactics. Most dropped chain rows (259 of 290) are lost at one step: CAPEC pattern has no ATT&CK technique.**

- Tactics reached: 8 of 14
- Not reached: Resource Development, Initial Access, Execution, Command and Control, Exfiltration, Impact
- CVEs with a complete chain: 11 of 40

_Dropped chain rows by reason_

| Item | Count | Bar | Detail |
|---|---|---|---|
| CAPEC pattern has no ATT&CK technique | 259 | ████████████████████ |  |
| CWE has no usable CAPEC pattern | 29 | ██ |  |
| CVE has no CWE | 2 |  |  |

> Tactics not reached show gaps in public cross-references, not evidence that the device is safe from them.
