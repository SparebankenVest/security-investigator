# Fake-Download Campaign — Trojanized Inno Setup Installers Delivering Monetization Payloads

**Created:** 2026-11-06  
**Platform:** Both  
**Tables:** DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceEvents  
**Keywords:** trojanized installer, Inno Setup, cracked software, offer_execution, WorldProxyPool, residential proxy, BOINC, CharityEngine, monetization, PUA, scheduled task, SYSTEM, watchdog.ps1, is-*.tmp  
**MITRE:** T1204.002, T1053.005, T1036, T1564.003, T1071.001, T1105, T1496  
**Domains:** endpoint  
**Timeframe:** Last 30 days (configurable)  
**Source:** [Microsoft Threat Intelligence — Fake-download campaign uses trojanized installers to deliver monetization payloads (2026-11-03)](https://www.microsoft.com/en-us/security/blog/2026/11/03/fake-download-campaign-uses-trojanized-installers-deliver-monetization-payloads/)

---

## Threat Overview

Fake-download lures (cracked / free-software themes) deliver trojanized **Inno Setup** installers. The installers unpack to `%TEMP%\is-*.tmp\`, run staged helpers (`eld*.exe`, `set_*.exe`, `FirstFast[1].exe`, `SecondRunner[1].exe`) with Inno-style arguments (`/SL5`, `/SPAWNWND`, `/FIRSTWND`), call back to offer-server URLs (`d=inno&r=offer_execution[_fail]`) and silently install "monetization" payloads (`/qn /S /quiet /norestart`):

- **WorldProxyPool** residential-proxy agent (`sdk-agent.exe`, `sdk-agent.updater.exe`, `watchdog.ps1`) with SYSTEM scheduled tasks `WorldProxyPoolAgent` (startup), `WorldProxyPoolWatchdog` (every 5 min, hidden PowerShell) and `WorldProxyPoolUpdater` (hourly)
- **CharityEngine / BOINC** (`boinc.exe`, `charityengine.exe`, `ce11.exe`, VirtualBox MSI) under `C:\Program Files\BOINC\`
- **Advanced Windows Manager** (`AdvancedWindowsManager.exe`, `Windows Updater.exe`)

## TTP Summary

| Stage | Technique | MITRE | Query |
|---|---|---|---|
| Execution | User-run trojanized installer | T1204.002 | 2, 6 |
| Staging | Helpers run from Inno temp dir | T1036 | 2, 3 |
| Callback | Web protocol callbacks, domain sweep | T1071.001, T1105 | 1, 3, 4 |
| Persistence | SYSTEM scheduled tasks, hidden PowerShell | T1053.005, T1564.003 | 5 |
| Impact | Resource hijacking (proxy / compute) | T1496 | 5 |
| Known samples | Published SHA-256 | T1204.002 | 6 |

## Hunt Pitfalls

- **Inno Setup is common and legitimate.** `/SL5=` with `/SPAWNWND` or `/FIRSTWND` also appears on many benign Inno installers (e.g., Git for Windows, KeePass, R, WinSCP, VS Code user setup). Do NOT alert on the Inno argument pattern alone; key on the staged helper names, callbacks, or SYSTEM tasks.
- Network events from `is-*.tmp` parents were observed only from benign tooling in testing; review before escalating.
- `RemoteUrl` is often a bare host without the query string; callback-URL matching (Query 1) only fires when the full URL is captured. Use the domain sweep (Query 4) for coverage.

## IOC Reference (published by Microsoft)

**Callback domains in the article IOC table:** `beliefdesk[.]xyz`, `companyharbor[.]xyz`, `signalpane[.]cfd`, `inkact[.]xyz`, `wishgrove[.]cfd`

**Additional domains in the article's own hunting query:** `orbittrack[.]cfd`, `prairielink[.]cfd`, `willowbox[.]xyz`, `stonestation[.]cfd`, `foldlodge[.]xyz`, `friendsanchor[.]xyz`, `fallport[.]cfd`, `wishcourt[.]cfd`, `cratebase[.]cfd`, `belieftrack[.]cfd`

**SHA-256**

| Hash |
|---|
| `006510ce1da2b7410376f0788c19e55616eb4bcc30072d25b7d0871dc32aa11c` |
| `21306fc5716f95e252388f920314b42f1c8bcc7df67cb4d39da30217b96f4044` |
| `72750d32b440e9f2b6d05ff3d218a561a75d3d75fb976b461fa59897674a7f70` |
| `ab2c2dd37fdcfe1e7620a57f98c80bd063258bea145adc0cc6a0f8b1e24c6a8f` |
| `452a210bba4c8d08f7cb7733a816d7220a7fa570a469aea0a997cfc8b594b6a0` |
| `523fb81fae0c7beba7b5171243cc0dee7a4d04ae0483be9172eef2394a5a2152` |
| `55cd3d36fdcc58016a64398357b2c9724a060da9f0d09266e537a61ec9552e4f` |

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Inno-Style Installer Callback URLs (`d=inno&r=offer_execution`)](#query-1-inno-style-installer-callback-urls-dinnorofferexecution) | Investigation | `DeviceNetworkEvents` |
| 2 | [Staged Helper Execution from Inno Temp Directory](#query-2-staged-helper-execution-from-inno-temp-directory) | Investigation | `DeviceProcessEvents` |
| 3 | [Network Activity from Inno Temp Directory Binaries (Hunting)](#query-3-network-activity-from-inno-temp-directory-binaries-hunting) | Investigation | `DeviceNetworkEvents` |
| 4 | [Published Domain Sweep](#query-4-published-domain-sweep) | Investigation | `DeviceNetworkEvents` |
| 5 | [WorldProxyPool / BOINC Payload Artifacts and SYSTEM Tasks](#query-5-worldproxypool--boinc-payload-artifacts-and-system-tasks) | Investigation | `DeviceEvents` + multi |
| 6 | [Published SHA-256 Sweep](#query-6-published-sha-256-sweep) | Investigation | `DeviceFileEvents` + `DeviceProcessEvents` |


## Query 1: Inno-Style Installer Callback URLs (`d=inno&r=offer_execution`)

**Purpose:** Detect the offer-execution callback pattern published by Microsoft.  
**Severity:** High  
**MITRE:** T1071.001, T1105

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CommandAndControl"
title: "Inno offer-execution callback from {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "A callback matching the trojanized Inno installer campaign was observed. Identify the initiating installer, review the download source, and investigate for WorldProxyPool/BOINC persistence on the device."
adaptation_notes: "Single-table, row-level; includes Timestamp, ReportId, DeviceId. Specific string match, low FP expectation."
-->

```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "d=inno" and RemoteUrl has_any ("r=offer_execution", "r=offer_execution_fail")
| project Timestamp, DeviceName, DeviceId, RemoteUrl, RemoteIP, InitiatingProcessFileName,
    InitiatingProcessFolderPath, InitiatingProcessCommandLine, ReportId
```

## Query 2: Staged Helper Execution from Inno Temp Directory

**Purpose:** Staged helper binaries executing from `%TEMP%\is-*.tmp\`.  
**Severity:** High  
**MITRE:** T1204.002, T1036

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "Inno staged helper executed on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Review the parent installer, its origin and hash. Check for SYSTEM scheduled tasks and proxy/BOINC software on the device."
adaptation_notes: "Row-level on DeviceProcessEvents with mandatory columns; stage-name filter avoids the broad legitimate Inno installer population."
-->

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FolderPath matches regex @"(?i)\\Temp\\is-[^\\]+\.tmp\\"
| where FileName matches regex @"(?i)^(eld[0-9]+|set_[0-9]+|FirstFast(\[1\])?|SecondRunner(\[1\])?)\.exe$"
| project Timestamp, DeviceName, DeviceId, FileName, FolderPath, ProcessCommandLine, SHA256,
    InitiatingProcessFileName, InitiatingProcessFolderPath, AccountName, ReportId
```

## Query 3: Network Activity from Inno Temp Directory Binaries (Hunting)

**Purpose:** Outbound connections from binaries running in `is-*.tmp`.  
**Severity:** Medium  
**MITRE:** T1071.001, T1105

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Summarize-based hunting aggregation; convert to row-level and add mandatory columns before promoting."
-->

```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFolderPath matches regex @"(?i)\\Temp\\is-[^\\]+\.tmp\\"
| where ActionType == "ConnectionSuccess" and RemoteIPType == "Public"
| summarize Conns = count(), Devices = dcount(DeviceName), Urls = make_set(RemoteUrl, 3) by InitiatingProcessFileName
| order by Conns desc
```

## Query 4: Published Domain Sweep

**Purpose:** Any connection to the callback/offer domains from the article.  
**Severity:** High  
**MITRE:** T1071.001

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CommandAndControl"
title: "Connection to trojanized-installer campaign domain from {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Identify the initiating process, isolate the device if an installer from Downloads/Temp is responsible, and hunt for WorldProxyPool/BOINC artifacts."
adaptation_notes: "Direct IOC match; extend the list as the operator rotates infrastructure."
-->

```kql
let Domains = dynamic(["beliefdesk.xyz","companyharbor.xyz","signalpane.cfd","inkact.xyz","wishgrove.cfd",
    "orbittrack.cfd","prairielink.cfd","willowbox.xyz","stonestation.cfd","foldlodge.xyz",
    "friendsanchor.xyz","fallport.cfd","wishcourt.cfd","cratebase.cfd","belieftrack.cfd"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (Domains)
| project Timestamp, DeviceName, DeviceId, RemoteUrl, RemoteIP, RemotePort,
    InitiatingProcessFileName, InitiatingProcessFolderPath, ReportId
```

## Query 5: WorldProxyPool / BOINC Payload Artifacts and SYSTEM Tasks

**Purpose:** Process, scheduled-task and file artifacts of the monetization payloads.  
**Severity:** High  
**MITRE:** T1053.005, T1564.003, T1496

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Persistence"
title: "WorldProxyPool/BOINC monetization payload artifact on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Review the scheduled tasks and installed software, determine the delivering installer, and remove the unauthorized agent via the endpoint management console."
adaptation_notes: "Union across three device tables (not NRT-eligible; 1H appropriate). BOINC is legitimate volunteer-computing software; confirm it is unsanctioned before action."
-->

```kql
union isfuzzy=true
(DeviceProcessEvents
 | where Timestamp > ago(30d)
 | where ProcessCommandLine has_any ("WorldProxyPool", "sdk-agent", "watchdog.ps1")
     or FolderPath has_any (@"\WorldProxyPool\", @"\BOINC\")
 | project Timestamp, SourceTable = "Process", DeviceName, DeviceId, ActionType, FileName, FolderPath,
     Detail = ProcessCommandLine, InitiatingProcessFileName, ReportId),
(DeviceEvents
 | where Timestamp > ago(30d)
 | where ActionType in ("ScheduledTaskCreated", "ScheduledTaskUpdated")
 | where AdditionalFields has "WorldProxyPool"
 | project Timestamp, SourceTable = "DeviceEvents", DeviceName, DeviceId, ActionType, FileName = "", FolderPath = "",
     Detail = tostring(AdditionalFields), InitiatingProcessFileName, ReportId),
(DeviceFileEvents
 | where Timestamp > ago(30d)
 | where FolderPath has_any (@"\WorldProxyPool\", @"\ProgramData\BOINC\", @"\Program Files\BOINC\")
     or FileName in~ ("sdk-agent.exe", "sdk-agent.updater.exe", "charityengine.exe", "ce11.exe")
 | project Timestamp, SourceTable = "File", DeviceName, DeviceId, ActionType, FileName, FolderPath,
     Detail = "", InitiatingProcessFileName, ReportId)
```

## Query 6: Published SHA-256 Sweep

**Purpose:** Direct hash match on published installer/helper samples.  
**Severity:** High  
**MITRE:** T1204.002

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "Trojanized Inno installer binary on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Published campaign hash observed. Isolate the device and investigate the delivering download and any persistence."
adaptation_notes: "Highest fidelity; coverage decays as the operator rebuilds payloads, so pair with Queries 1-5."
-->

```kql
let H = dynamic([
  "006510ce1da2b7410376f0788c19e55616eb4bcc30072d25b7d0871dc32aa11c",
  "21306fc5716f95e252388f920314b42f1c8bcc7df67cb4d39da30217b96f4044",
  "72750d32b440e9f2b6d05ff3d218a561a75d3d75fb976b461fa59897674a7f70",
  "ab2c2dd37fdcfe1e7620a57f98c80bd063258bea145adc0cc6a0f8b1e24c6a8f",
  "452a210bba4c8d08f7cb7733a816d7220a7fa570a469aea0a997cfc8b594b6a0",
  "523fb81fae0c7beba7b5171243cc0dee7a4d04ae0483be9172eef2394a5a2152",
  "55cd3d36fdcc58016a64398357b2c9724a060da9f0d09266e537a61ec9552e4f"]);
union isfuzzy=true
(DeviceProcessEvents
 | where Timestamp > ago(30d)
 | where SHA256 in~ (H) or InitiatingProcessSHA256 in~ (H)
 | project Timestamp, SourceTable = "DeviceProcessEvents", DeviceName, DeviceId, ActionType, FileName, FolderPath, SHA256, ReportId),
(DeviceFileEvents
 | where Timestamp > ago(30d)
 | where SHA256 in~ (H) or InitiatingProcessSHA256 in~ (H)
 | project Timestamp, SourceTable = "DeviceFileEvents", DeviceName, DeviceId, ActionType, FileName, FolderPath, SHA256, ReportId)
```
