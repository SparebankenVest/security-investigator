# SCKit — ScreenConnect Abuse, RelayTrap Persistence and Technician-Session Targeting — Threat Hunts

**Created:** 2026-11-20  
**Platform:** Microsoft Defender XDR  
**Tables:** DeviceNetworkEvents, DeviceProcessEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceEvents  
**Keywords:** SCKit, ScreenConnect, ConnectWise Control, RMM abuse, RelayTrap, TrapWatch, RelayTrapLiteAlert, ToolboxRelayUploader, Shared Toolbox, Panel-Lateral, Stage0Loader, sc.msi, EadF.php, .ASPXAUTH, cookie theft, DPAPI, Defender exclusion, technician session, CVE-2026-84869, CWInstall, ConnectWiseControl  
**MITRE:** T1219, T1059.001, T1059.003, T1547.001, T1053.005, T1562.001, T1539, T1555.003, T1105, T1070.004  
**Domains:** endpoint  
**Timeframe:** Last 30 days (configurable)  
**Source:** [SCKit abuses ScreenConnect to deploy remote access and target technician sessions (2026-11-13)](https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/)

---

## Threat Overview

SCKit is a toolkit that abuses ConnectWise ScreenConnect. ScreenConnect remote commands launch command-shell, batch and PowerShell stages that fetch a decoder, a toolkit bundle and extra ScreenConnect client installers from campaign infrastructure. On the endpoint the toolkit persists under `C:\ProgramData\RelayTrap` with a `RelayTrapLiteAlert` Run value and a scheduled task running a watcher (`-PollSeconds 10`). The watcher builds `RelayTrap.exe` from local ScreenConnect client libraries to push a launcher to technicians who connect. A browser component steals `.ASPXAUTH` cookies (database queries, browser memory scanning, DPAPI) and uses `ToolboxRelayUploader.exe` to queue payloads through the Shared Toolbox. Defender path-exclusion registry writes protect staged MSI and `CWInstall_…\Installer.ps1`. The article names no actor; it cites a server-side RMM+ extension authentication flaw and the CVE-2026-84869 client fix (ScreenConnect client 26.6.5 and later).

### TTP Summary

| Capability | TTP |
|---|---|
| Execution | ScreenConnect remote commands launch cmd, batch and PowerShell stages (T1219, T1059.001, T1059.003) |
| Ingress tool transfer | PowerShell and `curl.exe` retrieve decoder, toolkit and client installers; `/EadF.php`, `c=Exploited<N>` (T1105) |
| Persistence | Extra ScreenConnect clients with automatic start; `RelayTrapLiteAlert` Run value; RelayTrap/TrapWatch scheduled task (T1547.001, T1053.005) |
| Defense evasion | Defender path exclusions; PowerShell loader deletes `k<32hex>.ps1` (T1562.001, T1070.004) |
| Credential access | `.ASPXAUTH` cookie theft from Chrome, Edge, Opera, Opera GX via SQLite, VSS and memory scanning; DPAPI (T1539, T1555.003) |

### ⚠️ Hunt Pitfalls

| Pitfall | Mitigation |
|---|---|
| **ScreenConnect is legitimate software** | Allowlist your own instance (enrolled instance ID / relay host) and approved deployment tooling; the signal is an unknown relay or the toolkit artifacts. |
| **Defender exclusion writes are mostly Defender's own** | `MsMpEng.exe` mirrors effective policy into the exclusion keys. Query 6 excludes it unless the path names toolkit artifacts. |
| **Keyword hunts match the analyst's own shells** | Command-line searches for `SCKit`, `RelayTrap` etc. match shells that run these very searches. Check the initiating process before escalating. |
| **SHA-256 is usually unpopulated in `DeviceFileEvents`** | Match SHA-1 for file events (Query 3). |
| **RelayTrap is compiled per client** | Hashes change per build; rely on Run value, task names and `ProgramData\RelayTrap` paths. |

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Connections to SCKit Infrastructure](#query-1-connections-to-sckit-infrastructure) | Investigation | `DeviceNetworkEvents` |
| 2 | [Toolkit Command-Line Markers](#query-2-toolkit-command-line-markers) | Investigation | `DeviceProcessEvents` |
| 3 | [Installer, Archive, Uploader and Loader Artifacts](#query-3-installer-archive-uploader-and-loader-artifacts) | Investigation | `DeviceFileEvents` |
| 4 | [RelayTrap Persistence in the Registry](#query-4-relaytrap-persistence-in-the-registry) | Investigation | `DeviceRegistryEvents` + `RelayTrapLiteAlert` |
| 5 | [RelayTrap and TrapWatch Scheduled Tasks](#query-5-relaytrap-and-trapwatch-scheduled-tasks) | Detection | `DeviceEvents` |
| 6 | [Defender Path Exclusions for Toolkit Artifacts](#query-6-defender-path-exclusions-for-toolkit-artifacts) | Investigation | `DeviceRegistryEvents` |
| 7 | [Silent ScreenConnect Client Installs](#query-7-silent-screenconnect-client-installs) | Investigation | `DeviceProcessEvents` |
| 8 | [ScreenConnect-Spawned Shells That Download or Run Encoded Commands](#query-8-screenconnect-spawned-shells-that-download-or-run-encoded-commands) | Investigation | `DeviceProcessEvents` |


## IOC Reference

IOCs are copied from the source article (defanged there). Operators rotate infrastructure; refresh from current Microsoft TI before relying on sweeps.

| Indicator | Type | Role |
|---|---|---|
| ns[.]mo7sen[.]dev | Domain | Decoder, bundle, script, utility retrieval |
| sc[.]payproofkit[.]com | Domain | Unauthorized ScreenConnect panel and installer source |
| cdn007-digitaldownloads[.]com | Domain | Campaign infrastructure; configured installer source |
| newnewnew[.]gotdns[.]org | Domain | Associated ScreenConnect relay |
| soxnewwork[.]homedns[.]org | Domain | Associated ScreenConnect relay |
| 185[.]99[.]255[.]28 | IPv4 | Unauthorized ScreenConnect server and installer source |
| 155[.]94[.]150[.]39 | IPv4 | Address associated with the unauthorized panel |
| 2588ef5c15954b10 | Client ID | Unauthorized ScreenConnect client identifier |
| ed630cc2c873b091 | Client ID | Unauthorized ScreenConnect client identifier |
| 0be01e7bd69cfdd222645d49bb5ad9961372fef2 | SHA-1 | sc.msi |
| 3f81c9c874a896c46e4bccea2fad2eaa3d9f2054 | SHA-1 | Staged toolkit ZIP |
| 13ce33b19daee3963f7e15d461b191c38f6bc0d3 | SHA-1 | Uploader |
| 61a672a13f03a9e81f573535ee92b1ed6cb7e848a33a06048865312d4e185ae2 | SHA-256 | sc.msi installer package |
| 8e6912deed82e80bb6bd66f73509d024b1f78b993515366d8317e69a97cff4f4 | SHA-256 | Staged toolkit ZIP |
| 8cb5f48bbe70b5248db7f327f3d1ad6649df5c767d2a7e0711ee147fd92e06af | SHA-256 | ToolboxRelayUploader.exe |
| 94b93c649b0ae0281352da9d01761fa9195ab1e6ac7010af3b9ba1646355eb11 | SHA-256 | Panel-Lateral-free.ps1 |
| 7a9aca9fdd4dcc13fe497cabdb13ca1e5d6a529271c8aa495e5ca1c1c80271ec | SHA-256 | Panel-Lateral.ps1 |
| b93f10f30ee453d1e1c046fec9d141c41d7680be5cd46c3aeb3febe0f4953b4d | SHA-256 | LabConfig.ps1 helper |
| 3c7a98f0fdb6235b8076319c74dc1085f7b349b6d750416dd0cadb07d7972ec4 | SHA-256 | RelayTrap.cs source |
| d2ed7a7bf4f8ac9c7969e9b3a07ebd4dda0d858f372c876ac0a041611698de9a | SHA-256 | TrapWatch.ps1 |
| 4a1dd3cd2ea14368afadf7e9dfdd63b104e3981ef8c85bbb6510919b810af04b | SHA-256 | trapkit\install.ps1 |
| cf50d73fa8117a758093b1344de41cd6a6ccddc645cdda1fa91a9264efe93956 | SHA-256 | Lite-Alert.ps1 |
| 81cc2baa35b798d6084bd078662fa29ff28df02c46c6ccdb2b43bde97d19f781 | SHA-256 | Stage0Loader.ps1 |
| 43b7a5e56f9e6c7b74e1ce2b7b5af63f383084625fcc2d3a5985fa1059e2db95 | SHA-256 | Run-Lateral-Full.bat |
| 50659748723e906c8b3d3c0386bd4cf692f693a3e23639398c1a14d0c31fed61 | SHA-256 | runnew.cmd |
| 5dd3a6ba806ac472663e243cfc1c034c534d5d9a42ec362c3dbf0f8d950148d0 | SHA-256 | Stop-LabTrap.bat cleanup-mode launcher |
| 454c43d296b1276bde9a4f6ff1da2221cb35ccdb2fc7991bdd572e45bce12a8a | SHA-256 | TRAP-PROOF.bat proof artifact |

---

## Query 1: Connections to SCKit Infrastructure

**Purpose:** Direct sweep for connections to the published domains and IPs. A clean result means no endpoint contacted them in the window.  
**Severity:** High  
**MITRE:** T1219, T1105  
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CommandAndControl"
title: "Connection to SCKit ScreenConnect infrastructure on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "A device contacted infrastructure tied to the SCKit ScreenConnect toolkit. Investigate through a separate channel (not ScreenConnect), isolate the device, review installed ScreenConnect clients and their relay destination, and include connecting technician workstations in scope."
adaptation_notes: "Row-level, projects Timestamp, DeviceId, DeviceName, ReportId. Validated: 0 rows over 30 days (AH). Direct IOC match, low noise; the IOC list rots - refresh periodically."
-->

```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (
    "ns.mo7sen.dev", "sc.payproofkit.com", "cdn007-digitaldownloads.com",
    "newnewnew.gotdns.org", "soxnewwork.homedns.org")
    or RemoteIP in ("185.99.255.28", "155.94.150.39")
| project Timestamp, DeviceId, DeviceName, RemoteUrl, RemoteIP,
    InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId
```

**Expected results:** 0 rows in an unaffected environment. Any row warrants triage of the initiating process.

---

## Query 2: Toolkit Command-Line Markers

**Purpose:** Finds command lines with distinctive toolkit names, staging paths, installer markers or cookie-query strings. Word-boundary regex limits accidental substring matches.  
**Severity:** High  
**MITRE:** T1059.001, T1539, T1105  
<!-- cd-metadata
cd_ready: false
adaptation_notes: "Command-line keyword search that also matches analyst and AI-agent shells running these same searches (the only rows seen in the validation tenant), so it is triage, not auto-alerting. For CD, keep /EadF.php with c=Exploited plus ToolboxRelayUploader and drop the families that self-match."
-->

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine contains "/EadF.php"
    or ProcessCommandLine contains "c=Exploited"
    or ProcessCommandLine matches regex @"(?i)(^|[^A-Za-z0-9+/])(SCKit|RelayTrap|TrapWatch|Panel-Lateral|ToolboxRelayUploader|Stop-LabTrap|Stage0Loader)([^A-Za-z0-9+/]|$)"
    or ProcessCommandLine matches regex @"(?i)\.ASPXAUTH.{0,200}(Cookies|sqlite)|(sqlite3?|Cookies).{0,200}\.ASPXAUTH"
| project Timestamp, DeviceId, DeviceName, FileName, InitiatingProcessFileName,
    ProcessCommandLine, ReportId
| order by Timestamp desc
```

**Expected results:** No rows from real toolkit activity. Rows from shells whose command line merely contains the search strings are self-matches; check the parent process.

---

## Query 3: Installer, Archive, Uploader and Loader Artifacts

**Purpose:** Matches the published SHA-1 hashes and the generated `k<32hex>.ps1` loader files, which are detectable independently of hashes or infrastructure.  
**Severity:** High  
**MITRE:** T1105, T1070.004  
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "SCKit artifact on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "A file matching the SCKit installer, toolkit ZIP, uploader hash or the generated k<32hex>.ps1 loader pattern was observed. Investigate through a separate channel, review ScreenConnect clients and persistence (Run key, scheduled tasks), and check connecting technician workstations."
adaptation_notes: "Row-level on DeviceFileEvents. SHA-1 used because SHA-256 is usually unpopulated. Validated: 0 rows over 30 days (AH)."
-->

```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA1 in~ (
    "0be01e7bd69cfdd222645d49bb5ad9961372fef2",
    "3f81c9c874a896c46e4bccea2fad2eaa3d9f2054",
    "13ce33b19daee3963f7e15d461b191c38f6bc0d3")
    or FileName matches regex @"(?i)^k[0-9a-f]{32}\.ps1$"
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, FolderPath,
    SHA1, InitiatingProcessFileName, ReportId
```

**Expected results:** 0 rows in an unaffected environment.

---

## Query 4: RelayTrap Persistence in the Registry

**Purpose:** Detects writes of the `RelayTrapLiteAlert` Run value or any value referencing `RelayTrap`.  
**Severity:** High  
**MITRE:** T1547.001  
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Persistence"
title: "RelayTrap persistence registry value on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "A RelayTrap Run value was written. Treat the device and any technician who connected to it as compromised: isolate, preserve ScreenConnect console and endpoint evidence, and revoke ScreenConnect and identity-provider sessions from a clean device."
adaptation_notes: "Row-level on DeviceRegistryEvents; distinctive value name, very low noise. Validated: 0 rows over 30 days (AH)."
-->

```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType == "RegistryValueSet"
| where RegistryValueName =~ "RelayTrapLiteAlert"
    or RegistryValueData contains "RelayTrap"
| project Timestamp, DeviceId, DeviceName, RegistryKey, RegistryValueName,
    RegistryValueData, InitiatingProcessFileName, ReportId
```

**Expected results:** 0 rows in an unaffected environment.

---

## Query 5: RelayTrap and TrapWatch Scheduled Tasks

**Purpose:** Finds scheduled-task events whose definition references RelayTrap or TrapWatch.  
**Severity:** High  
**MITRE:** T1053.005  
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Persistence"
title: "RelayTrap/TrapWatch scheduled task on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "A scheduled task referencing RelayTrap or TrapWatch was created or changed. Inspect the task definition (trigger, executable, arguments), isolate the device and follow the SCKit remediation guidance."
adaptation_notes: "Row-level on DeviceEvents. Validated: 0 rows over 30 days (AH); distinctive IOC-style match."
-->

```kql
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType contains "ScheduledTask"
| where AdditionalFields has_any ("RelayTrap", "TrapWatch")
| project Timestamp, DeviceId, DeviceName, ActionType, AdditionalFields,
    InitiatingProcessFileName, ReportId
```

**Expected results:** 0 rows in an unaffected environment.

---

## Query 6: Defender Path Exclusions for Toolkit Artifacts

**Purpose:** Finds Defender path-exclusion writes that name ScreenConnect installers or toolkit paths, or that come from a process other than Defender itself.  
**Severity:** Medium  
**MITRE:** T1562.001  
<!-- cd-metadata
cd_ready: false
adaptation_notes: "Row-level and suitable for CD after allowlisting admin tooling that writes exclusions (GPO/MDM, security agents). Validated: tuned to 0 rows over 30 days (AH). Untuned, the same key returned 18 rows across 9 devices, all written by MsMpEng.exe for admin-defined developer paths - the noise this tuning removes."
-->

```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType == "RegistryValueSet"
| where RegistryKey contains @"\Windows Defender\Exclusions\Paths"
| where InitiatingProcessFileName !~ "MsMpEng.exe"
    or RegistryValueName has_any ("ConnectWiseControl", "CWInstall", "RelayTrap", "SCKitBundle", @"\Windows\Temp")
| project Timestamp, DeviceId, DeviceName, RegistryKey, RegistryValueName,
    RegistryValueData, InitiatingProcessFileName, ReportId
```

**Expected results:** 0 rows when no exclusions are written outside Defender policy mirroring. Verify authorization of any row.

---

## Query 7: Silent ScreenConnect Client Installs

**Purpose:** Finds silent `msiexec` installs of ScreenConnect/ConnectWise Control packages (including `sc.msi`), the mechanism for adding extra unauthorized clients.  
**Severity:** Medium  
**MITRE:** T1219  
<!-- cd-metadata
cd_ready: false
adaptation_notes: "Legitimate where ScreenConnect is deployed; needs an allowlist of approved parents/instances before CD use. Validated: 0 rows over 30 days (AH)."
-->

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "msiexec.exe"
| where ProcessCommandLine has_any ("ScreenConnect", "ConnectWiseControl", "sc.msi")
| where ProcessCommandLine has_any ("/qn", "/quiet", "/q")
| project Timestamp, DeviceId, DeviceName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId
```

**Expected results:** Rows only where ScreenConnect is deployed; compare to approved deployments.

---

## Query 8: ScreenConnect-Spawned Shells That Download or Run Encoded Commands

**Purpose:** Finds shells spawned by the ScreenConnect client service that download content or run encoded commands, plus any shell referencing the campaign domains.  
**Severity:** High  
**MITRE:** T1059.001, T1059.003, T1105  
<!-- cd-metadata
cd_ready: false
adaptation_notes: "Legitimate remote support can run downloads and encoded scripts; allowlist approved scripts and technicians before CD use. Validated: 0 rows over 30 days (AH)."
-->

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "curl.exe")
| where ProcessCommandLine has_any ("mo7sen", "payproofkit", "cdn007-digitaldownloads")
    or (InitiatingProcessFileName in~ ("ScreenConnect.ClientService.exe", "ScreenConnect.WindowsClient.exe")
        and FileName in~ ("powershell.exe", "cmd.exe")
        and ProcessCommandLine has_any ("-enc", "-EncodedCommand", "DownloadString", "DownloadFile", "iwr", "curl", "Invoke-WebRequest"))
| project Timestamp, DeviceId, DeviceName, FileName, ProcessCommandLine,
    InitiatingProcessFileName, ReportId
```

**Expected results:** 0 rows without ScreenConnect abuse; review legitimate support sessions separately.

---

## General Tuning Notes

1. **IOC refresh.** Domains, relays and client IDs rotate; RelayTrap builds differ per client. Refresh from Microsoft TI and keep the behavioral queries (3, 4, 5, 6, 8) as the durable layer.
2. **Telemetry gaps.** In-memory browser cookie scanning leaves little endpoint telemetry beyond process and SQLite command lines (Query 2). Pair with ScreenConnect audit and Toolbox history.
3. **Inventory first.** Keep an inventory of approved ScreenConnect instances and relay hosts and exclude them in Queries 7 and 8.
4. **CD-readiness.** Queries 1, 3, 4 and 5 are `cd_ready: true`; Queries 2, 6, 7 and 8 are `cd_ready: false` with notes. All eight were executed in Advanced Hunting; none returned toolkit activity.
5. **Remediation.** Investigate through a separate channel (Defender live response), update technician clients to 26.6.5 or later, and revoke ScreenConnect and identity-provider sessions from a clean device.

---

## References

- Microsoft Threat Intelligence — [SCKit abuses ScreenConnect to deploy remote access and target technician sessions](https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/)
- MITRE ATT&CK — [T1219 Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- Companion file: [`queries/threat-intelligence/2026-09/storm_2570_ransomware_affiliate_tradecraft.md`](../2026-09/storm_2570_ransomware_affiliate_tradecraft.md)
