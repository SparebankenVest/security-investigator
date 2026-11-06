# Storm-2603 — Fileless ToolShell Attack Using Velociraptor and Tunneling Tools

**Created:** 2026-11-06  
**Platform:** Both  
**Tables:** DeviceNetworkEvents, DeviceProcessEvents, DeviceFileEvents  
**Keywords:** Storm-2603, ToolShell, SharePoint, CVE-2025-53770, CVE-2025-53771, w3wp, in-memory webshell, Velociraptor, CVE-2025-6264, cloudflared, VS Code tunnel, Zoho Assist, rsndispot.sys, Warlock, ToolPane  
**MITRE:** T1190, T1505.003, T1055, T1572, T1090, T1068, T1136.001, T1219, T1105, T1218.007, T1562.001, T1574.002, T1486  
**Domains:** endpoint, exposure  
**Timeframe:** Last 30 days (configurable)  
**Source:** [Securelist — Storm-2603 fileless ToolShell attack (2026-11-05)](https://securelist.com/storm-2603-fileless-toolshell-attack/121467/)

---

## Threat Overview

Storm-2603 exploits on-premises SharePoint (ToolShell, CVE-2025-53770 / CVE-2025-53771) to run an in-memory webshell inside `w3wp.exe`, then installs Velociraptor (v0.73.4.0, abusing CVE-2025-6264) via `msiexec` from a Supabase-hosted MSI. Persistence and tunneling use Zoho Assist unattended agents, the VS Code CLI tunnel, cloudflared and a reverse proxy. A vulnerable driver (`rsndispot.sys`) is used to kill AV ahead of Warlock ransomware, with a renamed `7z.exe` sideloading a malicious DLL.

## TTP Summary

| Stage | Technique | MITRE | Query |
|---|---|---|---|
| Initial access | SharePoint ToolShell exploit | T1190 | 1, 3 |
| Webshell | In-memory webshell in w3wp | T1505.003, T1055 | 3 |
| Tooling / C2 | Velociraptor, cloudflared, VS Code tunnel, Zoho Assist | T1219, T1572, T1090, T1105 | 1, 4 |
| Defense evasion | Vulnerable driver, DLL sideloading | T1562.001, T1574.002 | 5 |
| Known samples | Published MD5 hashes | — | 2 |

## Hunt Pitfalls

- **`199.232.210.172` is a shared Fastly CDN IP** (Windows Update, Office, Teams). It matched thousands of events and is deliberately excluded from Query 1.
- **Inbound `ConnectionAttempt` events** from the published IPs indicate internet scanning/probing of exposed hosts, not outbound C2. Treat as exposure signals and review the targeted hosts, firewall and WAF logs.
- **VS Code `code-tunnel.exe`** (`tunnel kill`, `--delegate-to-editor`) launched by `code.exe` is routine developer behaviour; Query 4 excludes `code.exe` parents.
- **Azure CLI from IIS app pools** (`cmd.exe /c az account get-access-token`) is a `w3wp` child process seen legitimately; Query 3 excludes it and restricts to SharePoint app pools.
- Keep noisy branches in separate queries — a union with an unfiltered branch can hide results from file-only branches.

## IOC Reference (published by Securelist)

| Type | Value |
|---|---|
| IP (SPN node) | `45.91.94[.]204` |
| IP (C2 relay — shared Fastly CDN, FP-prone) | `199.232.210[.]172` |
| IP (bulletproof C2) | `91.224.92[.]121` |
| IP (SPN node) | `49.51.132[.]100` |
| IP (bulletproof C2) | `204.76.203[.]219` |
| URL (Velociraptor MSI) | `hxxps://vdfccjpnedujhrzscjtq[.]supabase[.]co/storage/v1/object/public/image/v4[.]msi` |
| URL (Velociraptor server) | `hxxps://auth[.]qgtxtebl[.]workers[.]dev/` |
| URL (cloudflared) | `hxxps://github[.]com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64[.]msi` |
| URL (Zoho Assist agent) | `hxxps://files[.]catbox[.]moe/8f7vex[.]msi` |
| File | `C:\ProgramFiles\Velociraptor\Velociraptor.exe` |
| File | `C:\ProgramFiles(x86)\ZohoMeeting\UnAttended\ZohoMeeting.7z` |
| MD5 | `FD91321BF7FF7245DDA9B7B5D791ACE8` (webshell) |
| MD5 | `3A55D8F8F29716C694671834D8C6CB29` (Velociraptor.exe) |
| MD5 | `991EC6E04413F2D4D29341C17A8A54D5` (VS Code) |
| MD5 | `3D553B9061C03F891CE97D7D2E64DDEE` (VS Code Insiders) |
| MD5 | `2C32E44A013CBFC5A323EFB7694701D2` (tunneling exe) |
| MD5 | `112A86ECA3CB5A0B5E20AB744CC5AF93` (7z.exe renamed) |
| MD5 | `A930F81E3FB0A226EC5904D9043A17B8` (ZohoMeeting.7z) |
| MD5 | `054a32d6033b1744dca7f49b2e466ea2` (rsndispot.sys) |
| MD5 | `2d9ebf9c042f596f435865b40edad928` (Warlock DLL, mentioned in text) |

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Published C2 / SPN IPs and Download URLs](#query-1-published-c2--spn-ips-and-download-urls) | Investigation | `DeviceNetworkEvents` |
| 2 | [Published MD5 Sweep](#query-2-published-md5-sweep) | Investigation | `DeviceFileEvents` + `DeviceProcessEvents` |
| 3 | [Suspicious Child Processes of IIS `w3wp.exe` Hosting SharePoint](#query-3-suspicious-child-processes-of-iis-w3wpexe-hosting-sharepoint) | Investigation | `DeviceProcessEvents` |
| 4 | [Tunneling and Remote-Management Tooling](#query-4-tunneling-and-remote-management-tooling) | Investigation | `DeviceProcessEvents` |
| 5 | [Vulnerable Driver and Tooling File Artifacts](#query-5-vulnerable-driver-and-tooling-file-artifacts) | Investigation | `DeviceFileEvents` |


## Query 1: Published C2 / SPN IPs and Download URLs

**Purpose:** Network events to published IPs and hosting URLs. Inbound `ConnectionAttempt` hits indicate scanning of exposed hosts.  
**Severity:** Medium  
**MITRE:** T1190, T1105, T1219

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CommandAndControl"
title: "Storm-2603 infrastructure contact on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Check ActionType and direction. Outbound success to these IPs/URLs warrants isolation and SharePoint compromise review; inbound attempts warrant exposed-host firewall/WAF review and IP blocking."
adaptation_notes: "Fastly IP 199.232.210.172 excluded. Medium severity because inbound probes are expected for exposed hosts; filter to ActionType == ConnectionSuccess for a higher-fidelity variant."
-->

```kql
let IPs = dynamic(["45.91.94.204","91.224.92.121","49.51.132.100","204.76.203.219"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (IPs)
    or RemoteUrl has_any ("vdfccjpnedujhrzscjtq.supabase.co", "qgtxtebl.workers.dev", "files.catbox.moe/8f7vex")
| project Timestamp, DeviceName, DeviceId, ActionType, RemoteIP, RemotePort, LocalPort, RemoteUrl,
    InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId
```

## Query 2: Published MD5 Sweep

**Purpose:** Match published MD5 hashes on process and file events.  
**Severity:** High  
**MITRE:** T1505.003, T1219, T1562.001

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Malware"
title: "Storm-2603 tooling hash on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Isolate the device, review SharePoint server integrity and rotate machine keys."
adaptation_notes: "Hashes for VS Code binaries (legitimate software) are listed in the article; confirm the file path and version before escalating those two."
-->

```kql
let M = dynamic(["FD91321BF7FF7245DDA9B7B5D791ACE8","3A55D8F8F29716C694671834D8C6CB29","991EC6E04413F2D4D29341C17A8A54D5",
    "3D553B9061C03F891CE97D7D2E64DDEE","2C32E44A013CBFC5A323EFB7694701D2","112A86ECA3CB5A0B5E20AB744CC5AF93",
    "A930F81E3FB0A226EC5904D9043A17B8","054a32d6033b1744dca7f49b2e466ea2","2d9ebf9c042f596f435865b40edad928"]);
union isfuzzy=true
(DeviceProcessEvents
 | where Timestamp > ago(30d)
 | where MD5 in~ (M)
 | project Timestamp, SourceTable = "Process", DeviceName, DeviceId, ActionType, FileName, FolderPath, MD5, ReportId),
(DeviceFileEvents
 | where Timestamp > ago(30d)
 | where MD5 in~ (M)
 | project Timestamp, SourceTable = "File", DeviceName, DeviceId, ActionType, FileName, FolderPath, MD5, ReportId)
```

## Query 3: Suspicious Child Processes of IIS `w3wp.exe` Hosting SharePoint

**Purpose:** Webshell command execution and `msiexec` installs spawned by SharePoint app pools.  
**Severity:** High  
**MITRE:** T1190, T1505.003, T1105

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Tuned for SharePoint pool command lines and excludes Azure CLI token calls; the app-pool filter depends on the environment's naming and should be validated before promotion."
-->

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where InitiatingProcessCommandLine has_any ("SharePoint", "-ap")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "msiexec.exe", "certutil.exe", "whoami.exe", "net.exe", "net1.exe", "curl.exe", "bitsadmin.exe")
| where ProcessCommandLine !has "az account get-access-token"
| project Timestamp, DeviceName, DeviceId, FileName, ProcessCommandLine,
    InitiatingProcessCommandLine, AccountName, ReportId
```

## Query 4: Tunneling and Remote-Management Tooling

**Purpose:** cloudflared service/token use, VS Code tunnel not launched by the editor, and Velociraptor.  
**Severity:** High  
**MITRE:** T1572, T1090, T1219

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CommandAndControl"
title: "Tunneling or remote-management tool launched on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Determine who installed the tool; on SharePoint or server hosts treat as suspected compromise."
adaptation_notes: "Excludes code.exe parents (routine VS Code tunnel housekeeping). Allowlist sanctioned cloudflared/Velociraptor deployments."
-->

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName =~ "cloudflared.exe" and ProcessCommandLine has_any (" run", "--token"))
    or (FileName =~ "code-tunnel.exe" and InitiatingProcessFileName !~ "code.exe")
    or FileName =~ "Velociraptor.exe"
| project Timestamp, DeviceName, DeviceId, FileName, FolderPath, ProcessCommandLine,
    InitiatingProcessFileName, AccountName, ReportId
```

## Query 5: Vulnerable Driver and Tooling File Artifacts

**Purpose:** `rsndispot.sys`, Velociraptor and Zoho unattended directories, and ToolPane compiled assemblies.  
**Severity:** High  
**MITRE:** T1562.001, T1505.003, T1219

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "DefenseEvasion"
title: "Storm-2603 file artifact on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Investigate the creating process and isolate the host; review for ransomware precursors."
adaptation_notes: "File-only query (split from process branches to avoid noise)."
-->

```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName =~ "rsndispot.sys"
    or FolderPath has @"\Velociraptor\"
    or FolderPath has @"\ZohoMeeting\UnAttended\"
    or (FolderPath has "Temporary ASP.NET Files" and FileName startswith "App_Web_toolpane")
| project Timestamp, DeviceName, DeviceId, ActionType, FileName, FolderPath,
    InitiatingProcessFileName, ReportId
```
