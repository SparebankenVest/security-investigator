# VOLTA Infostealer — LLM-Driven Victim Prioritization via OpenRouter

**Created:** 2026-11-06  
**Platform:** Both  
**Tables:** DeviceFileEvents, DeviceProcessEvents, DeviceNetworkEvents  
**Keywords:** VOLTA, VOLTA-AUTODOXER, infostealer, OpenRouter, LLM, victim prioritization, App-Bound Encryption, headless Chrome, Identity_Report.txt, AI_Analysis.txt, volta_dox.zip, Wi-Fi profile dump, Telegram exfiltration  
**MITRE:** T1555.003, T1539, T1552, T1005, T1560, T1041, T1102, T1070.004  
**Domains:** endpoint  
**Timeframe:** Last 30 days (configurable)  
**Source:** [Cisco Talos — Appraisal by AI: Model-driven victim prioritization in the VOLTA infostealer (2026-10-31)](https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/)

---

## Threat Overview

VOLTA is a self-deleting Windows infostealer. After stealing browser credentials, tokens and system data, it posts an evidence bundle to the OpenRouter API (`https://openrouter[.]ai/api/v1/chat/completions`) so an LLM can score and prioritize the victim. Reported default model is `anthropic/claude-opus-4.6` with fallbacks `moonshotai/kimi-k2` and `google/gemini-2.5-flash`. Results and stolen data are staged as `Identity_Report.txt`, `AI_Analysis.txt`, `volta_dox.zip`, `volta_log.zip`, `volta_doxnet.zip` and `%APPDATA%\volta_debug.txt`, then exfiltrated (Telegram). Chrome App-Bound Encryption is bypassed using `chrome --headless` launched by a non-browser process.

## TTP Summary

| Stage | Technique | MITRE | Query |
|---|---|---|---|
| Credential access | Browser credentials / tokens via headless Chrome | T1555.003, T1539 | 4 |
| Collection | Local data, staged archives | T1005, T1560 | 2 |
| Analysis / C2 | LLM API call over HTTPS | T1102, T1071.001 | 3 |
| Exfiltration | Telegram | T1041 | — (no query) |
| Cleanup | Self-delete | T1070.004 | — (no query) |
| Known sample | Published SHA-256 / filenames | — | 1 |

## Hunt Pitfalls

- **OpenRouter is a legitimate service.** Browsers and AI/dev tooling on user endpoints legitimately reach `openrouter.ai`; testing showed only browser helper and developer-app traffic. Alert only on unexpected initiating processes after baselining.
- **Headless Chromium is very noisy** from browsers, Node.js, WSL, Playwright, VS Code and scripting hosts. Exclude known browsers and developer tooling parents; treat remaining parents as leads, not detections.
- Only one sample hash is published; the malware self-deletes and rebuilds, so rely on behaviour (Queries 2-4).

## IOC Reference (published by Talos)

| Type | Value |
|---|---|
| SHA-256 | `57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279` |
| Sample file names | `9BY0tjwOc3ut.exe`, `yLP9m5J3i2Aw.exe` |
| URL | `https://openrouter[.]ai/api/v1/chat/completions` |
| Artifacts | `Identity_Report.txt`, `AI_Analysis.txt`, `volta_dox.zip`, `volta_log.zip`, `volta_doxnet.zip`, `volta_debug.txt` |

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Published Sample Hash and File Name Sweep](#query-1-published-sample-hash-and-file-name-sweep) | Investigation | `DeviceFileEvents` + `DeviceProcessEvents` |
| 2 | [VOLTA Staging Artifact Files](#query-2-volta-staging-artifact-files) | Investigation | `DeviceFileEvents` |
| 3 | [OpenRouter API Access by Initiating Process (Hunting)](#query-3-openrouter-api-access-by-initiating-process-hunting) | Investigation | `DeviceNetworkEvents` |
| 4 | [Headless Chromium Launched by a Non-Browser Parent (Hunting)](#query-4-headless-chromium-launched-by-a-non-browser-parent-hunting) | Investigation | `DeviceProcessEvents` |


## Query 1: Published Sample Hash and File Name Sweep

**Purpose:** Match the published sample by SHA-256 or file name.  
**Severity:** High  
**MITRE:** T1555.003

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Malware"
title: "VOLTA infostealer sample on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Isolate the device, reset credentials and revoke sessions for accounts used in browsers on it, and investigate for data exfiltration."
adaptation_notes: "Direct IOC match across process and file events; row-level with mandatory columns."
-->

```kql
let H = "57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279";
let N = dynamic(["9BY0tjwOc3ut.exe","yLP9m5J3i2Aw.exe"]);
union isfuzzy=true
(DeviceProcessEvents
 | where Timestamp > ago(30d)
 | where SHA256 =~ H or InitiatingProcessSHA256 =~ H or FileName in~ (N)
 | project Timestamp, SourceTable = "Process", DeviceName, DeviceId, ActionType, FileName, FolderPath, SHA256, ReportId),
(DeviceFileEvents
 | where Timestamp > ago(30d)
 | where SHA256 =~ H or FileName in~ (N)
 | project Timestamp, SourceTable = "File", DeviceName, DeviceId, ActionType, FileName, FolderPath, SHA256, ReportId)
```

## Query 2: VOLTA Staging Artifact Files

**Purpose:** Creation of VOLTA's characteristic output files.  
**Severity:** High  
**MITRE:** T1005, T1560

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Collection"
title: "VOLTA staging artifact created on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Investigate the creating process, isolate the device and reset credentials for browser-stored accounts."
adaptation_notes: "Specific file names; low FP expectation. Note that Identity_Report.txt and AI_Analysis.txt are generic-sounding, so review the initiating process."
-->

```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FileName in~ ("volta_debug.txt", "volta_log.zip", "volta_dox.zip", "volta_doxnet.zip", "Identity_Report.txt", "AI_Analysis.txt")
| project Timestamp, DeviceName, DeviceId, ActionType, FileName, FolderPath,
    InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, ReportId
```

## Query 3: OpenRouter API Access by Initiating Process (Hunting)

**Purpose:** Identify which processes talk to OpenRouter; investigate unexpected ones.  
**Severity:** Medium  
**MITRE:** T1102, T1071.001

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Summarize-based hunt requiring an environment baseline/allowlist of sanctioned AI tooling and browsers."
-->

```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "openrouter.ai"
| summarize Conns = count(), Devices = dcount(DeviceId), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
    by InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Conns desc
```

## Query 4: Headless Chromium Launched by a Non-Browser Parent (Hunting)

**Purpose:** App-Bound Encryption bypass pattern — headless browser spawned by an unusual parent.  
**Severity:** Medium  
**MITRE:** T1555.003, T1539

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Very noisy: browsers, Node.js, WSL, Playwright, VS Code and scripting hosts legitimately launch headless Chromium. Requires a parent allowlist/rarity filter before promotion."
-->

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("chrome.exe", "msedge.exe", "brave.exe")
| where ProcessCommandLine has "--headless"
| summarize Runs = count(), Devices = dcount(DeviceId) by InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Runs asc
```
