# Endpoint Auditing: Network & Process Correlation via PowerShell

![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=flat&logo=powershell&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D4?style=flat&logo=windows&logoColor=white)
![Domain](https://img.shields.io/badge/Domain-Endpoint_Auditing-4CAF50?style=flat&logoColor=white)

**Analyst:** Denis O. Onduso  
**Focus:** Live network socket enumeration, PID-to-process mapping, administrative process inspection

---

## Objective

Use native Windows PowerShell tooling to enumerate all active network connections on a live endpoint and attribute each connection to its originating process — establishing whether any unauthorized or unexpected external communication is occurring.

---

## Environment

- Windows host with PowerShell running under elevated (Administrator) privileges
- `netstat` used for socket enumeration; cross-referenced against the running process table

---

## Analysis

### Network Socket Enumeration

`netstat -abno` was executed under an elevated session to capture the full connection state of the endpoint, including:

- All active TCP connections and their states (`ESTABLISHED`, `LISTENING`, `TIME_WAIT`)
- UDP listeners
- The owning executable (`-b`) and PID (`-o`) for each socket
- Local and remote address/port pairs

Running without elevation returns incomplete results — certain system-level sockets owned by protected services are hidden from standard user context. Administrative execution was required to get a complete picture.

### PID-to-Process Mapping

Connections of interest were isolated by state and remote port, then cross-referenced against the process table using the PID column:

- Port 443 (`ESTABLISHED`) traffic was attributed to `msedge.exe` — confirmed legitimate browser activity
- `LISTENING` sockets on local ports were mapped to `svchost.exe` instances, each verified against their expected service group
- No connections were found originating from processes running outside `C:\Windows\System32\` or `C:\Program Files\`

### Executable Verification

For each process with an active outbound connection, the image path and signing status were checked. All established connections were attributed to signed, path-verified executables. No unsigned binaries with active network connections were identified.

---

## Key Findings

All active outbound connections on the endpoint were attributable to known, signed executables at expected file paths. No unauthorized external communication was detected. The PID correlation workflow confirmed that `netstat -abno` combined with process table cross-referencing is sufficient for rapid triage of suspicious outbound connections without requiring a third-party tool.

---

## Commands Reference

| Command | Purpose |
|---------|---------|
| `netstat -abno` | Full socket enumeration with executable name, PID, and connection state |
| `Get-Process -Id <PID>` | Retrieve process details by PID for cross-referencing |
| `Get-AuthenticodeSignature` | Verify digital signature of a process executable |
| `Get-NetTCPConnection` | PowerShell-native alternative to netstat with object output for filtering |

---

## Tools

- **Windows PowerShell** (elevated) — socket enumeration, process mapping, signature verification
- **netstat** — native TCP/UDP connection state capture

---

## MITRE ATT&CK Relevance

| Technique | ID | Relevance |
|-----------|----|-----------|
| System Network Connections Discovery | T1049 | Enumerating active connections to identify C2 or exfiltration |
| Process Discovery | T1057 | PID mapping to attribute connections to specific processes |
| Masquerading | T1036 | Image path verification to detect processes mimicking legitimate names |
| Signed Binary Proxy Execution | T1218 | Checking for abuse of signed executables to proxy malicious traffic |
