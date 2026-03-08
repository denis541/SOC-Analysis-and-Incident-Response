# Endpoint Analysis: Process & Network Visibility with Sysinternals TCPView

![Sysinternals](https://img.shields.io/badge/Sysinternals-TCPView-0078D4?style=flat&logo=windows&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D4?style=flat&logo=windows&logoColor=white)
![Domain](https://img.shields.io/badge/Domain-Endpoint_Analysis-4CAF50?style=flat&logoColor=white)

**Analyst:** Denis O. Onduso  
**Focus:** Host-based process monitoring, network connection mapping, and system baseline establishment

---

## Objective

Map all active processes to their network endpoints in real time using Sysinternals TCPView, identify baseline system behavior for core Windows processes, and observe how user-initiated activity dynamically changes the endpoint's network footprint.

---

## Environment

- Windows host with Sysinternals Suite deployed
- TCPView (`Tcpview.exe`) used for live TCP/UDP endpoint visibility across all running processes

---

## Analysis

### Baseline: Core System Processes

Before introducing any user activity, the following system processes were observed and documented to establish a clean baseline:

| Process | PID Type | Network Behavior | Security Note |
|---------|----------|------------------|---------------|
| `lsass.exe` | System | No external connections — local authentication traffic only | Path must be `C:\Windows\System32\lsass.exe`. Any deviation (e.g. `lsasss.exe`, wrong path) is a strong masquerading indicator |
| `svchost.exe` | System | Multiple local port listeners; hosts various Windows service groups | Legitimate instances run under `C:\Windows\System32\`. Multiple instances are normal — verify parent is `services.exe` |
| `System` | Kernel | Minimal, predictable local traffic | Should not establish outbound internet connections |

### Dynamic Analysis: Monitoring User-Initiated Activity

With the baseline captured, Microsoft Edge was launched while TCPView remained open. The following changes were observed in real time:

- `msedge.exe` spawned multiple child processes immediately on launch
- New outbound TCP connections appeared within seconds, targeting remote IPs on **port 443 (HTTPS)** and **port 80 (HTTP)**
- Connection states cycled through: `SYN_SENT` → `ESTABLISHED` → `TIME_WAIT` → removed
- On closing the browser, all associated connections transitioned to `TIME_WAIT` and were cleared from the view as the OS completed the TCP teardown sequence

This confirmed that TCPView provides sufficient granularity to attribute specific network connections to specific processes in real time — a core capability for triage during an endpoint investigation.

---

## Key Findings

The analysis confirmed that legitimate system processes (`lsass.exe`, `svchost.exe`) maintain predictable, locally scoped network behavior. Any outbound connections from these processes would be immediately anomalous and warrant investigation.

User-space processes like `msedge.exe` behave exactly as expected — dynamic, high-connection-count, short-lived sessions to CDN and web infrastructure. Knowing what normal looks like here is what makes abnormal (e.g. a browser process connecting to a non-standard port, or `lsass.exe` with any outbound connection) detectable.

---

## Tools

- **Sysinternals TCPView** — real-time process-to-endpoint mapping
- **Windows Command Line** — tool execution and directory navigation

---

## MITRE ATT&CK Relevance

| Technique | ID | Relevance |
|-----------|----|-----------|
| Process Discovery | T1057 | Enumerating running processes to understand system state |
| System Network Connections Discovery | T1049 | Mapping active connections per process |
| Masquerading | T1036 | lsass.exe path verification detects process name spoofing |
