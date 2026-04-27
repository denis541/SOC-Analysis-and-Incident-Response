 ![Wireshark](https://img.shields.io/badge/Wireshark-1679C2?style=flat&logo=wireshark&logoColor=white)     
![Splunk](https://img.shields.io/badge/Splunk-000000?style=flat&logo=splunk&logoColor=white)       
![Elastic](https://img.shields.io/badge/Elastic_Stack-005571?style=flat&logo=elastic&logoColor=white)       
![Suricata](https://img.shields.io/badge/Suricata-EF7B29?style=flat&logoColor=white)                 
![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=flat&logo=powershell&logoColor=white)            
 ![Windows](https://img.shields.io/badge/Sysinternals-0078D4?style=flat&logo=windows&logoColor=white)  
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-E01B1B?style=flat&logoColor=white)  
![Zeek](https://img.shields.io/badge/Zeek-2F6FAD?style=flat&logoColor=white)
![Security Onion](https://img.shields.io/badge/Security_Onion-4CAF50?style=flat&logoColor=white) 
![Volatility](https://img.shields.io/badge/Volatility_Framework-6C3483?style=flat&logoColor=white)
![NIST](https://img.shields.io/badge/NIST_CSF-003087?style=flat&logoColor=white) 
![MIT License](https://img.shields.io/badge/License-MIT-lightgrey?style=flat)
# Security Operations & Incident Response Portfolio

**Denis O. Onduso** · SOC Analysis · Digital Forensics · Detection Engineering  
📧 Denis.Onduso@outlook.com

---

## Overview

This repository documents hands-on security operations work across endpoint forensics, network traffic analysis, cryptographic validation, and full incident response investigations. Each project follows analyst-level methodology — starting from raw evidence, working through tool-assisted investigation, and ending with documented findings and recommendations.

The work spans 18 projects organized by discipline, from foundational endpoint visibility through to multi-stage malware analysis using real PCAP data.

---

## Highlighted Investigations

### Remcos RAT & Dridex Infection — Multi-Stage Endpoint Compromise
`Wireshark` `Zeek` `Suricata` `Kibana` `Elastic Stack`

Investigated a multi-stage infection chain triggered on 2019-03-19. NSM alerts fired on encrypted C2 traffic to an external IP, leading to discovery of two malicious executables retrieved via HTTP GET requests. Analysis confirmed Remcos RAT check-ins on non-standard ports alongside Dridex-associated SSL certificates originating from `31.22.4.176`. Payload extraction from the PCAP revealed an MZ (hex `4D 5A`) file signature. SHA256 hash `2a9b0ed40f1f0bc0c13ff35d304689e9cadd633781cbcad1c2d2b92ced3f1c85` was verified against Cisco Talos Intelligence as a confirmed malicious downloader. Recommendations included host isolation, firewall blacklisting of the C2 IP, and forced credential reset given Remcos's credential-harvesting capability.

→ [Full investigation](./18_Remcos%20RAT%20%26%20Dridex%20Infection%20Analysis)

---

### SQL Injection & DNS Exfiltration — Web Application Compromise
`Security Onion` `Zeek` `Suricata` `Kibana` `capME`

Analyzed a June 2020 web server breach using pre-loaded Zeek and Suricata logs in a Security Onion environment. HTTP URI analysis in Kibana revealed a classic SQL injection payload targeting the credit card table:

```
username='+union+select+ccid,ccnumber,ccv,expiration,null+from+credit_cards+--+
```

Post-exploitation, DNS log analysis identified an exfiltration channel — unusually long subdomain query strings encoding PII and card data (e.g. `ccnumber.signature.data.maliciousdomain.com`). Detection rules drafted in Suricata syntax to flag both SQLi patterns and anomalous DNS query lengths. Remediation report covers parameterized query implementation and DNS monitoring controls.

→ [Full investigation](./15_SQL%20Injection%20%26%20DNS%20Exfiltration%20Investigation)

---

### FTP Post-Exploitation Data Exfiltration
`Wireshark` `Zeek` `Log Correlation`

Investigated unauthorized FTP-based data transfer following an endpoint compromise. Correlated authentication events with outbound transfer activity, identified data staging behavior prior to exfiltration, quantified the volume of data moved, and established attacker dwell time through timeline reconstruction.

→ [Full investigation](./16_SOC-CaseStudy-PostExploitation-FTP-Exfil)

---

### Rig Exploit Kit — Drive-By Malware Delivery
`Wireshark` `PCAP Analysis` `Malware Triage`

Analyzed traffic patterns associated with the Rig EK delivery mechanism, tracing the redirect chain from initial landing page through payload delivery. Extracted and documented malware artifacts from the packet capture.

→ [Full investigation](./17_SOC-CaseStudy-RigEK-Malware-Analysis)

---

## Project Index

### Endpoint Analysis

| # | Project | Tools | Focus |
|---|---------|-------|-------|
| 01 | [Endpoint Analysis — TCPView](./01_Endpoint-Analysis_Sysinternals-TCPView) | Sysinternals TCPView | Process-to-network mapping; baseline vs. anomalous connection detection |
| 02 | [Endpoint Forensics — Process Explorer](./02_Endpoint-Forensics_Sysinternals-Process-Explorer) | Sysinternals Process Explorer | Parent-child process relationships, DLL inspection, memory strings |
| 03 | [Endpoint Auditing — PowerShell Forensics](./03_Endpoint-Auditing_PowerShell-Forensics) | PowerShell, Script Block Logging | Auditing execution context, command-line argument analysis |
| 04 | [System Resource Audit](./04_System-Resource-Audit_Performance-Monitoring) | Performance Monitor, Sysinternals | Baseline resource profiling for anomaly detection |

### Network Analysis

| # | Project | Tools | Focus |
|---|---------|-------|-------|
| 05 | [Network Path Analysis — ICMP Forensics](./05_Network-Path-Analysis_ICMP-Forensics) | Wireshark, tracert | Hop-by-hop path reconstruction, TTL analysis |
| 06 | [Packet Analysis — Protocol Basics](./06_Packet-Analysis_Wireshark-Protocol-Basics) | Wireshark | TCP/IP dissection, stream reassembly, filter construction |
| 14 | [Network Forensics — Malware Extraction](./14_Network-Forensics-Malware-Extraction) | Wireshark, NetworkMiner | Payload carving from PCAP, file signature identification |

### Defensive Controls

| # | Project | Tools | Focus |
|---|---------|-------|-------|
| 07 | [ACL Hardening](./07_Defensive-Control_ACL-Hardening) | Windows ACL, icacls | Permission auditing, least-privilege enforcement |

### Cryptographic Validation

| # | Project | Tools | Focus |
|---|---------|-------|-------|
| 08 | [Symmetric Encryption Validation](./08_symmetric-encryption-validation) | OpenSSL, PowerShell | Cipher strength assessment, encryption implementation review |
| 09 | [Data Integrity Validation](./09_Data-integrity-validation) | SHA256, MD5 | Hash-based file integrity verification |
| 10 | [PKI Trust Validation](./10_PKI-trust-validation) | Certificate analysis tools | Certificate chain parsing, issuer verification |

### Detection Engineering & Log Analysis

| # | Project | Tools | Focus |
|---|---------|-------|-------|
| 11 | [Log Normalization & ETL](./11_log-normalization-and-etl) | PowerShell, Regex | Heterogeneous log source standardization |
| 12 | [File Integrity Audit](./12_File-Integrity-Audit) | PowerShell, Hashing | Detecting unauthorized file modification |
| 13 | [Log Normalization Utility](./13_log-normalization-utility) | PowerShell | Reusable parsing utility for structured log output |

### Incident Response Case Studies

| # | Project | Threat | Tools |
|---|---------|--------|-------|
| 15 | [SQL Injection & DNS Exfiltration](./15_SQL%20Injection%20%26%20DNS%20Exfiltration%20Investigation) | SQLi + DNS tunneling | Security Onion, Zeek, Kibana |
| 16 | [Post-Exploitation FTP Exfiltration](./16_SOC-CaseStudy-PostExploitation-FTP-Exfil) | Data exfiltration | Wireshark, Zeek |
| 17 | [Rig Exploit Kit Analysis](./17_SOC-CaseStudy-RigEK-Malware-Analysis) | Drive-by download | Wireshark, PCAP triage |
| 18 | [Remcos RAT & Dridex Infection](./18_Remcos%20RAT%20%26%20Dridex%20Infection%20Analysis) | RAT + banking trojan | Wireshark, Zeek, Elastic, Talos |

---

## Technical Stack

**Endpoint:** Sysinternals Suite (TCPView, Process Explorer, Autoruns), Windows Event Logs, PowerShell Script Block Logging, Prefetch/ShimCache analysis  
**Network:** Wireshark, Zeek (Bro), tcpdump, NetworkMiner, capME  
**SIEM / Detection:** Splunk, Security Onion, Kibana / Elastic Stack, Suricata, Sguil  
**Forensics:** FTK Imager, Autopsy, Volatility Framework  
**Threat Intel:** MITRE ATT&CK, Cisco Talos Intelligence, ABUSE.CH SSL Blacklist  
**Frameworks:** MITRE ATT&CK · NIST CSF · Cyber Kill Chain · ISO/IEC 27001

---

## Contact

**Denis O. Onduso**  
Security Operations & Incident Response  
Denis.Onduso@outlook.com
