# Log Normalization & Temporal Data Transformation

![AWK](https://img.shields.io/badge/Tool-AWK-FCC624?style=flat&logo=linux&logoColor=black)
![Domain](https://img.shields.io/badge/Domain-Detection_Engineering-4CAF50?style=flat&logoColor=white)
![SIEM](https://img.shields.io/badge/Output-SIEM_Ready-0078D4?style=flat&logoColor=white)

**Analyst:** Denis O. Onduso  
**Focus:** Unix epoch timestamp conversion, field delimiter normalization, null value handling, SIEM ingestion preparation

---

## Objective

Transform raw, heterogeneous security log data into a normalized, consistently structured format suitable for SIEM ingestion and cross-source correlation — addressing the timestamp inconsistencies, delimiter variations, and null entries that break automated parsing pipelines.

---

## Background

Security events originate from dozens of sources — firewalls, web servers, authentication systems, EDR agents — each with its own log format, field order, and timestamp representation. A firewall might log in Unix epoch. A web server logs in Apache Combined Log Format. An application logs in ISO-8601. Before any of these sources can be correlated in a SIEM, they must be normalized to a common schema.

This is the ETL (Extract, Transform, Load) step in security data pipelines. Getting it wrong means events are indexed out of order, correlation rules fire on misaligned timestamps, or null entries corrupt the dataset entirely. This project addresses each of those failure modes directly.

---

## Implementation

### Epoch-to-Human-Readable Timestamp Conversion

Raw application logs contained Unix epoch timestamps (integer seconds since 1970-01-01 00:00:00 UTC) in the third field, pipe-delimited:

```bash
# Convert epoch timestamps in field 3 to human-readable format
awk 'BEGIN {FS=OFS="|"} {$3=strftime("%c",$3)} {print}' application_raw.log
```

| Component | Function |
|-----------|----------|
| `FS=OFS="\|"` | Sets both input and output field separator to pipe — preserves all surrounding fields unchanged |
| `strftime("%c", $3)` | Casts the integer epoch value in field 3 to a locale-aware datetime string |
| `{print}` | Outputs the full reconstructed record with the transformed timestamp |

Targeting `$3` specifically rather than processing the entire line preserves field integrity — IP addresses, usernames, and event codes in other fields are untouched.

### Delimiter Normalization

Logs from different sources used inconsistent delimiters (pipe `|` vs comma `,`). A secondary transformation standardized all output to pipe-delimited format for downstream SIEM ingestion:

```bash
# Normalize comma-delimited logs to pipe-delimited
awk 'BEGIN {FS=","; OFS="|"} {$1=$1; print}' mixed_delimiter.log
```

`$1=$1` forces AWK to rebuild the record using the new output separator — without it, the OFS change has no effect on fields that haven't been explicitly modified.

### Null Value Handling — The 1969 Artifact

During processing, an empty trailing line in the raw log produced a timestamp of `Dec 31, 1969`. This is a classic null epoch error: an empty or null value is interpreted as `0`, which maps to `1969-12-31 23:59:59 UTC` — one second before the Unix epoch origin.

Fix applied:

```bash
# Skip records where the epoch field is zero or empty
awk 'BEGIN {FS=OFS="|"} $3 != "" && $3 != "0" {$3=strftime("%c",$3); print}' application_raw.log
```

In production ETL pipelines, null and zero-epoch records must be either dropped or flagged for review before ingestion. A SIEM that ingests 1969 timestamps will misorder events in timeline views and potentially corrupt correlation rule logic that calculates time deltas between events.

---

## Use Cases in Security Operations

**Incident timeline construction:** Aligning Apache web server logs with Linux auth logs to trace attacker lateral movement requires both sources to share a common timestamp format. A one-second misalignment between sources can place a privilege escalation before the initial access event in a timeline — making the sequence unreadable.

**SIEM ingestion:** Elasticsearch and Splunk index events by timestamp. Inconsistent formats cause parsing failures, incorrect field extraction, or events landing in the wrong time bucket. Normalized logs ingest cleanly and are immediately searchable.

**Time-delta anomaly detection:** Calculating the duration between a login event and a sensitive file access (a common lateral movement detection pattern) requires timestamps to be in a consistent, mathematically operable format. Epoch integers or ISO-8601 strings both work — mixed formats do not.

---

## Key Findings

Epoch timestamp conversion was validated successfully — raw integer timestamps were transformed to human-readable strings with field integrity preserved. Delimiter normalization confirmed that the `$1=$1` rebuild pattern is required to force AWK to apply the new OFS. Null value handling correctly identified and excluded the 1969 artifact, and the fix was incorporated into the production-ready pipeline. The normalized output was verified as compatible with pipe-delimited SIEM ingestion formats.

---

## MITRE ATT&CK Relevance

| Technique | ID | Relevance |
|-----------|----|-----------|
| Indicator Removal: Timestomp | T1070.006 | Timestamp normalization is prerequisite to detecting manipulated event times |
| Impair Defenses: Disable or Modify Tools | T1562 | Malformed log entries (including null epochs) can impair SIEM correlation rules |
| Exfiltration Over Alternative Protocol | T1048 | Accurate timeline reconstruction from normalized logs supports exfiltration investigation |
| Lateral Movement Detection | — | Cross-source log correlation is the primary method for tracing attacker movement between systems |
