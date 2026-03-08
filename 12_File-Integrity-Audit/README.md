# File Integrity Verification Utility

![PowerShell](https://img.shields.io/badge/Tool-PowerShell_5.1+-5391FE?style=flat&logo=powershell&logoColor=white)
![Domain](https://img.shields.io/badge/Domain-Endpoint_Forensics-4CAF50?style=flat&logoColor=white)
![Algorithm](https://img.shields.io/badge/Algorithm-SHA--256-003087?style=flat&logoColor=white)

**Analyst:** Denis O. Onduso  
**Focus:** SHA-256 hash-based file comparison, PowerShell execution policy handling, binary-level integrity validation

---

## Objective

Build and validate a PowerShell utility that performs cryptographic integrity verification between two files — detecting unauthorized substitution, corruption, or tampering at the binary level using SHA-256 hash comparison.

---

## Use Case

File integrity verification is a routine step in several SOC and IR workflows:

- **Evidence handling:** Hashing acquired files before and after analysis confirms the working copy has not been modified
- **Malware triage:** Comparing a suspicious binary against a known-clean version of the same filename detects trojanized substitutions
- **Software validation:** Verifying that a downloaded or deployed binary matches the vendor-published hash before execution in a production environment

---

## Execution Policy Handling

Windows PowerShell's default execution policy (`Restricted`) blocks all script execution regardless of source. Running this utility on a standard endpoint requires a scoped bypass.

The correct approach is a **process-level bypass** — scoped to a single PowerShell session rather than a permanent system-wide policy change:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File ".\Hashcompaire.ps1"
```

This flag creates an isolated execution context. When the PowerShell process terminates, the system's original policy is fully restored — no registry modifications, no persistent policy change.

**What not to do:** `Set-ExecutionPolicy Bypass -Scope LocalMachine` is a permanent, system-wide change that removes a meaningful defense-in-depth control. In a SOC or hardened environment, that change would itself be a detection event.

---

## Functional Logic

The utility runs a three-stage workflow:

**1. Input handling** — Accepts file paths for the source (known-good reference) and target (file under inspection). Paths are sanitized to handle trailing whitespace and quote characters that cause silent failures in `Get-FileHash`.

**2. Hash generation** — Computes SHA-256 hashes for both files using `Get-FileHash`:

```powershell
$sourceHash = (Get-FileHash -Path $sourcePath -Algorithm SHA256).Hash
$targetHash = (Get-FileHash -Path $targetPath -Algorithm SHA256).Hash
```

**3. Comparison and output** — Performs a boolean string comparison and returns a clear result:

```powershell
if ($sourceHash -eq $targetHash) {
    Write-Output "[PASS] Files are identical. Hashes match."
    Write-Output "Hash: $sourceHash"
} else {
    Write-Output "[FAIL] Hash mismatch detected. Files differ."
    Write-Output "Source: $sourceHash"
    Write-Output "Target: $targetHash"
}
```

A `[FAIL]` result means the files differ at the binary level — even a single changed byte produces a completely different SHA-256 hash.

---

## Algorithm Selection

SHA-256 is the default and recommended algorithm for this utility. The `-Algorithm` parameter accepts other values, but:

| Algorithm | Recommended | Reason |
|-----------|-------------|--------|
| SHA-256 | Yes | Current standard; no known practical collision attack |
| SHA-512 | Yes | Higher assurance; larger output |
| MD5 | No | Collision attacks demonstrated; unsuitable for security validation |
| SHA-1 | No | Practical collision demonstrated (SHAttered, 2017) |

Never use MD5 or SHA-1 for integrity validation in a security context, even if the target system or vendor still publishes MD5 checksums for legacy compatibility.

---

## Requirements

- PowerShell 5.1 or PowerShell Core 7.x+
- Read access to both target files
- No elevated privileges required for file hashing (elevation needed only if files are in protected system paths)

---

## Key Findings

The utility correctly identified matching and non-matching file pairs in all test cases. Input sanitization prevented silent failures on paths with trailing whitespace — a common source of false `[FAIL]` results in naive implementations. The process-level execution policy bypass was confirmed to leave no persistent changes to system policy after session termination. SHA-256 was validated as the appropriate algorithm; MD5 and SHA-1 were excluded based on known cryptographic weaknesses.

---

## MITRE ATT&CK Relevance

| Technique | ID | Relevance |
|-----------|----|-----------|
| Modify System Image | T1601 | Hash comparison detects binary substitution or modification of system files |
| Masquerading: Match Legitimate Name | T1036.005 | Trojanized binaries with legitimate filenames are detected by hash mismatch against known-good reference |
| Indicator Removal: Timestomp | T1070.006 | Hash verification catches tampering even when file timestamps are manipulated |
| Supply Chain Compromise | T1195 | Pre-deployment hash verification against vendor-published checksums is a primary supply chain control |
