# Data Integrity Validation: Cryptographic Hash Functions

![SHA-256](https://img.shields.io/badge/Algorithm-SHA--256_FIPS_180--4-003087?style=flat&logoColor=white)
![Domain](https://img.shields.io/badge/Domain-Cryptographic_Validation-4CAF50?style=flat&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux_CLI-FCC624?style=flat&logo=linux&logoColor=black)

**Analyst:** Denis O. Onduso  
**Focus:** SHA-256 hash generation, avalanche effect validation, batch integrity verification, algorithm deprecation analysis

---

## Objective

Use SHA-256 to generate and verify cryptographic hashes of files, validate the avalanche effect through controlled input modification, and perform batch integrity checking against a signature file — establishing the hash-based verification methodology used in evidence handling, malware analysis, and software supply chain validation.

---

## Background

A cryptographic hash function maps an input of arbitrary size to a fixed-length output (256 bits for SHA-256). It is a one-way operation — given a hash, it is computationally infeasible to recover the original input. SHA-256 is defined under NIST FIPS 180-4 and remains the current standard for integrity verification. MD5 and SHA-1 are deprecated for security use — known collision attacks against both make them unsuitable for integrity validation in any context where tampering is a concern.

In an incident response context, hashing is used to: verify evidence integrity before and after analysis, confirm that a file matches a known-malicious or known-clean hash from threat intelligence, and validate software downloads before deployment in a hardened environment.

---

## Implementation

### Hash Generation

```bash
# Generate SHA-256 hash of a file
openssl sha256 <filename>

# Alternative using coreutils
sha256sum <filename>
```

Both commands produce identical output for the same input — the choice between them is environment-dependent. `sha256sum` is standard on Linux; `openssl sha256` works across Linux, macOS, and Windows with OpenSSL installed.

### Batch Integrity Verification

```bash
# Verify a file against a provided signature file
sha256sum -c sample.img_SHA256.sig
```

A result of `OK` confirms the file's byte stream is identical to the source at the time the signature was generated. Any modification — even a single bit — produces a different hash and a `FAILED` result. This is the standard verification step before using a disk image or software package in a forensic or production environment.

---

## Validation Tests

### Avalanche Effect

The avalanche effect was tested by hashing two nearly identical inputs:

| Input | SHA-256 Hash (truncated) |
|-------|--------------------------|
| `Grandma` | `a3f1c8...` |
| `Grandpa` | `d92e47...` |

A single character change produced a completely different hash with no observable relationship between the two outputs. This confirms that SHA-256 provides no partial information about the degree of change — any modification is immediately and fully detectable.

### Determinism

The same file was hashed multiple times across separate sessions:

| Run | Hash Output |
|-----|-------------|
| Run 1 | Identical |
| Run 2 | Identical |
| Run 3 | Identical |

Consistent output across runs confirms deterministic behavior — a prerequisite for reliable integrity checking.

---

## Algorithm Comparison

| Algorithm | Status | Reason |
|-----------|--------|--------|
| MD5 | Deprecated | Collision attacks demonstrated — two different inputs can produce the same hash |
| SHA-1 | Deprecated | Practical collision attack demonstrated (SHAttered, 2017) |
| SHA-256 | Current standard | No known practical collision attack; NIST FIPS 180-4 compliant |
| SHA-512 | Current standard | Larger output (512-bit); preferred for higher-assurance contexts |

This project uses SHA-256 and SHA-512 exclusively. MD5 hashes appear in some threat intelligence feeds for legacy reasons but should never be used as the sole integrity check in an active investigation.

---

## Key Findings

SHA-256 hash generation and batch verification were validated successfully. The avalanche effect test confirmed that single-character input changes produce entirely different hashes with no detectable relationship. Batch verification via `sha256sum -c` correctly identified matching and non-matching files. The integrity-vs-authenticity distinction is operationally important: a matching hash confirms the file has not changed, but does not confirm who created it — for provenance verification, hashing should be paired with a digital signature (GPG/PGP).

---

## MITRE ATT&CK Relevance

| Technique | ID | Relevance |
|-----------|----|-----------|
| Indicator Removal: Timestomp | T1070.006 | Hash verification detects file modification even when timestamps are manipulated |
| Modify System Image | T1601 | Hashing firmware or system images detects unauthorized modification |
| Supply Chain Compromise | T1195 | Hash verification of software packages is a primary supply chain integrity control |
| Malware Identification | — | Hash matching against threat intel feeds (VirusTotal, Talos) is a core triage step in malware analysis |
