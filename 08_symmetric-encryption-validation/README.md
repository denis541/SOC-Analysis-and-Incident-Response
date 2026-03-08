# Symmetric Cryptographic Operations: AES-256 Encryption & Validation

![AES-256](https://img.shields.io/badge/Algorithm-AES--256-0078D4?style=flat&logoColor=white)
![Domain](https://img.shields.io/badge/Domain-Cryptographic_Validation-4CAF50?style=flat&logoColor=white)
![Standard](https://img.shields.io/badge/Standard-NIST_FIPS_197-003087?style=flat&logoColor=white)

**Analyst:** Denis O. Onduso  
**Focus:** AES-256 encryption and decryption workflow, key sensitivity validation, Base64 encoding for transport, AEAD mode awareness

---

## Objective

Implement and validate AES-256 symmetric encryption end-to-end — encrypting plaintext to ciphertext using a pre-shared key, encoding for transport, and decrypting to confirm integrity. Identify failure modes when key material is incorrect and evaluate the security considerations relevant to production deployment.

---

## Background

AES (Advanced Encryption Standard) is a NIST-standardized block cipher operating on 128-bit blocks with key sizes of 128, 192, or 256 bits. AES-256 is the variant used here — the largest key size, offering 2²⁵⁶ possible keys and no known practical attack faster than brute force against a properly implemented instance.

In a SOC or incident response context, understanding AES is operationally relevant for: evaluating whether data at rest is adequately protected, identifying weak encryption configurations during security assessments, and recognizing when encrypted channels are being abused for C2 communication.

---

## Implementation

### Encryption Workflow

| Step | Detail |
|------|--------|
| Algorithm | AES-256 (block cipher, CBC mode) |
| Key | Pre-shared secret key (PSK) — 256-bit |
| Input | Plaintext data |
| Output | Base64-encoded ciphertext |
| Encoding rationale | Base64 ensures ciphertext survives transmission over text-based protocols (SMTP, HTTP headers) without byte corruption |

The PSK was used directly for this validation exercise. In production, key material of this kind would be managed through a Key Management System (KMS) — never hardcoded or transmitted alongside the ciphertext.

### Decryption Workflow

Successful decryption required:
- Exact algorithm match (AES-256, same mode and padding scheme)
- Exact key match — a single bit difference in the key produces entirely different output
- Correct IV (Initialization Vector) where CBC mode is used — the IV must be known to the recipient

Decryption confirmed the original plaintext was recovered without data loss, validating both the encryption and the transport encoding.

---

## Key Sensitivity Testing

Decryption was intentionally attempted with an incorrect key to document failure behavior:

| Failure Mode | Cause | Observable Result |
|--------------|-------|-------------------|
| Padding error | Key mismatch causes incorrect block alignment on final block | Decryption library throws padding exception |
| Garbage output | Wrong key produces mathematically valid but meaningless plaintext | Random byte output with no recoverable data |

Both failure modes confirm that AES provides no partial decryption — without the correct key, nothing is recoverable. This is the expected security property.

---

## Security Considerations

**Key entropy:** AES-256 is only as strong as the key used. A weak or short passphrase fed into key derivation reduces effective security significantly. Production implementations should use a proper KDF (e.g. PBKDF2, Argon2) to derive key material from passphrases.

**No authentication:** AES in CBC mode provides confidentiality but not authentication — an attacker who can manipulate the ciphertext may be able to flip bits in the plaintext without detection. For production use, **AES-GCM** (an AEAD mode) provides both encryption and authentication in a single operation, detecting any tampering before decryption is attempted.

**IV reuse:** Reusing the same IV with the same key in CBC mode breaks confidentiality. IVs must be unique per encryption operation, though they do not need to be secret.

---

## Key Findings

AES-256 encryption and decryption were validated end-to-end with correct key material. Key sensitivity testing confirmed that incorrect keys produce either padding exceptions or garbage output — no partial data leakage occurs. Base64 encoding preserved ciphertext integrity across the simulated transport layer. The exercise also identified the operational gap between CBC mode (confidentiality only) and GCM mode (confidentiality + integrity) — a distinction relevant when evaluating encryption implementations during security assessments.

---

## MITRE ATT&CK Relevance

| Technique | ID | Relevance |
|-----------|----|-----------|
| Encrypted Channel | T1573 | Understanding AES implementation enables evaluation of whether C2 channels are using strong or weak encryption |
| Data Encrypted for Impact | T1486 | Ransomware commonly uses AES for file encryption — understanding the algorithm informs recovery analysis |
| Steal or Forge Authentication Certificates | T1649 | Weak key management practices expose key material to theft |
| Obfuscated Files or Information | T1027 | Base64-encoded ciphertext is a common obfuscation pattern in malware payloads |
