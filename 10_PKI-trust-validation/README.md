# PKI & Trust Store Analysis: Certificate Chain Validation and SSL Inspection Detection

![PKI](https://img.shields.io/badge/Domain-PKI_Trust_Validation-003087?style=flat&logoColor=white)
![TLS](https://img.shields.io/badge/Protocol-SSL/TLS-0078D4?style=flat&logoColor=white)
![Domain](https://img.shields.io/badge/Domain-Network_Forensics-4CAF50?style=flat&logoColor=white)

**Analyst:** Denis O. Onduso  
**Focus:** Certificate chain parsing, CA trust store analysis, SSL inspection detection via fingerprint comparison, certificate pinning

---

## Objective

Analyze the PKI trust model underpinning HTTPS, validate certificate chain integrity from leaf to root CA, and demonstrate how SSL inspection proxies subvert the chain of trust — including the methodology for detecting active interception on a network.

---

## Background

Every HTTPS connection relies on a chain of trust rooted in the operating system or browser's trusted CA store. When a browser connects to `github.com`, it validates that the presented certificate was signed by an intermediate CA, which was signed by a root CA that exists in the local trust store. If any link in that chain is missing, expired, or signed by an untrusted entity, the connection fails.

This model is exploited — both legitimately and maliciously — through SSL inspection. By injecting a custom root CA into a device's trust store, a proxy can intercept and decrypt HTTPS traffic, re-sign it with its own certificate, and forward it to the destination. The browser sees a valid chain and shows a padlock. The traffic is fully visible to the proxy.

---

## Certificate Chain Structure

| Layer | Role | Signing Authority |
|-------|------|-------------------|
| Root CA | Trust anchor; self-signed | Trusted implicitly by OS/browser CA store (e.g. DigiCert Global Root) |
| Intermediate CA | Issued by Root; signs leaf certs | Root CA — kept offline to limit Root exposure |
| Leaf Certificate | Presented by the website | Intermediate CA — contains domain name, expiry, public key |

The Root CA is kept offline in production PKI deployments. Day-to-day certificate issuance is handled by the Intermediate CA — if the Intermediate is compromised, the Root can issue a new one without being exposed. A Root CA that is online and actively issuing leaf certificates is a misconfiguration worth flagging during a security assessment.

---

## SSL Inspection: How the Trust Model is Subverted

An SSL inspection proxy operates by:

1. Intercepting the TLS handshake before it reaches the destination server
2. Establishing a separate TLS session with the destination on behalf of the client
3. Generating an on-the-fly certificate for the destination domain, signed by a custom CA
4. Presenting that generated certificate to the client

If the custom CA has been added to the client's trust store — either by corporate MDM policy or by a malicious actor — the browser validates the chain successfully and shows a padlock. The traffic between the client and the proxy is fully decrypted.

**Legitimate use:** Corporate DLP and security monitoring  
**Malicious use:** Credential harvesting, session hijacking, data theft

---

## Detection Methodology: Fingerprint Comparison

SSL inspection is detectable by comparing the certificate fingerprint seen from an independent network against the fingerprint seen on the suspected host.

### Steps

1. From a clean reference device (mobile on cellular, or a known-clean external host), connect to the target site and record the SHA-256 certificate fingerprint
2. On the suspected host, view the certificate details for the same site (`Issuer`, `Fingerprint`, `Valid From/To`)
3. Compare the two fingerprints

| Indicator | Clean Connection | SSL Inspection Active |
|-----------|------------------|-----------------------|
| Fingerprint match | Yes | No — proxy-generated cert has different fingerprint |
| Issuer | Known public CA (DigiCert, Let's Encrypt) | Corporate entity or unknown CA |
| Root in public CA store | Yes | May be a privately distributed root |
| Certificate transparency log | Entry exists | Proxy-generated certs typically absent |

A mismatch in the `Issued By` field pointing to a corporate entity rather than a public CA is the most immediate indicator. Certificate Transparency (CT) logs provide a secondary check — legitimate certificates from public CAs are logged publicly and verifiable.

---

## Certificate Pinning

High-assurance applications (mobile banking, government portals) implement certificate pinning — hardcoding the expected certificate fingerprint or public key in the application itself. Even if a proxy's root CA is trusted by the OS, pinning causes the application to reject any certificate that does not match the pinned value, defeating transparent SSL inspection entirely.

Pinning bypasses are a category of mobile security research (Frida-based unpinning is common in penetration testing workflows), but for a standard browser-based user, pinning is not available — making fingerprint comparison the primary detection method.

---

## Key Findings

Certificate chain validation confirmed the three-layer PKI hierarchy (Root → Intermediate → Leaf) on inspected HTTPS connections. The SSL inspection detection methodology — fingerprint comparison across independent network paths — was validated as a reliable technique for identifying proxy interception. Certificates generated by inspection proxies are distinguishable by issuer field, fingerprint mismatch, and absence from Certificate Transparency logs. Certificate pinning was identified as the strongest client-side control against transparent interception, with relevant limitations noted for browser contexts.

---

## Tools

- **Browser certificate inspector** — certificate chain viewing, fingerprint extraction
- **OpenSSL CLI** — certificate parsing and fingerprint generation
- **Certificate Transparency logs** (crt.sh) — external verification of certificate issuance

```bash
# Extract and display certificate fingerprint via OpenSSL
openssl s_client -connect github.com:443 </dev/null 2>/dev/null | \
openssl x509 -fingerprint -sha256 -noout
```

---

## MITRE ATT&CK Relevance

| Technique | ID | Relevance |
|-----------|----|-----------|
| Adversary-in-the-Middle: SSL Stripping | T1557.002 | SSL inspection proxy operates on the same interception principle as a MitM attack |
| Steal Web Session Cookie | T1539 | Decrypted HTTPS traffic exposes session tokens to the proxy |
| Install Root Certificate | T1553.004 | Malicious actors install rogue root CAs to enable transparent interception |
| Subvert Trust Controls | T1553 | Understanding the trust model is prerequisite to detecting its subversion |
