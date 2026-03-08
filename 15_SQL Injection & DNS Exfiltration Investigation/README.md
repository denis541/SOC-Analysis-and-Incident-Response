# Incident Response: SQL Injection & DNS Exfiltration Investigation

![Security Onion](https://img.shields.io/badge/Platform-Security_Onion-4CAF50?style=flat&logoColor=white)
![Zeek](https://img.shields.io/badge/Tool-Zeek-2F6FAD?style=flat&logoColor=white)
![Domain](https://img.shields.io/badge/Domain-Incident_Response-E01B1B?style=flat&logoColor=white)

**Analyst:** Denis O. Onduso  
**Date:** June 2020 (log window)  
**Status:** Resolved — IOCs documented, detection rules drafted, remediation report completed

---

## Scenario

A web server breach was investigated using a Security Onion environment pre-loaded with Zeek and Suricata logs from a June 2020 exploit window. The investigation identified two distinct attack phases: initial database compromise via SQL injection, followed by covert data exfiltration over DNS.

---

## Environment

- **Platform:** Security Onion (Linux-based NSM distribution)
- **Log sources:** Zeek HTTP logs, Zeek DNS logs, Suricata alerts
- **Analysis tools:** Kibana / Elasticsearch, capME! (PCAP transcript viewer)

---

## Investigation

### Phase 1: Initial Compromise — SQL Injection

Analysis began in Kibana, filtering Zeek HTTP logs by the `uri` field for anomalous patterns. Abnormal URI strings containing SQL syntax were identified in the HTTP request log, isolating the attacker's IP and the targeted endpoint.

**Attack method:** UNION-based SQL injection targeting the web application's authentication form. The attacker bypassed authentication entirely and queried the backend database directly.

**Payload recovered from HTTP logs:**

```
username='+union+select+ccid,ccnumber,ccv,expiration,null+from+credit_cards+--+&password=
```

**What this payload does:**

- The leading `'` closes the string literal in the SQL query
- `UNION SELECT` appends a second query to the original, selecting from the `credit_cards` table
- Fields selected: `ccid`, `ccnumber`, `ccv`, `expiration` — full card data
- `null` pads the column count to match the original query's schema
- `--` comments out the rest of the original SQL, preventing a syntax error

The query was designed to return the entire contents of the credit card table to the attacker via the application's HTTP response.

| Finding | Detail |
|---------|--------|
| Attack type | UNION-based SQL injection |
| Target | Authentication form → credit_cards table |
| Data exposed | ccid, ccnumber, ccv, expiration for all records |
| Evidence source | Zeek HTTP logs, capME PCAP transcript |

📎 See `Screenshots/kibana_http_filter.png` and `Screenshots/capme_transcript.png`

---

### Phase 2: Data Exfiltration — DNS Tunneling

After the initial compromise, analysis shifted to Zeek DNS logs. An anomaly was identified: DNS queries with unusually long subdomain strings — far exceeding the length of any legitimate hostname lookup.

**Technique:** DNS tunneling — data encoded into subdomain labels of DNS A record queries, transmitted to an attacker-controlled domain. Since DNS traffic is rarely blocked at the perimeter and often not inspected, it is a reliable exfiltration channel.

**Example query structure observed:**

```
4532015112083619.1234.VISA.06/2022.maliciousdomain.com
```

Each query encodes a credit card record — card number, CVV, card type, and expiry — as subdomain labels. The attacker's DNS server logs each query, reconstructing the stolen dataset from the subdomain strings without any direct TCP connection to the victim's network.

| Finding | Detail |
|---------|--------|
| Exfiltration method | DNS tunneling over UDP port 53 |
| Data exfiltrated | PII and credit card records (ccnumber, CVV, expiry) |
| Detection indicator | Abnormally long DNS query strings; high query frequency to single external domain |
| Evidence source | Zeek DNS logs, dns_log_counts metrics |

📎 See `Screenshots/dns_log_counts.png`

---

## Detection Rules

Custom Suricata rules drafted to detect both attack patterns going forward:

**SQL injection detection** — alert on HTTP URIs containing UNION SELECT patterns:
```
alert http any any -> $HTTP_SERVERS any (msg:"SQL Injection UNION SELECT Attempt"; flow:to_server,established; content:"union+select"; http_uri; nocase; sid:1000001;)
```

**DNS tunneling detection** — alert on DNS queries exceeding normal hostname length:
```
alert dns any any -> any 53 (msg:"Abnormally Long DNS Query - Possible Tunneling"; dns.query; byte_test:1,>,52,0,relative; sid:1000002;)
```

Full detection logic: `documentation/detection_rules.md`

---

## Analyst Recommendations

**Immediate containment:**
- Block the attacker's source IP at the perimeter firewall
- Rotate all credentials and card data that may have been exposed
- Take the affected web server offline for re-imaging

**Eradication:**
- Patch the SQL injection vulnerability using parameterized queries — replace all string-concatenated SQL with prepared statements
- Audit remaining application endpoints for similar injection surfaces

**Hardening:**
- Implement DNS query length monitoring — flag queries exceeding 50 characters in subdomain labels
- Deploy a DNS security solution (RPZ or similar) to block resolution to newly registered or low-reputation domains
- Enable WAF rules for SQLi patterns on all public-facing web applications

Full remediation report: `documentation/remediation_report.md`

---

## MITRE ATT&CK Mapping

| Technique | ID | Phase | Detail |
|-----------|----|----|-------|
| Exploit Public-Facing Application | T1190 | Initial Access | SQL injection against the web application authentication endpoint |
| Data from Information Repositories | T1213 | Collection | UNION SELECT query dumping the full credit_cards table |
| Exfiltration Over Alternative Protocol: DNS | T1048.003 | Exfiltration | Credit card PII encoded in DNS subdomain query strings |
| Application Layer Protocol: DNS | T1071.004 | C2 / Exfil | DNS used as covert channel — low-suspicion, rarely blocked at perimeter |
