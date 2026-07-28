# AppSec Toolkit - Mappings

The **Mappings** directory contains reference data used by the AppSec Toolkit to classify findings according to widely accepted application security standards.

These mapping files allow the toolkit to automatically associate detected issues with OWASP categories, Common Weakness Enumerations (CWEs), and OWASP API Security risks during security assessments and report generation.

---

## Directory Structure

```
mappings/
│
├── api_security.json
├── cwe.json
└── owasp_top10.json
```

---

## Files

### `owasp_top10.json`

Contains the **OWASP Top 10 (2021)** categories.

Example:

```json
{
  "A01": "Broken Access Control",
  "A02": "Cryptographic Failures",
  "A03": "Injection"
}
```

Used by:

- HTTP Header Scanner
- SSL/TLS Checker
- Hash Identifier
- Password Checker
- Report Generator

---

### `api_security.json`

Contains the **OWASP API Security Top 10 (2023)** categories.

Example:

```json
{
  "API1:2023": {
    "name": "Broken Object Level Authorization",
    "severity": "Critical"
  }
}
```

Used by:

- JWT Analyzer
- HTTP Method Scanner
- API Security Reports
- Report Generator

---

### `cwe.json`

Contains mappings for **Common Weakness Enumeration (CWE)** identifiers.

Example:

```json
{
  "CWE-79": "Cross-Site Scripting",
  "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
  "CWE-521": "Weak Password Requirements"
}
```

Used by all security modules when generating reports.

---

## Purpose

The mapping files provide a centralized reference that enables the toolkit to:

- Map findings to OWASP Top 10 (2021)
- Map findings to OWASP API Security Top 10 (2023)
- Map findings to MITRE Common Weakness Enumeration (CWE)
- Produce standardized vulnerability reports
- Improve consistency across all modules

---

## Advantages

- Easy to maintain
- Human-readable JSON format
- Simple to extend
- Reusable across multiple modules
- Supports future security standards

---

## Example Usage

```python
import json

with open("mappings/cwe.json", "r", encoding="utf-8") as file:
    cwe = json.load(file)

print(cwe["CWE-327"])
```

Output:

```
Use of a Broken or Risky Cryptographic Algorithm
```

---

## Future Enhancements

Additional mapping files planned for future releases:

- CWE to CAPEC Mapping
- OWASP ASVS Mapping
- OWASP MASVS Mapping
- MITRE ATT&CK Mapping
- MITRE CAPEC Mapping
- NIST SP 800-53 Controls
- CIS Controls v8
- CVSS Severity Reference
- PCI DSS Requirement Mapping
- ISO/IEC 27001 Control Mapping

---

## References

- OWASP Top 10 (2021)
- OWASP API Security Top 10 (2023)
- MITRE Common Weakness Enumeration (CWE)
- FIRST CVSS v3.1 Specification

---

## Disclaimer

The mapping data is provided to support **authorized application security assessments**, secure software development, and security reporting. Users should verify mappings against the latest versions of the respective standards when producing formal security documentation.
