# AppSec Toolkit - Modules

This directory contains the core modules of the **AppSec Toolkit**, a Python-based toolkit for performing common application security assessments.

Each module is designed to perform a specific security function and can be used independently or through the main `app.py` entry point.

---

## Module Overview

| Module | Description |
|---------|-------------|
| `headers.py` | Analyzes HTTP security headers and identifies missing or misconfigured headers. |
| `jwt_decoder.py` | Decodes and analyzes JWT tokens without signature verification for security inspection. |
| `ssl_check.py` | Retrieves SSL/TLS certificate information and checks protocol versions and certificate validity. |
| `methods.py` | Enumerates supported HTTP methods and identifies potentially risky methods. |
| `hash_identifier.py` | Identifies common cryptographic hash algorithms based on hash format and length. |
| `password_checker.py` | Evaluates password strength using complexity and entropy analysis. |
| `base64_tool.py` | Encodes, decodes, and analyzes Base64-encoded data. |
| `cvss.py` | Parses CVSS v3.1 vectors and calculates vulnerability severity scores. |
| `report.py` | Generates security assessment reports in HTML, Markdown, and JSON formats. |

---

## Architecture

```
app.py
    │
    ├── headers.py
    ├── jwt_decoder.py
    ├── ssl_check.py
    ├── methods.py
    ├── hash_identifier.py
    ├── password_checker.py
    ├── base64_tool.py
    ├── cvss.py
    └── report.py
```

---

## Features

- HTTP Security Header Analysis
- JWT Inspection
- SSL/TLS Security Assessment
- HTTP Method Enumeration
- Password Strength Analysis
- Hash Identification
- Base64 Utilities
- CVSS v3.1 Calculator
- HTML, Markdown, and JSON Report Generation

---

## Usage

Most modules can be executed through the main application:

```bash
python app.py --headers https://example.com
python app.py --jwt <jwt_token>
python app.py --ssl example.com
python app.py --methods https://example.com
python app.py --hash 5f4dcc3b5aa765d61d8327deb882cf99
python app.py --password "Password123!"
python app.py --encode "Hello World"
python app.py --decode SGVsbG8gV29ybGQ=
python app.py --cvss "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
```

---

## Design Goals

- Modular architecture
- Easy to extend
- Python 3.10+
- Cross-platform compatibility
- Security-focused implementation
- Clean and readable code
- Suitable for educational and authorised security testing

---

## Future Enhancements

- DNS Analyzer
- WHOIS Lookup
- Port Scanner
- Security.txt Validator
- HTTP Response Analyzer
- CSP Policy Analyzer
- Cookie Security Analyzer
- API Security Scanner
- JWT Signature Verification
- SSL Grade Calculator
- Multi-threaded Scanning
- Plugin Support
- PDF Report Generation

---

## Disclaimer

This toolkit is intended **only for authorized security assessments, learning, and defensive security testing**. Always obtain appropriate permission before testing systems you do not own or administer.

---

**AppSec Toolkit v1.0**

Developed for Application Security Engineers, Penetration Testers, and Security Researchers.
