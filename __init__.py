"""
AppSec Toolkit
==============

Application Security Toolkit for security engineers, penetration testers,
and developers.

This package provides modules for:

- HTTP Security Header Analysis
- JWT Token Inspection
- SSL/TLS Security Analysis
- HTTP Method Enumeration
- Hash Identification
- Password Strength Assessment
- Base64 Encoding/Decoding
- CVSS v3.1 Score Calculation
- Security Report Generation

Author: <Swanoop Anjan Behera>
GitHub: https://github.com/Swanoop10082001/appsec-toolkit
License: MIT
Version: 1.0.0
"""

__title__ = "AppSec Toolkit"
__description__ = (
    "A Python toolkit for application security assessments and vulnerability analysis."
)
__author__ = "Swanoop Anjan Behera"
__email__ = "swanoop10082001@gmail.com"
__license__ = "MIT"
__version__ = "1.0.0"

# Import commonly used functions

from .headers import check_headers
from .jwt_decoder import decode_jwt
from .ssl_check import check_ssl
from .methods import check_methods
from .hash_identifier import identify_hash
from .password_checker import check_password
from .base64_tool import encode_base64, decode_base64
from .cvss import calculate_cvss
from .report import ReportGenerator

# Export public API

__all__ = [
    "check_headers",
    "decode_jwt",
    "check_ssl",
    "check_methods",
    "identify_hash",
    "check_password",
    "encode_base64",
    "decode_base64",
    "calculate_cvss",
    "ReportGenerator",
]
