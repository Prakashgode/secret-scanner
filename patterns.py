"""regex patterns for detecting common secrets in source code"""

import re

PATTERNS = {
    "AWS Access Key ID": re.compile(r'(AKIA[0-9A-Z]{16})'),
    "AWS Secret Key": re.compile(r'(?i)aws_secret_access_key\s*[=:]\s*[\'"]?([A-Za-z0-9/+=]{40})[\'"]?'),
    "GitHub Token": re.compile(r'(gh[ps]_[A-Za-z0-9_]{36,255})'),
    "Private Key": re.compile(r'-----BEGIN\s+(?:RSA|EC|DSA)?\s*PRIVATE\s+KEY-----'),
    "JWT Token": re.compile(r'(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})'),
}

# TODO: add database connection strings (mysql://, postgres://, mongodb://)
# TODO: add generic password detection
# TODO: severity levels per pattern
