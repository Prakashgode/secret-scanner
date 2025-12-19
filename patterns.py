"""regex patterns for detecting secrets in source code

growing list of patterns. each one has a name, compiled regex,
severity level, and description.
"""

import re

PATTERNS = [
    {
        "name": "AWS Access Key ID",
        "pattern": re.compile(r'(?:^|[^A-Za-z0-9/+=])(AKIA[0-9A-Z]{16})(?:[^A-Za-z0-9/+=]|$)'),
        "severity": "CRITICAL",
        "description": "AWS access key ID (starts with AKIA)",
    },
    {
        "name": "AWS Secret Access Key",
        "pattern": re.compile(r'(?i)aws_secret_access_key\s*[=:]\s*[\'"]?([A-Za-z0-9/+=]{40})[\'"]?'),
        "severity": "CRITICAL",
        "description": "AWS secret access key",
    },
    {
        "name": "GitHub Token",
        "pattern": re.compile(r'(?:^|[^A-Za-z0-9_])(gh[ps]_[A-Za-z0-9_]{36,255})(?:[^A-Za-z0-9_]|$)'),
        "severity": "HIGH",
        "description": "GitHub personal access or service token",
    },
    {
        "name": "Private Key",
        "pattern": re.compile(r'-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE\s+KEY(?:\s+BLOCK)?-----'),
        "severity": "CRITICAL",
        "description": "PEM private key header",
    },
    {
        "name": "JWT Token",
        "pattern": re.compile(r'(?:^|[^A-Za-z0-9_])(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})(?:[^A-Za-z0-9_-]|$)'),
        "severity": "HIGH",
        "description": "JSON Web Token",
    },
    {
        "name": "Database URL",
        "pattern": re.compile(r'(?:mysql|postgres|postgresql|mongodb|redis|amqp)://[^\s\'"]+:[^\s\'"]+@[^\s\'"]+'),
        "severity": "CRITICAL",
        "description": "Database connection string with credentials",
    },
    {
        "name": "Generic API Key",
        "pattern": re.compile(r'(?i)(?:api[_-]?key|apikey)\s*[=:]\s*[\'"]?([A-Za-z0-9_\-]{20,})[\'"]?'),
        "severity": "MEDIUM",
        "description": "Generic API key assignment",
    },
    {
        "name": "Generic Password",
        "pattern": re.compile(r'(?i)(?:password|passwd|pwd)\s*[=:]\s*[\'"]([^\'"]{8,})[\'"]'),
        "severity": "MEDIUM",
        "description": "Hardcoded password",
    },
]

# TODO: add GCP service account key, Azure client secret
