import re
from dataclasses import dataclass
from typing import List


@dataclass
class Rule:
    name: str
    pattern: str
    severity: str
    description: str

    def compile(self) -> re.Pattern:
        return re.compile(self.pattern)


# built-in detection rules
DEFAULT_RULES: List[Rule] = [
    Rule(
        name="AWS Access Key ID",
        pattern=r"(?:^|[^A-Za-z0-9/+=])(AKIA[0-9A-Z]{16})(?:[^A-Za-z0-9/+=]|$)",
        severity="CRITICAL",
        description="AWS access key ID (always starts with AKIA)",
    ),
    Rule(
        name="AWS Secret Access Key",
        pattern=r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        severity="CRITICAL",
        description="Amazon Web Services secret access key",
    ),
    Rule(
        name="GitHub Token",
        pattern=r"(?:^|[^A-Za-z0-9_])(gh[ps]_[A-Za-z0-9_]{36,255})(?:[^A-Za-z0-9_]|$)",
        severity="HIGH",
        description="GitHub personal access token or service token",
    ),
    Rule(
        name="Private Key",
        pattern=r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE\s+KEY(?:\s+BLOCK)?-----",
        severity="CRITICAL",
        description="PEM-encoded private key header",
    ),
    Rule(
        name="JWT Token",
        pattern=r"(?:^|[^A-Za-z0-9_])(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})(?:[^A-Za-z0-9_-]|$)",
        severity="HIGH",
        description="JSON Web Token (3-part base64url)",
    ),
    Rule(
        name="Database URL",
        pattern=r"(?:mysql|postgres|postgresql|mongodb|redis|amqp)://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+",
        severity="CRITICAL",
        description="Database connection string with embedded credentials",
    ),
    Rule(
        name="Generic API Key",
        pattern=r"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?",
        severity="MEDIUM",
        description="Generic API key assignment",
    ),
    Rule(
        name="Generic Password",
        pattern=r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
        severity="MEDIUM",
        description="Hardcoded password assignment",
    ),
]
