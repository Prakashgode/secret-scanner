import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


# skip these, they'll just produce garbage matches
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".pyc", ".pyo", ".class",
}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "env", ".env", ".tox", ".mypy_cache", ".pytest_cache",
}


@dataclass
class Finding:
    file: str
    line: int
    secret_type: str
    severity: str
    match_preview: str

    def __repr__(self) -> str:
        return f"Finding({self.secret_type} in {self.file}:{self.line} [{self.severity}])"


def _mask_secret(text: str, visible_chars: int = 4) -> str:
    if len(text) <= visible_chars:
        return "*" * len(text)
    return text[:visible_chars] + "*" * (len(text) - visible_chars)


# TODO: move these to a separate rules module
RULES = [
    {
        "name": "AWS Access Key ID",
        "pattern": r"(?:^|[^A-Za-z0-9/+=])(AKIA[0-9A-Z]{16})(?:[^A-Za-z0-9/+=]|$)",
        "severity": "CRITICAL",
    },
    {
        "name": "AWS Secret Access Key",
        "pattern": r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "severity": "CRITICAL",
    },
    {
        "name": "GitHub Token",
        "pattern": r"(?:^|[^A-Za-z0-9_])(gh[ps]_[A-Za-z0-9_]{36,255})(?:[^A-Za-z0-9_]|$)",
        "severity": "HIGH",
    },
    {
        "name": "Private Key",
        "pattern": r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE\s+KEY(?:\s+BLOCK)?-----",
        "severity": "CRITICAL",
    },
    {
        "name": "JWT Token",
        "pattern": r"(?:^|[^A-Za-z0-9_])(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})(?:[^A-Za-z0-9_-]|$)",
        "severity": "HIGH",
    },
    {
        "name": "Generic API Key",
        "pattern": r"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?",
        "severity": "MEDIUM",
    },
    {
        "name": "Generic Password",
        "pattern": r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
        "severity": "MEDIUM",
    },
]


class SecretScanner:
    def __init__(self):
        self._compiled = [(r, re.compile(r["pattern"])) for r in RULES]

    def scan_file(self, filepath: str) -> List[Finding]:
        path = Path(filepath)

        # skip binary files - was crashing on images before
        if path.suffix.lower() in BINARY_EXTENSIONS:
            return []

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return []

        findings: List[Finding] = []
        for line_num, line in enumerate(content.splitlines(), start=1):
            for rule, compiled in self._compiled:
                match = compiled.search(line)
                if match:
                    matched_text = match.group(1) if match.lastindex else match.group(0)
                    findings.append(
                        Finding(
                            file=str(path),
                            line=line_num,
                            secret_type=rule["name"],
                            severity=rule["severity"],
                            match_preview=_mask_secret(matched_text),
                        )
                    )
        return findings

    def scan_directory(self, directory: str) -> List[Finding]:
        findings: List[Finding] = []
        root = Path(directory)

        for dirpath, dirnames, filenames in os.walk(root):
            # prune dirs we don't care about
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                findings.extend(self.scan_file(filepath))

        return findings
