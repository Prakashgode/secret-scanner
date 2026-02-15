import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


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


# hardcoded rules for now, will refactor later
RULES = [
    {
        "name": "AWS Access Key ID",
        "pattern": r"(AKIA[0-9A-Z]{16})",
        "severity": "CRITICAL",
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
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                findings.extend(self.scan_file(filepath))
        return findings
