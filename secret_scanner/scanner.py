import math
import os
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .rules import DEFAULT_RULES, Rule, load_custom_rules

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
    "dist", "build", ".eggs",
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


def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


class SecretScanner:
    ENTROPY_THRESHOLD = 4.5  # tuned to reduce FPs, bump up if too noisy
    MIN_ENTROPY_LENGTH = 20

    def __init__(self, config_path: Optional[str] = None):
        self.rules: List[Rule] = list(DEFAULT_RULES)
        if config_path:
            self.rules.extend(load_custom_rules(config_path))
        self._compiled = [(rule, rule.compile()) for rule in self.rules]

    def scan_file(self, filepath: str) -> List[Finding]:
        path = Path(filepath)
        if path.suffix.lower() in BINARY_EXTENSIONS:
            return []

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return []

        findings: List[Finding] = []
        for line_num, line in enumerate(content.splitlines(), start=1):
            findings.extend(self._scan_line(str(path), line_num, line))

        return findings

    def scan_directory(self, directory: str) -> List[Finding]:
        findings: List[Finding] = []
        root = Path(directory)

        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                findings.extend(self.scan_file(filepath))

        return findings

    def scan_git_history(self, repo_path: str) -> List[Finding]:
        try:
            from git import Repo
        except ImportError:
            raise ImportError("GitPython required for git history scanning: pip install gitpython")

        repo = Repo(repo_path)
        findings: List[Finding] = []

        # cap at 500 commits so we don't choke on huge repos
        for commit in repo.iter_commits("--all", max_count=500):
            if not commit.parents:
                diffs = commit.diff(None, create_patch=True)
            else:
                diffs = commit.parents[0].diff(commit, create_patch=True)

            for diff in diffs:
                try:
                    patch = diff.diff.decode("utf-8", errors="ignore")
                except AttributeError:
                    continue

                filepath = diff.b_path or diff.a_path or "unknown"
                for line_num, line in enumerate(patch.splitlines(), start=1):
                    # only check added lines
                    if line.startswith("+") and not line.startswith("+++"):
                        added_line = line[1:]
                        for finding in self._scan_line(
                            f"{filepath} (commit {commit.hexsha[:8]})",
                            line_num,
                            added_line,
                        ):
                            findings.append(finding)

        return findings

    def _scan_line(self, filepath: str, line_num: int, line: str) -> List[Finding]:
        findings: List[Finding] = []

        for rule, compiled in self._compiled:
            match = compiled.search(line)
            if match:
                matched_text = match.group(1) if match.lastindex else match.group(0)
                findings.append(
                    Finding(
                        file=filepath,
                        line=line_num,
                        secret_type=rule.name,
                        severity=rule.severity,
                        match_preview=_mask_secret(matched_text),
                    )
                )

        findings.extend(self._entropy_check(filepath, line_num, line))

        return findings

    def _entropy_check(self, filepath: str, line_num: int, line: str) -> List[Finding]:
        """catches high-entropy strings the regex rules miss"""
        findings: List[Finding] = []
        assign_pattern = re.compile(
            r"""(?i)(?:secret|token|key|credential|auth)\s*[=:]\s*['"]?([A-Za-z0-9+/=_\-]{20,})['"]?"""
        )
        for match in assign_pattern.finditer(line):
            value = match.group(1)
            if len(value) >= self.MIN_ENTROPY_LENGTH:
                entropy = _shannon_entropy(value)
                if entropy >= self.ENTROPY_THRESHOLD:
                    findings.append(
                        Finding(
                            file=filepath,
                            line=line_num,
                            secret_type="High Entropy String",
                            severity="MEDIUM",
                            match_preview=_mask_secret(value),
                        )
                    )
        return findings
