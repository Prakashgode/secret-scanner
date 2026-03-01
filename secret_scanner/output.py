import json
from typing import List

from .scanner import Finding


class ConsoleFormatter:
    SEVERITY_COLORS = {
        "CRITICAL": "\033[91m",  # red
        "HIGH": "\033[93m",      # yellow
        "MEDIUM": "\033[94m",    # blue
        "LOW": "\033[37m",       # white
    }
    RESET = "\033[0m"

    def format(self, findings: List[Finding]) -> str:
        if not findings:
            return "No secrets detected."

        lines = [f"\n{'='*60}", f"  SecretScanner Results: {len(findings)} finding(s)", f"{'='*60}\n"]

        for f in findings:
            color = self.SEVERITY_COLORS.get(f.severity, "")
            lines.append(
                f"  {color}[{f.severity}]{self.RESET} {f.secret_type}\n"
                f"    File: {f.file}:{f.line}\n"
                f"    Preview: {f.match_preview}\n"
            )

        lines.append(f"{'='*60}")
        return "\n".join(lines)


class JsonFormatter:
    def format(self, findings: List[Finding]) -> str:
        results = {
            "total": len(findings),
            "findings": [
                {
                    "file": f.file,
                    "line": f.line,
                    "secret_type": f.secret_type,
                    "severity": f.severity,
                    "match_preview": f.match_preview,
                }
                for f in findings
            ],
        }
        return json.dumps(results, indent=2)


def format_results(findings: List[Finding], output_format: str = "console") -> str:
    formatters = {
        "console": ConsoleFormatter,
        "json": JsonFormatter,
    }
    formatter_class = formatters.get(output_format, ConsoleFormatter)
    return formatter_class().format(findings)
