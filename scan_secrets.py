#!/usr/bin/env python3
"""scan files for hardcoded AWS keys

just a quick script to check if any AWS access keys are committed
in our repos. AKIA prefix is always the start of an AWS access key ID.
"""

import re
import sys
import os

# AWS access key always starts with AKIA followed by 16 uppercase alphanumeric chars
AWS_KEY_RE = re.compile(r'(AKIA[0-9A-Z]{16})')

def scan_file(filepath):
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                match = AWS_KEY_RE.search(line)
                if match:
                    findings.append({
                        'file': filepath,
                        'line': line_num,
                        'key_preview': match.group(1)[:8] + '****',
                    })
    except (OSError, PermissionError):
        pass
    return findings

if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else '.'
    for root, dirs, files in os.walk(path):
        # skip .git
        dirs[:] = [d for d in dirs if d != '.git']
        for f in files:
            filepath = os.path.join(root, f)
            for finding in scan_file(filepath):
                print(f"FOUND: {finding['key_preview']} in {finding['file']}:{finding['line']}")
