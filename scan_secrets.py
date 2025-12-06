#!/usr/bin/env python3
"""scan files for hardcoded secrets - now with binary file skipping"""

import os
import sys
from patterns import PATTERNS

# these extensions are binary, skip them
BINARY_EXT = {
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg',
    '.woff', '.woff2', '.ttf', '.eot',
    '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
    '.exe', '.dll', '.so', '.dylib',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx',
    '.pyc', '.pyo', '.class',
}

SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv'}

def is_binary(filepath):
    _, ext = os.path.splitext(filepath)
    return ext.lower() in BINARY_EXT

def scan_file(filepath):
    if is_binary(filepath):
        return []
    
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                for name, pattern in PATTERNS.items():
                    if pattern.search(line):
                        findings.append({
                            'file': filepath,
                            'line': line_num,
                            'type': name,
                        })
    except (OSError, PermissionError):
        pass
    return findings

def scan_directory(directory):
    findings = []
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            filepath = os.path.join(root, f)
            findings.extend(scan_file(filepath))
    return findings

if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else '.'
    results = scan_directory(path)
    for r in results:
        print(f"[{r['type']}] {r['file']}:{r['line']}")
    print(f"\nTotal: {len(results)} findings")
