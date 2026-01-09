"""shannon entropy calculation for detecting high-randomness strings

the idea: secrets tend to have high entropy (randomness) compared to
normal code. if we see a string assigned to something like
secret= or token= that has entropy > 4.5, it's probably a real secret.

this catches stuff the regex patterns miss.
"""

import math
import re
from collections import Counter

def shannon_entropy(data):
    """calculate shannon entropy of a string"""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )

# threshold tuned to reduce false positives
# normal english text: ~3.5-4.0 bits
# random base64: ~5.5-6.0 bits  
# hex strings: ~3.5-4.0 bits
ENTROPY_THRESHOLD = 4.5
MIN_LENGTH = 20

ASSIGN_RE = re.compile(
    r'(?i)(?:secret|token|key|credential|auth)\s*[=:]\s*[\'"]?([A-Za-z0-9+/=_\-]{20,})[\'"]?'
)

def check_entropy(line):
    """check a line for high-entropy secret assignments"""
    findings = []
    for match in ASSIGN_RE.finditer(line):
        value = match.group(1)
        if len(value) >= MIN_LENGTH:
            ent = shannon_entropy(value)
            if ent >= ENTROPY_THRESHOLD:
                findings.append({
                    'value_preview': value[:4] + '****',
                    'entropy': round(ent, 2),
                })
    return findings
