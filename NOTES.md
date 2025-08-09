# Secret Scanner - Research Notes

## Approaches
- regex matching (trufflehog style)
- entropy-based detection
- ast parsing for hardcoded strings

## Regex vs Entropy
regex: lower false positives, misses custom formats
entropy: catches more but noisy
best approach: combine both

## Pattern Sources
- aws key format: AKIA[0-9A-Z]{16}
- github pat: ghp_[a-zA-Z0-9]{36}
- slack token: xoxb-
