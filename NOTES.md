# Secret Scanner - Research Notes

## Approaches
- regex matching (trufflehog style)
- entropy-based detection
- ast parsing for hardcoded strings

## Regex vs Entropy
regex: lower false positives, misses custom formats
entropy: catches more but noisy
best approach: combine both
