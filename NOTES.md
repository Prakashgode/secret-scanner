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

## Implementation Plan
1. file walker (skip .git, binaries)
2. rule engine with yaml config
3. entropy calculator
4. output formatters (console, json, sarif)
5. pre-commit hook integration
6. ci/cd integration (github actions)

start building in november, got other stuff going on rn
- look at detect-secrets by Yelp
- gitleaks patterns are good reference
- stripe key: sk_live_
- sendgrid: SG.
- twilio: SK[a-z0-9]{32}
# Azure patterns - coming soon
