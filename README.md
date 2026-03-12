# secret-scanner

![CI](https://github.com/Prakashgode/secret-scanner/actions/workflows/ci.yml/badge.svg)

CLI tool that scans codebases and git history for hardcoded secrets — API keys, tokens, passwords, private keys, etc.

## Install

```bash
git clone https://github.com/yourusername/secret-scanner.git
cd secret-scanner
pip install -e .
```

## Usage

```bash
# scan a directory
secret-scanner scan --path ./my-project

# include git history
secret-scanner scan --path ./my-project --git-history

# json output
secret-scanner scan --path ./my-project --output json

# custom rules
secret-scanner scan --path ./my-project --config custom-rules.yaml
```

## Sample Output

```
$ secret-scanner scan --path ./my-project

============================================================
  SecretScanner Results: 4 finding(s)
============================================================

  [CRITICAL] AWS Access Key ID
    File: config/settings.py:23
    Preview: AKIA****************

  [HIGH] JWT Token
    File: api/auth.py:45
    Preview: eyJh****************************************************

  [CRITICAL] Database URL
    File: docker-compose.yml:12
    Preview: post************************************

  [MEDIUM] Generic Password
    File: utils/db.py:8
    Preview: MyS3************

============================================================
```

## What it detects

| Secret Type       | Pattern                      | Severity |
|-------------------|------------------------------|----------|
| AWS Access Keys   | `AKIA[0-9A-Z]{16}`          | CRITICAL |
| AWS Secret Keys   | 40-char base64 string        | CRITICAL |
| GitHub Tokens     | `ghp_`, `gho_`, `ghs_`      | HIGH     |
| Private Keys      | `-----BEGIN * PRIVATE KEY`   | CRITICAL |
| JWT Tokens        | `eyJ...` (base64 segments)   | HIGH     |
| Database URLs     | `://user:pass@host/db`       | CRITICAL |
| Generic API Keys  | `api_key`, `apikey` patterns | MEDIUM   |
| Generic Passwords | `password =`, `passwd =`     | MEDIUM   |

Also does Shannon entropy checks on secret-like variable assignments to catch things the regex rules miss.

## Custom rules

```yaml
rules:
  - name: Slack Webhook
    pattern: "https://hooks\\.slack\\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+"
    severity: HIGH
    description: Slack incoming webhook URL

  - name: Internal API Key
    pattern: "mycompany_api_[a-zA-Z0-9]{32}"
    severity: CRITICAL
    description: Internal service API key
```

## Pre-commit hook

```yaml
repos:
  - repo: https://github.com/yourusername/secret-scanner
    rev: v0.1.0
    hooks:
      - id: secret-scanner
```

## Output formats

- `console` (default) — colored terminal output
- `json` — machine-readable, good for piping
- `sarif` — works with GitHub Advanced Security / VS Code

Exits with code 1 if anything is found, so it plays nicely in CI.

## Contributing

Open a PR. Add tests for any new detection patterns.

## License

MIT

