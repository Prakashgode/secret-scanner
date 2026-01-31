# secret-scanner plans

## done
- AWS key regex
- common secret patterns (github, jwt, private keys, db urls)
- binary file skipping
- entropy-based detection
- console output

## todo
- restructure as proper python package
- pre-commit hook (scan staged files before commit)
- custom rules via yaml config
- json and sarif output formats
- git history scanning (scan past commits for leaked secrets)
