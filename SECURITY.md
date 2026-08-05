# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please do **not** open a public issue. Report it privately to the maintainer and allow reasonable time for a fix before public disclosure.

## Responsible Use

This tool is intended for **authorized security testing only**. Use it exclusively against systems you own or have explicit written permission to test. Unauthorized use against third-party systems may be illegal in your jurisdiction.

## Handling of Secrets

- API keys and credentials are read from environment variables or config files that are git-ignored.
- Never commit real keys, tokens, or credentials.
- Example configs use placeholder values only.
