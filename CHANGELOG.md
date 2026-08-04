# Changelog

## [1.1.0] - 2026-08-04
### Added
- Parameter vulnerability classification (SSRF, IDOR, LFI, redirect, SQLi, XSS)
- Cloud asset detection (S3, GCS, Azure, DigitalOcean, Firebase)
- GraphQL endpoint detection
- Async bulk URL analysis via aiohttp

## [1.0.0] - 2026-07-10
### Initial Release
- 22 secret detection patterns (AWS, Stripe, GitHub, Slack, JWT...)
- Endpoint extraction from fetch/axios/XHR calls
- Parameter extraction
- JSON + colorized CLI reporting
