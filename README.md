# JSINTEL

JavaScript Intelligence Engine for Bug Bounty.

Modern web apps ship their entire API surface to the browser as JavaScript. Bundlers inline API keys, internal endpoints, and hidden parameters. JSINTEL extracts everything needed to map the attack surface.

## Features

- Secrets: AWS keys, Stripe keys, GitHub tokens, JWTs, private keys (40+ patterns)
- Endpoints: API routes, GraphQL, admin paths from fetch/axios/XHR calls
- Parameters: auto-classified by vuln class (SSRF, IDOR, LFI, redirect, SQLi, XSS)
- Cloud assets: S3, GCS, Azure blobs, DigitalOcean spaces

## Quick Start

    git clone https://github.com/nadirzhon/jsintel
    cd jsintel
    pip install -r requirements.txt
    python analyzer.py -f bundle.js
    python analyzer.py -u https://target.com/static/main.js
    python analyzer.py -l js_urls.txt -o report.json

## Bug bounty workflow

    subfinder -d target.com | httpx | gau | grep '.js$' | sort -u > js_urls.txt
    python analyzer.py -l js_urls.txt -o findings.json
    cat findings.json | jq '.[].interesting_params'

## Detection coverage

Cloud keys (AWS, Google, Stripe, Heroku, Mailgun, Twilio, SendGrid), auth tokens (GitHub, Slack, JWT, Bearer), private keys, endpoints, and cloud storage buckets.

## License

MIT. For authorized security testing and bug bounty programs only.
