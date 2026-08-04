#!/usr/bin/env python3
"""
JSINTEL — JavaScript Intelligence Engine
Extracts secrets, endpoints, parameters, and API maps from JavaScript files.
Author: nadirzhon | github.com/nadirzhon/jsintel
"""

import re
import json
import argparse
import asyncio
import hashlib
from urllib.parse import urljoin, urlparse
from datetime import datetime
from dataclasses import dataclass, field, asdict
from collections import defaultdict

try:
    import aiohttp
except ImportError:
    aiohttp = None

# ─────────────────────────────────────────────────────────────────────────────
# SECRET DETECTION PATTERNS
# Each pattern is (name, regex, confidence, severity)
# ─────────────────────────────────────────────────────────────────────────────
SECRET_PATTERNS = [
    ("AWS Access Key",       r"AKIA[0-9A-Z]{16}",                                    "HIGH",   "CRITICAL"),
    ("AWS Secret Key",       r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",        "MEDIUM", "CRITICAL"),
    ("Google API Key",       r"AIza[0-9A-Za-z\-_]{35}",                              "HIGH",   "HIGH"),
    ("Google OAuth",         r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com","HIGH",  "MEDIUM"),
    ("Firebase URL",         r"https://[a-z0-9-]+\.firebaseio\.com",                 "HIGH",   "MEDIUM"),
    ("Stripe Live Key",      r"sk_live_[0-9a-zA-Z]{24}",                             "HIGH",   "CRITICAL"),
    ("Stripe Publishable",   r"pk_live_[0-9a-zA-Z]{24}",                             "HIGH",   "LOW"),
    ("GitHub Token",         r"gh[pousr]_[0-9a-zA-Z]{36}",                           "HIGH",   "CRITICAL"),
    ("GitHub OAuth",         r"gho_[0-9a-zA-Z]{36}",                                 "HIGH",   "CRITICAL"),
    ("Slack Token",          r"xox[baprs]-[0-9a-zA-Z-]{10,48}",                      "HIGH",   "HIGH"),
    ("Slack Webhook",        r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+",    "HIGH",   "MEDIUM"),
    ("JWT Token",            r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "MEDIUM", "MEDIUM"),
    ("Private Key",          r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----","HIGH", "CRITICAL"),
    ("Mailgun API Key",      r"key-[0-9a-zA-Z]{32}",                                 "MEDIUM", "HIGH"),
    ("Twilio API Key",       r"SK[0-9a-fA-F]{32}",                                   "MEDIUM", "HIGH"),
    ("SendGrid API Key",     r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",          "HIGH",   "HIGH"),
    ("Heroku API Key",       r"(?i)heroku(.{0,20})?['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]", "MEDIUM", "HIGH"),
    ("Facebook Token",       r"EAACEdEose0cBA[0-9A-Za-z]+",                          "MEDIUM", "MEDIUM"),
    ("Generic API Key",      r"(?i)(?:api[_-]?key|apikey)['\"\s:=]{1,4}['\"][0-9a-zA-Z\-_]{16,45}['\"]", "LOW", "MEDIUM"),
    ("Generic Secret",       r"(?i)(?:secret|passwd|password|token)['\"\s:=]{1,4}['\"][0-9a-zA-Z\-_!@#$%]{8,45}['\"]", "LOW", "MEDIUM"),
    ("Bearer Token",         r"(?i)bearer\s+[a-zA-Z0-9_\-\.=]{20,}",                 "LOW",    "MEDIUM"),
    ("Basic Auth",           r"(?i)basic\s+[a-zA-Z0-9=:_\+/-]{16,}",                 "LOW",    "MEDIUM"),
]

# ─────────────────────────────────────────────────────────────────────────────
# ENDPOINT / URL EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────
ENDPOINT_PATTERNS = [
    # Relative and absolute API paths
    r"['\"`](/(?:api|v[0-9]|rest|graphql|internal|admin|auth|user|account)[a-zA-Z0-9_/{}.\-]*)['\"`]",
    r"['\"`](https?://[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}[a-zA-Z0-9/_{}.\-?=&]*)['\"`]",
    # fetch/axios/XHR calls
    r"(?:fetch|axios(?:\.(?:get|post|put|delete|patch))?|\.open)\s*\(\s*['\"`]([^'\"`]+)['\"`]",
    r"url\s*[:=]\s*['\"`]([^'\"`]+)['\"`]",
]

# ─────────────────────────────────────────────────────────────────────────────
# PARAMETER EXTRACTION (for fuzzing / IDOR / SSRF hunting)
# ─────────────────────────────────────────────────────────────────────────────
PARAM_PATTERNS = [
    r"['\"`]([a-zA-Z_][a-zA-Z0-9_]{2,30})['\"`]\s*:",          # object keys
    r"[?&]([a-zA-Z_][a-zA-Z0-9_]{2,30})=",                     # query params
    r"(?:getParameter|params\.get|searchParams\.get)\s*\(\s*['\"`]([a-zA-Z0-9_]+)['\"`]",
    r"\.([a-zA-Z_][a-zA-Z0-9_]{2,30})\s*=\s*(?:req|request|params|query|body)",
]

# Interesting params for bug bounty
INTERESTING_PARAMS = {
    "ssrf":     ["url","uri","link","src","dest","redirect","return","next","target","proxy","fetch","site","host","domain","callback","webhook"],
    "idor":     ["id","user","uid","account","order","invoice","doc","file","key","number","no","ref"],
    "lfi":      ["file","path","page","include","doc","folder","root","dir","template","php_path"],
    "redirect": ["redirect","url","next","return","returnurl","goto","dest","destination","continue","redir","r","u"],
    "sqli":     ["id","user","username","email","search","query","filter","sort","order","category"],
    "xss":      ["q","search","query","message","comment","name","keyword","term","text","content"],
}

# ─────────────────────────────────────────────────────────────────────────────
# GRAPHQL / S3 / CLOUD DETECTION
# ─────────────────────────────────────────────────────────────────────────────
CLOUD_PATTERNS = [
    ("S3 Bucket",         r"[a-z0-9.\-]+\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com"),
    ("S3 Bucket (path)",  r"s3\.amazonaws\.com/[a-z0-9.\-_]+"),
    ("GCS Bucket",        r"storage\.googleapis\.com/[a-z0-9.\-_]+"),
    ("Azure Blob",        r"[a-z0-9]+\.blob\.core\.windows\.net"),
    ("DigitalOcean Space",r"[a-z0-9.\-]+\.digitaloceanspaces\.com"),
    ("GraphQL Endpoint",  r"['\"`]([^'\"`]*/graphql[^'\"`]*)['\"`]"),
]

@dataclass
class Finding:
    kind: str
    value: str
    context: str = ""
    severity: str = "INFO"
    confidence: str = "MEDIUM"
    source: str = ""

@dataclass
class AnalysisResult:
    source: str
    secrets: list = field(default_factory=list)
    endpoints: list = field(default_factory=list)
    parameters: dict = field(default_factory=dict)
    cloud_assets: list = field(default_factory=list)
    interesting_params: dict = field(default_factory=dict)
    stats: dict = field(default_factory=dict)


class JSAnalyzer:
    def __init__(self, source_name="input"):
        self.source = source_name

    def _context(self, text, match_start, width=40):
        start = max(0, match_start - width)
        end = min(len(text), match_start + width)
        snippet = text[start:end].replace("\n", " ")
        return f"...{snippet}..."

    def extract_secrets(self, js):
        found = []
        seen = set()
        for name, pattern, conf, sev in SECRET_PATTERNS:
            for m in re.finditer(pattern, js):
                val = m.group(0)
                # Dedup + filter obvious false positives
                h = hashlib.md5((name + val).encode()).hexdigest()
                if h in seen:
                    continue
                seen.add(h)
                # Skip very common false positives
                if name.startswith("Generic") and any(fp in val.lower() for fp in ["example","test","xxxx","0000","your_","placeholder","dummy"]):
                    continue
                found.append(Finding(
                    kind=name, value=val[:80],
                    context=self._context(js, m.start()),
                    severity=sev, confidence=conf, source=self.source
                ))
        return found

    def extract_endpoints(self, js):
        endpoints = set()
        for pattern in ENDPOINT_PATTERNS:
            for m in re.finditer(pattern, js):
                ep = m.group(1) if m.lastindex else m.group(0)
                ep = ep.strip("'\"`")
                # Filter noise
                if len(ep) < 2 or len(ep) > 200:
                    continue
                if ep.startswith(("data:","blob:","javascript:","#")):
                    continue
                if any(ep.endswith(ext) for ext in [".png",".jpg",".gif",".svg",".css",".woff",".woff2",".ttf",".ico"]):
                    continue
                endpoints.add(ep)
        return sorted(endpoints)

    def extract_parameters(self, js):
        params = defaultdict(int)
        for pattern in PARAM_PATTERNS:
            for m in re.finditer(pattern, js):
                p = m.group(1)
                if p and 2 < len(p) < 31 and not p.startswith("_"):
                    # Skip common JS keywords/methods
                    if p in ("function","return","typeof","length","prototype","constructor","undefined","default","children","className","onClick","onChange"):
                        continue
                    params[p] += 1
        return dict(sorted(params.items(), key=lambda x: -x[1]))

    def classify_interesting_params(self, params):
        result = defaultdict(list)
        param_names = set(p.lower() for p in params)
        for vuln, keywords in INTERESTING_PARAMS.items():
            for kw in keywords:
                if kw in param_names:
                    result[vuln].append(kw)
        return dict(result)

    def extract_cloud_assets(self, js):
        assets = []
        seen = set()
        for name, pattern in CLOUD_PATTERNS:
            for m in re.finditer(pattern, js):
                val = (m.group(1) if m.lastindex else m.group(0)).strip("'\"`")
                if val not in seen:
                    seen.add(val)
                    assets.append(Finding(kind=name, value=val[:120], source=self.source,
                                          severity="MEDIUM" if "Bucket" in name or "Blob" in name else "INFO"))
        return assets

    def analyze(self, js):
        secrets   = self.extract_secrets(js)
        endpoints = self.extract_endpoints(js)
        params    = self.extract_parameters(js)
        cloud     = self.extract_cloud_assets(js)
        interesting = self.classify_interesting_params(params)

        return AnalysisResult(
            source=self.source,
            secrets=[asdict(s) for s in secrets],
            endpoints=endpoints,
            parameters=params,
            cloud_assets=[asdict(c) for c in cloud],
            interesting_params=interesting,
            stats={
                "secrets_found": len(secrets),
                "endpoints_found": len(endpoints),
                "params_found": len(params),
                "cloud_assets_found": len(cloud),
                "critical_secrets": sum(1 for s in secrets if s.severity == "CRITICAL"),
            }
        )


# ─────────────────────────────────────────────────────────────────────────────
# ASYNC URL FETCHING
# ─────────────────────────────────────────────────────────────────────────────
async def fetch_js(session, url):
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status == 200:
                return await resp.text()
    except Exception:
        pass
    return None


async def analyze_urls(urls):
    if aiohttp is None:
        print("[!] aiohttp not installed — run: pip install aiohttp")
        return []
    results = []
    async with aiohttp.ClientSession(headers={"User-Agent":"Mozilla/5.0 (JSINTEL)"}) as session:
        tasks = [fetch_js(session, u) for u in urls]
        contents = await asyncio.gather(*tasks)
        for url, content in zip(urls, contents):
            if content:
                analyzer = JSAnalyzer(url)
                results.append(analyzer.analyze(content))
                print(f"[+] Analyzed {url} — {len(content)} bytes")
            else:
                print(f"[-] Failed to fetch {url}")
    return results


# ─────────────────────────────────────────────────────────────────────────────
# REPORTING
# ─────────────────────────────────────────────────────────────────────────────
SEV_COLORS = {"CRITICAL":"\033[91m","HIGH":"\033[93m","MEDIUM":"\033[96m","LOW":"\033[90m","INFO":"\033[92m"}
RESET = "\033[0m"

def print_report(result: AnalysisResult):
    print(f"\n{'='*60}")
    print(f"  JSINTEL Report — {result.source}")
    print(f"{'='*60}")
    s = result.stats
    print(f"  Secrets: {s['secrets_found']} ({s['critical_secrets']} critical) | "
          f"Endpoints: {s['endpoints_found']} | Params: {s['params_found']} | Cloud: {s['cloud_assets_found']}")

    if result.secrets:
        print(f"\n  🔑 SECRETS")
        for sec in result.secrets:
            c = SEV_COLORS.get(sec['severity'], '')
            print(f"    {c}[{sec['severity']}] {sec['kind']}: {sec['value']}{RESET}")

    if result.interesting_params:
        print(f"\n  🎯 INTERESTING PARAMS (bug bounty)")
        for vuln, params in result.interesting_params.items():
            print(f"    {vuln.upper()}: {', '.join(params)}")

    if result.cloud_assets:
        print(f"\n  ☁️  CLOUD ASSETS")
        for a in result.cloud_assets:
            print(f"    [{a['kind']}] {a['value']}")

    if result.endpoints:
        print(f"\n  🌐 ENDPOINTS ({len(result.endpoints)} total, showing 15)")
        for ep in result.endpoints[:15]:
            print(f"    {ep}")


def main():
    parser = argparse.ArgumentParser(description="JSINTEL — JavaScript Intelligence Engine")
    parser.add_argument("-f", "--file", help="Local JS file to analyze")
    parser.add_argument("-u", "--url", help="Single JS URL to fetch and analyze")
    parser.add_argument("-l", "--list", help="File containing list of JS URLs")
    parser.add_argument("-o", "--output", help="Output JSON report file")
    parser.add_argument("--secrets-only", action="store_true", help="Only report secrets")
    args = parser.parse_args()

    results = []

    if args.file:
        with open(args.file, encoding="utf-8", errors="ignore") as f:
            js = f.read()
        results.append(JSAnalyzer(args.file).analyze(js))
    elif args.url:
        results = asyncio.run(analyze_urls([args.url]))
    elif args.list:
        with open(args.list) as f:
            urls = [l.strip() for l in f if l.strip()]
        results = asyncio.run(analyze_urls(urls))
    else:
        parser.error("Provide --file, --url, or --list")

    for r in results:
        print_report(r)

    if args.output:
        with open(args.output, "w") as f:
            json.dump([asdict(r) for r in results], f, indent=2)
        print(f"\n[*] Report saved to {args.output}")

    # Summary
    total_secrets = sum(r.stats["secrets_found"] for r in results)
    total_critical = sum(r.stats["critical_secrets"] for r in results)
    if total_critical:
        print(f"\n\033[91m[!] {total_critical} CRITICAL secrets found across {len(results)} file(s)!{RESET}")


if __name__ == "__main__":
    main()
