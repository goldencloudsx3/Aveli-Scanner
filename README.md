# Aveli Scanner

Real-time internet-wide website vulnerability scanner. Monitors newly deployed
and recently changed websites for critical security vulnerabilities.

## What It Detects

| Category | Examples |
|---|---|
| Exposed API Keys | AWS, Google, GitHub, GitLab, DigitalOcean, Heroku |
| Payment Keys | Stripe live keys, Square tokens, PayPal secrets, Twilio |
| Crypto / Web3 | Ethereum private keys, BIP39 seed phrases, Solana keys |
| Private Keys | PEM-encoded RSA/EC/OPENSSH private keys |
| Database Creds | MongoDB URIs, PostgreSQL/MySQL connection strings, Redis |
| OAuth / Tokens | GitHub PATs, Slack tokens, Discord bot tokens, JWTs |
| Sensitive Files | `.env`, `wp-config.php`, `.git/config`, backup dumps |
| Security Headers | Missing HSTS, CSP, X-Frame-Options, CORS misconfig |

## Discovery Sources

- **Certificate Transparency Logs** — real-time stream of new TLS certs via `certstream`
- **Common Crawl CDX** — queries the latest Common Crawl index for sensitive URL patterns
- **URLScan.io** — polls recently scanned pages
- **OpenPhish** — phishing URL feed (opt-in)
- **Top-sites probe** — generates sensitive-path probes for high-value domains

## Installation

```bash
# Clone
git clone https://github.com/goldencloudsx3/Aveli-Scanner.git
cd Aveli-Scanner

# Create virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate          # macOS/Linux

# Install dependencies
pip install -r requirements.txt

# Install as CLI tool (optional)
pip install -e .
```

## Usage

```bash
# Run with all defaults (reports CRITICAL + HIGH findings)
python -m aveli

# Or if installed as a CLI tool
aveli

# More aggressive scan
aveli --workers 40 --rps 50

# Only CRITICAL findings
aveli --min-severity critical

# Save findings to JSONL file
aveli --output findings.jsonl

# Scan a custom list of URLs (one per line)
aveli --no-ct --no-cc --urls my_urls.txt

# Include medium severity and enable OpenPhish
aveli --min-severity medium --openphish

# Show all options
aveli --help
```

## CLI Options

| Flag | Default | Description |
|---|---|---|
| `--workers` / `-w` | 20 | Concurrent HTTP workers |
| `--rps` | 20.0 | Max requests per second |
| `--min-severity` / `-s` | high | Minimum severity to report |
| `--output` / `-o` | — | JSONL file for saving findings |
| `--config` / `-c` | aveli.yml | Custom config file path |
| `--urls` | — | Text file with seed URLs |
| `--no-ct` | — | Disable Certificate Transparency source |
| `--no-cc` | — | Disable Common Crawl source |
| `--no-urlscan` | — | Disable URLScan.io source |
| `--openphish` | — | Enable OpenPhish feed |
| `--no-probe` | — | Disable top-sites path probing |
| `--no-headers` | — | Skip security header analysis |
| `--no-content` | — | Skip body secret scanning |
| `--timeout` | 12 | HTTP request timeout in seconds |
| `--verbose` / `-v` | — | Enable debug logging |
| `--stats-interval` | 15 | Stats print frequency in seconds |

## Configuration File

Edit `aveli.yml` to set persistent defaults:

```yaml
workers: 20
requests_per_second: 20.0
request_timeout: 12
min_severity: high
check_headers: true
check_content: true
check_url_patterns: true
verify_ssl: false
```

Environment variable overrides use the `AVELI_` prefix:

```bash
AVELI_WORKERS=50 AVELI_MIN_SEVERITY=critical aveli
```

## Output Format

Findings are printed as colour-coded panels in the terminal. With `--output`,
each finding is also appended as a JSON line:

```json
{
  "url": "https://example.com/.env",
  "vuln_type": "Stripe Live Secret Key",
  "category": "Payment Processor Key",
  "severity": "CRITICAL",
  "evidence": "sk_live_ab12cd**********ef56",
  "description": "Exposed Stripe live secret key ...",
  "remediation": "Roll key immediately in Stripe Dashboard ...",
  "confidence": 0.99,
  "cvss_score": 10.0,
  "tags": ["stripe", "payment", "live"]
}
```

## Architecture

```
Discovery Sources                Scanner Core           Reporter
-----------------                ------------           --------
CT Log Stream     ----+
Common Crawl CDX -----+   URL Queue --> Workers --> Result Queue --> Terminal
URLScan.io        ----+                 (async       (findings)      (rich UI)
OpenPhish         ----+                 aiohttp)         |
Top-sites probe   ----+                             JSONL file
```

## Ethics & Responsible Use

This tool is built for **defensive security research**. It reports vulnerabilities
so that site owners can be notified and fix them before attackers exploit them.

- Do not use findings to access systems without authorisation
- Responsibly disclose critical findings to the affected site owner
- Respect `robots.txt` in custom URL scans
- Use `--rps` to avoid overwhelming small sites

## Requirements

- Python 3.11+
- macOS, Linux (or WSL on Windows)
