"""
Secret and credential detection engine.

Detects exposed API keys, tokens, private keys, crypto secrets,
and other high-value credentials in website content.
"""

import re

from .entropy import passes_entropy_check
# Re-export shared types so existing callers (from .detectors.secrets import ...) keep working.
from .types import Finding, Severity, VulnCategory  # noqa: F401


def _redact(match: str, keep_prefix: int = 6, keep_suffix: int = 4) -> str:
    """Redact a matched secret, keeping only a short prefix/suffix for evidence."""
    if len(match) <= keep_prefix + keep_suffix + 4:
        return f"{match[:keep_prefix]}{'*' * 6}"
    return f"{match[:keep_prefix]}{'*' * 8}{match[-keep_suffix:]}"


# ---------------------------------------------------------------------------
# Pattern registry
# Each entry: (regex_pattern, name, category, severity, confidence, cvss, description, remediation, tags)
# ---------------------------------------------------------------------------

_PATTERN_REGISTRY: list[tuple] = [
    # ── Cloud Providers ───────────────────────────────────────────────────
    (
        r"AKIA[0-9A-Z]{16}",
        "AWS Access Key ID",
        VulnCategory.CLOUD_CREDS,
        Severity.CRITICAL,
        0.99,
        9.8,
        "Exposed AWS Access Key ID grants programmatic access to AWS services.",
        "Rotate the key immediately via AWS IAM. Audit CloudTrail for unauthorized usage.",
        ["aws", "cloud", "iam"],
    ),
    (
        r"(?i)(aws_secret_access_key|aws_secret)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "AWS Secret Access Key",
        VulnCategory.CLOUD_CREDS,
        Severity.CRITICAL,
        0.97,
        9.8,
        "Exposed AWS Secret Access Key allows full programmatic AWS access.",
        "Rotate key in AWS IAM and audit all API activity via CloudTrail.",
        ["aws", "cloud", "iam"],
    ),
    (
        r"AIza[0-9A-Za-z\-_]{35}",
        "Google API Key",
        VulnCategory.CLOUD_CREDS,
        Severity.HIGH,
        0.95,
        8.1,
        "Exposed Google API Key may allow unauthorized calls to Google services (Maps, Vision, etc.).",
        "Restrict key in Google Cloud Console by referrer/IP and rotate immediately.",
        ["google", "gcp", "api-key"],
    ),
    (
        r"ya29\.[0-9A-Za-z\-_]+",
        "Google OAuth Access Token",
        VulnCategory.OAUTH_TOKEN,
        Severity.CRITICAL,
        0.92,
        9.1,
        "Live Google OAuth token allows impersonation of the authenticated user.",
        "Revoke token at https://myaccount.google.com/permissions and implement token storage best practices.",
        ["google", "oauth", "token"],
    ),
    (
        r"(?i)AZURE[_\-]?(CLIENT_SECRET|AD_CLIENT_SECRET_VALUE)\s*[=:]\s*['\"]?([a-zA-Z0-9~._\-]{34,44})['\"]?",
        "Azure Client Secret",
        VulnCategory.CLOUD_CREDS,
        Severity.CRITICAL,
        0.93,
        9.3,
        "Exposed Azure client secret enables authentication as the registered application.",
        "Rotate secret in Azure AD and review service principal permissions.",
        ["azure", "cloud", "ad"],
    ),

    # ── Payment Processors ────────────────────────────────────────────────
    (
        r"sk_live_[0-9a-zA-Z]{24,}",
        "Stripe Live Secret Key",
        VulnCategory.PAYMENT_KEY,
        Severity.CRITICAL,
        0.99,
        10.0,
        "Exposed Stripe live secret key allows full control over charges, refunds, and customer data.",
        "Roll key immediately in Stripe Dashboard. Review all recent API calls.",
        ["stripe", "payment", "live"],
    ),
    (
        r"rk_live_[0-9a-zA-Z]{24,}",
        "Stripe Live Restricted Key",
        VulnCategory.PAYMENT_KEY,
        Severity.CRITICAL,
        0.99,
        9.5,
        "Exposed Stripe restricted live key with elevated privileges.",
        "Roll key immediately in Stripe Dashboard.",
        ["stripe", "payment", "live"],
    ),
    (
        r"(?i)(sq0atp|sq0csp)-[0-9A-Za-z\-_]{22,}",
        "Square Access Token / App Secret",
        VulnCategory.PAYMENT_KEY,
        Severity.CRITICAL,
        0.97,
        9.8,
        "Exposed Square credential allows full access to transactions and merchant data.",
        "Revoke token in Square Developer Dashboard immediately.",
        ["square", "payment"],
    ),
    (
        r"(?i)paypal[_\s\-]?(client_secret|secret)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{16,60})['\"]?",
        "PayPal Client Secret",
        VulnCategory.PAYMENT_KEY,
        Severity.CRITICAL,
        0.88,
        9.5,
        "Exposed PayPal client secret enables unauthorized payment API calls.",
        "Regenerate credentials in PayPal Developer Portal.",
        ["paypal", "payment"],
    ),
    (
        r"AC[a-z0-9]{32}",
        "Twilio Account SID",
        VulnCategory.EXPOSED_KEY,
        Severity.HIGH,
        0.87,
        7.5,
        "Twilio Account SID exposed (pair with auth token for full access).",
        "Rotate credentials in Twilio Console.",
        ["twilio", "sms", "communications"],
    ),
    (
        r"SK[0-9a-fA-F]{32}",
        "Twilio Auth Token / API Key",
        VulnCategory.PAYMENT_KEY,
        Severity.CRITICAL,
        0.92,
        9.0,
        "Exposed Twilio API key enables sending SMS/calls billed to the account.",
        "Revoke in Twilio Console and audit message history.",
        ["twilio", "sms"],
    ),

    # ── Version Control & CI/CD ───────────────────────────────────────────
    (
        r"ghp_[a-zA-Z0-9]{36}",
        "GitHub Personal Access Token (Classic)",
        VulnCategory.OAUTH_TOKEN,
        Severity.CRITICAL,
        0.99,
        9.3,
        "Exposed GitHub PAT allows repository access with the user's full permissions.",
        "Revoke token at GitHub Settings > Developer settings > Personal access tokens.",
        ["github", "vcs", "token"],
    ),
    (
        r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}",
        "GitHub Fine-Grained PAT",
        VulnCategory.OAUTH_TOKEN,
        Severity.CRITICAL,
        0.99,
        9.3,
        "Exposed GitHub fine-grained personal access token.",
        "Revoke at GitHub Settings > Developer settings > Personal access tokens.",
        ["github", "vcs", "token"],
    ),
    (
        r"gho_[a-zA-Z0-9]{36}",
        "GitHub OAuth Access Token",
        VulnCategory.OAUTH_TOKEN,
        Severity.CRITICAL,
        0.99,
        9.1,
        "Exposed GitHub OAuth token allows acting as the authenticated user.",
        "Revoke token via GitHub OAuth Apps settings.",
        ["github", "oauth"],
    ),
    (
        r"glpat-[a-zA-Z0-9\-_]{20}",
        "GitLab Personal Access Token",
        VulnCategory.OAUTH_TOKEN,
        Severity.CRITICAL,
        0.99,
        9.3,
        "Exposed GitLab PAT enables repository and CI/CD pipeline access.",
        "Revoke at GitLab Profile > Access Tokens.",
        ["gitlab", "vcs", "token"],
    ),

    # ── Messaging & Communication ─────────────────────────────────────────
    (
        r"xox[baprs]-[0-9A-Za-z]{10,48}",
        "Slack Token",
        VulnCategory.OAUTH_TOKEN,
        Severity.HIGH,
        0.96,
        8.5,
        "Exposed Slack token enables reading messages and posting as bot/user.",
        "Revoke at api.slack.com/apps and rotate the token.",
        ["slack", "messaging"],
    ),
    (
        r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}",
        "Slack Webhook URL",
        VulnCategory.EXPOSED_SECRET,
        Severity.HIGH,
        0.98,
        7.5,
        "Exposed Slack webhook URL allows sending arbitrary messages to the workspace.",
        "Rotate the webhook in Slack App settings.",
        ["slack", "webhook"],
    ),
    (
        r"(?i)discord[_\-]?(bot[_\-]?token|token)\s*[=:]\s*['\"]?([A-Za-z0-9]{24}\.[A-Za-z0-9]{6}\.[A-Za-z0-9_\-]{27,})['\"]?",
        "Discord Bot Token",
        VulnCategory.OAUTH_TOKEN,
        Severity.CRITICAL,
        0.95,
        9.0,
        "Exposed Discord bot token allows full control of the bot account.",
        "Regenerate token in Discord Developer Portal.",
        ["discord", "bot"],
    ),

    # ── Email Services ────────────────────────────────────────────────────
    (
        r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",
        "SendGrid API Key",
        VulnCategory.EXPOSED_KEY,
        Severity.HIGH,
        0.98,
        8.5,
        "Exposed SendGrid API key allows sending email as the account owner.",
        "Revoke key in SendGrid Settings > API Keys.",
        ["sendgrid", "email"],
    ),
    (
        r"key-[0-9a-zA-Z]{32}",
        "Mailgun API Key",
        VulnCategory.EXPOSED_KEY,
        Severity.HIGH,
        0.85,
        8.0,
        "Possible Mailgun API key exposure.",
        "Rotate key in Mailgun Settings.",
        ["mailgun", "email"],
    ),

    # ── Cryptocurrency & Web3 ─────────────────────────────────────────────
    (
        r"-----BEGIN\s+(?:EC|RSA|DSA|OPENSSH)?\s*PRIVATE KEY(?:\s+BLOCK)?-----",
        "Private Key (PEM)",
        VulnCategory.PRIVATE_KEY,
        Severity.CRITICAL,
        0.99,
        10.0,
        "PEM-encoded private key exposed. Can be used to impersonate servers or decrypt traffic.",
        "Remove immediately. Revoke and reissue certificate. Rotate all dependent credentials.",
        ["private-key", "crypto", "pem"],
    ),
    (
        r"(?i)(private[_\-]?key|priv[_\-]?key)\s*[=:]\s*['\"]?(0x[0-9a-fA-F]{64})['\"]?",
        "Ethereum Private Key",
        VulnCategory.CRYPTO_SECRET,
        Severity.CRITICAL,
        0.97,
        10.0,
        "Ethereum private key exposed. Provides full control over the associated wallet.",
        "Transfer funds immediately to a secure wallet. Never reuse this key.",
        ["ethereum", "web3", "crypto", "wallet"],
    ),
    (
        r"0x[0-9a-fA-F]{64}(?![0-9a-fA-F])",
        "Possible Raw Ethereum Private Key",
        VulnCategory.CRYPTO_SECRET,
        Severity.CRITICAL,
        0.75,
        9.5,
        "64-byte hex value consistent with an Ethereum private key.",
        "Verify if this is a private key. If so, transfer funds and rotate immediately.",
        ["ethereum", "web3", "crypto"],
    ),
    (
        r"(?i)(solana[_\-]?private[_\-]?key|sol[_\-]?secret)\s*[=:]\s*['\"]?([1-9A-HJ-NP-Za-km-z]{87,88})['\"]?",
        "Solana Private Key",
        VulnCategory.CRYPTO_SECRET,
        Severity.CRITICAL,
        0.93,
        10.0,
        "Exposed Solana private key grants full control of the associated wallet.",
        "Transfer funds to a new wallet immediately.",
        ["solana", "web3", "crypto", "wallet"],
    ),

    # ── Database Credentials ──────────────────────────────────────────────
    (
        r"(?i)(?:mongodb(?:\+srv)?://|mongo_uri\s*[=:]\s*['\"]?)((?:[^:]+):(?:[^@]+)@[^\s'\"]+)",
        "MongoDB Connection String with Credentials",
        VulnCategory.DATABASE_CREDS,
        Severity.CRITICAL,
        0.96,
        9.8,
        "MongoDB connection string with embedded credentials.",
        "Rotate database credentials and use environment variable injection.",
        ["mongodb", "database", "credentials"],
    ),
    (
        r"(?i)(?:postgres(?:ql)?://|mysql://|mariadb://)([^:]+):([^@\s]+)@",
        "SQL Database Connection String",
        VulnCategory.DATABASE_CREDS,
        Severity.CRITICAL,
        0.95,
        9.5,
        "SQL database URI with credentials embedded in URL.",
        "Rotate database password and use environment variables or secrets management.",
        ["database", "sql", "credentials"],
    ),
    (
        r"(?i)redis://:([^@\s]{8,})@",
        "Redis Connection with Password",
        VulnCategory.DATABASE_CREDS,
        Severity.HIGH,
        0.92,
        8.5,
        "Redis connection string with embedded password.",
        "Rotate Redis AUTH password and restrict network access.",
        ["redis", "database", "credentials"],
    ),

    # ── JWT Tokens ────────────────────────────────────────────────────────
    (
        r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
        "JSON Web Token (JWT)",
        VulnCategory.JWT_TOKEN,
        Severity.HIGH,
        0.94,
        7.8,
        "Live JWT token exposed. May contain sensitive claims and allow session hijacking.",
        "Invalidate token, shorten TTL, and never embed live tokens in public content.",
        ["jwt", "auth", "session"],
    ),

    # ── CI/CD & Infra ─────────────────────────────────────────────────────
    (
        r"(?i)(npm_token|NPM_TOKEN|NODE_AUTH_TOKEN)\s*[=:]\s*['\"]?(npm_[a-zA-Z0-9]{36})['\"]?",
        "NPM Publish Token",
        VulnCategory.EXPOSED_KEY,
        Severity.HIGH,
        0.97,
        8.5,
        "Exposed NPM token allows publishing packages to the registry.",
        "Revoke token at npmjs.com/settings/tokens.",
        ["npm", "supply-chain", "token"],
    ),
    (
        r"(?i)travis[_\s]ci[_\s]token\s*[=:]\s*['\"]?([a-zA-Z0-9]{20,})['\"]?",
        "Travis CI Token",
        VulnCategory.EXPOSED_SECRET,
        Severity.HIGH,
        0.88,
        8.0,
        "Travis CI token may expose build secrets and trigger pipelines.",
        "Revoke token in Travis CI settings.",
        ["travis", "ci", "token"],
    ),
    (
        r"(?i)(heroku[_\-]?api[_\-]?key)\s*[=:]\s*['\"]?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})['\"]?",
        "Heroku API Key",
        VulnCategory.CLOUD_CREDS,
        Severity.CRITICAL,
        0.95,
        9.0,
        "Exposed Heroku API key enables full platform access.",
        "Rotate key at dashboard.heroku.com/account.",
        ["heroku", "cloud", "paas"],
    ),
    (
        r"(?i)(digitalocean[_\-]?token|do_token)\s*[=:]\s*['\"]?([a-fA-F0-9]{64})['\"]?",
        "DigitalOcean Personal Access Token",
        VulnCategory.CLOUD_CREDS,
        Severity.CRITICAL,
        0.95,
        9.3,
        "Exposed DigitalOcean token grants full droplet/infrastructure access.",
        "Revoke token in DigitalOcean control panel.",
        ["digitalocean", "cloud", "token"],
    ),

    # ── Sensitive Files ───────────────────────────────────────────────────
    # These are matched against URLs, not body content
]

# Compiled patterns for performance
_COMPILED: list[tuple] = [
    (re.compile(p[0]), *p[1:])
    for p in _PATTERN_REGISTRY
]


def scan_content(url: str, content: str, max_findings: int = 50) -> list[Finding]:
    """Scan page content for secrets and credentials."""
    findings: list[Finding] = []

    for compiled_re, name, category, severity, confidence, cvss, description, remediation, tags in _COMPILED:
        for match in compiled_re.finditer(content):
            raw = match.group(0)
            # Use last capture group if present (to get the actual secret, not the full match)
            if match.lastindex:
                try:
                    raw = match.group(match.lastindex)
                except IndexError:
                    pass  # keep raw = match.group(0)

            if not passes_entropy_check(raw, category):
                continue

            evidence = _redact(raw)

            findings.append(Finding(
                url=url,
                vuln_type=name,
                category=category,
                severity=severity,
                description=description,
                evidence=f"{name}: {evidence}",
                confidence=confidence,
                remediation=remediation,
                cvss_score=cvss,
                tags=tags,
            ))

            if len(findings) >= max_findings:
                return findings

    return findings


# URL-based pattern checks (match against the URL string)
_SENSITIVE_URL_PATTERNS: list[tuple] = [
    (
        re.compile(r"(?i)\.env(?:\.|$)"),
        "Exposed .env File",
        VulnCategory.SENSITIVE_FILE,
        Severity.CRITICAL,
        0.95,
        9.8,
        ".env file publicly accessible — likely contains credentials and API keys.",
        "Block access via web server config (deny all to .env files).",
        ["env", "config", "sensitive-file"],
    ),
    (
        re.compile(r"(?i)(wp-config\.php|config\.php|settings\.php|database\.yml|secrets\.yml|credentials\.json|\.npmrc|\.pypirc|\.aws/credentials)"),
        "Exposed Configuration File",
        VulnCategory.SENSITIVE_FILE,
        Severity.CRITICAL,
        0.92,
        9.5,
        "Sensitive configuration file is publicly accessible.",
        "Block access via web server rules. Move secrets to a secrets manager.",
        ["config", "sensitive-file"],
    ),
    (
        re.compile(r"(?i)(/\.git/config|/\.git/HEAD|/\.svn/entries)"),
        "Exposed VCS Repository",
        VulnCategory.SENSITIVE_FILE,
        Severity.HIGH,
        0.98,
        8.8,
        "Version control metadata exposed — source code and history may be recoverable.",
        "Block .git directory via web server rules and audit what was exposed.",
        ["git", "vcs", "source-code"],
    ),
    (
        re.compile(r"(?i)(/backup|/dump|/sql|/db\.sql|/database\.sql|/backup\.zip|/backup\.tar\.gz)"),
        "Possible Backup/Dump File",
        VulnCategory.SENSITIVE_FILE,
        Severity.HIGH,
        0.75,
        8.5,
        "Possible database dump or backup file accessible publicly.",
        "Remove file from public directory. Restrict backup storage.",
        ["backup", "database", "sensitive-file"],
    ),
    (
        re.compile(r"(?i)(/phpinfo\.php|/test\.php|/info\.php|/php_info\.php)"),
        "PHP Info Page Exposed",
        VulnCategory.INFO_DISCLOSURE,
        Severity.MEDIUM,
        0.95,
        5.3,
        "PHP info page reveals server configuration, environment variables, and loaded modules.",
        "Remove phpinfo() pages from production.",
        ["phpinfo", "info-disclosure"],
    ),
    (
        re.compile(r"(?i)/graphql(?:\?|$)"),
        "GraphQL Endpoint (Possible Introspection)",
        VulnCategory.INFO_DISCLOSURE,
        Severity.MEDIUM,
        0.80,
        5.0,
        "GraphQL endpoint may have introspection enabled, leaking full schema.",
        "Disable introspection in production. Add authentication.",
        ["graphql", "api"],
    ),
]


# Body content validators — confirm the response body actually matches the expected file type.
# This prevents false positives from SPA catch-all routing (sites returning HTTP 200 for any URL).
_ENV_CONTENT_RE = re.compile(r"(?m)^(?:export\s+)?[A-Z_][A-Z0-9_]{2,}\s*=", re.MULTILINE)
_GIT_CONFIG_RE  = re.compile(r"\[core\]|\[remote|repositoryformatversion", re.IGNORECASE)
_PHP_CONFIG_RE  = re.compile(r"<\?php|DB_NAME|DB_PASSWORD|define\s*\(", re.IGNORECASE)
_SQL_DUMP_RE    = re.compile(r"CREATE TABLE|INSERT INTO|-- MySQL dump|LOCK TABLES", re.IGNORECASE)
_YAML_CREDS_RE  = re.compile(r"(?m)^\s*(?:password|secret|token|key|database|username)\s*:", re.MULTILINE | re.IGNORECASE)
_JSON_CREDS_RE  = re.compile(r'"(?:password|secret|token|api_key|access_key|private_key)"\s*:', re.IGNORECASE)
_NPMRC_RE       = re.compile(r"//registry\.npmjs\.org|_authToken|_auth\s*=", re.IGNORECASE)

_URL_BODY_VALIDATORS: dict[str, re.Pattern] = {
    "Exposed .env File":          _ENV_CONTENT_RE,
    "Exposed Configuration File": None,   # per-URL logic below
    "Exposed VCS Repository":     _GIT_CONFIG_RE,
    "Possible Backup/Dump File":  _SQL_DUMP_RE,
}


def _validate_body_for_url(name: str, url: str, body: str) -> bool:
    """Return True if body content matches what we expect for this URL pattern."""
    url_lower = url.lower()

    if name == "Exposed .env File":
        return bool(_ENV_CONTENT_RE.search(body))

    if name == "Exposed VCS Repository":
        return bool(_GIT_CONFIG_RE.search(body))

    if name == "Possible Backup/Dump File":
        return bool(_SQL_DUMP_RE.search(body))

    if name == "Exposed Configuration File":
        if "wp-config.php" in url_lower or "config.php" in url_lower or "settings.php" in url_lower:
            return bool(_PHP_CONFIG_RE.search(body))
        if "database.yml" in url_lower or "secrets.yml" in url_lower:
            return bool(_YAML_CREDS_RE.search(body))
        if "credentials.json" in url_lower:
            return bool(_JSON_CREDS_RE.search(body))
        if ".npmrc" in url_lower or ".pypirc" in url_lower:
            return bool(_NPMRC_RE.search(body))
        if ".aws/credentials" in url_lower:
            return bool(re.search(r"aws_access_key_id|aws_secret_access_key", body, re.IGNORECASE))
        return False   # unknown subtype — reject to avoid false positives

    # PHP info, GraphQL — URL match + 200 is sufficient signal
    return True


def scan_url(url: str, body: str = "") -> list[Finding]:
    """Check URL path for sensitive file/endpoint patterns.

    When body is provided (non-empty), validate that the response content
    actually matches the expected file type.  This eliminates false positives
    caused by SPA catch-all routing that returns HTTP 200 for any URL.
    """
    findings: list[Finding] = []
    for compiled_re, name, category, severity, confidence, cvss, description, remediation, tags in _SENSITIVE_URL_PATTERNS:
        if not compiled_re.search(url):
            continue
        # Body validation: skip findings where body doesn't match expected content
        if body and name in _URL_BODY_VALIDATORS:
            if not _validate_body_for_url(name, url, body):
                continue
        findings.append(Finding(
            url=url,
            vuln_type=name,
            category=category,
            severity=severity,
            description=description,
            evidence=f"URL: {url}",
            confidence=confidence,
            remediation=remediation,
            cvss_score=cvss,
            tags=tags,
        ))
    return findings
