"""
HTTP Security Header analysis.

Checks for missing or misconfigured security headers that represent
high-impact vulnerabilities.
"""

from .secrets import Finding, VulnCategory, Severity


_REQUIRED_HEADERS: list[tuple] = [
    (
        "Strict-Transport-Security",
        "Missing HSTS Header",
        Severity.HIGH,
        7.4,
        "Without HSTS, users are vulnerable to SSL stripping and downgrade attacks.",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        ["hsts", "tls", "mitm"],
    ),
    (
        "Content-Security-Policy",
        "Missing Content-Security-Policy",
        Severity.HIGH,
        7.2,
        "No CSP header allows XSS attacks to execute arbitrary JavaScript.",
        "Implement a restrictive CSP. Start with: Content-Security-Policy: default-src 'self'",
        ["csp", "xss"],
    ),
    (
        "X-Frame-Options",
        "Missing X-Frame-Options (Clickjacking)",
        Severity.MEDIUM,
        6.1,
        "Without X-Frame-Options the page can be embedded in iframes enabling clickjacking.",
        "Add: X-Frame-Options: DENY (or use CSP frame-ancestors directive).",
        ["clickjacking", "iframe"],
    ),
    (
        "X-Content-Type-Options",
        "Missing X-Content-Type-Options",
        Severity.LOW,
        4.3,
        "Without this header browsers may MIME-sniff responses leading to XSS.",
        "Add: X-Content-Type-Options: nosniff",
        ["mime-sniffing", "xss"],
    ),
    (
        "Permissions-Policy",
        "Missing Permissions-Policy",
        Severity.LOW,
        3.5,
        "No Permissions-Policy header; browser features (camera, mic, geolocation) uncontrolled.",
        "Add a Permissions-Policy header restricting unused browser features.",
        ["permissions", "feature-policy"],
    ),
]

_DANGEROUS_HEADERS: list[tuple] = [
    (
        "Server",
        "Server Version Disclosure",
        Severity.LOW,
        3.7,
        "Server header reveals software and version, aiding fingerprinting.",
        "Configure web server to suppress or genericize the Server header.",
        ["info-disclosure", "fingerprinting"],
    ),
    (
        "X-Powered-By",
        "Technology Fingerprinting via X-Powered-By",
        Severity.LOW,
        3.5,
        "X-Powered-By header discloses backend technology stack.",
        "Remove X-Powered-By header in server/framework configuration.",
        ["info-disclosure", "fingerprinting"],
    ),
]


def scan_headers(url: str, headers: dict[str, str]) -> list[Finding]:
    """Analyze HTTP response headers for security issues."""
    findings: list[Finding] = []
    lower_headers = {k.lower(): v for k, v in headers.items()}

    for header_name, vuln_name, severity, cvss, description, remediation, tags in _REQUIRED_HEADERS:
        if header_name.lower() not in lower_headers:
            findings.append(Finding(
                url=url,
                vuln_type=vuln_name,
                category=VulnCategory.SECURITY_HEADER,
                severity=severity,
                description=description,
                evidence=f"Header '{header_name}' absent from response",
                confidence=1.0,
                remediation=remediation,
                cvss_score=cvss,
                tags=tags,
            ))

    # Check CORS misconfiguration
    acao = lower_headers.get("access-control-allow-origin", "")
    acac = lower_headers.get("access-control-allow-credentials", "")
    if acao == "*" and acac.lower() == "true":
        findings.append(Finding(
            url=url,
            vuln_type="CORS Wildcard + Credentials",
            category=VulnCategory.SECURITY_HEADER,
            severity=Severity.CRITICAL,
            description="CORS is configured with wildcard origin AND credentials=true. "
                        "This is invalid per spec but some browsers/proxies may honor it.",
            evidence="Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
            confidence=1.0,
            remediation="Specify explicit allowed origins. Never combine wildcard with credentials.",
            cvss_score=9.0,
            tags=["cors", "credentials", "api"],
        ))
    elif acao == "*":
        findings.append(Finding(
            url=url,
            vuln_type="CORS Wildcard Origin",
            category=VulnCategory.SECURITY_HEADER,
            severity=Severity.MEDIUM,
            description="CORS allows requests from any origin. Evaluate if this is intentional.",
            evidence="Access-Control-Allow-Origin: *",
            confidence=0.85,
            remediation="Restrict CORS to known trusted origins.",
            cvss_score=5.4,
            tags=["cors", "api"],
        ))

    # Check for verbose server headers
    for header_name, vuln_name, severity, cvss, description, remediation, tags in _DANGEROUS_HEADERS:
        val = lower_headers.get(header_name.lower())
        if val and len(val) > 2:
            findings.append(Finding(
                url=url,
                vuln_type=vuln_name,
                category=VulnCategory.INFO_DISCLOSURE,
                severity=severity,
                description=description,
                evidence=f"{header_name}: {val}",
                confidence=0.9,
                remediation=remediation,
                cvss_score=cvss,
                tags=tags,
            ))

    return findings
