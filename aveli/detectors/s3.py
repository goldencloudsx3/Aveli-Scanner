"""
AWS S3 bucket misconfiguration detector.

Checks S3 bucket responses for:
  - Publicly listable buckets (ListBucketResult XML response)
  - Sensitive files exposed in public bucket listings
  - Publicly readable buckets containing data

Only fires on URLs whose hostname matches *.s3.amazonaws.com or the
path-style endpoint s3.amazonaws.com/<bucket>.
"""

import re
from typing import Optional

from .types import Finding, Severity, VulnCategory

# Hostnames we recognise as S3 endpoints
_S3_VHOST_RE = re.compile(
    r"^(?P<bucket>[a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9])\.s3[.\-]"
    r"(?:[a-z0-9\-]+\.)?amazonaws\.com$",
    re.IGNORECASE,
)
_S3_PATH_RE = re.compile(
    r"^s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com/(?P<bucket>[^/?#]+)",
    re.IGNORECASE,
)

# Filename patterns that indicate high-value data inside a bucket listing
_SENSITIVE_KEY_RE = re.compile(
    r"<Key>([^<]*"
    r"(?:\.env|\.pem|\.key|\.p12|\.pfx|id_rsa|id_ecdsa|id_ed25519"
    r"|credentials|secrets?|password|passwd|shadow|\.aws|config\.json"
    r"|database\.yml|backup|dump\.sql|\.npmrc|\.htpasswd"
    r"|private[_\-]?key|access[_\-]?key|secret[_\-]?key"
    r"|token|api[_\-]?key)[^<]*)"
    r"</Key>",
    re.IGNORECASE,
)

# Broad pattern to confirm this is an S3 listing response
_LIST_BUCKET_RE = re.compile(r"<ListBucketResult", re.IGNORECASE)


def _extract_bucket(url: str) -> Optional[str]:
    """Return the bucket name from a virtual-hosted or path-style S3 URL."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    m = _S3_VHOST_RE.match(parsed.netloc)
    if m:
        return m.group("bucket")
    m = _S3_PATH_RE.match(parsed.netloc + parsed.path)
    if m:
        return m.group("bucket")
    return None


def is_s3_url(url: str) -> bool:
    """Return True if the URL points to an S3 endpoint."""
    return _extract_bucket(url) is not None


def scan_s3_response(
    url: str,
    body: Optional[str],
    status: int,
) -> list[Finding]:
    """
    Analyse an S3 response for misconfiguration findings.

    Returns an empty list if the URL is not an S3 endpoint or if no
    misconfiguration is detected.
    """
    if not is_s3_url(url):
        return []

    bucket = _extract_bucket(url) or url
    findings: list[Finding] = []

    if status == 200 and body and _LIST_BUCKET_RE.search(body):
        # Bucket listing is publicly accessible
        sensitive_keys = _SENSITIVE_KEY_RE.findall(body)

        if sensitive_keys:
            preview = ", ".join(sensitive_keys[:5])
            if len(sensitive_keys) > 5:
                preview += f" … (+{len(sensitive_keys) - 5} more)"
            findings.append(Finding(
                url=url,
                vuln_type="Public S3 Bucket with Sensitive Files",
                category=VulnCategory.S3_MISCONFIGURATION,
                severity=Severity.CRITICAL,
                description=(
                    f"S3 bucket '{bucket}' is publicly listable AND contains "
                    f"files with sensitive-sounding names. Attackers can download "
                    f"credentials, keys, or configuration files directly."
                ),
                evidence=f"Sensitive keys: {preview}",
                confidence=0.97,
                remediation=(
                    "1. Immediately set bucket ACL to private. "
                    "2. Enable S3 Block Public Access at the account level. "
                    "3. Rotate any exposed credentials found in the bucket. "
                    "4. Enable S3 server access logging and review past access."
                ),
                cvss_score=10.0,
                tags=["aws", "s3", "public-bucket", "sensitive-files", "cloud"],
            ))
        else:
            # Listing exposed but no obviously sensitive filenames detected
            findings.append(Finding(
                url=url,
                vuln_type="Publicly Listable S3 Bucket",
                category=VulnCategory.S3_MISCONFIGURATION,
                severity=Severity.HIGH,
                description=(
                    f"S3 bucket '{bucket}' allows public listing of all objects. "
                    f"Attackers can enumerate every file stored in this bucket."
                ),
                evidence="HTTP 200 with <ListBucketResult> XML response body",
                confidence=0.99,
                remediation=(
                    "Enable S3 Block Public Access on the bucket and account. "
                    "Review bucket policy and ACLs. Audit stored objects for "
                    "sensitive content."
                ),
                cvss_score=7.5,
                tags=["aws", "s3", "public-bucket", "cloud"],
            ))

    elif status == 200 and body and "amazonaws.com" in url:
        # 200 on a bucket root without ListBucketResult can mean the bucket
        # serves a static website — still worth noting but lower severity
        if body.strip().startswith("<?xml") and "<Error>" not in body:
            findings.append(Finding(
                url=url,
                vuln_type="Publicly Accessible S3 Bucket",
                category=VulnCategory.S3_MISCONFIGURATION,
                severity=Severity.MEDIUM,
                description=(
                    f"S3 bucket '{bucket}' returns HTTP 200 without a bucket "
                    f"listing, but appears publicly accessible. Objects may be "
                    f"directly readable if their ACLs allow it."
                ),
                evidence="HTTP 200 on S3 bucket root; no listing but accessible",
                confidence=0.70,
                remediation=(
                    "Review bucket policy and object ACLs. Enable S3 Block "
                    "Public Access unless public hosting is intentional."
                ),
                cvss_score=5.3,
                tags=["aws", "s3", "public-bucket", "cloud"],
            ))

    return findings
