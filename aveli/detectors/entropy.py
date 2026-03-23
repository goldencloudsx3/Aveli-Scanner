"""
Entropy scoring and placeholder detection for false-positive reduction.

Every regex match from scan_content passes through two gates before
becoming a finding:

1. Shannon entropy  — low-entropy strings are almost certainly fake/template
   values (e.g. "AAAAAAAAAAAAAAAA", "changeme123", "your-api-key-here").

2. Placeholder patterns — known template/example strings that appear in
   documentation, blog posts, and config templates but are not real secrets.

Sensitive-file URL findings (VulnCategory.SENSITIVE_FILE) are exempt —
there is no secret string to measure; the finding is the URL itself.
"""

import math
import re

from .secrets import VulnCategory

# ── Entropy thresholds ────────────────────────────────────────────────────
# Real secrets in these categories must look sufficiently random.
# Threshold is bits-per-character (Shannon entropy). Real API keys / tokens
# typically score 4.0–5.5; placeholder strings like "changeme" score <2.5.
_MIN_ENTROPY_HIGH_VALUE = 3.2
_MIN_ENTROPY_DEFAULT = 2.5

_HIGH_ENTROPY_CATEGORIES = {
    VulnCategory.EXPOSED_KEY,
    VulnCategory.EXPOSED_SECRET,
    VulnCategory.CLOUD_CREDS,
    VulnCategory.PAYMENT_KEY,
    VulnCategory.OAUTH_TOKEN,
    VulnCategory.DATABASE_CREDS,
    VulnCategory.CRYPTO_SECRET,
}

# ── Placeholder patterns ───────────────────────────────────────────────────
_PLACEHOLDER_RES: list[re.Pattern] = [
    # Generic template wording
    re.compile(r"(?i)(your[-_\s]?|my[-_\s]?|example[-_\s]?|sample[-_\s]?|dummy[-_\s]?|fake[-_\s]?)"),
    re.compile(r"(?i)(replace[-_\s]?me|change[-_\s]?me|todo|fixme|placeholder|insert[-_\s]?here)"),
    re.compile(r"(?i)(key[-_\s]?here|secret[-_\s]?here|token[-_\s]?here|api[-_\s]?key[-_\s]?here)"),
    # Common repeated junk sequences
    re.compile(r"(?i)^(x{4,}|0{4,}|1{4,}|a{4,}|f{4,}|9{4,})"),
    re.compile(r"(?i)(123456789|abcdefgh|qwerty|password|letmein)"),
    # Stripe / Square test-mode prefixes — real keys but not live
    re.compile(r"(?i)^(sk_test_|pk_test_|rk_test_|sq0atp_sandbox|sq0csp_sandbox)"),
    # Documentation placeholders
    re.compile(r"(?i)^(test|demo|dev|sandbox|staging|development)[-_]"),
]


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character. Empty string → 0.0."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


def is_placeholder(s: str) -> bool:
    """Return True if the string looks like a template or example value."""
    for pat in _PLACEHOLDER_RES:
        if pat.search(s):
            return True
    # Character repetition check: if one character makes up >60 % of the
    # string, the string is too uniform to be a real secret.
    if len(s) > 8:
        most_freq = max(s.count(c) for c in set(s)) / len(s)
        if most_freq > 0.60:
            return True
    return False


def passes_entropy_check(raw_secret: str, category: VulnCategory) -> bool:
    """
    Return True if the raw matched string should be kept as a finding.

    SENSITIVE_FILE findings are always kept — the finding is the URL itself,
    not a string secret.
    """
    if category == VulnCategory.SENSITIVE_FILE:
        return True

    cleaned = raw_secret.strip().strip("'\"` ")

    # Too short to be real
    if len(cleaned) < 8:
        return False

    if is_placeholder(cleaned):
        return False

    threshold = (
        _MIN_ENTROPY_HIGH_VALUE
        if category in _HIGH_ENTROPY_CATEGORIES
        else _MIN_ENTROPY_DEFAULT
    )
    return shannon_entropy(cleaned) >= threshold
