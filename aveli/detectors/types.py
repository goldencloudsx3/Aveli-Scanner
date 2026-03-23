"""
Shared data types for the detector layer.

Kept in a separate module so both secrets.py and entropy.py can import
from here without creating a circular dependency.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnCategory(str, Enum):
    EXPOSED_KEY = "Exposed API Key"
    EXPOSED_SECRET = "Exposed Secret/Token"
    PRIVATE_KEY = "Private Key / Certificate"
    CRYPTO_SECRET = "Crypto / Web3 Secret"
    DATABASE_CREDS = "Database Credentials"
    CLOUD_CREDS = "Cloud Provider Credentials"
    PAYMENT_KEY = "Payment Processor Key"
    OAUTH_TOKEN = "OAuth / SSO Token"
    JWT_TOKEN = "JWT Token"
    SENSITIVE_FILE = "Sensitive File Exposure"
    SECURITY_HEADER = "Missing Security Header"
    OPEN_REDIRECT = "Open Redirect"
    INFO_DISCLOSURE = "Information Disclosure"


@dataclass
class Finding:
    url: str
    vuln_type: str
    category: VulnCategory
    severity: Severity
    description: str
    evidence: str           # Redacted snippet of matching content
    confidence: float       # 0.0 - 1.0
    remediation: str
    cvss_score: Optional[float] = None
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "vuln_type": self.vuln_type,
            "category": self.category.value,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "remediation": self.remediation,
            "cvss_score": self.cvss_score,
            "tags": self.tags,
        }
