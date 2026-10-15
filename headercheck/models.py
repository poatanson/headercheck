"""Data models shared by the checkers, scoring and reporters."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Status(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    ERROR = "ERROR"  # could not be measured; excluded from scoring

    @classmethod
    def from_score(cls, score: int) -> "Status":
        if score >= 90:
            return cls.PASS
        if score >= 50:
            return cls.WARN
        return cls.FAIL


@dataclass
class CheckResult:
    id: str
    name: str
    category: str  # "headers" | "tls"
    score: int | None  # 0-100, None when status is ERROR
    status: Status
    value: str | None = None  # raw observed value (header value, issuer, ...)
    detail: str = ""

    @classmethod
    def scored(cls, id: str, name: str, category: str, score: int,
               value: str | None = None, detail: str = "") -> "CheckResult":
        score = max(0, min(100, score))
        return cls(id, name, category, score, Status.from_score(score), value, detail)

    @classmethod
    def error(cls, id: str, name: str, category: str, detail: str) -> "CheckResult":
        return cls(id, name, category, None, Status.ERROR, None, detail)


@dataclass
class HttpResult:
    requested_url: str
    final_url: str | None = None
    status_code: int | None = None
    headers: dict[str, list[str]] = field(default_factory=dict)  # lower-cased name -> values
    redirect_chain: list[str] = field(default_factory=list)
    cert_verified: bool = True
    error: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def is_https(self) -> bool:
        return bool(self.final_url and self.final_url.startswith("https://"))


@dataclass
class CertInfo:
    subject: str
    issuer: str
    issuer_org: str | None
    not_before: str
    not_after: str
    days_left: int
    san: list[str]
    signature_algorithm: str | None
    key_type: str
    key_bits: int | None
    verified: bool | None  # None = could not be verified (no common cipher with local OpenSSL)
    verify_error: str | None = None


@dataclass
class TlsResult:
    host: str
    port: int
    cert: CertInfo | None = None
    protocols: dict[str, bool | None] = field(default_factory=dict)  # None = untestable locally
    weak_ciphers: dict[str, str | bool | None] = field(default_factory=dict)  # group -> accepted suite name | False | None(untestable)
    negotiated: str | None = None  # "TLSv1.3 / TLS_AES_128_GCM_SHA256"
    error: str | None = None
    notes: list[str] = field(default_factory=list)


@dataclass
class CategoryScore:
    score: float | None
    grade: str  # A-F or "Error"


@dataclass
class TargetReport:
    target: str
    host: str
    grade: str
    score: float | None
    categories: dict[str, CategoryScore]
    checks: list[CheckResult]
    grade_caps: list[str]
    errors: list[str]
    http: HttpResult | None
    tls: TlsResult | None
    scanned_at: str
