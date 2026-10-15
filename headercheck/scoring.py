"""Weighted scoring and A-F grading.

Each check yields 0-100. Category score = weighted mean of the checks that
could be measured (ERROR checks are dropped and the weights re-normalised).
Overall = weighted mean of the categories. Grade caps then stop a single
critical defect (expired cert, RC4, ...) from being averaged away.
"""
from __future__ import annotations

from .models import CategoryScore, CheckResult, Status

ERROR_GRADE = "Error"

CATEGORY_WEIGHTS: dict[str, float] = {"headers": 0.5, "tls": 0.5}

CHECK_WEIGHTS: dict[str, dict[str, float]] = {
    "headers": {
        "csp": 30,          # main XSS / injection mitigation
        "hsts": 25,         # blocks SSL stripping / downgrade to HTTP
        "xfo": 15,          # clickjacking
        "xcto": 10,         # MIME sniffing
        "referrer": 10,     # URL leakage (browser default is already decent)
        "permissions": 10,  # defence-in-depth for powerful browser features
    },
    "tls": {
        "protocols": 30,    # TLS 1.0/1.1 -> BEAST/POODLE-class downgrade risk
        "ciphers": 30,      # RC4/3DES/NULL break confidentiality outright
        "cert_trust": 25,   # untrusted / mismatched cert = MITM-able
        "cert_expiry": 15,  # outage + warning risk, but a time-bound issue
    },
}

GRADE_THRESHOLDS = [(90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F")]
GRADE_ORDER = "ABCDF"


def score_to_grade(score: float) -> str:
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


def weighted_score(checks: list[CheckResult], weights: dict[str, float]) -> float | None:
    measured = [(c, weights.get(c.id, 0)) for c in checks if c.status is not Status.ERROR and c.score is not None]
    total = sum(w for _, w in measured)
    if total == 0:
        return None
    return round(sum(c.score * w for c, w in measured) / total, 1)


def grade_caps(checks: list[CheckResult]) -> list[tuple[str, str]]:
    """Return (max_grade, reason) for every critical finding."""
    by_id = {c.id: c for c in checks}
    caps: list[tuple[str, str]] = []

    def ok(cid: str) -> CheckResult | None:
        c = by_id.get(cid)
        return c if c and c.status is not Status.ERROR else None

    if (c := ok("cert_expiry")) and c.score == 0:
        caps.append(("F", "인증서 만료"))
    if (c := ok("cert_trust")) and c.score == 0:
        caps.append(("F", f"신뢰할 수 없는 인증서 ({c.detail})"))
    if (c := ok("ciphers")) and c.score == 0:
        caps.append(("F", f"치명적 취약 cipher 허용 ({c.value})"))
    if (c := ok("protocols")):
        if c.score == 0:
            caps.append(("F", "TLS 1.2/1.3 미지원"))
        elif c.score <= 50:
            caps.append(("C", "TLS 1.0/1.1 허용"))
    if (c := ok("ciphers")) and 0 < c.score <= 40:
        caps.append(("C", "3DES cipher 허용"))
    if (c := ok("hsts")) and c.score == 0:
        caps.append(("B", "HSTS 없음/무효"))
    if (c := ok("csp")) and c.score == 0:
        caps.append(("B", "CSP 없음"))
    return caps


def apply_caps(grade: str, caps: list[tuple[str, str]]) -> str:
    worst = max([GRADE_ORDER.index(grade)] + [GRADE_ORDER.index(g) for g, _ in caps])
    return GRADE_ORDER[worst]


def score_target(checks: list[CheckResult], *, fatal_errors: list[str] | None = None
                 ) -> tuple[str, float | None, dict[str, CategoryScore], list[str]]:
    """Return (grade, score, per-category scores, applied cap reasons).

    The overall grade is "Error" when a category could not be measured at all
    (unreachable host, TLS handshake impossible, ...) or `fatal_errors` is set.
    """
    categories: dict[str, CategoryScore] = {}
    for cat, weights in CHECK_WEIGHTS.items():
        cat_checks = [c for c in checks if c.category == cat]
        if not cat_checks:
            continue  # category not run (e.g. --only headers)
        s = weighted_score(cat_checks, weights)
        if s is None:
            categories[cat] = CategoryScore(None, ERROR_GRADE)
        else:
            categories[cat] = CategoryScore(s, apply_caps(score_to_grade(s), grade_caps(cat_checks)))

    if fatal_errors or not categories or any(c.score is None for c in categories.values()):
        return ERROR_GRADE, None, categories, []

    total_w = sum(CATEGORY_WEIGHTS[c] for c in categories)
    overall = round(sum(categories[c].score * CATEGORY_WEIGHTS[c] for c in categories) / total_w, 1)
    caps = grade_caps(checks)
    base = score_to_grade(overall)
    # only report caps that actually lowered the grade
    applied = [f"최대 {g}: {reason}" for g, reason in caps if GRADE_ORDER.index(g) > GRADE_ORDER.index(base)]
    return apply_caps(base, caps), overall, categories, applied
