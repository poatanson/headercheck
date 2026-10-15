from headercheck.models import CheckResult
from headercheck.scoring import ERROR_GRADE, score_target, score_to_grade, weighted_score


def h(id, score):
    return CheckResult.scored(id, id, "headers", score)


def t(id, score, value=None):
    return CheckResult.scored(id, id, "tls", score, value)


def perfect():
    return [h(i, 100) for i in ("csp", "hsts", "xfo", "xcto", "referrer", "permissions")] + \
           [t(i, 100) for i in ("protocols", "ciphers", "cert_trust", "cert_expiry")]


def test_grade_boundaries():
    assert score_to_grade(90) == "A"
    assert score_to_grade(89.9) == "B"
    assert score_to_grade(60) == "D"
    assert score_to_grade(59.9) == "F"


def test_perfect_is_a():
    grade, score, cats, caps = score_target(perfect())
    assert (grade, score, caps) == ("A", 100, [])
    assert cats["headers"].grade == cats["tls"].grade == "A"


def test_weighted_mean_uses_weights():
    checks = [h("csp", 0), h("hsts", 100)]
    assert weighted_score(checks, {"csp": 30, "hsts": 25}) == round(100 * 25 / 55, 1)


def test_error_checks_are_excluded_and_renormalised():
    checks = [h("csp", 100), CheckResult.error("hsts", "hsts", "headers", "boom")]
    assert weighted_score(checks, {"csp": 30, "hsts": 25}) == 100


def test_expired_cert_caps_to_f():
    checks = [c if c.id != "cert_expiry" else t("cert_expiry", 0) for c in perfect()]
    grade, score, _, caps = score_target(checks)
    assert score > 90 and grade == "F"
    assert any("인증서 만료" in c for c in caps)


def test_tls10_caps_to_c():
    checks = [c if c.id != "protocols" else t("protocols", 30) for c in perfect()]
    assert score_target(checks)[0] == "C"


def test_missing_hsts_caps_to_b():
    checks = [c if c.id != "hsts" else h("hsts", 0) for c in perfect()]
    grade, score, _, _ = score_target(checks)
    assert grade == "B"


def test_unmeasurable_category_gives_error_grade():
    checks = [c for c in perfect() if c.category == "headers"] + \
             [CheckResult.error(i, i, "tls", "handshake failed") for i in ("protocols", "ciphers")]
    grade, score, cats, _ = score_target(checks)
    assert grade == ERROR_GRADE and score is None
    assert cats["tls"].grade == ERROR_GRADE
    assert cats["headers"].grade == "A"


def test_fatal_error_gives_error_grade():
    assert score_target(perfect(), fatal_errors=["DNS 실패"])[0] == ERROR_GRADE


def test_single_category_mode():
    checks = [c for c in perfect() if c.category == "headers"]
    grade, score, cats, _ = score_target(checks)
    assert grade == "A" and set(cats) == {"headers"}
