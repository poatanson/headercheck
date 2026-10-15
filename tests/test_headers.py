import pytest

from headercheck.headers import (analyze_headers, check_csp, check_hsts, check_permissions_policy,
                                 check_referrer_policy, check_xcto, check_xfo, parse_csp)


def hd(**kw):
    return {k.replace("_", "-").lower(): [v] if isinstance(v, str) else v for k, v in kw.items()}


@pytest.mark.parametrize("value,score", [
    ("max-age=31536000; includeSubDomains; preload", 100),
    ("max-age=63072000; includeSubDomains", 100),
    ("max-age=31536000", 90),
    ("max-age=15552000", 70),
    ("max-age=86400", 40),
    ("max-age=300", 20),
    ("max-age=0", 0),
    ("includeSubDomains", 0),           # no max-age -> invalid
    ('max-age="31536000"; includeSubDomains', 100),
    ("max-age=abc", 0),
])
def test_hsts(value, score):
    assert check_hsts(hd(strict_transport_security=value), is_https=True).score == score


def test_hsts_ignored_over_http():
    r = check_hsts(hd(strict_transport_security="max-age=31536000"), is_https=False)
    assert r.score == 0 and "HTTPS" in r.detail


def test_hsts_missing():
    assert check_hsts({}, is_https=True).score == 0


@pytest.mark.parametrize("csp,score", [
    ("default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'self'", 100),
    ("default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'", 60),
    ("script-src 'self' 'unsafe-inline' 'nonce-abc'; object-src 'none'; base-uri 'none'", 100),
    ("default-src 'self' 'unsafe-eval'; object-src 'none'; base-uri 'none'", 80),
    ("default-src *; base-uri 'none'", 60),     # wildcard -30, object-src not none -10
    ("upgrade-insecure-requests", 45),          # no script restriction -40, object -10, base-uri -5
])
def test_csp(csp, score):
    assert check_csp(hd(content_security_policy=csp)).score == score


def test_csp_report_only_and_missing():
    assert check_csp(hd(content_security_policy_report_only="default-src 'self'")).score == 30
    assert check_csp({}).score == 0


def test_parse_csp_multiple_headers():
    d = parse_csp(["default-src 'self'", "script-src 'none'; frame-ancestors 'none'"])
    assert d["default-src"] == ["'self'"] and d["frame-ancestors"] == ["'none'"]


@pytest.mark.parametrize("value,score", [("DENY", 100), ("sameorigin", 100),
                                         ("ALLOW-FROM https://a.com", 30), ("bogus", 0)])
def test_xfo(value, score):
    assert check_xfo(hd(x_frame_options=value)).score == score


def test_xfo_satisfied_by_frame_ancestors():
    assert check_xfo({}, {"frame-ancestors": ["'self'"]}).score == 100
    assert check_xfo({}).score == 0


def test_xcto():
    assert check_xcto(hd(x_content_type_options="nosniff")).score == 100
    assert check_xcto(hd(x_content_type_options="sniff")).score == 0
    assert check_xcto({}).score == 0


@pytest.mark.parametrize("value,score", [
    ("strict-origin-when-cross-origin", 100), ("no-referrer", 100),
    ("origin", 70), ("no-referrer-when-downgrade", 40), ("unsafe-url", 0),
    ("unsafe-url, strict-origin", 100),   # last known policy wins
    ("whatever", 50),
])
def test_referrer(value, score):
    assert check_referrer_policy(hd(referrer_policy=value)).score == score


def test_referrer_missing_uses_browser_default():
    assert check_referrer_policy({}).score == 50


@pytest.mark.parametrize("value,score", [
    ("camera=(), microphone=(), geolocation=(), payment=()", 100),
    ("camera=(), microphone=()", 80),
    ("interest-cohort=()", 60),
    ("camera=*", 40),
])
def test_permissions_policy(value, score):
    assert check_permissions_policy(hd(permissions_policy=value)).score == score


def test_permissions_policy_legacy_and_missing():
    assert check_permissions_policy(hd(feature_policy="camera 'none'")).score == 40
    assert check_permissions_policy({}).score == 0


def test_analyze_headers_returns_six_checks():
    ids = [c.id for c in analyze_headers({}, is_https=True)]
    assert ids == ["csp", "hsts", "xfo", "xcto", "referrer", "permissions"]
