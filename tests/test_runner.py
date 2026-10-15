import asyncio
import json

import pytest

from headercheck import cli, runner
from headercheck.models import HttpResult, TlsResult
from headercheck.targets import load_targets, parse_target

GOOD_HEADERS = {
    "content-security-policy": ["default-src 'none'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'"],
    "strict-transport-security": ["max-age=31536000; includeSubDomains"],
    "x-content-type-options": ["nosniff"],
    "referrer-policy": ["no-referrer"],
    "permissions-policy": ["camera=(), microphone=(), geolocation=(), usb=()"],
}


def good_tls(host, port, timeout):
    from tests.test_tls import make_cert
    from headercheck.tls import parse_certificate
    return TlsResult(host, port,
                     cert=parse_certificate(make_cert(), verified=True),
                     protocols={"TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True},
                     weak_ciphers={"RC4": False, "3DES": False})


@pytest.fixture
def fake_network(monkeypatch):
    calls = {"active": 0, "peak": 0}

    async def fake_fetch(session, url, **kw):
        calls["active"] += 1
        calls["peak"] = max(calls["peak"], calls["active"])
        await asyncio.sleep(0.02)
        calls["active"] -= 1
        if "nxdomain" in url:
            return HttpResult(url, error="DNS 조회 실패 (존재하지 않는 도메인?)")
        if "loop" in url:
            return HttpResult(url, error="리다이렉트 횟수 초과 (최대 3회)")
        return HttpResult(url, final_url=url, status_code=200, headers=GOOD_HEADERS)

    def fake_tls(host, port, timeout):
        if "nxdomain" in host:
            return TlsResult(host, port, error="DNS 조회 실패: nxdomain")
        if "nohandshake" in host:
            return TlsResult(host, port, error="TLS 핸드셰이크 실패: SSLV3_ALERT_HANDSHAKE_FAILURE",
                             protocols={k: False for k in ("TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3")})
        return good_tls(host, port, timeout)

    monkeypatch.setattr(runner, "fetch_headers", fake_fetch)
    monkeypatch.setattr(runner, "collect_tls", fake_tls)
    return calls


def run(targets, **kw):
    return asyncio.run(runner.scan_all([parse_target(t) for t in targets], **kw))


def test_good_site_gets_a(fake_network):
    [r] = run(["good.test"])
    assert r.grade == "A" and r.errors == []


def test_error_cases_do_not_crash_and_are_reported(fake_network):
    reports = run(["good.test", "nxdomain.test", "nohandshake.test", "loop.test"])
    assert [r.target for r in reports] == ["good.test", "nxdomain.test", "nohandshake.test", "loop.test"]
    good, nx, nohs, loop = reports
    assert good.grade == "A"
    for r in (nx, nohs, loop):
        assert r.grade == "Error" and r.score is None and r.errors
    assert any("DNS" in e for e in nx.errors)
    assert any("핸드셰이크" in e for e in nohs.errors)
    assert nohs.categories["headers"].grade == "A"  # the measurable half is still reported
    assert any("리다이렉트" in e for e in loop.errors)


def test_concurrency_limit(fake_network):
    run([f"s{i}.test" for i in range(12)], concurrency=3)
    assert fake_network["peak"] == 3


def test_internal_exception_becomes_error_report(fake_network, monkeypatch):
    def boom(*a):
        raise RuntimeError("unexpected")
    monkeypatch.setattr(runner, "collect_tls", boom)
    [r] = run(["good.test"])
    assert r.grade == "Error" and "RuntimeError" in r.errors[0]


def test_only_headers(fake_network):
    [r] = run(["good.test"], check_tls=False)
    assert set(r.categories) == {"headers"} and r.tls is None


def test_cli_writes_reports_and_fail_under(fake_network, tmp_path):
    lst = tmp_path / "list.txt"
    lst.write_text("# comment\ngood.test\nnxdomain.test  # inline comment\ngood.test\n", encoding="utf-8")
    out_json, out_md = tmp_path / "o" / "r.json", tmp_path / "o" / "r.md"
    code = cli.main(["-f", str(lst), "--json", str(out_json), "--md", str(out_md), "--fail-under", "B"])
    assert code == 1  # nxdomain -> Error
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert [t["target"] for t in data["targets"]] == ["good.test", "nxdomain.test"]  # deduplicated
    assert data["summary"] == {"A": 1, "Error": 1}
    md = out_md.read_text(encoding="utf-8")
    assert "| good.test | **A**" in md and "**오류**" in md


def test_cli_usage_errors(tmp_path):
    assert cli.main([]) == 2
    assert cli.main(["-f", str(tmp_path / "missing.txt")]) == 2


def test_parse_target():
    t = parse_target("Example.com")
    assert (t.host, t.port, t.url) == ("example.com", 443, "https://example.com/")
    t = parse_target("https://example.com:8443/login?x=1")
    assert (t.host, t.port, t.url) == ("example.com", 8443, "https://example.com:8443/login?x=1")
    assert parse_target("http://example.com").port == 443
    assert parse_target("한국.kr").host == "xn--3e0b707e.kr"
    with pytest.raises(ValueError):
        parse_target("ftp://x")


def test_load_targets_dedup(tmp_path):
    f = tmp_path / "l.txt"
    f.write_text("a.com\n\n# x\nhttps://a.com/\n", encoding="utf-8")
    assert [t.url for t in load_targets(["b.com"], str(f))] == ["https://b.com/", "https://a.com/"]
