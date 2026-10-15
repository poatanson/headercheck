"""HTTP security header collection (aiohttp) and analysis (pure functions)."""
from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin

import aiohttp

from .models import CheckResult, HttpResult

CATEGORY = "headers"
USER_AGENT = "headercheck/1.0 (+security header & TLS audit)"
REDIRECT_CODES = {301, 302, 303, 307, 308}


# --------------------------------------------------------------------------- #
# Collection
# --------------------------------------------------------------------------- #
async def fetch_headers(session: aiohttp.ClientSession, url: str, *, timeout: float = 5.0,
                        max_redirects: int = 3, allow_http_fallback: bool = False) -> HttpResult:
    """GET `url`, following up to `max_redirects` redirects by hand.

    Never raises: network problems end up in `HttpResult.error`.
    """
    result = HttpResult(requested_url=url)
    try:
        await _follow(session, url, result, timeout, max_redirects)
    except aiohttp.ClientConnectorDNSError:
        result.error = "DNS 조회 실패 (존재하지 않는 도메인?)"
    except (aiohttp.ClientConnectorError, aiohttp.ClientSSLError, aiohttp.ServerDisconnectedError,
            TimeoutError, asyncio.TimeoutError) as exc:
        if allow_http_fallback and url.startswith("https://") and not result.redirect_chain:
            fallback = await fetch_headers(session, "http://" + url[len("https://"):],
                                           timeout=timeout, max_redirects=max_redirects)
            fallback.requested_url = url
            fallback.notes.insert(0, f"HTTPS 연결 실패({_describe(exc)}) → HTTP로 폴백")
            return fallback
        result.error = f"HTTP 요청 실패: {_describe(exc)}"
    except aiohttp.ClientError as exc:
        result.error = f"HTTP 요청 실패: {_describe(exc)}"
    return result


async def _follow(session: aiohttp.ClientSession, url: str, result: HttpResult,
                  timeout: float, max_redirects: int) -> None:
    client_timeout = aiohttp.ClientTimeout(total=timeout)
    visited: set[str] = set()
    current = url
    while True:
        if current in visited:
            result.error = f"리다이렉트 루프 감지: {current}"
            return
        visited.add(current)
        try:
            resp_ctx = session.get(current, allow_redirects=False, timeout=client_timeout,
                                   ssl=True if result.cert_verified else False)
            async with resp_ctx as resp:
                status, headers, location = resp.status, resp.headers, resp.headers.get("Location")
        except aiohttp.ClientConnectorCertificateError as exc:
            if not result.cert_verified:
                raise
            # Keep going without verification so headers are still reported;
            # the TLS checker scores the certificate problem itself.
            result.cert_verified = False
            result.notes.append(f"인증서 검증 실패 상태에서 헤더 수집: {_describe(exc)}")
            visited.discard(current)
            continue

        result.final_url = current
        result.status_code = status
        result.headers = _multidict_to_lists(headers)
        if status in REDIRECT_CODES and location:
            if len(result.redirect_chain) >= max_redirects:
                result.error = f"리다이렉트 횟수 초과 (최대 {max_redirects}회)"
                return
            nxt = urljoin(current, location)
            if current.startswith("https://") and nxt.startswith("http://"):
                result.notes.append(f"HTTPS → HTTP 다운그레이드 리다이렉트: {nxt}")
            result.redirect_chain.append(f"{status} {current} -> {nxt}")
            current = nxt
            continue
        return


def _multidict_to_lists(headers) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for k, v in headers.items():
        out.setdefault(k.lower(), []).append(v)
    return out


def _describe(exc: BaseException) -> str:
    if isinstance(exc, (TimeoutError, asyncio.TimeoutError)):
        return "타임아웃"
    if isinstance(exc, aiohttp.ClientConnectorError):
        os_err = exc.os_error
        reason = getattr(os_err, "reason", None) or getattr(os_err, "verify_message", None)             or os_err.strerror or str(os_err)
        return f"{exc.host}:{exc.port} 연결 실패 ({reason})"
    msg = str(exc) or exc.__class__.__name__
    return f"{exc.__class__.__name__}: {msg}"[:300]


# --------------------------------------------------------------------------- #
# Analysis (pure functions: headers dict -> CheckResult)
# --------------------------------------------------------------------------- #
def analyze_headers(headers: dict[str, list[str]], is_https: bool) -> list[CheckResult]:
    csp = parse_csp(headers.get("content-security-policy", []))
    return [
        check_csp(headers),
        check_hsts(headers, is_https),
        check_xfo(headers, csp),
        check_xcto(headers),
        check_referrer_policy(headers),
        check_permissions_policy(headers),
    ]


def parse_csp(values: list[str]) -> dict[str, list[str]]:
    """Merge one or more CSP header values into {directive: [sources]}.

    Multiple policies are all enforced by browsers; for scoring we keep the
    first occurrence of each directive which is a reasonable approximation.
    """
    directives: dict[str, list[str]] = {}
    for value in values:
        for policy in value.split(","):
            for part in policy.split(";"):
                tokens = part.strip().split()
                if tokens:
                    directives.setdefault(tokens[0].lower(), [t for t in tokens[1:]])
    return directives


_NONCE_OR_HASH = re.compile(r"^'(nonce-|sha256-|sha384-|sha512-)", re.I)


def check_csp(headers: dict[str, list[str]]) -> CheckResult:
    name = "Content-Security-Policy"
    values = headers.get("content-security-policy", [])
    if not values:
        report_only = headers.get("content-security-policy-report-only")
        if report_only:
            return CheckResult.scored("csp", name, CATEGORY, 30, report_only[0],
                                      "Report-Only 모드만 존재 (차단하지 않음)")
        return CheckResult.scored("csp", name, CATEGORY, 0, None, "헤더 없음")

    d = parse_csp(values)
    score, issues = 100, []
    script = d.get("script-src", d.get("default-src"))
    if script is None:
        score -= 40
        issues.append("script-src/default-src 없음 (스크립트 제한 없음)")
    else:
        lowered = [s.lower() for s in script]
        has_nonce_hash = any(_NONCE_OR_HASH.match(s) for s in script)
        if "'unsafe-inline'" in lowered and not has_nonce_hash:
            score -= 40
            issues.append("script에 'unsafe-inline' 허용")
        if "'unsafe-eval'" in lowered:
            score -= 20
            issues.append("script에 'unsafe-eval' 허용")
        broad = [s for s in lowered if s in ("*", "http:", "https:", "data:")]
        if broad:
            score -= 30
            issues.append(f"script에 광범위한 소스 허용: {' '.join(broad)}")
    obj = d.get("object-src", d.get("default-src"))
    if obj is None or [s.lower() for s in obj] != ["'none'"]:
        score -= 10
        issues.append("object-src 'none' 아님")
    if "base-uri" not in d:
        score -= 5
        issues.append("base-uri 미지정")
    if len(values) > 1:
        issues.append(f"CSP 헤더 {len(values)}개 (모두 적용됨)")
    return CheckResult.scored("csp", name, CATEGORY, score, "; ".join(values)[:500],
                              "; ".join(issues) or "양호")


def check_hsts(headers: dict[str, list[str]], is_https: bool) -> CheckResult:
    name = "Strict-Transport-Security"
    values = headers.get("strict-transport-security", [])
    if not is_https:
        return CheckResult.scored("hsts", name, CATEGORY, 0, values[0] if values else None,
                                  "HTTPS 응답이 아니어서 HSTS 무효")
    if not values:
        return CheckResult.scored("hsts", name, CATEGORY, 0, None, "헤더 없음")

    value = values[0]
    params = {p.split("=", 1)[0].strip().lower(): (p.split("=", 1)[1].strip().strip('"') if "=" in p else "")
              for p in value.split(";") if p.strip()}
    if "max-age" not in params:
        return CheckResult.scored("hsts", name, CATEGORY, 0, value, "max-age 누락 → 무효")
    try:
        max_age = int(params["max-age"])
    except ValueError:
        return CheckResult.scored("hsts", name, CATEGORY, 0, value, "max-age 값 파싱 불가")

    sub, preload = "includesubdomains" in params, "preload" in params
    days = max_age // 86400
    if max_age <= 0:
        score, msg = 0, "max-age=0 (HSTS 해제)"
    elif max_age >= 31536000:
        score, msg = (100, f"max-age {days}일") if sub else (90, f"max-age {days}일, includeSubDomains 없음")
    elif max_age >= 15552000:
        score, msg = 70, f"max-age {days}일 (1년 미만)"
    elif max_age >= 86400:
        score, msg = 40, f"max-age {days}일 (180일 미만)"
    else:
        score, msg = 20, f"max-age {max_age}초 (너무 짧음)"
    if preload:
        msg += ", preload"
    if len(values) > 1:
        msg += f" (헤더 {len(values)}개 중복)"
    return CheckResult.scored("hsts", name, CATEGORY, score, value, msg)


def check_xfo(headers: dict[str, list[str]], csp: dict[str, list[str]] | None = None) -> CheckResult:
    name = "X-Frame-Options"
    values = headers.get("x-frame-options", [])
    frame_ancestors = (csp or {}).get("frame-ancestors")
    if frame_ancestors is not None:
        return CheckResult.scored("xfo", name, CATEGORY, 100,
                                  values[0] if values else None,
                                  f"CSP frame-ancestors로 보호됨 ({' '.join(frame_ancestors) or '빈 값'})")
    if not values:
        return CheckResult.scored("xfo", name, CATEGORY, 0, None, "헤더 없음 (frame-ancestors도 없음)")
    v = values[0].strip().upper()
    if v in ("DENY", "SAMEORIGIN"):
        return CheckResult.scored("xfo", name, CATEGORY, 100, values[0], "양호")
    if v.startswith("ALLOW-FROM"):
        return CheckResult.scored("xfo", name, CATEGORY, 30, values[0],
                                  "ALLOW-FROM은 최신 브라우저가 무시함 → frame-ancestors 권장")
    return CheckResult.scored("xfo", name, CATEGORY, 0, values[0], "알 수 없는 값")


def check_xcto(headers: dict[str, list[str]]) -> CheckResult:
    name = "X-Content-Type-Options"
    values = headers.get("x-content-type-options", [])
    if not values:
        return CheckResult.scored("xcto", name, CATEGORY, 0, None, "헤더 없음")
    if values[0].strip().lower() == "nosniff":
        return CheckResult.scored("xcto", name, CATEGORY, 100, values[0], "양호")
    return CheckResult.scored("xcto", name, CATEGORY, 0, values[0], "값이 nosniff가 아님")


_REFERRER_SCORES = {
    "no-referrer": 100, "same-origin": 100, "strict-origin": 100,
    "strict-origin-when-cross-origin": 100,
    "origin": 70, "origin-when-cross-origin": 70,
    "no-referrer-when-downgrade": 40,
    "unsafe-url": 0,
}


def check_referrer_policy(headers: dict[str, list[str]]) -> CheckResult:
    name = "Referrer-Policy"
    values = headers.get("referrer-policy", [])
    if not values:
        return CheckResult.scored("referrer", name, CATEGORY, 50, None,
                                  "헤더 없음 (브라우저 기본값 strict-origin-when-cross-origin 적용)")
    # Browsers use the last policy they understand in a comma-separated list.
    tokens = [t.strip().lower() for v in values for t in v.split(",") if t.strip()]
    known = [t for t in tokens if t in _REFERRER_SCORES]
    if not known:
        return CheckResult.scored("referrer", name, CATEGORY, 50, ", ".join(values), "알 수 없는 값 → 기본값 적용")
    policy = known[-1]
    score = _REFERRER_SCORES[policy]
    detail = "양호" if score == 100 else f"{policy}: 교차 출처로 URL 정보 노출"
    return CheckResult.scored("referrer", name, CATEGORY, score, ", ".join(values), detail)


SENSITIVE_FEATURES = ("camera", "microphone", "geolocation", "payment", "usb")


def check_permissions_policy(headers: dict[str, list[str]]) -> CheckResult:
    name = "Permissions-Policy"
    values = headers.get("permissions-policy", [])
    if not values:
        if headers.get("feature-policy"):
            return CheckResult.scored("permissions", name, CATEGORY, 40, headers["feature-policy"][0],
                                      "레거시 Feature-Policy만 존재")
        return CheckResult.scored("permissions", name, CATEGORY, 0, None, "헤더 없음")

    policy: dict[str, str] = {}
    for v in values:
        for item in v.split(","):
            if "=" in item:
                k, _, allow = item.partition("=")
                policy.setdefault(k.strip().lower(), allow.strip())
    restricted, wildcard = [], []
    for feat in SENSITIVE_FEATURES:
        allow = policy.get(feat)
        if allow is None:
            continue
        if allow == "*":
            wildcard.append(feat)
        elif allow in ("()", "(self)", "self"):
            restricted.append(feat)
    score = min(100, 60 + 10 * len(restricted)) - 20 * len(wildcard)
    detail = f"민감 기능 제한: {', '.join(restricted) or '없음'}"
    if wildcard:
        detail += f"; 전체 허용(*): {', '.join(wildcard)}"
    return CheckResult.scored("permissions", name, CATEGORY, score, ", ".join(values)[:500], detail)
