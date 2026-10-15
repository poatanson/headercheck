"""Async orchestration: many targets concurrently, one TargetReport each."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Callable

import aiohttp

from .headers import USER_AGENT, analyze_headers, fetch_headers
from .models import CheckResult, HttpResult, TargetReport, TlsResult
from .scoring import ERROR_GRADE, score_target
from .targets import Target
from .tls import analyze_tls, collect_tls

HEADER_CHECKS = (("csp", "Content-Security-Policy"), ("hsts", "Strict-Transport-Security"),
                 ("xfo", "X-Frame-Options"), ("xcto", "X-Content-Type-Options"),
                 ("referrer", "Referrer-Policy"), ("permissions", "Permissions-Policy"))


async def scan_target(session: aiohttp.ClientSession, target: Target, *, timeout: float,
                      max_redirects: int, check_headers: bool = True, check_tls: bool = True) -> TargetReport:
    """Scan one target. Never raises: any unexpected failure becomes an Error report."""
    http: HttpResult | None = None
    tls: TlsResult | None = None
    errors: list[str] = []
    checks: list[CheckResult] = []
    try:
        # Headers (aiohttp) and TLS (blocking ssl in a worker thread) run side by side.
        http_task = (fetch_headers(session, target.url, timeout=timeout, max_redirects=max_redirects,
                                   allow_http_fallback="://" not in target.raw)
                     if check_headers else _none())
        tls_task = asyncio.to_thread(collect_tls, target.host, target.port, timeout) if check_tls else _none()
        http, tls = await asyncio.gather(http_task, tls_task)

        if http is not None:
            if http.error:
                errors.append(f"[headers] {http.error}")
                checks += [CheckResult.error(cid, name, "headers", http.error) for cid, name in HEADER_CHECKS]
            else:
                checks += analyze_headers(http.headers, http.is_https)
        if tls is not None:
            if tls.error:
                errors.append(f"[tls] {tls.error}")
            checks += analyze_tls(tls)
    except Exception as exc:  # defensive: a bug must not kill the whole batch
        errors.append(f"[internal] {exc.__class__.__name__}: {exc}")
        return _report(target, ERROR_GRADE, None, {}, checks, [], errors, http, tls)

    fatal = [e for e in errors if "DNS 조회 실패" in e]
    grade, score, categories, caps = score_target(checks, fatal_errors=fatal)
    return _report(target, grade, score, categories, checks, caps, errors, http, tls)


async def _none():
    return None


def _report(target, grade, score, categories, checks, caps, errors, http, tls) -> TargetReport:
    return TargetReport(target=target.raw, host=target.host, grade=grade, score=score,
                        categories=categories, checks=checks, grade_caps=caps, errors=errors,
                        http=http, tls=tls, scanned_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))


async def scan_all(targets: list[Target], *, concurrency: int = 10, timeout: float = 5.0,
                   max_redirects: int = 3, check_headers: bool = True, check_tls: bool = True,
                   on_done: Callable[[TargetReport], None] | None = None) -> list[TargetReport]:
    """Scan every target with at most `concurrency` in flight; results keep input order."""
    sem = asyncio.Semaphore(concurrency)
    connector = aiohttp.TCPConnector(limit=concurrency * 2, ttl_dns_cache=300)
    async with aiohttp.ClientSession(connector=connector, headers={"User-Agent": USER_AGENT}) as session:
        async def one(t: Target) -> TargetReport:
            async with sem:
                report = await scan_target(session, t, timeout=timeout, max_redirects=max_redirects,
                                           check_headers=check_headers, check_tls=check_tls)
            if on_done:
                on_done(report)
            return report

        return list(await asyncio.gather(*(one(t) for t in targets)))
