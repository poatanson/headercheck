"""Reporters: rich console tables, JSON and Markdown files."""
from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .models import Status, TargetReport

GRADE_STYLE = {"A": "bold green", "B": "green", "C": "yellow", "D": "dark_orange", "F": "bold red",
               "Error": "bold magenta"}
STATUS_STYLE = {Status.PASS: "green", Status.WARN: "yellow", Status.FAIL: "red", Status.ERROR: "magenta"}
CATEGORY_LABEL = {"headers": "Headers", "tls": "TLS"}


def _grade(grade: str) -> Text:
    return Text(grade, style=GRADE_STYLE.get(grade, ""))


def _num(v: float | None) -> str:
    return "-" if v is None else f"{v:g}"


def _cat(r: TargetReport, cat: str) -> Text:
    c = r.categories.get(cat)
    if c is None:
        return Text("-", style="dim")
    return Text.assemble(_grade(c.grade), f" {_num(c.score)}" if c.score is not None else "")


# --------------------------------------------------------------------------- #
# Console
# --------------------------------------------------------------------------- #
def summary_table(reports: list[TargetReport]) -> Table:
    t = Table(title="보안 점검 요약", box=box.ROUNDED, header_style="bold cyan", expand=False)
    for col, kw in (("대상", {}), ("등급", {"justify": "center"}), ("점수", {"justify": "right"}),
                    ("Headers", {}), ("TLS", {}), ("인증서 만료", {"justify": "right"}),
                    ("발급기관", {}), ("프로토콜", {}), ("비고", {"overflow": "fold", "max_width": 48})):
        t.add_column(col, **kw)
    for r in reports:
        cert = r.tls.cert if r.tls else None
        days = "-" if cert is None else Text(f"{cert.days_left}일", style="red" if cert.days_left < 15 else "")
        protos = ", ".join(k.replace("TLSv", "") for k, v in (r.tls.protocols if r.tls else {}).items() if v) or "-"
        note = "; ".join(r.errors) or "; ".join(r.grade_caps)
        t.add_row(r.target, _grade(r.grade), _num(r.score), _cat(r, "headers"), _cat(r, "tls"),
                  days, (cert.issuer_org or cert.issuer) if cert else "-", protos,
                  Text(note, style="magenta" if r.errors else "dim"))
    return t


def detail_panel(r: TargetReport) -> Panel:
    t = Table(box=box.SIMPLE_HEAD, header_style="bold", expand=True)
    t.add_column("분류", width=7)
    t.add_column("항목", min_width=18)
    t.add_column("결과", justify="center", width=6)
    t.add_column("점수", justify="right", width=4)
    t.add_column("값", overflow="fold", max_width=40)
    t.add_column("설명", overflow="fold")
    for c in r.checks:
        t.add_row(CATEGORY_LABEL.get(c.category, c.category), c.name,
                  Text(c.status.value, style=STATUS_STYLE[c.status]), _num(c.score),
                  Text(_truncate(c.value or "-", 120), style="dim"), c.detail)
    parts: list = [t]
    info = []
    if r.http and r.http.final_url and r.http.final_url != r.http.requested_url:
        info.append(f"최종 URL: {r.http.final_url}")
    if r.http and r.http.redirect_chain:
        info.append("리다이렉트: " + " | ".join(r.http.redirect_chain))
    if r.tls and r.tls.negotiated:
        info.append(f"협상: {r.tls.negotiated}")
    for note in (r.http.notes if r.http else []) + (r.tls.notes if r.tls else []):
        info.append(f"참고: {note}")
    for cap in r.grade_caps:
        info.append(f"등급 상한 적용 → {cap}")
    for err in r.errors:
        info.append(f"[magenta]오류: {err}[/magenta]")
    if info:
        parts.append(Text.from_markup("\n".join(_escape(i) if not i.startswith("[magenta]") else i for i in info)))
    title = Text.assemble(f"{r.target}  ", _grade(r.grade), f"  {_num(r.score)}")
    return Panel(Group(*parts), title=title, title_align="left", border_style=GRADE_STYLE.get(r.grade, ""))


def print_console(reports: list[TargetReport], console: Console, details: bool) -> None:
    if details:
        for r in reports:
            console.print(detail_panel(r))
    console.print(summary_table(reports))


def _truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def _escape(s: str) -> str:
    return s.replace("[", r"\[")


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #
def _jsonable(obj):
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_jsonable(v) for v in obj]
    return obj


def to_json(reports: list[TargetReport]) -> dict:
    return {
        "tool": "headercheck",
        "version": __version__,
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": _grade_counts(reports),
        "targets": [_jsonable(asdict(r)) for r in reports],
    }


def write_json(reports: list[TargetReport], path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(to_json(reports), ensure_ascii=False, indent=2), encoding="utf-8")


def _grade_counts(reports: list[TargetReport]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for r in reports:
        counts[r.grade] = counts.get(r.grade, 0) + 1
    return counts


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #
def _md(s: str | None) -> str:
    return (s or "-").replace("|", r"\|").replace("\n", " ")


def to_markdown(reports: list[TargetReport]) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = [f"# 보안 헤더 / TLS 점검 리포트", "",
           f"- 생성: {now} · headercheck {__version__}",
           f"- 대상: {len(reports)}개 · 등급 분포: " + ", ".join(f"{g} {n}" for g, n in sorted(_grade_counts(reports).items())),
           "", "## 요약", "",
           "| 대상 | 등급 | 점수 | Headers | TLS | 인증서 만료 | 발급기관 | 프로토콜 | 비고 |",
           "|---|:-:|--:|---|---|--:|---|---|---|"]
    for r in reports:
        cert = r.tls.cert if r.tls else None
        cats = []
        for cat in ("headers", "tls"):
            c = r.categories.get(cat)
            cats.append("-" if c is None else f"{c.grade} {_num(c.score)}".strip() if c.score is not None else c.grade)
        protos = ", ".join(k for k, v in (r.tls.protocols if r.tls else {}).items() if v) or "-"
        note = "; ".join(r.errors) or "; ".join(r.grade_caps)
        out.append(f"| {_md(r.target)} | **{r.grade}** | {_num(r.score)} | {cats[0]} | {cats[1]} | "
                   f"{f'{cert.days_left}일' if cert else '-'} | {_md(cert.issuer_org or cert.issuer) if cert else '-'} | "
                   f"{protos} | {_md(note)} |")

    for r in reports:
        out += ["", f"## {r.target} — {r.grade} ({_num(r.score)})", ""]
        if r.errors:
            out += [f"> **오류**: {_md(e)}  " for e in r.errors] + [""]
        if r.grade_caps:
            out += [f"- 등급 상한: {_md(c)}" for c in r.grade_caps] + [""]
        if r.http and r.http.final_url:
            out.append(f"- 최종 URL: `{r.http.final_url}` (HTTP {r.http.status_code})")
        if r.http and r.http.redirect_chain:
            out.append(f"- 리다이렉트: {_md(' → '.join(r.http.redirect_chain))}")
        if r.tls and r.tls.cert:
            c = r.tls.cert
            out.append(f"- 인증서: `{_md(c.subject)}` · 발급 `{_md(c.issuer)}` · 만료 {c.not_after[:10]} "
                       f"({c.days_left}일) · {c.key_type} {c.key_bits or ''} · {c.signature_algorithm}")
        if r.tls and r.tls.negotiated:
            out.append(f"- 협상: {r.tls.negotiated}")
        for note in (r.http.notes if r.http else []) + (r.tls.notes if r.tls else []):
            out.append(f"- 참고: {_md(note)}")
        out += ["", "| 분류 | 항목 | 결과 | 점수 | 값 | 설명 |", "|---|---|:-:|--:|---|---|"]
        for c in r.checks:
            out.append(f"| {CATEGORY_LABEL.get(c.category, c.category)} | {c.name} | {c.status.value} | "
                       f"{_num(c.score)} | {_md(_truncate(c.value or '-', 160))} | {_md(c.detail)} |")
    return "\n".join(out) + "\n"


def write_markdown(reports: list[TargetReport], path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(to_markdown(reports), encoding="utf-8")
