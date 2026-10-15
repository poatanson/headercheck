"""Command line entry point."""
from __future__ import annotations

import argparse
import asyncio
import sys
from concurrent.futures import ThreadPoolExecutor

from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeElapsedColumn

from . import __version__
from .report import print_console, write_json, write_markdown
from .runner import scan_all
from .scoring import ERROR_GRADE, GRADE_ORDER
from .targets import load_targets


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="headercheck",
        description="웹사이트 HTTP 보안 헤더 + TLS 설정 점검 (A~F 등급)")
    src = p.add_argument_group("대상")
    src.add_argument("-d", "--domain", action="append", default=[], metavar="DOMAIN",
                     help="점검할 도메인 또는 URL (여러 번 지정 가능)")
    src.add_argument("-f", "--file", metavar="PATH", help="도메인/URL 목록 파일 (한 줄에 하나, # 주석 허용)")
    p.add_argument("--json", metavar="PATH", help="JSON 리포트 저장 경로")
    p.add_argument("--md", metavar="PATH", help="Markdown 리포트 저장 경로")
    p.add_argument("-t", "--timeout", type=float, default=5.0, help="연결/요청 타임아웃 초 (기본 5)")
    p.add_argument("-c", "--concurrency", type=int, default=10, help="동시 점검 도메인 수 (기본 10)")
    p.add_argument("--max-redirects", type=int, default=3, help="최대 리다이렉트 횟수 (기본 3)")
    p.add_argument("--only", choices=("headers", "tls"), help="한 카테고리만 점검")
    p.add_argument("-v", "--details", action="store_true",
                   help="도메인별 상세 항목 표 출력 (대상이 1개면 자동)")
    p.add_argument("--fail-under", choices=list(GRADE_ORDER), metavar="GRADE",
                   help="이 등급보다 낮은(또는 Error) 대상이 있으면 종료 코드 1")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console()
    if not args.domain and not args.file:
        console.print("[red]-d 또는 -f로 점검 대상을 지정하세요.[/red] (도움말: -h)")
        return 2
    if args.timeout <= 0 or args.concurrency < 1 or args.max_redirects < 0:
        console.print("[red]timeout > 0, concurrency ≥ 1, max-redirects ≥ 0 이어야 합니다.[/red]")
        return 2
    try:
        targets = load_targets(args.domain, args.file)
    except (OSError, ValueError) as exc:
        console.print(f"[red]대상 로드 실패: {exc}[/red]")
        return 2
    if not targets:
        console.print("[red]점검할 대상이 없습니다.[/red]")
        return 2

    reports = asyncio.run(_run(targets, args, console))

    print_console(reports, console, details=args.details or len(reports) == 1)
    for path, writer in ((args.json, write_json), (args.md, write_markdown)):
        if path:
            try:
                writer(reports, path)
                console.print(f"[green]저장됨:[/green] {path}")
            except OSError as exc:
                console.print(f"[red]저장 실패 {path}: {exc}[/red]")
                return 2

    if args.fail_under:
        limit = GRADE_ORDER.index(args.fail_under)
        if any(r.grade == ERROR_GRADE or GRADE_ORDER.index(r.grade) > limit for r in reports):
            return 1
    return 0


async def _run(targets, args, console: Console):
    # TLS probes are blocking ssl/socket calls run via asyncio.to_thread
    asyncio.get_running_loop().set_default_executor(ThreadPoolExecutor(max_workers=args.concurrency))
    progress = Progress(TextColumn("[cyan]점검 중"), BarColumn(), MofNCompleteColumn(),
                        TextColumn("{task.description}"), TimeElapsedColumn(),
                        console=console, transient=True)
    with progress:
        task = progress.add_task("", total=len(targets))

        def done(r):
            progress.update(task, advance=1, description=f"{r.target} → {r.grade}")

        return await scan_all(targets, concurrency=args.concurrency, timeout=args.timeout,
                              max_redirects=args.max_redirects,
                              check_headers=args.only != "tls", check_tls=args.only != "headers",
                              on_done=done)


if __name__ == "__main__":
    sys.exit(main())
