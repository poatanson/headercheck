"""Input normalisation: domains / URLs / list files -> Target."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Target:
    raw: str
    host: str
    port: int
    url: str


def parse_target(raw: str) -> Target:
    raw = raw.strip()
    if not raw:
        raise ValueError("빈 대상")
    url = raw if "://" in raw else f"https://{raw}"
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"잘못된 대상: {raw!r}")
    host = parts.hostname.encode("idna").decode("ascii")
    # TLS is always probed on 443 unless an explicit https port was given
    port = parts.port if (parts.scheme == "https" and parts.port) else 443
    path = parts.path or "/"
    netloc = host if parts.port is None else f"{host}:{parts.port}"
    query = f"?{parts.query}" if parts.query else ""
    return Target(raw=raw, host=host, port=port, url=f"{parts.scheme}://{netloc}{path}{query}")


def load_targets(domains: list[str], file: str | None) -> list[Target]:
    raws = list(domains)
    if file:
        for line in Path(file).read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                raws.append(line)
    seen: set[str] = set()
    targets: list[Target] = []
    for raw in raws:
        t = parse_target(raw)
        if t.url not in seen:
            seen.add(t.url)
            targets.append(t)
    return targets
