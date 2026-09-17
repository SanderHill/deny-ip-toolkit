#!/usr/bin/env python3
"""Combine licensed local or remote IP lists into one normalized local file."""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import tempfile
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path


USER_AGENT = "deny-ip-toolkit/1.0"
DEFAULT_TIMEOUT = 60


class SourceError(RuntimeError):
    """Raised when a configured input source cannot be processed safely."""


def source_name(source: str) -> str:
    parsed = urllib.parse.urlparse(source)
    if parsed.scheme in {"http", "https"}:
        return Path(parsed.path).name or "download"
    return Path(source).name


def read_source(source: str, target_dir: Path, timeout: int) -> Path:
    parsed = urllib.parse.urlparse(source)
    if parsed.scheme in {"http", "https"}:
        destination = target_dir / source_name(source)
        request = urllib.request.Request(source, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                destination.write_bytes(response.read())
        except OSError as exc:
            raise SourceError(f"could not download {source}: {exc}") from exc
        return destination
    if parsed.scheme:
        raise SourceError(f"unsupported source scheme: {parsed.scheme}")
    path = Path(source).expanduser()
    if not path.is_file():
        raise SourceError(f"local source does not exist: {path}")
    return path


def candidate_files(source: Path, extract_dir: Path) -> list[Path]:
    if not zipfile.is_zipfile(source):
        return [source]
    extract_dir.mkdir(parents=True, exist_ok=True)
    root = extract_dir.resolve()
    with zipfile.ZipFile(source) as archive:
        for member in archive.infolist():
            target = (extract_dir / member.filename).resolve()
            if target != root and root not in target.parents:
                raise SourceError("ZIP contains an unsafe path")
        archive.extractall(extract_dir)
    return [path for path in extract_dir.rglob("*") if path.is_file()]


def extract_addresses(paths: list[Path]) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for path in paths:
        text = path.read_text(encoding="utf-8-sig", errors="ignore")
        for token in re.findall(r"(?<![\w.:])(?:[0-9A-Fa-f:.]+)(?![\w.:])", text):
            try:
                addresses.add(ipaddress.ip_address(token.strip(".:") or token))
            except ValueError:
                continue
    return addresses


def normalize(sources: list[str], output: Path, timeout: int = DEFAULT_TIMEOUT) -> int:
    if not sources:
        raise SourceError("configure at least one source")
    addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    with tempfile.TemporaryDirectory(prefix="deny-ip-toolkit-") as folder:
        workdir = Path(folder)
        for index, source in enumerate(sources):
            downloaded = read_source(source, workdir, timeout)
            paths = candidate_files(downloaded, workdir / f"source-{index}")
            addresses.update(extract_addresses(paths))
    if not addresses:
        raise SourceError("configured sources contained no valid IP addresses")
    ordered = sorted(addresses, key=lambda address: (address.version, int(address)))
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=output.parent, delete=False
    ) as handle:
        handle.write("\n".join(str(address) for address in ordered) + "\n")
        temporary = Path(handle.name)
    temporary.replace(output)
    return len(ordered)


def configured_sources(cli_sources: list[str]) -> list[str]:
    environment_sources = [
        line.strip() for line in os.getenv("SOURCE_URLS", "").splitlines() if line.strip()
    ]
    return [*cli_sources, *environment_sources]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", action="append", default=[])
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(os.getenv("OUTPUT_FILE", "./output/deny-ip-list.txt")),
    )
    parser.add_argument(
        "--timeout", type=int, default=int(os.getenv("HTTP_TIMEOUT", str(DEFAULT_TIMEOUT)))
    )
    args = parser.parse_args()
    try:
        count = normalize(configured_sources(args.source), args.output, args.timeout)
    except SourceError as exc:
        parser.error(str(exc))
    print(f"wrote {count} unique addresses to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

