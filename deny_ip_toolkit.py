#!/usr/bin/env python3
"""Combine licensed local or remote IP lists into one normalized local file."""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import stat
import tempfile
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path


USER_AGENT = "deny-ip-toolkit/1.0"
DEFAULT_TIMEOUT = 60
DEFAULT_MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024
DEFAULT_MAX_ZIP_MEMBERS = 1_000
DEFAULT_MAX_ZIP_MEMBER_BYTES = 25 * 1024 * 1024
DEFAULT_MAX_ZIP_TOTAL_BYTES = 100 * 1024 * 1024
DEFAULT_MAX_ZIP_COMPRESSION_RATIO = 100.0
COPY_CHUNK_BYTES = 64 * 1024
__version__ = "0.1.0"


class SourceError(RuntimeError):
    """Raised when a configured input source cannot be processed safely."""


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def source_name(source: str) -> str:
    parsed = urllib.parse.urlparse(source)
    if parsed.scheme in {"http", "https"}:
        return Path(parsed.path).name or "download"
    return Path(source).name


def read_source(
    source: str,
    target_dir: Path,
    timeout: int,
    max_download_bytes: int = DEFAULT_MAX_DOWNLOAD_BYTES,
) -> Path:
    parsed = urllib.parse.urlparse(source)
    if parsed.scheme in {"http", "https"}:
        destination = target_dir / source_name(source)
        request = urllib.request.Request(source, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                content_length = response.headers.get("Content-Length")
                if content_length is not None:
                    try:
                        declared_size = int(content_length)
                    except ValueError as exc:
                        raise SourceError("remote source has an invalid Content-Length") from exc
                    if declared_size < 0:
                        raise SourceError("remote source has an invalid Content-Length")
                    if declared_size > max_download_bytes:
                        raise SourceError(
                            f"remote source exceeds the {max_download_bytes}-byte download limit"
                        )
                downloaded = 0
                with destination.open("wb") as handle:
                    while chunk := response.read(COPY_CHUNK_BYTES):
                        downloaded += len(chunk)
                        if downloaded > max_download_bytes:
                            raise SourceError(
                                f"remote source exceeds the {max_download_bytes}-byte download limit"
                            )
                        handle.write(chunk)
        except OSError as exc:
            raise SourceError(f"could not download {source}: {exc}") from exc
        return destination
    if parsed.scheme:
        raise SourceError(f"unsupported source scheme: {parsed.scheme}")
    path = Path(source).expanduser()
    if not path.is_file():
        raise SourceError(f"local source does not exist: {path}")
    return path


def candidate_files(
    source: Path,
    extract_dir: Path,
    max_members: int = DEFAULT_MAX_ZIP_MEMBERS,
    max_member_bytes: int = DEFAULT_MAX_ZIP_MEMBER_BYTES,
    max_total_bytes: int = DEFAULT_MAX_ZIP_TOTAL_BYTES,
    max_compression_ratio: float = DEFAULT_MAX_ZIP_COMPRESSION_RATIO,
) -> list[Path]:
    if not zipfile.is_zipfile(source):
        return [source]
    extract_dir.mkdir(parents=True, exist_ok=True)
    root = extract_dir.resolve()
    with zipfile.ZipFile(source) as archive:
        members = [member for member in archive.infolist() if not member.is_dir()]
        if len(members) > max_members:
            raise SourceError(f"ZIP exceeds the {max_members}-member limit")
        total_size = 0
        for member in members:
            target = (extract_dir / member.filename).resolve()
            if target != root and root not in target.parents:
                raise SourceError("ZIP contains an unsafe path")
            if stat.S_ISLNK(member.external_attr >> 16):
                raise SourceError("ZIP contains a symbolic link")
            if member.flag_bits & 0x1:
                raise SourceError("ZIP contains an encrypted member")
            if member.file_size > max_member_bytes:
                raise SourceError(
                    f"ZIP member exceeds the {max_member_bytes}-byte limit"
                )
            total_size += member.file_size
            if total_size > max_total_bytes:
                raise SourceError(
                    f"ZIP exceeds the {max_total_bytes}-byte expanded-size limit"
                )
            if member.file_size and member.compress_size == 0:
                raise SourceError("ZIP member has an invalid compression ratio")
            ratio = member.file_size / max(member.compress_size, 1)
            if ratio > max_compression_ratio:
                raise SourceError(
                    f"ZIP member exceeds the {max_compression_ratio:g}:1 compression-ratio limit"
                )

        for member in members:
            target = (extract_dir / member.filename).resolve()
            target.parent.mkdir(parents=True, exist_ok=True)
            extracted = 0
            with (
                archive.open(member) as source_handle,
                target.open("wb") as target_handle,
            ):
                while chunk := source_handle.read(COPY_CHUNK_BYTES):
                    extracted += len(chunk)
                    if extracted > max_member_bytes or extracted > member.file_size:
                        raise SourceError("ZIP member expanded beyond its declared size")
                    target_handle.write(chunk)
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


def normalize(
    sources: list[str],
    output: Path,
    timeout: int = DEFAULT_TIMEOUT,
    max_download_bytes: int = DEFAULT_MAX_DOWNLOAD_BYTES,
    max_zip_members: int = DEFAULT_MAX_ZIP_MEMBERS,
    max_zip_member_bytes: int = DEFAULT_MAX_ZIP_MEMBER_BYTES,
    max_zip_total_bytes: int = DEFAULT_MAX_ZIP_TOTAL_BYTES,
    max_zip_compression_ratio: float = DEFAULT_MAX_ZIP_COMPRESSION_RATIO,
) -> int:
    if not sources:
        raise SourceError("configure at least one source")
    addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    with tempfile.TemporaryDirectory(prefix="deny-ip-toolkit-") as folder:
        workdir = Path(folder)
        for index, source in enumerate(sources):
            downloaded = read_source(source, workdir, timeout, max_download_bytes)
            paths = candidate_files(
                downloaded,
                workdir / f"source-{index}",
                max_zip_members,
                max_zip_member_bytes,
                max_zip_total_bytes,
                max_zip_compression_ratio,
            )
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
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--source", action="append", default=[])
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(os.getenv("OUTPUT_FILE", "./output/deny-ip-list.txt")),
    )
    parser.add_argument(
        "--timeout", type=int, default=int(os.getenv("HTTP_TIMEOUT", str(DEFAULT_TIMEOUT)))
    )
    parser.add_argument(
        "--max-download-bytes",
        type=positive_int,
        default=int(os.getenv("MAX_DOWNLOAD_BYTES", str(DEFAULT_MAX_DOWNLOAD_BYTES))),
    )
    parser.add_argument(
        "--max-zip-members",
        type=positive_int,
        default=int(os.getenv("MAX_ZIP_MEMBERS", str(DEFAULT_MAX_ZIP_MEMBERS))),
    )
    parser.add_argument(
        "--max-zip-member-bytes",
        type=positive_int,
        default=int(os.getenv("MAX_ZIP_MEMBER_BYTES", str(DEFAULT_MAX_ZIP_MEMBER_BYTES))),
    )
    parser.add_argument(
        "--max-zip-total-bytes",
        type=positive_int,
        default=int(os.getenv("MAX_ZIP_TOTAL_BYTES", str(DEFAULT_MAX_ZIP_TOTAL_BYTES))),
    )
    parser.add_argument(
        "--max-zip-compression-ratio",
        type=positive_float,
        default=float(
            os.getenv(
                "MAX_ZIP_COMPRESSION_RATIO", str(DEFAULT_MAX_ZIP_COMPRESSION_RATIO)
            )
        ),
    )
    args = parser.parse_args()
    try:
        count = normalize(
            configured_sources(args.source),
            args.output,
            args.timeout,
            args.max_download_bytes,
            args.max_zip_members,
            args.max_zip_member_bytes,
            args.max_zip_total_bytes,
            args.max_zip_compression_ratio,
        )
    except SourceError as exc:
        parser.error(str(exc))
    print(f"wrote {count} unique addresses to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
