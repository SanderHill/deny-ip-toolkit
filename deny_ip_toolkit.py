#!/usr/bin/env python3
"""Combine licensed local or remote IP lists into one normalized local file."""

from __future__ import annotations

import argparse
import bisect
import csv
import hashlib
import heapq
import ipaddress
import json
import math
import os
import re
import socket
import stat
import sys
import tempfile
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass, field
from fractions import Fraction
from io import TextIOBase
from pathlib import Path

from output_formats import OUTPUT_FORMATS, read_export, render_output

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

USER_AGENT = "deny-ip-toolkit/1.0"
DEFAULT_TIMEOUT = 60
DEFAULT_MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024
DEFAULT_MAX_ZIP_MEMBERS = 1_000
DEFAULT_MAX_ZIP_MEMBER_BYTES = 25 * 1024 * 1024
DEFAULT_MAX_ZIP_TOTAL_BYTES = 100 * 1024 * 1024
DEFAULT_MAX_ZIP_COMPRESSION_RATIO = 100.0
COPY_CHUNK_BYTES = 64 * 1024
OVERLAP_ACTIONS = {"find", "remove_single_ips", "remove_ranges"}
PROCESSING_SETTINGS = {
    "overlap_action",
    "max_ipv4_removal_percent",
    "max_ipv6_removal_percent",
}
__version__ = "0.1.0"

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPEntry = IPAddress | IPNetwork


class SourceError(RuntimeError):
    """Raised when a configured input source cannot be processed safely."""


@dataclass(frozen=True)
class SourceSpec:
    location: str
    sha256: str | None = None
    license: str | None = None
    license_url: str | None = None
    allowed_use: str | None = None


@dataclass(frozen=True)
class ProcessingConfig:
    overlap_action: str = "find"


@dataclass(frozen=True)
class EntryOccurrence:
    entry: IPEntry
    source: str
    line: int


@dataclass
class OverlapReport:
    occurrences: dict[IPEntry, list[EntryOccurrence]]
    covered_addresses: dict[IPAddress, IPNetwork]
    nested_networks: dict[IPNetwork, IPNetwork]
    ranges_with_individual_ips: set[IPNetwork]
    removed_entries: set[IPEntry] = field(default_factory=set)


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Apply the remote destination policy to every HTTP redirect."""

    def __init__(self, allow_private_sources: bool):
        super().__init__()
        self.allow_private_sources = allow_private_sources

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_remote_url(newurl, self.allow_private_sources)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def positive_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def environment_flag(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def redact_source(source: str) -> str:
    """Remove credentials, query values, and fragments from a remote source URL."""
    parsed = urllib.parse.urlsplit(source)
    if parsed.scheme not in {"http", "https"}:
        return source
    hostname = parsed.hostname or "invalid-host"
    if ":" in hostname:
        hostname = f"[{hostname}]"
    try:
        port = parsed.port
    except ValueError:
        port = None
    netloc = f"{hostname}:{port}" if port is not None else hostname
    query = "redacted" if parsed.query else ""
    return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, query, ""))


def validate_remote_url(source: str, allow_private_sources: bool = False) -> None:
    """Reject remote URLs that resolve outside globally reachable address space."""
    parsed = urllib.parse.urlsplit(source)
    safe_source = redact_source(source)
    if parsed.scheme not in {"http", "https"}:
        raise SourceError(
            f"unsupported remote source scheme: {parsed.scheme or 'missing'}"
        )
    if not parsed.hostname:
        raise SourceError(f"remote source has no hostname: {safe_source}")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise SourceError(f"remote source has an invalid port: {safe_source}") from exc
    try:
        results = socket.getaddrinfo(
            parsed.hostname,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror as exc:
        raise SourceError(f"could not resolve remote source: {safe_source}") from exc
    if not results:
        raise SourceError(f"remote source resolved to no addresses: {safe_source}")
    if allow_private_sources:
        return
    addresses = {ipaddress.ip_address(result[4][0]) for result in results}
    if any(not address.is_global for address in addresses):
        raise SourceError(
            f"remote source resolves to a non-public address: {safe_source}; "
            "use --allow-private-sources only for trusted sources"
        )


def source_name(source: str) -> str:
    parsed = urllib.parse.urlparse(source)
    if parsed.scheme in {"http", "https"}:
        name = Path(parsed.path).name
        return "download" if name in {"", ".", ".."} else name
    return Path(source).name


def load_source_manifest(path: Path) -> list[SourceSpec]:
    """Load and validate a versioned source manifest before any source is read."""
    try:
        with path.open("rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise SourceError(f"could not read source manifest {path}: {exc}") from exc
    if document.get("version") != 1:
        raise SourceError("source manifest version must be 1")
    sources = document.get("sources")
    if not isinstance(sources, list) or not sources:
        raise SourceError("source manifest must contain at least one [[sources]] entry")

    required = {"location", "license", "license_url", "sha256", "allowed_use"}
    specs: list[SourceSpec] = []
    for index, item in enumerate(sources, start=1):
        if not isinstance(item, dict):
            raise SourceError(f"source manifest entry {index} must be a table")
        missing = sorted(required - item.keys())
        if missing:
            raise SourceError(
                f"source manifest entry {index} is missing: {', '.join(missing)}"
            )
        if any(
            not isinstance(item[field], str) or not item[field].strip()
            for field in required
        ):
            raise SourceError(
                f"source manifest entry {index} fields must be non-empty strings"
            )
        digest = item["sha256"].lower()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise SourceError(f"source manifest entry {index} has an invalid SHA-256")
        license_url = urllib.parse.urlsplit(item["license_url"])
        if license_url.scheme not in {"http", "https"} or not license_url.hostname:
            raise SourceError(
                f"source manifest entry {index} has an invalid license_url"
            )
        location = item["location"]
        location_url = urllib.parse.urlsplit(location)
        if location_url.scheme not in {"", "http", "https"}:
            raise SourceError(
                f"source manifest entry {index} has an unsupported location scheme"
            )
        if not location_url.scheme:
            location = str((path.parent / location).resolve())
        specs.append(
            SourceSpec(
                location=location,
                sha256=digest,
                license=item["license"],
                license_url=item["license_url"],
                allowed_use=item["allowed_use"],
            )
        )
    return specs


def validate_overlap_action(action: str) -> str:
    if action not in OVERLAP_ACTIONS:
        choices = ", ".join(sorted(OVERLAP_ACTIONS))
        raise SourceError(f"overlap_action must be one of: {choices}")
    return action


RUNTIME_DEFAULTS = {
    "output_format": "text",
    "max_ipv4_removal_percent": None,
    "max_ipv6_removal_percent": None,
    "report_file": None,
    "sources": [],
    "sources_file": None,
    "output": Path("./output/deny-ip-list.txt"),
    "timeout": DEFAULT_TIMEOUT,
    "max_download_bytes": DEFAULT_MAX_DOWNLOAD_BYTES,
    "max_zip_members": DEFAULT_MAX_ZIP_MEMBERS,
    "max_zip_member_bytes": DEFAULT_MAX_ZIP_MEMBER_BYTES,
    "max_zip_total_bytes": DEFAULT_MAX_ZIP_TOTAL_BYTES,
    "max_zip_compression_ratio": DEFAULT_MAX_ZIP_COMPRESSION_RATIO,
    "allow_private_sources": False,
    "overlap_action": "find",
}
SETTING_ENV = {
    "output_format": "OUTPUT_FORMAT",
    "max_ipv4_removal_percent": "MAX_IPV4_REMOVAL_PERCENT",
    "max_ipv6_removal_percent": "MAX_IPV6_REMOVAL_PERCENT",
    "report_file": "REPORT_FILE",
    "sources": "SOURCE_URLS",
    "sources_file": "SOURCES_FILE",
    "output": "OUTPUT_FILE",
    "timeout": "HTTP_TIMEOUT",
    "max_download_bytes": "MAX_DOWNLOAD_BYTES",
    "max_zip_members": "MAX_ZIP_MEMBERS",
    "max_zip_member_bytes": "MAX_ZIP_MEMBER_BYTES",
    "max_zip_total_bytes": "MAX_ZIP_TOTAL_BYTES",
    "max_zip_compression_ratio": "MAX_ZIP_COMPRESSION_RATIO",
    "allow_private_sources": "ALLOW_PRIVATE_SOURCES",
    "overlap_action": "OVERLAP_ACTION",
}


def validate_setting(name: str, value):
    if name == "output_format":
        if not isinstance(value, str) or value not in OUTPUT_FORMATS:
            raise SourceError(
                f"output_format must be one of: {', '.join(OUTPUT_FORMATS)}"
            )
        return value
    if name in {"max_ipv4_removal_percent", "max_ipv6_removal_percent"}:
        if (
            type(value) not in {int, float}
            or not math.isfinite(value)
            or not 0 <= value <= 100
        ):
            raise SourceError(f"{name} must be a finite percentage from 0 to 100")
        return value
    if name == "sources":
        if not isinstance(value, list) or any(
            not isinstance(item, str) or not item.strip() for item in value
        ):
            raise SourceError("sources must be an array of non-empty strings")
        return value
    if name in {"output", "sources_file", "report_file"}:
        if not isinstance(value, (str, Path)) or not str(value).strip():
            raise SourceError(f"{name} must be a non-empty path")
        return Path(value).expanduser()
    if name == "allow_private_sources":
        if type(value) is not bool:
            raise SourceError("allow_private_sources must be a boolean")
        return value
    if name == "overlap_action":
        if not isinstance(value, str):
            raise SourceError("overlap_action must be a string")
        return validate_overlap_action(value)
    if name == "max_zip_compression_ratio":
        if type(value) not in {int, float} or not math.isfinite(value) or value <= 0:
            raise SourceError(f"{name} must be a finite positive number")
        return value
    if type(value) is not int or value <= 0:
        raise SourceError(f"{name} must be a positive integer")
    return value


def load_runtime_config(path: Path) -> dict:
    """Validate the complete TOML configuration before processing any source."""
    try:
        with path.open("rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise SourceError(f"could not read configuration {path}: {exc}") from exc
    if type(document.get("version")) is not int or document.get("version") != 1:
        raise SourceError("configuration version must be 1")
    if set(document) - {"version", "runtime", "processing"}:
        raise SourceError("configuration has unknown top-level fields")
    runtime = document.get("runtime", {})
    if not isinstance(runtime, dict):
        raise SourceError("configuration runtime section must be a table")
    if set(runtime) - (set(RUNTIME_DEFAULTS) - PROCESSING_SETTINGS):
        raise SourceError("configuration runtime section has unknown fields")
    processing = document.get("processing", {})
    if not isinstance(processing, dict):
        raise SourceError("configuration processing section must be a table")
    unknown = sorted(set(processing) - PROCESSING_SETTINGS)
    if unknown:
        raise SourceError(
            f"configuration processing section has unknown fields: {', '.join(unknown)}"
        )
    settings = {
        name: validate_setting(name, value)
        for name, value in {**runtime, **processing}.items()
    }
    for name in ("output", "sources_file", "report_file"):
        if name in settings and not settings[name].is_absolute():
            settings[name] = (path.resolve().parent / settings[name]).resolve()
    if "sources" in settings:
        settings["sources"] = [
            source
            if urllib.parse.urlsplit(source).scheme
            else str((path.resolve().parent / Path(source).expanduser()).resolve())
            for source in settings["sources"]
        ]
    return settings


def load_processing_config(path: Path) -> ProcessingConfig:
    return ProcessingConfig(
        overlap_action=load_runtime_config(path).get("overlap_action", "find")
    )


def resolve_runtime_settings(args: argparse.Namespace) -> dict:
    settings = dict(RUNTIME_DEFAULTS)
    if args.config_file:
        settings.update(load_runtime_config(args.config_file))
    for name, environment_name in SETTING_ENV.items():
        raw = os.getenv(environment_name)
        if raw is None or raw == "":
            continue
        if name == "sources":
            value = [line.strip() for line in raw.splitlines() if line.strip()]
        elif name == "allow_private_sources":
            if raw.strip().lower() not in {
                "1",
                "true",
                "yes",
                "on",
                "0",
                "false",
                "no",
                "off",
            }:
                raise SourceError(f"{environment_name} must be a boolean")
            value = raw.strip().lower() in {"1", "true", "yes", "on"}
        elif name in {
            "sources_file",
            "output",
            "report_file",
            "overlap_action",
            "output_format",
        }:
            value = raw
        else:
            try:
                value = (
                    float(raw)
                    if name
                    in {
                        "max_zip_compression_ratio",
                        "max_ipv4_removal_percent",
                        "max_ipv6_removal_percent",
                    }
                    else int(raw)
                )
            except ValueError as exc:
                raise SourceError(
                    f"{environment_name} has an invalid numeric value"
                ) from exc
        settings[name] = validate_setting(name, value)
    for name in RUNTIME_DEFAULTS:
        cli_name = "source" if name == "sources" else name
        value = getattr(args, cli_name, None)
        if value is not None:
            # Preserve the existing additive CLI + SOURCE_URLS source workflow.
            if name == "sources":
                settings[name] = [*value, *settings[name]]
            else:
                settings[name] = validate_setting(name, value)
    return settings


def verify_sha256(path: Path, expected: str) -> None:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(COPY_CHUNK_BYTES):
                digest.update(chunk)
    except OSError as exc:
        raise SourceError(f"could not read source file: {path.name}") from exc
    if digest.hexdigest() != expected:
        raise SourceError(f"source checksum mismatch: {path.name}")


def read_source(
    source: str,
    target_dir: Path,
    timeout: int,
    max_download_bytes: int = DEFAULT_MAX_DOWNLOAD_BYTES,
    allow_private_sources: bool = False,
) -> Path:
    parsed = urllib.parse.urlparse(source)
    if parsed.scheme in {"http", "https"}:
        validate_remote_url(source, allow_private_sources)
        safe_source = redact_source(source)
        destination = target_dir / source_name(source)
        try:
            request = urllib.request.Request(source, headers={"User-Agent": USER_AGENT})
            opener = urllib.request.build_opener(
                SafeRedirectHandler(allow_private_sources)
            )
            with opener.open(request, timeout=timeout) as response:
                declared_size = None
                content_length = response.headers.get("Content-Length")
                if content_length is not None:
                    try:
                        declared_size = int(content_length)
                    except ValueError as exc:
                        raise SourceError(
                            "remote source has an invalid Content-Length"
                        ) from exc
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
                if declared_size is not None and downloaded != declared_size:
                    raise SourceError(
                        "remote source size does not match Content-Length"
                    )
        except (OSError, ValueError) as exc:
            raise SourceError(
                f"could not download {safe_source}: {type(exc).__name__}"
            ) from exc
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
    try:
        is_archive = zipfile.is_zipfile(source)
    except OSError as exc:
        raise SourceError(f"could not read source file: {source.name}") from exc
    if not is_archive:
        if source.suffix.lower() == ".zip":
            raise SourceError("source is not a valid ZIP archive")
        return [source]
    extract_dir.mkdir(parents=True, exist_ok=True)
    root = extract_dir.resolve()
    try:
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
                        "ZIP member exceeds the "
                        f"{max_compression_ratio:g}:1 compression-ratio limit"
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
                            raise SourceError(
                                "ZIP member expanded beyond its declared size"
                            )
                        target_handle.write(chunk)
    except SourceError:
        raise
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise SourceError(f"could not read ZIP archive: {type(exc).__name__}") from exc
    return [path for path in extract_dir.rglob("*") if path.is_file()]


def extract_occurrences(
    paths: list[Path], source_label: str | None = None
) -> list[EntryOccurrence]:
    occurrences: list[EntryOccurrence] = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8-sig", errors="ignore")
        except OSError as exc:
            raise SourceError(f"could not read source file: {path.name}") from exc
        origin = source_label or str(path)
        if len(paths) > 1:
            origin = f"{origin}!{path.name}"
        for line_number, line in enumerate(text.splitlines(), start=1):
            for token in re.findall(
                r"(?<![\w.:/])(?:[0-9A-Fa-f:.]+(?:/\d{1,3})?)(?![\w.:/])",
                line,
            ):
                # Leading/trailing colons can be significant in IPv6 (::/0).
                candidate = token.strip(".") or token
                try:
                    entry: IPEntry
                    if "/" in candidate:
                        entry = ipaddress.ip_network(candidate, strict=False)
                    else:
                        entry = ipaddress.ip_address(candidate)
                except ValueError:
                    continue
                occurrences.append(EntryOccurrence(entry, origin, line_number))
    return occurrences


def extract_entries(paths: list[Path]) -> set[IPEntry]:
    return {occurrence.entry for occurrence in extract_occurrences(paths)}


def analyze_overlaps(occurrences: list[EntryOccurrence]) -> OverlapReport:
    grouped: dict[IPEntry, list[EntryOccurrence]] = {}
    for occurrence in occurrences:
        grouped.setdefault(occurrence.entry, []).append(occurrence)

    addresses_by_version: dict[int, list[IPAddress]] = {4: [], 6: []}
    networks_by_version: dict[int, list[IPNetwork]] = {4: [], 6: []}
    for entry in grouped:
        if isinstance(entry, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            networks_by_version[entry.version].append(entry)
        else:
            addresses_by_version[entry.version].append(entry)

    covered_addresses: dict[IPAddress, IPNetwork] = {}
    nested_networks: dict[IPNetwork, IPNetwork] = {}
    ranges_with_individual_ips: set[IPNetwork] = set()

    for version in (4, 6):
        addresses = sorted(addresses_by_version[version], key=int)
        networks = sorted(
            networks_by_version[version],
            key=lambda network: (
                int(network.network_address),
                -int(network.broadcast_address),
            ),
        )

        active: list[tuple[int, int, IPNetwork]] = []
        network_index = 0
        for address in addresses:
            address_value = int(address)
            while (
                network_index < len(networks)
                and int(networks[network_index].network_address) <= address_value
            ):
                network = networks[network_index]
                heapq.heappush(
                    active,
                    (-int(network.broadcast_address), network.prefixlen, network),
                )
                network_index += 1
            while active and -active[0][0] < address_value:
                heapq.heappop(active)
            if active:
                covered_addresses[address] = active[0][2]

        address_values = [int(address) for address in addresses]
        for network in networks:
            position = bisect.bisect_left(address_values, int(network.network_address))
            if position < len(address_values) and address_values[position] <= int(
                network.broadcast_address
            ):
                ranges_with_individual_ips.add(network)

        stack: list[IPNetwork] = []
        for network in networks:
            while stack and int(stack[-1].broadcast_address) < int(
                network.network_address
            ):
                stack.pop()
            if stack and network.subnet_of(stack[-1]):
                nested_networks[network] = stack[-1]
            stack.append(network)

    return OverlapReport(
        occurrences=grouped,
        covered_addresses=covered_addresses,
        nested_networks=nested_networks,
        ranges_with_individual_ips=ranges_with_individual_ips,
    )


def apply_overlap_action(
    entries: set[IPEntry], report: OverlapReport, action: str
) -> set[IPEntry]:
    action = validate_overlap_action(action)
    if action == "remove_single_ips":
        report.removed_entries = set(report.covered_addresses)
    elif action == "remove_ranges":
        report.removed_entries = set(report.ranges_with_individual_ips)
    else:
        report.removed_entries = set()
    return entries - report.removed_entries


def occurrence_label(occurrence: EntryOccurrence) -> str:
    return f"{occurrence.source}:{occurrence.line}"


def write_overlap_report(
    report: OverlapReport, action: str, stream: TextIOBase
) -> None:
    exact_groups = {
        entry: locations
        for entry, locations in report.occurrences.items()
        if len(locations) > 1
    }
    exact_count = sum(len(locations) - 1 for locations in exact_groups.values())
    stream.write("overlap analysis:\n")
    stream.write(f"  exact duplicates: {exact_count}\n")
    stream.write(f"  single IPs covered by ranges: {len(report.covered_addresses)}\n")
    stream.write(f"  nested ranges: {len(report.nested_networks)}\n")
    stream.write(f"  entries removed by {action}: {len(report.removed_entries)}\n")

    for entry in sorted(exact_groups, key=entry_sort_key):
        locations = ", ".join(occurrence_label(item) for item in exact_groups[entry])
        stream.write(f"  exact duplicate {entry}: {locations}\n")
    for address in sorted(report.covered_addresses, key=entry_sort_key):
        network = report.covered_addresses[address]
        address_location = occurrence_label(report.occurrences[address][0])
        network_location = occurrence_label(report.occurrences[network][0])
        stream.write(
            f"  covered IP {address} ({address_location}) by "
            f"{network} ({network_location})\n"
        )
    for network in sorted(report.nested_networks, key=entry_sort_key):
        parent = report.nested_networks[network]
        network_location = occurrence_label(report.occurrences[network][0])
        parent_location = occurrence_label(report.occurrences[parent][0])
        stream.write(
            f"  nested range {network} ({network_location}) in "
            f"{parent} ({parent_location})\n"
        )
    for entry in sorted(report.removed_entries, key=entry_sort_key):
        entry_location = occurrence_label(report.occurrences[entry][0])
        stream.write(f"  removed {entry} ({entry_location})\n")
    if action == "remove_ranges":
        stream.write(
            "WARNING: remove_ranges can reduce the blocked address space; "
            "unlisted addresses from removed ranges are no longer included.\n"
        )


def entry_sort_key(entry):
    if isinstance(entry, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return (entry.version, int(entry.network_address), 0, entry.prefixlen)
    return (entry.version, int(entry), 1, entry.max_prefixlen)


def load_previous_output(
    output: Path, output_format: str = "text"
) -> set[IPEntry] | None:
    """Read a normalized baseline strictly, rather than silently ignoring damage."""
    try:
        text = output.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        return None
    except (OSError, UnicodeError) as exc:
        raise SourceError("could not read previous output") from exc
    try:
        return read_export(text, output_format)
    except (ValueError, TypeError, KeyError, csv.Error) as exc:
        raise SourceError(
            "previous output is invalid for the selected output format"
        ) from exc


def coverage_intervals(entries: set[IPEntry], version: int) -> list[tuple[int, int]]:
    intervals = []
    for entry in entries:
        if entry.version != version:
            continue
        if isinstance(entry, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            intervals.append((int(entry.network_address), int(entry.broadcast_address)))
        else:
            intervals.append((int(entry), int(entry)))
    merged: list[tuple[int, int]] = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def coverage_comparison(
    previous: set[IPEntry], current: set[IPEntry], version: int
) -> dict:
    before = coverage_intervals(previous, version)
    after = coverage_intervals(current, version)
    before_count = sum(end - start + 1 for start, end in before)
    after_count = sum(end - start + 1 for start, end in after)
    retained = 0
    left = right = 0
    while left < len(before) and right < len(after):
        start = max(before[left][0], after[right][0])
        end = min(before[left][1], after[right][1])
        if start <= end:
            retained += end - start + 1
        if before[left][1] < after[right][1]:
            left += 1
        else:
            right += 1
    removed = before_count - retained
    return {
        "previous_addresses": before_count,
        "current_addresses": after_count,
        "added_addresses": after_count - retained,
        "removed_addresses": removed,
        "removed_percent": 100 * removed / before_count if before_count else 0.0,
    }


def compare_outputs(previous: set[IPEntry] | None, current: set[IPEntry]) -> dict:
    baseline = previous if previous is not None else set()
    coverage = {
        f"ipv{version}": coverage_comparison(baseline, current, version)
        for version in (4, 6)
    }
    return {
        "baseline_available": previous is not None,
        "previous_entries": len(baseline) if previous is not None else None,
        "current_entries": len(current),
        "added_entries": [
            str(entry) for entry in sorted(current - baseline, key=entry_sort_key)
        ],
        "removed_entries": [
            str(entry) for entry in sorted(baseline - current, key=entry_sort_key)
        ],
        "coverage": coverage,
        "coverage_changed": any(
            counts["added_addresses"] or counts["removed_addresses"]
            for counts in coverage.values()
        )
        if previous is not None
        else None,
        "safeguard_rejected": False,
    }


def enforce_removal_limits(comparison: dict, ipv4_limit, ipv6_limit) -> None:
    if not comparison["baseline_available"]:
        return
    for version, limit in ((4, ipv4_limit), (6, ipv6_limit)):
        if limit is None:
            continue
        counts = comparison["coverage"][f"ipv{version}"]
        # Compare exact integers/rational thresholds even for huge IPv6 ranges.
        if counts["previous_addresses"] and (
            Fraction(100 * counts["removed_addresses"], counts["previous_addresses"])
            > Fraction(str(limit))
        ):
            comparison["safeguard_rejected"] = True
            raise SourceError(
                f"IPv{version} removed coverage exceeds the {limit}% limit; "
                "previous output preserved"
            )


def _normalize(
    sources: list[str | SourceSpec],
    output: Path,
    timeout: int = DEFAULT_TIMEOUT,
    max_download_bytes: int = DEFAULT_MAX_DOWNLOAD_BYTES,
    max_zip_members: int = DEFAULT_MAX_ZIP_MEMBERS,
    max_zip_member_bytes: int = DEFAULT_MAX_ZIP_MEMBER_BYTES,
    max_zip_total_bytes: int = DEFAULT_MAX_ZIP_TOTAL_BYTES,
    max_zip_compression_ratio: float = DEFAULT_MAX_ZIP_COMPRESSION_RATIO,
    allow_private_sources: bool = False,
    overlap_action: str = "find",
    report_stream: TextIOBase | None = None,
    run_report: dict | None = None,
    previous_entries: set[IPEntry] | None = None,
    max_ipv4_removal_percent: float | None = None,
    max_ipv6_removal_percent: float | None = None,
    output_format: str = "text",
) -> int:
    if not sources:
        raise SourceError("configure at least one source")
    validate_overlap_action(overlap_action)
    occurrences: list[EntryOccurrence] = []
    with tempfile.TemporaryDirectory(prefix="deny-ip-toolkit-") as folder:
        workdir = Path(folder)
        for index, configured_source in enumerate(sources):
            spec = (
                configured_source
                if isinstance(configured_source, SourceSpec)
                else SourceSpec(configured_source)
            )
            downloaded = read_source(
                spec.location,
                workdir,
                timeout,
                max_download_bytes,
                allow_private_sources,
            )
            if spec.sha256:
                verify_sha256(downloaded, spec.sha256)
            if run_report is not None:
                run_report["sources"].append(
                    {
                        "location": redact_source(spec.location),
                        "license": spec.license,
                        "license_url": redact_source(spec.license_url)
                        if spec.license_url
                        else None,
                        "allowed_use": spec.allowed_use,
                        "expected_sha256": spec.sha256,
                        "checksum_verified": bool(spec.sha256),
                    }
                )
            paths = candidate_files(
                downloaded,
                workdir / f"source-{index}",
                max_zip_members,
                max_zip_member_bytes,
                max_zip_total_bytes,
                max_zip_compression_ratio,
            )
            occurrences.extend(extract_occurrences(paths, redact_source(spec.location)))
    entries = {occurrence.entry for occurrence in occurrences}
    if not entries:
        raise SourceError(
            "configured sources contained no valid IP addresses or networks"
        )
    report = analyze_overlaps(occurrences)
    entries = apply_overlap_action(entries, report, overlap_action)
    if run_report is not None:
        run_report.update(overlap_report_document(report, overlap_action, len(entries)))
    if report_stream is not None:
        write_overlap_report(report, overlap_action, report_stream)
    comparison = compare_outputs(previous_entries, entries)
    if run_report is not None:
        run_report["comparison"] = comparison
    if report_stream is not None:
        if not comparison["baseline_available"]:
            report_stream.write("comparison: first run, no previous output\n")
        else:
            report_stream.write(
                f"comparison: {len(comparison['added_entries'])} entries added, "
                f"{len(comparison['removed_entries'])} entries removed\n"
            )
            for action in ("added", "removed"):
                for entry in comparison[f"{action}_entries"]:
                    report_stream.write(f"  {action} {entry}\n")
            for family, counts in comparison["coverage"].items():
                report_stream.write(
                    f"  {family}: {counts['added_addresses']} addresses added, "
                    f"{counts['removed_addresses']} removed "
                    f"({counts['removed_percent']:.6g}% of previous coverage)\n"
                )
    enforce_removal_limits(
        comparison, max_ipv4_removal_percent, max_ipv6_removal_percent
    )
    try:
        serialized = render_output(entries, output_format)
    except ValueError as exc:
        raise SourceError(str(exc)) from exc
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="\n", dir=output.parent, delete=False
    ) as handle:
        handle.write(serialized)
        temporary = Path(handle.name)
    temporary.replace(output)
    if run_report is not None:
        run_report["output"] = {
            "path": str(output),
            "sha256": hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
            "format": output_format,
        }
    return len(entries)


def overlap_report_document(
    report: OverlapReport, action: str, output_count: int
) -> dict:
    def detail(entry):
        return {
            "entry": str(entry),
            "occurrences": [
                {"source": item.source, "line": item.line}
                for item in report.occurrences[entry]
            ],
        }

    ordered = sorted(report.occurrences, key=entry_sort_key)
    return {
        "counts": {
            "valid_occurrences": sum(
                len(items) for items in report.occurrences.values()
            ),
            "unique_entries": len(ordered),
            "exact_duplicates": sum(
                len(items) - 1 for items in report.occurrences.values()
            ),
            "covered_ips": len(report.covered_addresses),
            "nested_ranges": len(report.nested_networks),
            "removed_entries": len(report.removed_entries),
            "output_entries": output_count,
        },
        "exact_duplicates": [
            detail(entry) for entry in ordered if len(report.occurrences[entry]) > 1
        ],
        "covered_ips": [
            {**detail(entry), "covering_range": str(report.covered_addresses[entry])}
            for entry in sorted(report.covered_addresses, key=entry_sort_key)
        ],
        "nested_ranges": [
            {**detail(entry), "parent_range": str(report.nested_networks[entry])}
            for entry in sorted(report.nested_networks, key=entry_sort_key)
        ],
        "removed_entries": [
            detail(entry)
            for entry in sorted(report.removed_entries, key=entry_sort_key)
        ],
        "warnings": [
            "remove_ranges can reduce blocked address space; unlisted addresses "
            "from removed ranges are no longer included."
        ]
        if action == "remove_ranges"
        else [],
    }


def validate_report_path(path: Path, protected: list[Path]) -> None:
    target = path.resolve()
    for source in protected:
        if target == source.resolve() or (
            path.exists() and source.exists() and path.samefile(source)
        ):
            raise SourceError("report path must not overwrite an input or output file")


def save_run_report(path: Path, document: dict) -> None:
    temporary = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=path.parent, delete=False
        ) as handle:
            temporary = Path(handle.name)
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
        temporary.replace(path)
    except OSError as exc:
        raise SourceError(f"could not save run report: {type(exc).__name__}") from exc
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def normalize(
    sources: list[str | SourceSpec],
    output: Path,
    timeout: int = DEFAULT_TIMEOUT,
    max_download_bytes: int = DEFAULT_MAX_DOWNLOAD_BYTES,
    max_zip_members: int = DEFAULT_MAX_ZIP_MEMBERS,
    max_zip_member_bytes: int = DEFAULT_MAX_ZIP_MEMBER_BYTES,
    max_zip_total_bytes: int = DEFAULT_MAX_ZIP_TOTAL_BYTES,
    max_zip_compression_ratio: float = DEFAULT_MAX_ZIP_COMPRESSION_RATIO,
    allow_private_sources: bool = False,
    overlap_action: str = "find",
    report_stream: TextIOBase | None = None,
    report_file: Path | None = None,
    max_ipv4_removal_percent: float | None = None,
    max_ipv6_removal_percent: float | None = None,
    output_format: str = "text",
) -> int:
    locations = [
        item.location if isinstance(item, SourceSpec) else item for item in sources
    ]
    if report_file is not None:
        validate_report_path(
            report_file,
            [
                output,
                *[
                    Path(item).expanduser()
                    for item in locations
                    if not urllib.parse.urlsplit(item).scheme
                ],
            ],
        )
    document = {
        "schema_version": 1,
        "tool_version": __version__,
        "status": "running",
        "sources": [],
        "configured_sources": [redact_source(item) for item in locations],
        "settings": {
            "overlap_action": overlap_action,
            "timeout": timeout,
            "max_download_bytes": max_download_bytes,
            "max_zip_members": max_zip_members,
            "max_zip_member_bytes": max_zip_member_bytes,
            "max_zip_total_bytes": max_zip_total_bytes,
            "max_zip_compression_ratio": max_zip_compression_ratio,
            "allow_private_sources": allow_private_sources,
            "output_format": output_format,
            "max_ipv4_removal_percent": max_ipv4_removal_percent,
            "max_ipv6_removal_percent": max_ipv6_removal_percent,
        },
        "counts": None,
        "output": None,
        "warnings": [],
        "error": None,
        "comparison": None,
    }
    try:
        for name, limit in (
            ("max_ipv4_removal_percent", max_ipv4_removal_percent),
            ("max_ipv6_removal_percent", max_ipv6_removal_percent),
        ):
            if limit is not None:
                validate_setting(name, limit)
        validate_setting("output_format", output_format)
        previous_entries = load_previous_output(output, output_format)
        count = _normalize(
            sources,
            output,
            timeout,
            max_download_bytes,
            max_zip_members,
            max_zip_member_bytes,
            max_zip_total_bytes,
            max_zip_compression_ratio,
            allow_private_sources,
            overlap_action,
            report_stream,
            document,
            previous_entries,
            max_ipv4_removal_percent,
            max_ipv6_removal_percent,
            output_format,
        )
    except (SourceError, OSError) as exc:
        document["status"] = "failed"
        # Never serialize exception chains or arbitrary OS error messages.
        message = str(exc) if isinstance(exc, SourceError) else "could not write output"
        for location in locations:
            message = message.replace(location, redact_source(location))
        document["error"] = {"type": type(exc).__name__, "message": message}
        if report_file is not None:
            try:
                save_run_report(report_file, document)
            except SourceError as report_error:
                raise SourceError(f"{message}; {report_error}") from exc
        raise SourceError(message) from exc
    document["status"] = "success"
    if report_file is not None:
        save_run_report(report_file, document)
    return count


def configured_sources(cli_sources: list[str]) -> list[str]:
    environment_sources = [
        line.strip()
        for line in os.getenv("SOURCE_URLS", "").splitlines()
        if line.strip()
    ]
    return [*cli_sources, *environment_sources]


def configured_source_specs(
    cli_sources: list[str], manifest_path: Path | None
) -> list[str | SourceSpec]:
    sources: list[str | SourceSpec] = configured_sources(cli_sources)
    if manifest_path is not None:
        sources.extend(load_source_manifest(manifest_path))
    return sources


def configured_overlap_action(cli_action: str | None, config_path: Path | None) -> str:
    configured = (
        load_processing_config(config_path).overlap_action
        if config_path is not None
        else "find"
    )
    environment_action = os.getenv("OVERLAP_ACTION")
    return validate_overlap_action(cli_action or environment_action or configured)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument("--source", action="append", default=None)
    parser.add_argument("--output-format", choices=OUTPUT_FORMATS, default=None)
    for version in (4, 6):
        parser.add_argument(
            f"--max-ipv{version}-removal-percent",
            type=float,
            default=None,
            help=f"reject removal above this percentage of previous IPv{version} coverage (0-100)",
        )
    parser.add_argument(
        "--report-file",
        type=Path,
        default=None,
        help="optional versioned JSON processing report",
    )
    parser.add_argument(
        "--sources-file",
        type=Path,
        default=None,
        help="versioned TOML manifest containing licensed source metadata",
    )
    parser.add_argument(
        "--config-file",
        type=Path,
        default=Path(os.environ["CONFIG_FILE"]) if os.getenv("CONFIG_FILE") else None,
        help="versioned TOML processing configuration",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
    )
    parser.add_argument(
        "--timeout",
        type=positive_int,
        default=None,
    )
    parser.add_argument(
        "--max-download-bytes",
        type=positive_int,
        default=None,
    )
    parser.add_argument(
        "--max-zip-members",
        type=positive_int,
        default=None,
    )
    parser.add_argument(
        "--max-zip-member-bytes",
        type=positive_int,
        default=None,
    )
    parser.add_argument(
        "--max-zip-total-bytes",
        type=positive_int,
        default=None,
    )
    parser.add_argument(
        "--max-zip-compression-ratio",
        type=positive_float,
        default=None,
    )
    parser.add_argument(
        "--allow-private-sources",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="allow trusted sources on private, loopback, or link-local networks",
    )
    overlap_group = parser.add_mutually_exclusive_group()
    overlap_group.add_argument(
        "--find-duplicates",
        dest="overlap_action",
        action="store_const",
        const="find",
        help="report exact duplicates and overlaps without removing overlaps",
    )
    overlap_group.add_argument(
        "--deduplicate-single-ips",
        dest="overlap_action",
        action="store_const",
        const="remove_single_ips",
        help="remove individual IPs covered by a retained CIDR range",
    )
    overlap_group.add_argument(
        "--deduplicate-ranges",
        dest="overlap_action",
        action="store_const",
        const="remove_ranges",
        help="remove ranges containing explicit individual IPs",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        settings = resolve_runtime_settings(args)
        if settings["report_file"]:
            validate_report_path(
                settings["report_file"],
                [
                    settings["output"],
                    *[
                        path
                        for path in (args.config_file, settings["sources_file"])
                        if path is not None
                    ],
                ],
            )
        sources = list(settings["sources"])
        if settings["sources_file"]:
            sources.extend(load_source_manifest(settings["sources_file"]))
        count = normalize(
            sources,
            settings["output"],
            settings["timeout"],
            settings["max_download_bytes"],
            settings["max_zip_members"],
            settings["max_zip_member_bytes"],
            settings["max_zip_total_bytes"],
            settings["max_zip_compression_ratio"],
            settings["allow_private_sources"],
            settings["overlap_action"],
            sys.stdout,
            settings["report_file"],
            settings["max_ipv4_removal_percent"],
            settings["max_ipv6_removal_percent"],
            settings["output_format"],
        )
    except SourceError as exc:
        parser.error(str(exc))
    print(f"wrote {count} unique addresses to {settings['output']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
