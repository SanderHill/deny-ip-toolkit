#!/usr/bin/env python3
"""Combine licensed local or remote IP lists into one normalized local file."""

from __future__ import annotations

import argparse
import bisect
import hashlib
import heapq
import ipaddress
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
from io import TextIOBase
from pathlib import Path

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
    if parsed <= 0:
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


def load_processing_config(path: Path) -> ProcessingConfig:
    """Load the processing section of a versioned TOML configuration file."""
    try:
        with path.open("rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise SourceError(f"could not read configuration {path}: {exc}") from exc
    if document.get("version") != 1:
        raise SourceError("configuration version must be 1")
    processing = document.get("processing", {})
    if not isinstance(processing, dict):
        raise SourceError("configuration processing section must be a table")
    unknown = sorted(set(processing) - {"overlap_action"})
    if unknown:
        raise SourceError(
            f"configuration processing section has unknown fields: {', '.join(unknown)}"
        )
    action = processing.get("overlap_action", "find")
    if not isinstance(action, str):
        raise SourceError("configuration overlap_action must be a string")
    return ProcessingConfig(overlap_action=validate_overlap_action(action))


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
                candidate = token.strip(".:") or token
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
    if report_stream is not None:
        write_overlap_report(report, overlap_action, report_stream)
    ordered = sorted(entries, key=entry_sort_key)
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
    parser.add_argument("--source", action="append", default=[])
    parser.add_argument(
        "--sources-file",
        type=Path,
        default=Path(os.environ["SOURCES_FILE"]) if os.getenv("SOURCES_FILE") else None,
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
        default=Path(os.getenv("OUTPUT_FILE", "./output/deny-ip-list.txt")),
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=int(os.getenv("HTTP_TIMEOUT", str(DEFAULT_TIMEOUT))),
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
        default=int(
            os.getenv("MAX_ZIP_MEMBER_BYTES", str(DEFAULT_MAX_ZIP_MEMBER_BYTES))
        ),
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
    parser.add_argument(
        "--allow-private-sources",
        action="store_true",
        default=environment_flag("ALLOW_PRIVATE_SOURCES"),
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
        overlap_action = configured_overlap_action(
            args.overlap_action, args.config_file
        )
        count = normalize(
            configured_source_specs(args.source, args.sources_file),
            args.output,
            args.timeout,
            args.max_download_bytes,
            args.max_zip_members,
            args.max_zip_member_bytes,
            args.max_zip_total_bytes,
            args.max_zip_compression_ratio,
            args.allow_private_sources,
            overlap_action,
            sys.stdout,
        )
    except SourceError as exc:
        parser.error(str(exc))
    print(f"wrote {count} unique addresses to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
