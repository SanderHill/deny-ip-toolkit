# Deny IP Toolkit

[![GitHub release](https://img.shields.io/github/v/release/SanderHill/deny-ip-toolkit)](https://github.com/SanderHill/deny-ip-toolkit/releases)
[![CI](https://github.com/SanderHill/deny-ip-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/SanderHill/deny-ip-toolkit/actions/workflows/ci.yml)
[![CodeQL](https://github.com/SanderHill/deny-ip-toolkit/actions/workflows/codeql.yml/badge.svg)](https://github.com/SanderHill/deny-ip-toolkit/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)

A small, local-first tool for combining and normalizing IP blocklists. It reads
local files or explicitly configured HTTP(S) sources, validates IPv4 and IPv6
addresses and CIDR networks, removes duplicates, and writes a deterministic
list without expanding networks into individual addresses.

The project does **not** ship, mirror, or automatically publish third-party
blocklist data. Only use sources whose licence or terms allow your intended
use. Output stays local unless you choose to publish it yourself.

## Usage

Plain text is the default output. `--output-format` also supports `csv`, `json`,
`ipset`, `nftables`, and `synology` (DSM 7 Auto Block, individual IPv4 only).
Set `runtime.output_format` in TOML or `OUTPUT_FORMAT` in the environment for
scheduled runs. See [output formats and manual import instructions](docs/OUTPUT_FORMATS.md)
for supported entries, limitations and the distinction between JSON denylist
exports and JSON run reports. The toolkit exports files; it never applies rules.

```bash
python3 deny_ip_toolkit.py \
  --source ./my-own-list.txt \
  --source https://example.org/permissively-licensed-list.txt \
  --output ./output/deny-ip-list.txt
```

ZIP files containing text lists are supported. Sources can also be supplied
through `SOURCE_URLS`, separated by newlines:

```bash
SOURCE_URLS='https://example.org/list-a.txt
https://example.org/list-b.txt' \
OUTPUT_FILE=./output/deny-ip-list.txt \
python3 deny_ip_toolkit.py
```

CIDRs are preserved and normalized to their network address. For example,
`192.0.2.99/24` becomes `192.0.2.0/24`.

## Duplicate and overlap handling

Exact duplicate entries are always reduced to one output entry. The tool also
detects individual IP addresses covered by CIDR ranges and nested CIDR ranges.
By default it reports those semantic overlaps without removing either entry:

```bash
python3 deny_ip_toolkit.py \
  --source ./my-own-list.txt \
  --find-duplicates
```

Every finding includes the source and line number where available. Choose one
of two explicit deduplication modes when you want to change the output:

- `--deduplicate-single-ips` removes individual IPs covered by a retained CIDR
  range;
- `--deduplicate-ranges` removes every CIDR range containing at least one
  explicitly listed individual IP and retains the individual IPs.

For input containing `1.2.3.0/24` and `1.2.3.4`, the first mode keeps only the
range and the second keeps only the individual IP. Removing ranges can greatly
reduce the blocked address space because other addresses from those ranges are
not expanded or retained. The command prints a warning whenever that mode is
selected. IPv4 and IPv6 are analyzed independently.

For repeatable runs, copy `config.example.toml` to a private configuration
location:

```toml
version = 1

[processing]
overlap_action = "find"
```

Select it with `--config-file ./config.toml` or `CONFIG_FILE`. Supported values
are `find`, `remove_single_ips`, and `remove_ranges`. A CLI overlap option takes
precedence over `OVERLAP_ACTION`, which takes precedence over the configuration
file. Conflicting CLI options and unknown configuration values are rejected.

The same configuration file can include a `[runtime]` table with `sources`
(an array of source locations), `sources_file` (a licensed manifest), `output`, `output_format`,
`timeout`, `max_download_bytes`, `max_zip_members`,
`max_zip_member_bytes`, `max_zip_total_bytes`,
`max_zip_compression_ratio`, and `allow_private_sources`.
See `config.example.toml` for a complete example.

Relative local source, manifest, and output paths in TOML resolve from the
configuration directory. CLI and environment paths resolve from the working
directory. Explicit CLI values override explicit non-empty environment values,
then TOML, then built-in defaults. Source lists preserve the existing additive
behavior: CLI sources are added to the environment source list, or the TOML
source list when `SOURCE_URLS` is unset. A selected source manifest is added
and retains its required license and checksum validation.

Unknown configuration fields, incorrect types, non-positive limits and
non-finite ratios are rejected before sources are processed. Use
`--no-allow-private-sources` to explicitly disable that option even if the
configuration enables it.

## Saved processing reports

Use `--report-file ./output/run-report.json`, `REPORT_FILE`, or
`report_file` in the TOML `[runtime]` section to save a JSON report.
The report is replaced atomically and cannot target the denylist, local source,
selected manifest, or configuration file (including aliases).

Schema version 1 is documented in [the report format](docs/RUN_REPORT.md).
Successful reports contain counts, source metadata, findings with line
provenance, removed entries, warnings, processing settings and the SHA-256 of
the exact output bytes. URLs are redacted. Reports contain source data and
local paths: keep them private when appropriate.

Failures during source processing or output writing produce a failed report;
configuration/argument validation and unsafe report paths fail before report
creation. Completed sources are listed, but incomplete results must not be
used as a denylist. If saving the report fails after a successful run, the
command fails but the new denylist is already written. A failed processing run
preserves the previous valid denylist.

## Comparing with the previous list

Each run compares its candidate with the existing output before replacement.
The terminal and JSON report distinguish added/removed entries from actual
changes in covered addresses. Replacing a /24 with two equivalent /25 entries
changes the entries but not the blocked address space. IPv4 and IPv6 are
measured independently, without expanding networks into individual addresses.

To reject excessive loss of previous coverage:

```toml
[processing]
max_ipv4_removal_percent = 10.0
max_ipv6_removal_percent = 10.0
```

These optional settings also have CLI flags `--max-ipv4-removal-percent` and
`--max-ipv6-removal-percent`, and environment variables
`MAX_IPV4_REMOVAL_PERCENT` and `MAX_IPV6_REMOVAL_PERCENT`.
Values must be finite and between 0 and 100. Defaults disable the safeguards.
Loss strictly greater than the limit rejects the candidate and preserves the
previous output. Exactly meeting the limit is allowed; zero rejects any loss.
Added addresses elsewhere do not compensate for removed addresses. This
measures lost previous coverage, not the net decrease in address count.

Without previous output, the report identifies a first run and skips the limits.
An existing empty list is a valid zero-coverage baseline. Invalid or unreadable
previous output causes a failure rather than an unreliable comparison.
Back up and repair such a baseline before retrying.

The comparison uses the existing plain-text output and cannot tell why a source
changed or whether its addresses are appropriate. Avoid simultaneous runs
against the same output: comparison and replacement are not locked together.
IPv6 counts in JSON may exceed JavaScript's exact number range; consumers must
preserve large integers.

## Licensed source manifest

For repeatable runs, copy `sources.example.toml` to a private configuration
location and describe each permitted source:

```toml
version = 1

[[sources]]
location = "./my-permitted-list.txt"
license = "CC0-1.0"
license_url = "https://creativecommons.org/publicdomain/zero/1.0/"
sha256 = "<64 lowercase hexadecimal characters>"
allowed_use = "Redistribution and derived use permitted."
```

Run it with `python3 deny_ip_toolkit.py --sources-file ./sources.toml`, or set
`SOURCES_FILE`. Relative local paths are resolved from the manifest directory.
Every entry must contain all five metadata fields. The complete manifest is
validated before source processing starts, and each downloaded or local file
must match its SHA-256 checksum before it is parsed or extracted.
Generate that value with `sha256sum FILE` on Linux or `shasum -a 256 FILE` on
macOS.

Direct `--source` and `SOURCE_URLS` inputs remain available for ad-hoc use, but
they do not provide the manifest's provenance and integrity guarantees.

## Resource limits

Remote and archived inputs are treated as untrusted. The default limits are:

- 50 MiB per remote download;
- 1,000 files per ZIP archive;
- 25 MiB per expanded ZIP member;
- 100 MiB expanded data per ZIP archive; and
- a maximum ZIP compression ratio of 100:1 per member.

The command-line options `--max-download-bytes`, `--max-zip-members`,
`--max-zip-member-bytes`, `--max-zip-total-bytes`, and
`--max-zip-compression-ratio` override these defaults. The equivalent Docker
environment variables use the same uppercase names, for example
`MAX_DOWNLOAD_BYTES=10485760`. If an input violates a limit, the run fails
before replacing an existing output file.

## Remote-source safety

Every remote hostname is resolved before download. By default, the tool rejects
destinations that are not globally reachable, including loopback, private,
link-local, shared, reserved, and unspecified addresses. Redirect targets are
checked using the same policy. Credentials, query values, and fragments are
removed from error messages so signed URLs and tokens are not exposed.

For an intentionally trusted source on an internal network, use
`--allow-private-sources` or set `ALLOW_PRIVATE_SOURCES=true`. This opt-in
weakens SSRF protection and should not be used with untrusted source URLs.

## Docker

Copy `.env.example` to `.env`, configure sources you are permitted to use, and
optionally copy `config.example.toml` to `config/config.toml` and set
`CONFIG_FILE=/app/config/config.toml` in `.env`. Then run:

```bash
docker compose up --build
```

The generated list is written to `./output/deny-ip-list.txt`.
Docker Compose passes unset overrides as empty values, allowing TOML and the
tool's defaults to take effect. When specifying output in container TOML, use
`/app/output/deny-ip-list.txt` or a relative path that resolves into the mounted
output directory.

## Data and licensing

This repository is licensed under MIT. That licence applies to the software,
not to data processed with it. You are responsible for complying with the
licence and terms of every input source. Do not commit private, paid,
personal-use-only, or redistribution-restricted lists to this repository.
Manifest metadata records those terms; it does not grant additional rights.

## Development

```bash
python3 -m pip install --requirement requirements.txt
python3 -m unittest -v
python3 -m pip install --requirement requirements-dev.txt
ruff check .
ruff format --check .
bandit --recursive -ll deny_ip_toolkit.py
```

The project is currently at version `0.1.0`. See the
[roadmap](ROADMAP.md), [changelog](CHANGELOG.md),
[contribution guide](CONTRIBUTING.md), and [security policy](SECURITY.md).
