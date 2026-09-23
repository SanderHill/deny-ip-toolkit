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
optionally copy `config.example.toml` to `config/config.toml`. Then run:

```bash
docker compose up --build
```

The generated list is written to `./output/deny-ip-list.txt`.

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
