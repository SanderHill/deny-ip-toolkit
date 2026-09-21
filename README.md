# Deny IP Toolkit

[![GitHub release](https://img.shields.io/github/v/release/SanderHill/deny-ip-toolkit)](https://github.com/SanderHill/deny-ip-toolkit/releases)
[![CI](https://github.com/SanderHill/deny-ip-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/SanderHill/deny-ip-toolkit/actions/workflows/ci.yml)
[![CodeQL](https://github.com/SanderHill/deny-ip-toolkit/actions/workflows/codeql.yml/badge.svg)](https://github.com/SanderHill/deny-ip-toolkit/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)

A small, local-first tool for combining and normalizing IP blocklists. It reads
local files or explicitly configured HTTP(S) sources, validates IPv4 and IPv6
addresses, removes duplicates, and writes a deterministic list.

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

## Docker

Copy `.env.example` to `.env`, configure sources you are permitted to use, and
run:

```bash
docker compose up --build
```

The generated list is written to `./output/deny-ip-list.txt`.

## Data and licensing

This repository is licensed under MIT. That licence applies to the software,
not to data processed with it. You are responsible for complying with the
licence and terms of every input source. Do not commit private, paid,
personal-use-only, or redistribution-restricted lists to this repository.

## Development

```bash
python3 -m unittest -v
python3 -m pip install --requirement requirements-dev.txt
ruff check .
ruff format --check .
bandit --recursive -ll deny_ip_toolkit.py
```

The project is currently at version `0.1.0`. See the
[roadmap](ROADMAP.md), [changelog](CHANGELOG.md),
[contribution guide](CONTRIBUTING.md), and [security policy](SECURITY.md).
