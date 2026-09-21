# Deny IP Toolkit

[![GitHub release](https://img.shields.io/github/v/release/SanderHill/deny-ip-toolkit)](https://github.com/SanderHill/deny-ip-toolkit/releases)
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
```

The project is currently at version `0.1.0`. See the
[roadmap](ROADMAP.md), [changelog](CHANGELOG.md),
[contribution guide](CONTRIBUTING.md), and [security policy](SECURITY.md).
