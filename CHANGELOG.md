# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Configurable limits for remote downloads, ZIP members, expanded archive
  sizes, and compression ratios.
- Streaming downloads and archive extraction to avoid unbounded in-memory
  reads.
- CI tests for Python 3.10 through 3.14, Ruff checks, Bandit scanning, CodeQL
  analysis, and automated dependency update checks.

### Planned

- Safer remote-source validation.
- CIDR input support and additional output formats.

## [0.1.0] - 2026-09-21

### Added

- Local and HTTP(S) blocklist inputs.
- ZIP archive support with path-traversal protection.
- IPv4 and IPv6 validation, deduplication, and deterministic sorting.
- Atomic local output writes.
- Docker and Docker Compose examples.
- Synthetic unit tests, an MIT license, contribution guidance, and a security
  policy.

[Unreleased]: https://github.com/SanderHill/deny-ip-toolkit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/SanderHill/deny-ip-toolkit/releases/tag/v0.1.0
