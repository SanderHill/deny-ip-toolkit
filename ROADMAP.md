# Roadmap

Deny IP Toolkit aims to become a trustworthy, local-first pipeline for working
with blocklists whose terms permit the intended use. The roadmap is ordered by
risk reduction and user value, not by promised delivery dates.

## Now: harden untrusted input

- Stream downloads and enforce configurable size limits.
- Bound ZIP member count, expanded size, and compression ratio.
- Redact credentials and query parameters from errors and logs.
- Add opt-in controls for private-network and localhost sources.
- Test redirects, timeouts, malformed archives, and failure recovery.

## Next: improve interoperability and provenance

- Support IPv4 and IPv6 CIDR networks.
- Add a source manifest with license, checksum, and provenance metadata.
- Add a configuration file for Docker and scheduled use.
- Support Synology, ipset, nftables, CSV, and JSON output formats.
- Produce a machine-readable run summary and content hashes.

## Later: maintenance automation

- Add continuous integration across supported Python versions.
- Add static analysis, dependency review, and security scanning.
- Publish versioned container images and reproducible release artifacts.
- Add conditional downloads using ETag and Last-Modified metadata.

Ideas and contributions are welcome through
[GitHub Issues](https://github.com/SanderHill/deny-ip-toolkit/issues).
