# Contributing

Contributions are welcome through issues and pull requests.

## Before you start

- Search existing issues before opening a new one.
- Use a security advisory rather than a public issue for vulnerabilities.
- Keep changes focused and explain the user-facing reason for them.
- Open an issue first for large changes or new output formats.

Please keep the repository free of blocklist data unless its licence expressly
allows redistribution and the data is essential to a test. Tests should use
documentation-only IP ranges or small synthetic fixtures.

Before submitting a change, run:

```bash
python3 -m unittest -v
python3 -m pip install --requirement requirements-dev.txt
ruff check .
ruff format --check .
bandit --recursive -ll deny_ip_toolkit.py
```

CI runs the tests on every supported Python version (3.10 through 3.14).
CodeQL analyzes pushes, pull requests, and the default branch weekly.

Pull requests should include tests for changed behavior and update the README or
changelog when users need to know about the change. Maintainers may request
changes when a contribution weakens source licensing, privacy, or local-first
behavior.

## Release model

The project uses semantic versioning. See [docs/RELEASING.md](docs/RELEASING.md)
for the maintainer checklist.
