# Install a fixed release

Version 0.2.0 ships as a deterministic source archive and a GHCR container
image. Only public source code, synthetic tests and examples are included; no
private or redistribution-restricted list, password or local output is bundled.
The release's `SHA256SUMS` and GitHub build attestations allow verification.

## Source archive

Download `deny-ip-toolkit-0.2.0.tar.gz` and `SHA256SUMS` from the
[v0.2.0 release](https://github.com/SanderHill/deny-ip-toolkit/releases/tag/v0.2.0).
In the directory containing both files:

```sh
sha256sum -c SHA256SUMS
gh attestation verify deny-ip-toolkit-0.2.0.tar.gz -R SanderHill/deny-ip-toolkit
tar -xzf deny-ip-toolkit-0.2.0.tar.gz
cd deny-ip-toolkit-0.2.0
python3 deny_ip_toolkit.py --version
```

Python 3.10–3.14 is supported. On Python 3.10, install `requirements.txt`
inside your virtual environment first. Configure only sources whose terms
permit your intended use. Run `python3 deny_ip_toolkit.py --help` for options.

## Container image

Images are published to `ghcr.io/sanderhill/deny-ip-toolkit` for `linux/amd64`
and `linux/arm64`. The image runs as a non-root `app` user, writes only to the
mounted output directory, and never applies firewall rules. Version tag
`v0.2.0` points to the release; `latest` moves with future releases. For
strict reproducibility, deploy the manifest digest shown on the
release page, e.g. `ghcr.io/sanderhill/deny-ip-toolkit@sha256:<digest>`.

```sh
docker pull ghcr.io/sanderhill/deny-ip-toolkit:v0.2.0
docker run --rm \
  -v "$PWD/input:/app/input:ro" -v "$PWD/output:/app/output" \
  ghcr.io/sanderhill/deny-ip-toolkit:v0.2.0 \
  --source /app/input/permitted-list.txt --output /app/output/deny-ip-list.txt
```

If your host maps users differently, ensure the mounted output directory is
writable by the container's non-root user; do not use `--user 0`. The release
workflow smoke-tests both architectures and confirms that the default UID is
not zero. A pull-only Compose deployment may replace `build: .` with
`image: ghcr.io/sanderhill/deny-ip-toolkit:v0.2.0`; keep existing volumes and
environment settings.

## Upgrade and rollback

Back up your configuration and output before changing versions. Pull the new
exact tag (or digest), run `--version`, then test with a small permitted local
list. Only after confirming the output should you update scheduled jobs. To
roll back, restore the previous image digest or source archive and your saved
configuration/output. Do not substitute `latest` for a rollback target.

Release tags are protected against updates and deletion. Release automation
refuses to publish an existing version again. The digest is the immutable
identity of a container image; an OCI tag by itself is only a convenient name.
Releases are built solely from a tagged commit on `main`. The checklist is:

1. Update `__version__`, changelog, release notes, README and example docs.
2. Merge the release PR after unit, lint and security checks.
3. Create the `vX.Y.Z` tag on that merge commit (never move it).
4. Confirm the workflow's source archive checksum/reproducibility and amd64/arm64
   non-root smoke tests before registry/release publication.
5. Confirm the release assets, SHA256SUMS, attestations, manifest digest and
   end-user installation commands; only then mark the issue complete.
