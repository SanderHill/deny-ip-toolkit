"""Build a deterministic source archive from exactly the checked-out commit."""

from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import subprocess
from pathlib import Path


def read_version(root: Path) -> str:
    module = ast.parse((root / "deny_ip_toolkit.py").read_text(encoding="utf-8"))
    for statement in module.body:
        if isinstance(statement, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "__version__"
            for target in statement.targets
        ):
            value = ast.literal_eval(statement.value)
            if isinstance(value, str):
                return value
    raise ValueError("a static __version__ string is required")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--expected-version")
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    version = read_version(root)
    if arguments.expected_version and arguments.expected_version != version:
        parser.error("version does not match the selected release tag")
    prefix = f"deny-ip-toolkit-{version}/"
    archive = subprocess.run(
        ["git", "archive", "--format=tar", f"--prefix={prefix}", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout
    # A zero gzip timestamp and empty filename make repeated builds byte-identical.
    compressed = gzip.compress(archive, mtime=0)
    arguments.output_dir.mkdir(parents=True, exist_ok=True)
    name = f"deny-ip-toolkit-{version}.tar.gz"
    (arguments.output_dir / name).write_bytes(compressed)
    digest = hashlib.sha256(compressed).hexdigest()
    (arguments.output_dir / "SHA256SUMS").write_text(
        f"{digest}  {name}\n", encoding="ascii"
    )
    print(f"{name} {digest}")


if __name__ == "__main__":
    main()
