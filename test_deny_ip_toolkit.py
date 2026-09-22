import hashlib
import io
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from deny_ip_toolkit import (
    SafeRedirectHandler,
    SourceError,
    SourceSpec,
    __version__,
    candidate_files,
    load_source_manifest,
    normalize,
    read_source,
    redact_source,
    source_name,
    validate_remote_url,
)


class FakeResponse(io.BytesIO):
    def __init__(self, data: bytes, content_length: str | None = None):
        super().__init__(data)
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = content_length


class InterruptedResponse(FakeResponse):
    def __init__(self, data: bytes):
        super().__init__(data)
        self.read_count = 0

    def read(self, size=-1):
        self.read_count += 1
        if self.read_count > 1:
            raise OSError("connection interrupted")
        return super().read(min(size, 4))


class DenyIpToolkitTests(unittest.TestCase):
    @staticmethod
    def resolution(address: str, port: int = 443):
        family = 10 if ":" in address else 2
        return [(family, 1, 6, "", (address, port))]

    def test_version(self):
        self.assertEqual(__version__, "0.1.0")

    def test_combines_sorts_and_deduplicates_local_sources(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            first = root / "first.txt"
            second = root / "second.txt"
            output = root / "output" / "list.txt"
            first.write_text("8.8.8.8\n1.1.1.1\ninvalid\n", encoding="utf-8")
            second.write_text("1.1.1.1\n2001:db8::1\n", encoding="utf-8")
            self.assertEqual(normalize([str(first), str(second)], output), 3)
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                "1.1.1.1\n8.8.8.8\n2001:db8::1\n",
            )

    def test_normalizes_and_preserves_ipv4_and_ipv6_cidrs(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "networks.txt"
            output = root / "out.txt"
            source.write_text(
                "192.0.2.99/24\n192.0.2.0/24\n192.0.2.1\n"
                "2001:db8::1234/64\n2001:db8::/64\n",
                encoding="utf-8",
            )
            self.assertEqual(normalize([str(source)], output), 3)
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                "192.0.2.0/24\n192.0.2.1\n2001:db8::/64\n",
            )

    def test_loads_complete_manifest_and_resolves_local_location(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "list.txt"
            source.write_text("1.1.1.1\n", encoding="utf-8")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            manifest = root / "sources.toml"
            manifest.write_text(
                "version = 1\n"
                "[[sources]]\n"
                'location = "list.txt"\n'
                'license = "CC0-1.0"\n'
                'license_url = "https://creativecommons.org/publicdomain/zero/1.0/"\n'
                f'sha256 = "{digest}"\n'
                'allowed_use = "Redistribution permitted."\n',
                encoding="utf-8",
            )
            specs = load_source_manifest(manifest)
            self.assertEqual(specs[0].location, str(source.resolve()))
            output = root / "out.txt"
            self.assertEqual(normalize(specs, output), 1)
            self.assertEqual(output.read_text(encoding="utf-8"), "1.1.1.1\n")

    def test_rejects_incomplete_manifest_before_processing(self):
        with tempfile.TemporaryDirectory() as folder:
            manifest = Path(folder) / "sources.toml"
            manifest.write_text(
                'version = 1\n[[sources]]\nlocation = "list.txt"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(SourceError, "missing"):
                load_source_manifest(manifest)

    def test_rejects_manifest_with_invalid_checksum_format(self):
        with tempfile.TemporaryDirectory() as folder:
            manifest = Path(folder) / "sources.toml"
            manifest.write_text(
                "version = 1\n"
                "[[sources]]\n"
                'location = "list.txt"\n'
                'license = "CC0-1.0"\n'
                'license_url = "https://example.test/license"\n'
                'sha256 = "not-a-digest"\n'
                'allowed_use = "Permitted."\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(SourceError, "invalid SHA-256"):
                load_source_manifest(manifest)

    def test_rejects_invalid_manifest_checksum(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "list.txt"
            output = root / "out.txt"
            source.write_text("1.1.1.1\n", encoding="utf-8")
            output.write_text("9.9.9.9\n", encoding="utf-8")
            spec = SourceSpec(str(source), sha256="0" * 64)
            with self.assertRaisesRegex(SourceError, "checksum mismatch"):
                normalize([spec], output)
            self.assertEqual(output.read_text(encoding="utf-8"), "9.9.9.9\n")

    def test_extracts_safe_zip(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            archive = root / "source.zip"
            with zipfile.ZipFile(archive, "w") as zipped:
                zipped.writestr("nested/list.txt", "9.9.9.9\n")
            output = root / "out.txt"
            self.assertEqual(normalize([str(archive)], output), 1)
            self.assertEqual(output.read_text(encoding="utf-8"), "9.9.9.9\n")

    def test_rejects_zip_path_traversal(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            archive = root / "source.zip"
            with zipfile.ZipFile(archive, "w") as zipped:
                zipped.writestr("../outside.txt", "9.9.9.9\n")
            with self.assertRaises(SourceError):
                candidate_files(archive, root / "extract")

    def test_rejects_download_declared_over_limit(self):
        with tempfile.TemporaryDirectory() as folder:
            response = FakeResponse(b"1.1.1.1\n", content_length="100")
            opener = mock.Mock()
            opener.open.return_value = response
            with (
                mock.patch("deny_ip_toolkit.validate_remote_url"),
                mock.patch("urllib.request.build_opener", return_value=opener),
            ):
                with self.assertRaisesRegex(SourceError, "download limit"):
                    read_source(
                        "https://example.test/list.txt",
                        Path(folder),
                        timeout=1,
                        max_download_bytes=10,
                    )

    def test_rejects_streamed_download_over_limit(self):
        with tempfile.TemporaryDirectory() as folder:
            response = FakeResponse(b"1.1.1.1\n2.2.2.2\n")
            opener = mock.Mock()
            opener.open.return_value = response
            with (
                mock.patch("deny_ip_toolkit.validate_remote_url"),
                mock.patch("urllib.request.build_opener", return_value=opener),
            ):
                with self.assertRaisesRegex(SourceError, "download limit"):
                    read_source(
                        "https://example.test/list.txt",
                        Path(folder),
                        timeout=1,
                        max_download_bytes=10,
                    )

    def test_redacts_credentials_query_and_fragment(self):
        source = "https://user:password@example.test/list.txt?token=secret#section"
        self.assertEqual(
            redact_source(source),
            "https://example.test/list.txt?redacted",
        )

    def test_remote_source_name_cannot_escape_working_directory(self):
        self.assertEqual(source_name("https://example.test/.."), "download")
        self.assertEqual(source_name("https://example.test/."), "download")

    def test_accepts_globally_reachable_destination(self):
        with mock.patch(
            "socket.getaddrinfo", return_value=self.resolution("93.184.216.34")
        ):
            validate_remote_url("https://example.test/list.txt")

    def test_rejects_private_loopback_and_link_local_destinations(self):
        for address in ("10.0.0.1", "127.0.0.1", "169.254.1.1", "::1", "fe80::1"):
            with self.subTest(address=address):
                with mock.patch(
                    "socket.getaddrinfo", return_value=self.resolution(address)
                ):
                    with self.assertRaisesRegex(SourceError, "non-public address"):
                        validate_remote_url("https://example.test/list.txt")

    def test_rejects_mixed_public_and_private_dns_results(self):
        results = [
            *self.resolution("93.184.216.34"),
            *self.resolution("127.0.0.1"),
        ]
        with mock.patch("socket.getaddrinfo", return_value=results):
            with self.assertRaisesRegex(SourceError, "non-public address"):
                validate_remote_url("https://example.test/list.txt")

    def test_allows_explicitly_trusted_private_destination(self):
        with mock.patch(
            "socket.getaddrinfo", return_value=self.resolution("192.168.1.10")
        ):
            validate_remote_url(
                "https://internal.example.test/list.txt",
                allow_private_sources=True,
            )

    def test_redirects_are_validated(self):
        handler = SafeRedirectHandler(allow_private_sources=False)
        request = mock.Mock()
        with mock.patch("deny_ip_toolkit.validate_remote_url") as validate:
            with mock.patch.object(
                handler.__class__.__mro__[1],
                "redirect_request",
                return_value=mock.Mock(),
            ):
                handler.redirect_request(
                    request,
                    mock.Mock(),
                    302,
                    "Found",
                    {},
                    "https://redirect.example/list.txt",
                )
        validate.assert_called_once_with("https://redirect.example/list.txt", False)

    def test_redirect_to_private_destination_is_rejected(self):
        class RedirectingOpener:
            def __init__(self, handler):
                self.handler = handler

            def open(self, request, timeout):
                return self.handler.redirect_request(
                    request,
                    mock.Mock(),
                    302,
                    "Found",
                    {},
                    "https://private.example.test/list.txt",
                )

        def resolve(host, *args, **kwargs):
            address = "127.0.0.1" if host == "private.example.test" else "93.184.216.34"
            return self.resolution(address)

        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "out.txt"
            output.write_text("9.9.9.9\n", encoding="utf-8")
            with (
                mock.patch("socket.getaddrinfo", side_effect=resolve),
                mock.patch(
                    "urllib.request.build_opener",
                    side_effect=lambda handler: RedirectingOpener(handler),
                ),
            ):
                with self.assertRaisesRegex(SourceError, "non-public address"):
                    normalize(["https://example.test/list.txt"], output, timeout=1)
            self.assertEqual(output.read_text(encoding="utf-8"), "9.9.9.9\n")

    def test_timeout_preserves_existing_output_and_redacts_url(self):
        source = "https://user:password@example.test/list.txt?token=secret"
        output_contents = "9.9.9.9\n"
        opener = mock.Mock()
        opener.open.side_effect = TimeoutError("token=secret")
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "out.txt"
            output.write_text(output_contents, encoding="utf-8")
            with (
                mock.patch("deny_ip_toolkit.validate_remote_url"),
                mock.patch("urllib.request.build_opener", return_value=opener),
            ):
                with self.assertRaises(SourceError) as raised:
                    normalize([source], output, timeout=1)
            self.assertEqual(output.read_text(encoding="utf-8"), output_contents)
        message = str(raised.exception)
        self.assertIn("https://example.test/list.txt?redacted", message)
        self.assertNotIn("password", message)
        self.assertNotIn("token=secret", message)

    def test_interrupted_download_preserves_existing_output(self):
        opener = mock.Mock()
        opener.open.return_value = InterruptedResponse(b"1.1.1.1\n")
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "out.txt"
            output.write_text("9.9.9.9\n", encoding="utf-8")
            with (
                mock.patch("deny_ip_toolkit.validate_remote_url"),
                mock.patch("urllib.request.build_opener", return_value=opener),
            ):
                with self.assertRaisesRegex(SourceError, "could not download"):
                    normalize(["https://example.test/list.txt"], output, timeout=1)
            self.assertEqual(output.read_text(encoding="utf-8"), "9.9.9.9\n")

    def test_rejects_incomplete_content_length(self):
        opener = mock.Mock()
        opener.open.return_value = FakeResponse(b"1.1.1.1\n", content_length="100")
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "out.txt"
            output.write_text("9.9.9.9\n", encoding="utf-8")
            with (
                mock.patch("deny_ip_toolkit.validate_remote_url"),
                mock.patch("urllib.request.build_opener", return_value=opener),
            ):
                with self.assertRaisesRegex(SourceError, "Content-Length"):
                    normalize(["https://example.test/list.txt"], output, timeout=1)
            self.assertEqual(output.read_text(encoding="utf-8"), "9.9.9.9\n")

    def test_download_error_does_not_expose_url_secrets(self):
        source = "https://user:password@example.test/list.txt?token=secret"
        opener = mock.Mock()
        opener.open.side_effect = OSError("failure included token=secret")
        with tempfile.TemporaryDirectory() as folder:
            with (
                mock.patch("deny_ip_toolkit.validate_remote_url"),
                mock.patch("urllib.request.build_opener", return_value=opener),
            ):
                with self.assertRaises(SourceError) as raised:
                    read_source(source, Path(folder), timeout=1)
        message = str(raised.exception)
        self.assertIn("https://example.test/list.txt?redacted", message)
        self.assertNotIn("password", message)
        self.assertNotIn("token=secret", message)

    def test_rejects_zip_over_member_limit(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            archive = root / "source.zip"
            with zipfile.ZipFile(archive, "w") as zipped:
                zipped.writestr("one.txt", "1.1.1.1\n")
                zipped.writestr("two.txt", "2.2.2.2\n")
            with self.assertRaisesRegex(SourceError, "member limit"):
                candidate_files(archive, root / "extract", max_members=1)

    def test_rejects_zip_over_expanded_size_limit(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            archive = root / "source.zip"
            with zipfile.ZipFile(archive, "w") as zipped:
                zipped.writestr("list.txt", "1.1.1.1\n")
            with self.assertRaisesRegex(SourceError, "expanded-size limit"):
                candidate_files(archive, root / "extract", max_total_bytes=4)

    def test_rejects_suspicious_zip_compression_ratio(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            archive = root / "source.zip"
            with zipfile.ZipFile(
                archive, "w", compression=zipfile.ZIP_DEFLATED
            ) as zipped:
                zipped.writestr("zeros.txt", "0" * 10_000)
            with self.assertRaisesRegex(SourceError, "compression-ratio limit"):
                candidate_files(
                    archive,
                    root / "extract",
                    max_member_bytes=20_000,
                    max_total_bytes=20_000,
                    max_compression_ratio=2,
                )

    def test_rejects_corrupt_zip_and_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            archive = root / "source.zip"
            output = root / "out.txt"
            archive.write_bytes(b"PK\x03\x04truncated")
            output.write_text("9.9.9.9\n", encoding="utf-8")
            with self.assertRaisesRegex(SourceError, "not a valid ZIP"):
                normalize([str(archive)], output)
            self.assertEqual(output.read_text(encoding="utf-8"), "9.9.9.9\n")

    def test_rejects_encrypted_zip_member(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            archive = root / "source.zip"
            with zipfile.ZipFile(archive, "w") as zipped:
                zipped.writestr("list.txt", "1.1.1.1\n")
            data = bytearray(archive.read_bytes())
            for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
                position = data.index(signature)
                flags = int.from_bytes(
                    data[position + flag_offset : position + flag_offset + 2],
                    "little",
                )
                data[position + flag_offset : position + flag_offset + 2] = (
                    flags | 0x1
                ).to_bytes(2, "little")
            archive.write_bytes(data)
            output = root / "out.txt"
            output.write_text("9.9.9.9\n", encoding="utf-8")
            with self.assertRaisesRegex(SourceError, "encrypted member"):
                normalize([str(archive)], output)
            self.assertEqual(output.read_text(encoding="utf-8"), "9.9.9.9\n")

    def test_local_read_failure_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "source.txt"
            output = root / "out.txt"
            source.write_text("1.1.1.1\n", encoding="utf-8")
            output.write_text("9.9.9.9\n", encoding="utf-8")
            original_read_text = Path.read_text

            def fail_source_read(path, *args, **kwargs):
                if path == source:
                    raise OSError("read failed")
                return original_read_text(path, *args, **kwargs)

            with mock.patch.object(Path, "read_text", fail_source_read):
                with self.assertRaisesRegex(SourceError, "could not read source file"):
                    normalize([str(source)], output)
            self.assertEqual(original_read_text(output), "9.9.9.9\n")

    def test_limit_failure_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            archive = root / "source.zip"
            output = root / "out.txt"
            output.write_text("9.9.9.9\n", encoding="utf-8")
            with zipfile.ZipFile(archive, "w") as zipped:
                zipped.writestr("list.txt", "1.1.1.1\n")
            with self.assertRaisesRegex(SourceError, "member limit"):
                normalize([str(archive)], output, max_zip_members=0)
            self.assertEqual(output.read_text(encoding="utf-8"), "9.9.9.9\n")

    def test_requires_a_source(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(SourceError, "at least one source"):
                normalize([], Path(folder) / "out.txt")


if __name__ == "__main__":
    unittest.main()
