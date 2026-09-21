import io
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from deny_ip_toolkit import (
    SourceError,
    __version__,
    candidate_files,
    normalize,
    read_source,
)


class FakeResponse(io.BytesIO):
    def __init__(self, data: bytes, content_length: str | None = None):
        super().__init__(data)
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = content_length


class DenyIpToolkitTests(unittest.TestCase):
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
            with mock.patch("urllib.request.urlopen", return_value=response):
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
            with mock.patch("urllib.request.urlopen", return_value=response):
                with self.assertRaisesRegex(SourceError, "download limit"):
                    read_source(
                        "https://example.test/list.txt",
                        Path(folder),
                        timeout=1,
                        max_download_bytes=10,
                    )

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
