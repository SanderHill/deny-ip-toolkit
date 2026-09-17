import tempfile
import unittest
import zipfile
from pathlib import Path

from deny_ip_toolkit import SourceError, candidate_files, normalize


class DenyIpToolkitTests(unittest.TestCase):
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

    def test_requires_a_source(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(SourceError, "at least one source"):
                normalize([], Path(folder) / "out.txt")


if __name__ == "__main__":
    unittest.main()

