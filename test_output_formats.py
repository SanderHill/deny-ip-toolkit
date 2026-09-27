import hashlib
import io
import ipaddress
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from deny_ip_toolkit import (
    SourceError,
    build_parser,
    normalize,
    resolve_runtime_settings,
)
from output_formats import OUTPUT_FORMATS, read_export, render_output


class OutputFormatTests(unittest.TestCase):
    @staticmethod
    def entries(*values):
        return {
            ipaddress.ip_network(value) if "/" in value else ipaddress.ip_address(value)
            for value in values
        }

    def test_plain_text_default_unchanged(self):
        entries = self.entries("2001:db8::1", "192.0.2.3", "192.0.2.0/24")
        self.assertEqual(
            render_output(entries, "text"), "192.0.2.0/24\n192.0.2.3\n2001:db8::1\n"
        )

    def test_all_formats_round_trip_and_deterministic(self):
        for fmt in OUTPUT_FORMATS:
            with self.subTest(format=fmt):
                entries = self.entries("192.0.2.3", "192.0.2.1")
                if fmt != "synology":
                    entries |= self.entries(
                        "192.0.2.0/24", "2001:db8::1", "2001:db8::/64"
                    )
                rendered = render_output(entries, fmt)
                self.assertEqual(read_export(rendered, fmt), entries)
                self.assertEqual(
                    rendered, render_output(list(reversed(list(entries))), fmt)
                )

    def test_csv_fixture(self):
        self.assertEqual(
            render_output(self.entries("192.0.2.1", "2001:db8::/64"), "csv"),
            "entry,family,kind\n192.0.2.1,ipv4,address\n2001:db8::/64,ipv6,network\n",
        )

    def test_json_is_not_run_report(self):
        data = json.loads(render_output(self.entries("192.0.2.1"), "json"))
        self.assertEqual(
            data, {"schema_version": 1, "kind": "denylist", "entries": ["192.0.2.1"]}
        )
        with self.assertRaises(ValueError):
            read_export('{"schema_version": 1, "status": "success"}', "json")

    def test_ipset_fixture(self):
        self.assertEqual(
            render_output(self.entries("192.0.2.1", "2001:db8::/64"), "ipset"),
            "# deny-ip-toolkit export v1 ipset\n"
            "# entry 192.0.2.1\n# entry 2001:db8::/64\n"
            "create deny_ip4 hash:net family inet maxelem 65536\n"
            "add deny_ip4 192.0.2.1/32\n"
            "create deny_ip6 hash:net family inet6 maxelem 65536\n"
            "add deny_ip6 2001:db8::/64\n",
        )

    def test_nftables_fixture_collapses_coverage_without_expansion(self):
        self.assertEqual(
            render_output(self.entries("192.0.2.0/24", "192.0.2.1"), "nftables"),
            "# deny-ip-toolkit export v1 nftables\n"
            "# entry 192.0.2.0/24\n# entry 192.0.2.1\n"
            "table inet deny_ip_toolkit {\n"
            "    set deny_ip4 {\n        type ipv4_addr;\n        flags interval;\n"
            "        elements = { 192.0.2.0/24 };\n    }\n"
            "    set deny_ip6 {\n        type ipv6_addr;\n        flags interval;\n    }\n}\n",
        )

    def test_nftables_ipv6_universe_and_adjacent_hosts(self):
        rendered = render_output(
            self.entries("::/0", "192.0.2.0", "192.0.2.1"), "nftables"
        )
        self.assertIn("elements = { ::/0 };", rendered)
        self.assertIn("elements = { 192.0.2.0/31 };", rendered)

    def test_ipset_rejects_zero_prefix(self):
        for value in ("0.0.0.0/0", "::/0"):
            with self.assertRaisesRegex(ValueError, "/0"):
                render_output(self.entries(value), "ipset")

    def test_synology_conservative_subset(self):
        self.assertEqual(
            render_output(self.entries("192.0.2.1"), "synology"), "192.0.2.1\n"
        )
        for value in ("192.0.2.0/24", "192.0.2.1/32", "2001:db8::1"):
            with self.assertRaisesRegex(ValueError, "individual IPv4"):
                render_output(self.entries(value), "synology")

    def test_modified_exports_rejected(self):
        for fmt in ("json", "csv", "ipset", "nftables"):
            with self.subTest(format=fmt):
                rendered = render_output(self.entries("192.0.2.1"), fmt)
                with self.assertRaises(ValueError):
                    read_export(rendered + "# unexpected\n", fmt)
        rendered = render_output(self.entries("192.0.2.1"), "ipset")
        with self.assertRaises(ValueError):
            read_export(
                rendered.replace("add deny_ip4 192.0.2.1", "add deny_ip4 192.0.2.2"),
                "ipset",
            )

    def test_ipset_equivalent_hosts_are_added_once(self):
        entries = self.entries(
            "192.0.2.1", "192.0.2.1/32", "2001:db8::1", "2001:db8::1/128"
        )
        rendered = render_output(entries, "ipset")
        self.assertEqual(rendered.count("add deny_ip4 192.0.2.1/32\n"), 1)
        self.assertEqual(rendered.count("add deny_ip6 2001:db8::1/128\n"), 1)
        self.assertEqual(read_export(rendered, "ipset"), entries)

    def test_empty_exports(self):
        for fmt in OUTPUT_FORMATS:
            self.assertEqual(read_export(render_output(set(), fmt), fmt), set())

    def test_all_formats_normalize_report_compare_and_reject_loss(self):
        for fmt in OUTPUT_FORMATS:
            with self.subTest(format=fmt), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source, output, report = (
                    root / "source",
                    root / "output",
                    root / "report",
                )
                source.write_text("192.0.2.1\n192.0.2.2\n")
                normalize(
                    [str(source)],
                    output,
                    output_format=fmt,
                    report_file=report,
                    report_stream=io.StringIO(),
                )
                previous = output.read_bytes()
                data = json.loads(report.read_text())
                self.assertEqual(data["output"]["format"], fmt)
                self.assertEqual(
                    data["output"]["sha256"], hashlib.sha256(previous).hexdigest()
                )
                normalize(
                    [str(source)],
                    output,
                    output_format=fmt,
                    max_ipv4_removal_percent=0,
                    report_stream=io.StringIO(),
                )
                self.assertEqual(output.read_bytes(), previous)
                source.write_text("192.0.2.1\n")
                with self.assertRaises(SourceError):
                    normalize(
                        [str(source)],
                        output,
                        output_format=fmt,
                        max_ipv4_removal_percent=0,
                        report_stream=io.StringIO(),
                    )
                self.assertEqual(output.read_bytes(), previous)

    def test_unsupported_export_preserves_previous_output(self):
        for fmt, value in (("synology", "2001:db8::1"), ("ipset", "::/0")):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source, output = root / "source", root / "output"
                previous = render_output(self.entries("192.0.2.1"), fmt)
                output.write_text(previous)
                source.write_text(value + "\n")
                with self.assertRaises(SourceError):
                    normalize(
                        [str(source)],
                        output,
                        output_format=fmt,
                        report_stream=io.StringIO(),
                    )
                self.assertEqual(output.read_text(), previous)

    def test_wrong_baseline_format_is_not_silently_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "source", root / "output"
            source.write_text("192.0.2.1\n")
            output.write_text("192.0.2.1\n")
            with self.assertRaisesRegex(SourceError, "previous output"):
                normalize([str(source)], output, output_format="json")
            self.assertEqual(output.read_text(), "192.0.2.1\n")

    def test_configuration_precedence_and_invalid_value(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.dict(os.environ, {}, clear=True),
        ):
            config = Path(directory) / "config.toml"
            config.write_text('version = 1\n[runtime]\noutput_format = "csv"\n')
            args = build_parser().parse_args(["--config-file", str(config)])
            self.assertEqual(resolve_runtime_settings(args)["output_format"], "csv")
            with mock.patch.dict(os.environ, {"OUTPUT_FORMAT": "ipset"}):
                self.assertEqual(
                    resolve_runtime_settings(args)["output_format"], "ipset"
                )
                args = build_parser().parse_args(
                    ["--config-file", str(config), "--output-format", "json"]
                )
                self.assertEqual(
                    resolve_runtime_settings(args)["output_format"], "json"
                )
            with mock.patch.dict(os.environ, {"OUTPUT_FORMAT": "invalid"}):
                with self.assertRaises(SourceError):
                    resolve_runtime_settings(args)


if __name__ == "__main__":
    unittest.main()
