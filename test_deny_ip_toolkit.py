import hashlib
import io
import ipaddress
import json
import os
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
    build_parser,
    candidate_files,
    compare_outputs,
    configured_overlap_action,
    load_processing_config,
    load_runtime_config,
    load_source_manifest,
    main,
    normalize,
    read_source,
    redact_source,
    resolve_runtime_settings,
    save_run_report,
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
    def entries(*values):
        return {
            ipaddress.ip_network(value) if "/" in value else ipaddress.ip_address(value)
            for value in values
        }

    def test_equivalent_representations_have_no_coverage_loss(self):
        before = self.entries("192.0.2.0/24", "192.0.2.4", "2001:db8::/64")
        after = self.entries(
            "192.0.2.0/25",
            "192.0.2.128/25",
            "2001:db8::/65",
            "2001:db8:0:0:8000::/65",
        )
        comparison = compare_outputs(before, after)
        self.assertFalse(comparison["coverage_changed"])
        self.assertTrue(comparison["added_entries"])
        self.assertTrue(comparison["removed_entries"])
        self.assertEqual(comparison["coverage"]["ipv4"]["previous_addresses"], 256)
        self.assertEqual(comparison["coverage"]["ipv6"]["previous_addresses"], 2**64)
        for family in ("ipv4", "ipv6"):
            self.assertEqual(comparison["coverage"][family]["removed_addresses"], 0)

    def test_additions_do_not_mask_removed_coverage(self):
        comparison = compare_outputs(
            self.entries("192.0.2.0/24"),
            self.entries("192.0.2.0/25", "198.51.100.0/24"),
        )
        counts = comparison["coverage"]["ipv4"]
        self.assertEqual(counts["removed_addresses"], 128)
        self.assertEqual(counts["added_addresses"], 256)
        self.assertEqual(counts["removed_percent"], 50)

    def test_first_run_and_empty_baseline_are_distinct(self):
        current = self.entries("192.0.2.4")
        first = compare_outputs(None, current)
        empty = compare_outputs(set(), current)
        self.assertFalse(first["baseline_available"])
        self.assertIsNone(first["coverage_changed"])
        self.assertTrue(empty["baseline_available"])
        self.assertTrue(empty["coverage_changed"])
        self.assertEqual(empty["coverage"]["ipv4"]["removed_percent"], 0)

    def test_safeguard_rejection_report_and_recovery(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source, output, report = (
                root / "input.txt",
                root / "out.txt",
                root / "report.json",
            )
            output.write_text("192.0.2.0/24\n", encoding="utf-8")
            source.write_text("192.0.2.0/25\n", encoding="utf-8")
            with self.assertRaisesRegex(SourceError, "previous output preserved"):
                normalize(
                    [str(source)],
                    output,
                    report_file=report,
                    max_ipv4_removal_percent=49,
                )
            self.assertEqual(output.read_text(), "192.0.2.0/24\n")
            document = json.loads(report.read_text())
            self.assertEqual(document["status"], "failed")
            self.assertTrue(document["comparison"]["safeguard_rejected"])
            self.assertIsNone(document["output"])
            normalize(
                [str(source)], output, report_file=report, max_ipv4_removal_percent=50
            )
            document = json.loads(report.read_text())
            self.assertEqual(document["status"], "success")
            self.assertEqual(document["comparison"]["previous_entries"], 1)
            self.assertEqual(
                document["comparison"]["coverage"]["ipv4"]["removed_percent"], 50
            )
            self.assertEqual(output.read_text(), "192.0.2.0/25\n")

    def test_ipv6_safeguard_handles_large_counts_without_expansion(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source, output = root / "input.txt", root / "out.txt"
            output.write_text("::/0\n", encoding="utf-8")
            source.write_text("::/1\n", encoding="utf-8")
            with self.assertRaisesRegex(SourceError, "IPv6"):
                normalize([str(source)], output, max_ipv6_removal_percent=0)
            normalize([str(source)], output, max_ipv6_removal_percent=50)
            self.assertEqual(output.read_text(), "::/1\n")

    def test_corrupt_previous_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source, output = root / "input.txt", root / "out.txt"
            source.write_text("192.0.2.4\n", encoding="utf-8")
            output.write_text("broken baseline\n", encoding="utf-8")
            with self.assertRaisesRegex(SourceError, "previous output"):
                normalize([str(source)], output)
            self.assertEqual(output.read_text(), "broken baseline\n")

    def test_first_run_skips_limits_and_equivalent_change_passes_zero_limit(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source, output, report = (
                root / "input.txt",
                root / "out.txt",
                root / "report.json",
            )
            source.write_text("192.0.2.0/24\n", encoding="utf-8")
            normalize(
                [str(source)], output, report_file=report, max_ipv4_removal_percent=0
            )
            self.assertFalse(
                json.loads(report.read_text())["comparison"]["baseline_available"]
            )
            source.write_text("192.0.2.0/25\n192.0.2.128/25\n", encoding="utf-8")
            normalize(
                [str(source)], output, report_file=report, max_ipv4_removal_percent=0
            )
            document = json.loads(report.read_text())
            self.assertFalse(document["comparison"]["coverage_changed"])
            self.assertEqual(document["comparison"]["current_entries"], 2)

    def test_interval_comparison_matches_small_address_sets(self):
        candidates = [
            self.entries("192.0.2.0/29", "192.0.2.4/30"),
            self.entries("192.0.2.0/30", "192.0.2.8/30"),
            self.entries("192.0.2.2", "192.0.2.8"),
            set(),
        ]

        def expanded(entries):
            addresses = set()
            for entry in entries:
                if isinstance(entry, ipaddress.IPv4Network):
                    addresses.update(int(address) for address in entry)
                else:
                    addresses.add(int(entry))
            return addresses

        for before in candidates:
            for after in candidates:
                with self.subTest(before=before, after=after):
                    counts = compare_outputs(before, after)["coverage"]["ipv4"]
                    old, new = expanded(before), expanded(after)
                    self.assertEqual(counts["removed_addresses"], len(old - new))
                    self.assertEqual(counts["added_addresses"], len(new - old))

    def test_removal_limits_configuration_and_validation(self):
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / "config.toml"
            config.write_text(
                "version = 1\n[processing]\nmax_ipv4_removal_percent = 10.0\n"
                "max_ipv6_removal_percent = 0\n",
                encoding="utf-8",
            )
            with mock.patch.dict(
                os.environ, {"MAX_IPV4_REMOVAL_PERCENT": "20"}, clear=True
            ):
                settings = resolve_runtime_settings(
                    build_parser().parse_args(
                        [
                            "--config-file",
                            str(config),
                            "--max-ipv4-removal-percent",
                            "30",
                        ]
                    )
                )
                self.assertEqual(settings["max_ipv4_removal_percent"], 30)
                self.assertEqual(settings["max_ipv6_removal_percent"], 0)
                for invalid in ("nan", "-1", "101"):
                    with self.subTest(value=invalid):
                        with self.assertRaises(SourceError):
                            resolve_runtime_settings(
                                build_parser().parse_args(
                                    ["--max-ipv6-removal-percent", invalid]
                                )
                            )

    def test_failed_report_replacement_preserves_previous_report(self):
        with tempfile.TemporaryDirectory() as folder:
            report_file = Path(folder) / "report.json"
            report_file.write_text('{"status":"previous"}', encoding="utf-8")
            with mock.patch.object(
                Path, "replace", side_effect=OSError("write failed")
            ):
                with self.assertRaisesRegex(SourceError, "could not save run report"):
                    save_run_report(report_file, {"status": "success"})
            self.assertEqual(report_file.read_text(), '{"status":"previous"}')
            self.assertEqual(list(Path(folder).iterdir()), [report_file])

    def test_cli_rejects_report_targeting_configuration(self):
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / "config.toml"
            contents = 'version = 1\n[runtime]\nreport_file = "config.toml"\n'
            config.write_text(contents, encoding="utf-8")
            with (
                mock.patch.dict(os.environ, {}, clear=True),
                mock.patch("sys.argv", ["tool", "--config-file", str(config)]),
                mock.patch("sys.stderr", io.StringIO()),
            ):
                with self.assertRaises(SystemExit):
                    main()
            self.assertEqual(config.read_text(), contents)

    def test_json_reports_all_modes_and_exact_output_hash(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "input.txt"
            source.write_text(
                "192.0.2.0/24\n192.0.2.0/25\n192.0.2.4\n192.0.2.4\n",
                encoding="utf-8",
            )
            output = root / "out.txt"
            report_file = root / "report.json"
            for action, expected_count in [
                ("find", 3),
                ("remove_single_ips", 2),
                ("remove_ranges", 1),
            ]:
                with self.subTest(action=action):
                    normalize(
                        [str(source)],
                        output,
                        overlap_action=action,
                        report_file=report_file,
                    )
                    document = json.loads(report_file.read_text())
                    self.assertEqual(document["schema_version"], 1)
                    self.assertEqual(document["status"], "success")
                    self.assertEqual(
                        document["counts"]["output_entries"], expected_count
                    )
                    self.assertEqual(document["counts"]["exact_duplicates"], 1)
                    self.assertEqual(document["counts"]["nested_ranges"], 1)
                    self.assertEqual(
                        document["covered_ips"][0]["occurrences"][0]["line"], 3
                    )
                    self.assertEqual(
                        document["output"]["sha256"],
                        hashlib.sha256(output.read_bytes()).hexdigest(),
                    )
                    self.assertEqual(
                        bool(document["warnings"]), action == "remove_ranges"
                    )

    def test_failed_json_report_preserves_output_and_redacts_url(self):
        source = "https://user:password@example.test/list.txt?token=secret#private"
        opener = mock.Mock()
        opener.open.side_effect = TimeoutError("token=secret")
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            output = root / "out.txt"
            output.write_text("192.0.2.9\n", encoding="utf-8")
            report_file = root / "report.json"
            with (
                mock.patch("deny_ip_toolkit.validate_remote_url"),
                mock.patch("urllib.request.build_opener", return_value=opener),
            ):
                with self.assertRaises(SourceError):
                    normalize([source], output, report_file=report_file)
            document = json.loads(report_file.read_text())
            self.assertEqual(document["status"], "failed")
            self.assertIsNone(document["output"])
            self.assertIn("could not download", document["error"]["message"])
            for secret in ("password", "token=secret", "#private"):
                self.assertNotIn(secret, report_file.read_text())
            self.assertEqual(output.read_text(), "192.0.2.9\n")

    def test_report_cannot_overwrite_input_output_or_alias(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "input.txt"
            source.write_text("192.0.2.4\n", encoding="utf-8")
            output = root / "out.txt"
            output.write_text("192.0.2.9\n", encoding="utf-8")
            alias = root / "alias.json"
            alias.symlink_to(source)
            for target in (source, output, alias):
                with self.subTest(target=target):
                    with self.assertRaisesRegex(SourceError, "must not overwrite"):
                        normalize([str(source)], output, report_file=target)
            self.assertEqual(source.read_text(), "192.0.2.4\n")
            self.assertEqual(output.read_text(), "192.0.2.9\n")

    def test_report_file_cli_overrides_toml(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            config = root / "config.toml"
            config.write_text(
                'version = 1\n[runtime]\nreport_file = "report.json"\n',
                encoding="utf-8",
            )
            with mock.patch.dict(os.environ, {}, clear=True):
                settings = resolve_runtime_settings(
                    build_parser().parse_args(["--config-file", str(config)])
                )
                self.assertEqual(settings["report_file"], root / "report.json")
                settings = resolve_runtime_settings(
                    build_parser().parse_args(
                        [
                            "--config-file",
                            str(config),
                            "--report-file",
                            "cli.json",
                        ]
                    )
                )
                self.assertEqual(settings["report_file"], Path("cli.json"))

    def test_cli_config_run_uses_relative_manifest_and_checksum(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            source = root / "input.txt"
            source.write_text("192.0.2.0/24\n192.0.2.4\n", encoding="utf-8")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            manifest = root / "sources.toml"
            manifest.write_text(
                'version = 1\n[[sources]]\nlocation = "input.txt"\n'
                'license = "CC0-1.0"\nlicense_url = "https://example.test/license"\n'
                f'sha256 = "{digest}"\nallowed_use = "Test fixture"\n',
                encoding="utf-8",
            )
            config = root / "config.toml"
            config.write_text(
                'version = 1\n[runtime]\nsources_file = "sources.toml"\n'
                'output = "out.txt"\n[processing]\n'
                'overlap_action = "remove_single_ips"\n',
                encoding="utf-8",
            )
            with (
                mock.patch.dict(os.environ, {}, clear=True),
                mock.patch("sys.argv", ["tool", "--config-file", str(config)]),
                mock.patch("sys.stdout", io.StringIO()),
            ):
                self.assertEqual(main(), 0)
                self.assertEqual((root / "out.txt").read_text(), "192.0.2.0/24\n")
                source.write_text("192.0.2.9\n", encoding="utf-8")
                with mock.patch("sys.stderr", io.StringIO()):
                    with self.assertRaises(SystemExit):
                        main()
                self.assertEqual((root / "out.txt").read_text(), "192.0.2.0/24\n")

    def test_runtime_config_resolves_paths_and_precedence(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            config = root / "config.toml"
            config.write_text(
                'version = 1\n[runtime]\nsources = ["input.txt"]\n'
                'sources_file = "sources.toml"\noutput = "out.txt"\ntimeout = 12\n'
                "allow_private_sources = true\n[processing]\n"
                'overlap_action = "remove_ranges"\n',
                encoding="utf-8",
            )
            with mock.patch.dict(os.environ, {}, clear=True):
                args = build_parser().parse_args(["--config-file", str(config)])
                settings = resolve_runtime_settings(args)
                self.assertEqual(settings["sources"], [str(root / "input.txt")])
                self.assertEqual(settings["sources_file"], root / "sources.toml")
                self.assertEqual(settings["output"], root / "out.txt")
                self.assertEqual(settings["timeout"], 12)
                self.assertEqual(settings["overlap_action"], "remove_ranges")
                with mock.patch.dict(
                    os.environ,
                    {
                        "HTTP_TIMEOUT": "20",
                        "OVERLAP_ACTION": "",
                        "SOURCE_URLS": "env.txt",
                    },
                ):
                    args = build_parser().parse_args(
                        [
                            "--config-file",
                            str(config),
                            "--timeout",
                            "30",
                            "--source",
                            "cli.txt",
                            "--no-allow-private-sources",
                        ]
                    )
                    settings = resolve_runtime_settings(args)
                    self.assertEqual(settings["timeout"], 30)
                    self.assertEqual(settings["sources"], ["cli.txt", "env.txt"])
                    self.assertFalse(settings["allow_private_sources"])
                    self.assertEqual(settings["overlap_action"], "remove_ranges")

    def test_runtime_config_rejects_invalid_fields_even_when_overridden(self):
        invalid = [
            "version = true",
            "version = 1\nunknown = 3",
            "version = 1\n[runtime]\ntimout = 3",
            "version = 1\n[runtime]\ntimeout = 0",
            "version = 1\n[runtime]\ntimeout = true",
            'version = 1\n[runtime]\nsources = "a.txt"',
            "version = 1\n[runtime]\nmax_zip_compression_ratio = inf",
            'version = 1\n[runtime]\nallow_private_sources = "true"',
        ]
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / "config.toml"
            for document in invalid:
                with self.subTest(document=document):
                    config.write_text(document, encoding="utf-8")
                    with self.assertRaises(SourceError):
                        load_runtime_config(config)

    def test_invalid_environment_settings_fail_before_source_reads(self):
        for key, value in [
            ("HTTP_TIMEOUT", "bad"),
            ("MAX_ZIP_MEMBERS", "0"),
            ("MAX_ZIP_COMPRESSION_RATIO", "nan"),
            ("ALLOW_PRIVATE_SOURCES", "maybe"),
        ]:
            with self.subTest(key=key):
                with mock.patch.dict(os.environ, {key: value}, clear=True):
                    args = build_parser().parse_args([])
                    with self.assertRaises(SourceError):
                        resolve_runtime_settings(args)

    def test_compose_empty_overrides_preserve_config_choice(self):
        compose = Path(__file__).with_name("docker-compose.yml").read_text()
        self.assertIn('OVERLAP_ACTION: "${OVERLAP_ACTION:-}"', compose)
        self.assertNotIn('OVERLAP_ACTION: "${OVERLAP_ACTION:-find}"', compose)
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / "config.toml"
            config.write_text(
                'version = 1\n[processing]\noverlap_action = "remove_single_ips"',
                encoding="utf-8",
            )
            with mock.patch.dict(os.environ, {"OVERLAP_ACTION": ""}, clear=True):
                settings = resolve_runtime_settings(
                    build_parser().parse_args(["--config-file", str(config)])
                )
                self.assertEqual(settings["overlap_action"], "remove_single_ips")

    @staticmethod
    def resolution(address: str, port: int = 443):
        family = 10 if ":" in address else 2
        return [(family, 1, 6, "", (address, port))]

    def test_version(self):
        self.assertEqual(__version__, "0.2.0")

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

    def test_find_duplicates_reports_provenance_without_removing_overlaps(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            first = root / "first.txt"
            second = root / "second.txt"
            output = root / "out.txt"
            report = io.StringIO()
            first.write_text("1.2.3.0/24\n1.2.3.4\n1.2.3.128/25\n", encoding="utf-8")
            second.write_text("invalid\n1.2.3.4\n", encoding="utf-8")
            self.assertEqual(
                normalize(
                    [str(first), str(second)],
                    output,
                    overlap_action="find",
                    report_stream=report,
                ),
                3,
            )
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                "1.2.3.0/24\n1.2.3.4\n1.2.3.128/25\n",
            )
            report_text = report.getvalue()
            self.assertIn("exact duplicates: 1", report_text)
            self.assertIn("single IPs covered by ranges: 1", report_text)
            self.assertIn("nested ranges: 1", report_text)
            self.assertIn(f"{first}:2", report_text)
            self.assertIn(f"{second}:2", report_text)

    def test_remove_single_ips_keeps_covering_ipv4_and_ipv6_ranges(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "source.txt"
            output = root / "out.txt"
            source.write_text(
                "1.2.3.0/24\n1.2.3.4\n8.8.8.8\n2001:db8::/64\n2001:db8::1\n",
                encoding="utf-8",
            )
            self.assertEqual(
                normalize([str(source)], output, overlap_action="remove_single_ips"),
                3,
            )
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                "1.2.3.0/24\n8.8.8.8\n2001:db8::/64\n",
            )

    def test_remove_ranges_keeps_explicit_ips_and_warns(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "source.txt"
            output = root / "out.txt"
            report = io.StringIO()
            source.write_text(
                "1.2.3.0/24\n1.2.3.0/25\n1.2.3.4\n8.8.8.0/24\n",
                encoding="utf-8",
            )
            self.assertEqual(
                normalize(
                    [str(source)],
                    output,
                    overlap_action="remove_ranges",
                    report_stream=report,
                ),
                2,
            )
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                "1.2.3.4\n8.8.8.0/24\n",
            )
            report_text = report.getvalue()
            self.assertIn("removed 1.2.3.0/24", report_text)
            self.assertIn("removed 1.2.3.0/25", report_text)
            self.assertIn("WARNING: remove_ranges", report_text)

    def test_loads_processing_overlap_action(self):
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / "config.toml"
            config.write_text(
                'version = 1\n[processing]\noverlap_action = "remove_single_ips"\n',
                encoding="utf-8",
            )
            self.assertEqual(
                load_processing_config(config).overlap_action,
                "remove_single_ips",
            )

    def test_cli_and_environment_override_processing_config(self):
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / "config.toml"
            config.write_text(
                'version = 1\n[processing]\noverlap_action = "remove_single_ips"\n',
                encoding="utf-8",
            )
            with mock.patch.dict(os.environ, {"OVERLAP_ACTION": "remove_ranges"}):
                self.assertEqual(
                    configured_overlap_action(None, config), "remove_ranges"
                )
                self.assertEqual(configured_overlap_action("find", config), "find")

    def test_rejects_unknown_processing_overlap_action(self):
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / "config.toml"
            config.write_text(
                'version = 1\n[processing]\noverlap_action = "surprise"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(SourceError, "overlap_action"):
                load_processing_config(config)

    def test_cli_rejects_conflicting_overlap_actions(self):
        parser = build_parser()
        with mock.patch("sys.stderr", io.StringIO()):
            with self.assertRaises(SystemExit):
                parser.parse_args(["--find-duplicates", "--deduplicate-single-ips"])

    def test_invalid_overlap_action_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "source.txt"
            output = root / "out.txt"
            source.write_text("1.2.3.4\n", encoding="utf-8")
            output.write_text("9.9.9.9\n", encoding="utf-8")
            with self.assertRaisesRegex(SourceError, "overlap_action"):
                normalize([str(source)], output, overlap_action="surprise")
            self.assertEqual(output.read_text(encoding="utf-8"), "9.9.9.9\n")

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
