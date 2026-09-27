"""Deterministic file exports; never applies firewall configuration."""

import csv
import io
import ipaddress
import json

OUTPUT_FORMATS = ("text", "csv", "json", "ipset", "nftables", "synology")


def parse_entry(value):
    if not isinstance(value, str):
        raise ValueError("entry must be a string")
    return (
        ipaddress.ip_network(value, strict=False)
        if "/" in value
        else ipaddress.ip_address(value)
    )


def sort_key(entry):
    if isinstance(entry, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return (entry.version, int(entry.network_address), 0, entry.prefixlen)
    return (entry.version, int(entry), 1, entry.max_prefixlen)


def render_output(entries, output_format):
    if output_format not in OUTPUT_FORMATS:
        raise ValueError("unknown output format")
    ordered = sorted(entries, key=sort_key)
    values = [str(entry) for entry in ordered]
    if output_format == "text":
        return "\n".join(values) + "\n"
    if output_format == "synology":
        if any(not isinstance(entry, ipaddress.IPv4Address) for entry in ordered):
            raise ValueError(
                "Synology Auto Block export supports individual IPv4 addresses only"
            )
        return "\n".join(values) + "\n"
    if output_format == "json":
        return (
            json.dumps(
                {"schema_version": 1, "kind": "denylist", "entries": values},
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
    if output_format == "csv":
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(["entry", "family", "kind"])
        for entry in ordered:
            writer.writerow(
                [
                    str(entry),
                    f"ipv{entry.version}",
                    "network" if "/" in str(entry) else "address",
                ]
            )
        return buffer.getvalue()
    lines = [f"# deny-ip-toolkit export v1 {output_format}"]
    # Preserve exact canonical entries for the next run's comparison. The body
    # is verified against these entries on read, so edits cannot hide changes.
    lines.extend(f"# entry {entry}" for entry in values)
    if output_format == "ipset":
        if any("/" in str(entry) and entry.prefixlen == 0 for entry in ordered):
            raise ValueError("ipset hash:net cannot store /0 networks")
        for version, family in ((4, "inet"), (6, "inet6")):
            # A host and its /32 or /128 are the same ipset element. Emit each
            # only once, without merging distinct networks into unsupported /0.
            family_entries = sorted(
                {
                    ipaddress.ip_network(
                        str(entry)
                        if "/" in str(entry)
                        else f"{entry}/{entry.max_prefixlen}"
                    )
                    for entry in ordered
                    if entry.version == version
                },
                key=sort_key,
            )
            lines.append(
                f"create deny_ip{version} hash:net family {family} "
                f"maxelem {max(65536, len(family_entries))}"
            )
            lines.extend(f"add deny_ip{version} {entry}" for entry in family_entries)
    else:
        lines.append("table inet deny_ip_toolkit {")
        for version in (4, 6):
            networks = [
                ipaddress.ip_network(
                    str(entry)
                    if "/" in str(entry)
                    else f"{entry}/{entry.max_prefixlen}"
                )
                for entry in ordered
                if entry.version == version
            ]
            # Remove overlap in serialization only; preserve identical coverage.
            collapsed = list(ipaddress.collapse_addresses(networks))
            lines.extend(
                [
                    f"    set deny_ip{version} {{",
                    f"        type ipv{version}_addr;",
                    "        flags interval;",
                ]
            )
            if collapsed:
                elements = ", ".join(str(network) for network in collapsed)
                lines.append(f"        elements = {{ {elements} }};")
            lines.append("    }")
        lines.append("}")
    return "\n".join(lines) + "\n"


def read_export(text, output_format):
    """Read only the tool's own exports, never execute or evaluate their text."""
    if output_format in {"text", "synology"}:
        entries = {
            parse_entry(line.strip()) for line in text.splitlines() if line.strip()
        }
        if output_format == "synology":
            render_output(entries, output_format)
        return entries
    if output_format == "json":
        document = json.loads(text)
        if (
            not isinstance(document, dict)
            or type(document.get("schema_version")) is not int
            or document["schema_version"] != 1
            or document.get("kind") != "denylist"
            or not isinstance(document.get("entries"), list)
        ):
            raise ValueError("not a version 1 denylist export")
        entries = {parse_entry(value) for value in document["entries"]}
    elif output_format == "csv":
        reader = csv.DictReader(io.StringIO(text))
        if reader.fieldnames != ["entry", "family", "kind"]:
            raise ValueError("invalid CSV export header")
        entries = {parse_entry(row["entry"]) for row in reader}
    elif output_format in {"ipset", "nftables"}:
        lines = text.splitlines()
        if not lines or lines[0] != f"# deny-ip-toolkit export v1 {output_format}":
            raise ValueError("not a tool-generated firewall export")
        entries = {
            parse_entry(line[len("# entry ") :])
            for line in lines
            if line.startswith("# entry ")
        }
    else:
        raise ValueError("unknown output format")
    if render_output(entries, output_format) != text:
        raise ValueError("previous export has been modified or has an invalid format")
    return entries
