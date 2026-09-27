# Run report format, version 1

Reports are JSON objects. Consumers must check schema_version and status before
using results. Unknown future fields may be ignored; a different schema_version
requires explicit consumer support.

| Field | Type | Meaning |
| --- | --- | --- |
| schema_version | integer | Format version, currently 1 |
| tool_version | string | Software version |
| status | string | success or failed in a saved report |
| configured_sources | array of strings | Requested locations with URL secrets removed |
| sources | array of objects | Sources completed through download/checksum verification |
| settings | object | Effective overlap action, timeout, limits and private-source option |
| counts | object or null | Valid occurrence, unique entry, duplicate, covered IP, nested range, removed entry and output entry counts |
| exact_duplicates | array | Repeated canonical entries with all occurrences |
| covered_ips | array | Covered individual entries with a representative covering_range |
| nested_ranges | array | Nested ranges with their immediate parent_range |
| removed_entries | array | Entries removed by the selected overlap action |
| warnings | array of strings | Policy warnings, including range removal |
| output | object or null | Output path and SHA-256 of the exact UTF-8 output bytes |
| error | object or null | Failure type and safe message |

Source objects contain location, license, license_url, allowed_use,
expected_sha256 and checksum_verified. Missing metadata is null.
Occurrence objects contain source and one-based line. Findings contain entry
and occurrences; CIDR entries are canonicalized. Exact duplicate counts count
occurrences beyond the first, not duplicate groups. Removal counts count unique
entries. IPv4 and IPv6 results are independent.

Successful reports contain all finding arrays and counts; failed reports can
omit finding arrays and have null counts/output if processing stopped early.
An output hash describes file bytes, not the effective blocked address space.
Completed source metadata and partial analysis in failed reports are diagnostic.

Reports use a temporary file in the destination directory and atomic replacement.
Unsafe paths are rejected before writing. Argument/configuration/manifest
validation failures before processing do not produce reports.
List output and report replacement are separate operations: a report-write
failure after list replacement does not roll back the newly written list.
