# Output formats (export schema v1)

Plain text remains the default. Select a format using `--output-format`,
`OUTPUT_FORMAT`, or `output_format` under `[runtime]` in the TOML configuration.
Precedence is CLI > nonempty environment > TOML > defaults. The output filename
is independent of its format; choose a matching extension explicitly.

```sh
python deny_ip_toolkit.py --source permitted-list.txt --output-format nftables --output deny-ip.nft
python deny_ip_toolkit.py --source permitted-list.txt --output-format json --output denylist.json --report-file run-report.json
```

| Format | Supported entries | Intended consumer |
| --- | --- | --- |
| `text` | IPv4, IPv6, CIDR | One canonical entry per line |
| `csv` | IPv4, IPv6, CIDR | Header: `entry,family,kind`; family `ipv4`/`ipv6`, kind `address`/`network` |
| `json` | IPv4, IPv6, CIDR | Object with `schema_version: 1`, `kind: "denylist"`, and `entries` string array |
| `ipset` | IPv4, IPv6, CIDR except /0 | Linux ipset `restore`, `hash:net` sets |
| `nftables` | IPv4, IPv6, CIDR | Linux nftables native file syntax with interval sets |
| `synology` | Individual IPv4 only | DSM 7 Auto Block text-list importer |

The JSON denylist contains entries to consume; the separate JSON **run report**
contains status, provenance, statistics, comparisons and output hashes. These
are different documents and neither can substitute for the other.

## Firewall imports are manual

The toolkit only writes files. It does not run these commands, install rules,
connect to a NAS, or start blocking traffic. Back up your configuration and test
on a non-production system before importing. The examples assume new, unused
set/table names. Do not repeatedly import into existing objects: restore/add
operations can retain old entries. Replacement and rule attachment remain your
responsibility. The toolkit's atomic output write does not make a downstream
firewall import atomic.

### ipset

Targets the documented Linux ipset `hash:net` create/add/restore syntax, not a
vendor-specific appliance format. It creates `deny_ip4` (`family inet`) and
`deny_ip6` (`family inet6`), including an empty set for an absent family. `maxelem`
is at least 65536 or the number of entries in that family. /0 is rejected before
writing because `hash:net` does not support it. No existing sets are flushed.
Hosts use explicit /32 or /128 prefixes; equivalent host and host-prefix entries
are added once, while their original forms remain in comparison comments.

```sh
sudo ipset restore < deny-ip.ipset
```

Sets alone do not block traffic; firewall rules must reference them. Consult the
[official ipset manual](https://ipset.netfilter.org/ipset.man.html) for kernel
support, restore semantics, sizing and rule integration.

### nftables

Targets native nftables syntax: table `inet deny_ip_toolkit`, sets `deny_ip4`
(`ipv4_addr`) and `deny_ip6` (`ipv6_addr`) with `flags interval`. There are **no
chains or blocking rules**. Overlapping/adjacent networks are collapsed in the
set body to disjoint CIDRs with identical address coverage, regardless of the
processing overlap mode. Original selected entries remain in comments for
accurate next-run comparisons. Even /0 does not expand into individual IPs.

```sh
sudo nft --check --file deny-ip.nft
sudo nft --file deny-ip.nft
```

Review and attach sets to rules yourself. See the
[official nftables manual](https://www.netfilter.org/projects/nftables/manpage.html)
for file syntax, interval sets and checking configuration. Kernel/tool versions
must support these features; no distribution-specific minimum version is claimed.

### Synology DSM 7 Auto Block

This is a plain-text list for **Auto Block's Allow/Block List import**, not a
Synology firewall-rule export. In DSM use Control Panel > Security > Protection >
Auto Block > Allow/Block List, choose the block list and its import action; check
the format preview in your DSM version before importing.

The exporter conservatively supports individual IPv4 addresses only. Any CIDR
or IPv6 entry rejects the whole export rather than dropping entries or expanding
ranges. This restriction describes our supported subset, not a claim that all
DSM versions reject other forms. See
[Synology's DSM 7 protection documentation](https://kb.synology.com/en-us/DSM/help/DSM/AdminCenter/connection_security_protection?version=7).
No NAS-specific import has been tested by this project.

## Repeat runs and safety

Every format is deterministic, UTF-8 and LF terminated. Serialization failures
leave the previous output unchanged. Loss safeguards compare the same canonical
entries and address coverage as text mode, and reports hash the actual exported
bytes. Existing non-text exports must be unmodified toolkit-generated v1 files:
the reader verifies their body, not just embedded entry comments. It never
executes firewall files. Arbitrary native ipset/nftables files are not accepted
as comparison baselines. Text baselines may contain valid IP/CIDR lines.

Use a new output path when changing formats; an incompatible old baseline causes
an error instead of bypassing safety checks. Generated fixtures and unit tests
cover syntax, round trips and failure recovery. Actual Linux firewall imports
have not been exercised in the local development environment; check against your
installed tools and kernel before production use.
