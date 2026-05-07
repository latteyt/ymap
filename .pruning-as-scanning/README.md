# Pruning as Scanning

This directory contains the helper script used to run prefix pruning scans
with the current YMap config format.

## Script

`pruning-as-scanning.sh` generates INI files with these sections:

- `[Interface]`
- `[Runtime]`
- `[Scan]`
- `[Optional]`

It currently uses:

- `Scan.type = net`
- `Scan.module = icmp6_echo`
- `Scan.input = IANA` or a prefix file
- `Optional.limit`
- `Optional.iid = rand`

## Processing

The script uses a shell pipeline with `awk` to filter scan output and derive
`prefix24.txt`, `prefix32.txt`, `prefix40.txt`, and `prefix48.txt`.

## Inputs

- `IF_NAME` is required.
- Optional environment variables:
  - `SCAN_RATE` (default: `100000`)
  - `SHARD` (default: `1`)
  - `SEED` (optional; YMap will use an internal random seed if omitted)

## Outputs

The script writes generated configs and intermediate results under
`.pruning-as-scanning/`, including a dated `outputYYYYMMDD.txt` log.

The resulting files can be deduplicated with [buniq](https://github.com/latteyt/buniq).
