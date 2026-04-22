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
- `Optional.seed`
- `Optional.limit`
- `Optional.iid = rand`

## AWK selection

The script prefers `mawk` when available.
If `mawk` is not installed, it falls back to `awk`.

## Inputs

- `IF_NAME` is required.
- Optional environment variables:
  - `SCAN_RATE` (default: `200000`)
  - `SHARD` (default: `2`)
  - `SEED` (default: `521`)

## Outputs

The script writes generated configs and intermediate results under
`.pruning-as-scanning/`.
