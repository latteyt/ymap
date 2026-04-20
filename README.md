# YMap

![YMap Screenshot](screenshot.png)

> **中文说明** | [简体中文](README_CN.md)

YMap is a modular IPv6 single-packet scanner written in modern C++.

It is designed for Internet-wide IPv6 periphery discovery, and it is also useful for IPv6 research, security testing, and topology analysis.

This project implements the paper:

> **Pruning as Scanning: Towards Internet-Wide IPv6 Network Periphery Discovery**
> IEEE INFOCOM 2025
> [[Paper]](https://ieeexplore.ieee.org/document/11044733)

## Features

- Single-packet scanning
- Two scan modes: `net` and `ip`
- Pluggable probe modules
- Multi-threaded sending with rate limiting
- Real-time monitoring
- INI-based configuration

## Build

Requirements:

- CMake 3.20+
- A C++20 compiler
- libpcap development headers
- Boost libraries
- Linux

Install on Debian/Ubuntu:

```bash
sudo apt-get install build-essential cmake libpcap-dev libboost-dev
```

Build:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build
```

Binary: `build/ymap`

## Configuration

YMap takes one INI file path as its only argument.

Required keys:

- `Net.IF`
- `Net.L2Dst`
- `Net.L3Src`
- `Scan.type`
- `Scan.module`
- `Scan.input`
- `Scan.iid`

Notes:

- `Scan.type` must be `net` or `ip`
- `Scan.iid` is required even in `ip` mode
- `Runtime.shard` must be a positive power of two
- `Runtime.limit` must be `<= 64`
- `Scan.output` is optional; if omitted, output goes to stdout
- If `Scan.output` is set, the file must not already exist

### `[Net]`

| Key | Meaning |
|---|---|
| `IF` | Network interface name |
| `L2Dst` | Destination MAC address |
| `L3Src` | Source IPv6 address |

### `[Runtime]`

| Key | Meaning | Default |
|---|---|---|
| `rate` | Probe rate in packets per second | `10000` |
| `repeat` | Number of repetitions | `1` |
| `shard` | Sender thread count | `1` |
| `seed` | Random seed for `net` mode | `42` |
| `limit` | Prefix expansion depth for `net` mode | `48` |

### `[Scan]`

| Key | Meaning |
|---|---|
| `type` | `net` or `ip` |
| `module` | Probe module name |
| `input` | Input file path |
| `output` | Output file path |
| `iid` | IID mode: `rand`, decimal, or hex |

## Scan Modes

### `net`

Reads one IPv6 prefix per line and expands each prefix to the configured `Runtime.limit`.

Example input:

```text
2001:db8::/32
2a00:1620::/32
```

### `ip`

Reads one IPv6 address per line and scans addresses directly.

Example input:

```text
2001:db8::1
2001:db8::2
```

## Built-in Modules

### `icmp6_echo`

Sends ICMPv6 Echo Request probes.

Output fields:

- target address
- responder address
- ICMPv6 type
- ICMPv6 code
- hop count estimate
- elapsed time

### `udp6_coap`

Sends UDP probes to CoAP port `5683` with a fixed `/.well-known/core` request payload.

Output fields:

- responder IPv6 address
- source port
- CoAP response class/detail

## Example

```ini
[Net]
IF = eth0
L2Dst = aa:bb:cc:dd:ee:ff
L3Src = 2001:db8::1

[Runtime]
rate = 10000
repeat = 1
shard = 4
seed = 12345
limit = 48

[Scan]
type = net
module = udp6_coap
input = prefix.txt
output = output.txt
iid = rand
```

## Module System

Each probe module implements `probe_module_t`:

```cpp
struct probe_module_t {
  std::string name;
  bool (*module_init)();
  void (*module_clear)();
  size_t (*make_packet)(unsigned char*, struct in6_addr*);
  void (*handle_packet)(const unsigned char*, size_t);
  bool (*validate_packet)(const unsigned char*, size_t);
  std::string pcap_filter;
};
```

Register a module with `REGISTER_PROBE_MODULE(name)`.

## Notes

- `module_init()` opens the output handle.
- `module_clear()` flushes and closes it.
- `make_packet()` builds one probe packet per target.
- `validate_packet()` filters matching responses.
- `handle_packet()` writes the final result.
