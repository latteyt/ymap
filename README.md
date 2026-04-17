# Ymap

A **Fast, Modular and Internet-wide** IPv6 network scanner.

## Overview

Ymap is a **IPv6 single-packet scanner** written in **modern C++**. While primarily designed for **Internet-wide IPv6 Network Periphery Discovery**, it is also suitable for various IPv6 scanning activities including network research, security assessments, and topology analysis.

This tool is the implementation of the research paper:

> **Pruning as Scanning: Towards Internet-Wide IPv6 Network Periphery Discovery**
> IEEE INFOCOM 2025
> [[Paper]](https://ieeexplore.ieee.org/document/11044733)

## Features

- **Single-packet Scanning**: One probe packet per target for efficient, high-speed scanning
- **Modern C++20**: Written from scratch in clean, modern C++ code
- **Modular Architecture**: Pluggable probe modules for custom payloads (ICMPv6, UDP, etc.)
- **High Performance**: Multi-threaded sending with configurable rate limiting (token bucket algorithm)
- **IPv6 Native**: Purpose-built for IPv6 address space scanning
- **Configurable**: INI-based configuration with comprehensive parameters
- **Real-time Monitoring**: Live statistics display (packets sent/received, drop rate, ETA)
- **Flexible IID Generation**: Random or fixed Interface Identifiers for targeted scanning

## Requirements

### Build Dependencies

- CMake >= 3.20
- C++20 compatible compiler (GCC/Clang)
- libpcap development libraries

### System Dependencies

- Linux kernel (for AF_PACKET sockets)
- Boost libraries (Boost.Hash, Boost.PropertyTree)

### Installation

On Debian/Ubuntu:
```bash
sudo apt-get install build-essential cmake libpcap-dev libboost-dev
```

On Fedora/RHEL:
```bash
sudo dnf install gcc-c++ cmake libpcap-devel libboost-devel
```

## Building

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build
```

The binary will be created at `build/ymap`.

## Usage

```bash
./ymap config.ini
```

### Configuration Reference

Create a `config.ini` file with the following sections:

#### `[Net]` - Network Settings

| Parameter | Description | Example |
|-----------|-------------|---------|
| `L3Src` | Source IPv6 address | `2001:db8::1` |
| `L2Dst` | Gateway MAC address | `aa:bb:cc:dd:ee:ff` |
| `IF` | Network interface name | `eth0` |

#### `[IO]` - Input/Output

| Parameter | Description | Example |
|-----------|-------------|---------|
| `input` | File containing IPv6 prefixes to scan | `prefix` |
| `output` | Output file for results (defaults to stdout if not specified) | `output.txt` |

#### `[Runtime]` - Runtime Settings

| Parameter | Description | Default |
|-----------|-------------|---------|
| `seed` | Random seed for LCG address generation | - |
| `rate` | Probe rate (packets per second) | 1000 |
| `limit` | Maximum prefix length to scan | 48 |
| `repeat` | Number of scan repetitions | 1 |
| `shard` | Number of sender threads (power of 2) | 1 |

#### `[IID]` - Interface Identifier

| Parameter | Description | Options |
|-----------|-------------|---------|
| `mode` | IID generation mode | `rand`, `0`, `0x1`, etc. |

#### `[Scan]` - Scan Configuration

| Parameter | Description | Example |
|-----------|-------------|---------|
| `type` | Probe module name | `icmpv6echo` |

### Example Configuration

```ini
[Net]
L3Src   = 2001:db8::1
L2Dst   = aa:bb:cc:dd:ee:ff
IF      = eth0

[IO]
input   = prefix
output  = output.txt

[Runtime]
seed    = 12345
rate    = 10000
limit   = 48
repeat  = 1
shard   = 4

[IID]
mode    = rand

[Scan]
type    = icmpv6echo
```

### Input File Format

The input file should contain one IPv6 prefix per line:

```
2001:16f8::/32
2a00:1620::/32
2001:067c:12e8::/48
```

## Output Format

Results are written in CSV format:

```
<target_ip>,<respondent_ip>,<icmp_type>,<icmp_code>,<ttl>,<rtt_ms>,
```

| Field | Description |
|-------|-------------|
| `target_ip` | The probed IPv6 address |
| `respondent_ip` | The IPv6 address that responded |
| `icmp_type` | ICMPv6 type (129 = Echo Reply, 1 = Destination Unreachable, etc.) |
| `icmp_code` | ICMPv6 code |
| `ttl` | Hop limit from the response |
| `rtt_ms` | Round-trip time in milliseconds |

### Example Output

```
2001:16f8:0004:0780:bf7b:2337:5c91:56d8,2001:16f8:0bb2:003a:0000:0000:0000:0003,1,3,15,3949,
2a00:1620:0191:7e39:07d4:fc3a:9fa7:9b93,2001:0760:ffff:0164:0000:0000:0000:0003,1,3,17,3953,
```

## Architecture

### Thread Model

Ymap uses a multi-threaded architecture:

1. **Sender Threads**: Probe target addresses with rate limiting (token bucket)
2. **Receiver Thread**: Capture response packets using libpcap
3. **Monitor Thread**: Display real-time statistics

### Probe Module System

Ymap features a modular probe system that allows **custom payload design**. Each module implements:

```cpp
struct probe_module_t {
  std::string name;              // Module name
  bool (*module_init)();         // Initialization
  void (*module_clear)();        // Cleanup
  size_t (*make_packet)(...);    // Packet construction
  void (*handle_packet)(...);    // Response handler
  bool (*validate_packet)(...);  // Response validator
  std::string pcap_filter;       // BPF filter string
};
```

You can implement custom modules to define your own probe payloads for different scanning strategies.

Currently supported modules:
- **icmpv6echo**: ICMPv6 Echo Request/Reply probing (default)

### Address Generation

Ymap uses a **Enhanced** Linear Congruential Generator (LCG) for traversing the **Fragmented** IPv6 address spaces, allowing for deterministic and efficient address space coverage.

## Troubleshooting

### Common Issues

**Permission denied when opening network interface**
```bash
sudo ./build/ymap config.ini
```

**No responses received**
- Verify source IPv6 address is correct and reachable
- Check firewall rules (ICMPv6 must be allowed)
- Ensure gateway MAC address is correct
- Try increasing the rate gradually

**libpcap errors**
- Install libpcap development packages
- Verify network interface name is correct

### Performance Tuning

- Increase `shard` for more sender threads (use power of 2)
- Adjust `rate` based on network capacity
- Use appropriate `limit` prefix length to focus scanning

## Contributing

Contributions are welcome. Please ensure:

1. New probe modules follow the `probe_module_t` interface
2. Code follows existing style conventions
3. Changes are documented

## License

This work is licensed under **CC BY-NC 4.0**.

For licensing inquiries, please contact the author.

[![License: CC BY-NC 4.0](https://img.shields.io/badge/License-CC%20BY--NC%204.0-blue.svg)](https://creativecommons.org/licenses/by-nc/4.0/)

## Citation

If you use this tool in your research, please cite:

```
@inproceedings{yang2025pruning,
  title={Pruning as scanning: Towards internet-wide ipv6 network periphery discovery},
  author={Yang, Tao and Hu, Ling and Hou, Bingnan and Yang, Zhenzhong and Cai, Zhiping},
  booktitle={Proceedings of the IEEE Conference on Computer Communications},
  pages={1--10},
  year={2025},
  organization={IEEE}
}

```

## Status

This software is still under active development. If you encounter any bugs or have feature requests, please report them via [GitHub Issues](https://github.com/anomalyco/ymap/issues).

## Contact

For questions or collaboration inquiries, please contact the author directly.
