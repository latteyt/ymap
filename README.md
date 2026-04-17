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

The output format is defined by each probe module's `handle_packet` function. Different modules can output different fields and formats based on their specific requirements. Refer to the module implementation for the exact output format.

## Architecture

### Thread Model

Ymap uses a multi-threaded architecture:

1. **Sender Threads**: Probe target addresses with rate limiting (token bucket)
2. **Receiver Thread**: Capture response packets using libpcap
3. **Monitor Thread**: Display real-time statistics

### Probe Module System

Ymap features a modular probe system that allows **custom payload design**. Each module implements the `probe_module_t` interface:

```cpp
struct probe_module_t {
  std::string name;                                     // Module name
  bool (*module_init)();                                // Initialization
  void (*module_clear)();                               // Cleanup
  size_t (*make_packet)(unsigned char*, in6_addr*, uint16_t);  // Build probe packet
  void (*handle_packet)(const unsigned char*, size_t);  // Process response
  bool (*validate_packet)(const unsigned char*, size_t); // Validate response
  std::string pcap_filter;                              // BPF filter for libpcap
};
```

#### Function Lifecycle

| Function | When Called | Purpose |
|----------|------------|---------|
| `module_init()` | **Startup** (before scanning begins) | Initialize module state, open output file, allocate resources |
| `make_packet()` | **Per target** (in sender threads) | Construct probe packet with custom payload for each target address |
| `validate_packet()` | **Per received packet** (in receiver thread) | Check if packet is a valid response to our probe using hash/sequence matching |
| `handle_packet()` | **After validation** (in receiver thread) | Extract information from valid response, write to output |
| `module_clear()` | **Shutdown** (after all scanning completes) | Flush buffers, close files, free resources |

#### Writing a Custom Module

1. Implement all function pointers in `probe_module_t`
2. Use `make_packet()` to construct your probe payload (return packet size)
3. Use `validate_packet()` to match responses (hash-based or sequence-based)
4. Use `handle_packet()` to format and output results
5. Register with `REGISTER_PROBE_MODULE(your_module_name)`

#### Minimal Example

```cpp
#include "module_register.hpp"
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

static FILE *fp = nullptr;

bool module_init() {
    // Called once at startup
    fp = conf.output.empty() ? stdout : fopen(conf.output.c_str(), "w");
    return fp != nullptr;
}

void module_clear() {
    // Called once at shutdown
    if (fp) { fclose(fp); fp = nullptr; }
}

size_t make_packet(unsigned char *buf, struct in6_addr *dst, uint16_t seq) {
    // Build ICMPv6 Echo Request
    // Returns: size of packet to send (IPv6 header + payload)
    auto *ip = (struct ip6_hdr *)buf;
    auto *icmp = (struct icmp6_hdr *)(ip + 1);

    ip->ip6_dst = *dst;                          // Target address
    ip->ip6_src = conf.l3_src;                   // Source address
    // ... set other IPv6 header fields ...

    icmp->icmp6_type = ICMP6_ECHO_REQUEST;
    icmp->icmp6_seq = seq;                       // Use seq for matching
    // ... set ICMPv6 fields and checksum ...

    return sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr);  // Return packet size
}

bool validate_packet(const unsigned char *pkt, size_t len) {
    // Check if packet is a valid response to our probe
    auto *ip = (struct ip6_hdr *)(pkt + sizeof(struct ethhdr));
    auto *icmp = (struct icmp6_hdr *)(ip + 1);

    // Match: is this ICMPv6 Echo Reply to our address?
    if (icmp->icmp6_type != ICMP6_ECHO_REPLY) return false;
    if (ip->ip6_dst != conf.l3_src) return false;

    return true;
}

void handle_packet(const unsigned char *pkt, size_t len) {
    // Process valid response, write output
    auto *ip = (struct ip6_hdr *)(pkt + sizeof(struct ethhdr));
    fprintf(fp, "%s\n", inet_ntop(AF_INET6, &ip->ip6_src, buf, sizeof(buf)));
}

probe_module_t my_module = {
    .name = "my_module",
    .module_init = module_init,
    .module_clear = module_clear,
    .make_packet = make_packet,
    .handle_packet = handle_packet,
    .validate_packet = validate_packet,
    .pcap_filter = "ip6 && icmp6",
};

REGISTER_PROBE_MODULE(my_module);
```

#### Key Points

| Function | Notes |
|----------|-------|
| `module_init` | Access global config via `conf` object; return `false` on failure |
| `make_packet` | `seq` parameter is a sequence counter from sender; return total packet size |
| `validate_packet` | Parse Ethernet + IPv6 + protocol header; return `true` if response matches |
| `handle_packet` | Write results to `fp` (opened in `module_init`); use `conf.output` for filename |

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

This software is still under active development. If you encounter any bugs or have feature requests, please report them via [GitHub Issues](https://github.com/latteyt/ymap/issues).

## Contact

For questions or collaboration inquiries, please contact the author directly.
