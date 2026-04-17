# YMap: 又一个用于 IPv6 互联网的 ZMap

![YMap 截图](screenshot.png)

> **中文说明** | [English](README.md)

## 概述

YMap 是一个用**现代 C++** 编写的 **IPv6 单包扫描器**。虽然主要设计用于**互联网级 IPv6 网络边缘发现**，但也适用于各种 IPv6 扫描活动，包括网络研究、安全评估和拓扑分析。

本工具是以下研究论文的实现：

> **Pruning as Scanning: Towards Internet-Wide IPv6 Network Periphery Discovery**
> IEEE INFOCOM 2025
> [[论文]](https://ieeexplore.ieee.org/document/11044733)

## 功能特点

- **单包扫描**：每个目标仅发送一个探测包，高效高速
- **现代 C++20**：从头开始使用简洁、现代的 C++ 代码编写
- **模块化架构**：可插拔的探测模块，支持自定义 payloads（ICMPv6、UDP 等）
- **高性能**：多线程发送，支持可配置的速率限制（令牌桶算法）
- **原生 IPv6**：专为 IPv6 地址空间扫描而构建
- **灵活配置**：基于 INI 的配置，提供全面的参数设置
- **实时监控**：实时显示统计信息（发送/接收数据包数量、丢包率、预计完成时间）
- **灵活的 IID 生成**：支持随机或固定的接口标识符，用于定向扫描

## 系统要求

### 编译依赖

- CMake >= 3.20
- C++20 兼容编译器（GCC/Clang）
- libpcap 开发库

### 系统依赖

- Linux 内核（用于 AF_PACKET 套接字）
- Boost 库（Boost.Hash、Boost.PropertyTree）

### 安装

在 Debian/Ubuntu 上：
```bash
sudo apt-get install build-essential cmake libpcap-dev libboost-dev
```

在 Fedora/RHEL 上：
```bash
sudo dnf install gcc-c++ cmake libpcap-devel libboost-devel
```

## 编译构建

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build
```

可执行文件将位于 `build/ymap`。

## 使用方法

```bash
./ymap config.ini
```

### 配置参考

创建一个包含以下部分的 `config.ini` 文件：

#### `[Net]` - 网络设置

| 参数 | 描述 | 示例 |
|------|------|------|
| `L3Src` | 源 IPv6 地址 | `2001:db8::1` |
| `L2Dst` | 网关 MAC 地址 | `aa:bb:cc:dd:ee:ff` |
| `IF` | 网络接口名称 | `eth0` |

#### `[IO]` - 输入/输出

| 参数 | 描述 | 示例 |
|------|------|------|
| `input` | 包含要扫描的 IPv6 前缀的文件 | `prefix` |
| `output` | 结果输出文件（未指定时默认为 stdout） | `output.txt` |

#### `[Runtime]` - 运行时设置

| 参数 | 描述 | 默认值 |
|------|------|--------|
| `seed` | LCG 地址生成的随机种子 | - |
| `rate` | 探测速率（每秒数据包数） | 1000 |
| `limit` | 要扫描的最大前缀长度 | 48 |
| `repeat` | 扫描重复次数 | 1 |
| `shard` | 发送线程数（2 的幂） | 1 |

#### `[IID]` - 接口标识符

| 参数 | 描述 | 选项 |
|------|------|------|
| `mode` | IID 生成模式 | `rand`、`0`、`0x1` 等 |

#### `[Scan]` - 扫描配置

| 参数 | 描述 | 示例 |
|------|------|------|
| `type` | 探测模块名称 | `icmpv6echo` |

### 配置示例

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

### 输入文件格式

输入文件应每行包含一个 IPv6 前缀：

```
2001:16f8::/32
2a00:1620::/32
2001:067c:12e8::/48
```

## 输出格式

输出格式由每个探测模块的 `handle_packet` 函数定义。不同的模块可以根据其特定需求输出不同的字段和格式。具体输出格式请参考模块实现。

## 架构设计

### 线程模型

YMap 采用多线程架构：

1. **发送线程**：使用速率限制（令牌桶）向目标地址发送探测包
2. **接收线程**：使用 libpcap 捕获响应数据包
3. **监控线程**：显示实时统计信息

### 探测模块系统

YMap 具有模块化的探测系统，支持**自定义 payload 设计**。每个模块需要实现 `probe_module_t` 接口：

```cpp
struct probe_module_t {
  std::string name;                                     // 模块名称
  bool (*module_init)();                                // 初始化
  void (*module_clear)();                               // 清理
  size_t (*make_packet)(unsigned char*, in6_addr*, uint16_t);  // 构建探测包
  void (*handle_packet)(const unsigned char*, size_t);  // 处理响应
  bool (*validate_packet)(const unsigned char*, size_t); // 验证响应
  std::string pcap_filter;                              // libpcap 的 BPF 过滤器
};
```

#### 函数生命周期

| 函数 | 调用时机 | 用途 |
|------|----------|------|
| `module_init()` | **启动时**（扫描开始前） | 初始化模块状态、打开输出文件、分配资源 |
| `make_packet()` | **每个目标**（在发送线程中） | 为每个目标地址构造带自定义 payload 的探测包 |
| `validate_packet()` | **每个接收到的包**（在接收线程中） | 使用哈希/序列匹配检查数据包是否为对我们探测的有效响应 |
| `handle_packet()` | **验证之后**（在接收线程中） | 从有效响应中提取信息，写入输出 |
| `module_clear()` | **关闭时**（所有扫描完成后） | 刷新缓冲区、关闭文件、释放资源 |

#### 编写自定义模块

1. 实现 `probe_module_t` 中的所有函数指针
2. 使用 `make_packet()` 构建探测 payload（返回数据包大小）
3. 使用 `validate_packet()` 匹配响应（基于哈希或序列）
4. 使用 `handle_packet()` 格式化并输出结果
5. 使用 `REGISTER_PROBE_MODULE(your_module_name)` 注册

#### 最小示例

```cpp
#include "module_register.hpp"
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <cstring>

static FILE *fp = nullptr;

bool module_init() {
    // 启动时调用一次
    fp = conf.output.empty() ? stdout : fopen(conf.output.c_str(), "w");
    return fp != nullptr;
}

void module_clear() {
    // 关闭时调用一次
    if (fp) { fclose(fp); fp = nullptr; }
}

size_t make_packet(unsigned char *buf, struct in6_addr *dst, uint16_t seq) {
    // 构建 ICMPv6 Echo Request
    // 返回值：发送的数据包大小（IPv6 头 + 负载）
    auto *ip = (struct ip6_hdr *)buf;
    auto *icmp = (struct icmp6_hdr *)(ip + 1);

    std::memcpy(&ip->ip6_dst, dst, sizeof(struct in6_addr));      // 目标地址
    std::memcpy(&ip->ip6_src, &conf.l3_src, sizeof(struct in6_addr));  // 源地址
    // ... 设置其他 IPv6 头字段 ...

    icmp->icmp6_type = ICMP6_ECHO_REQUEST;
    icmp->icmp6_seq = seq;                       // 使用 seq 进行匹配
    // ... 设置 ICMPv6 字段和校验和 ...

    return sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr);  // 返回数据包大小
}

bool validate_packet(const unsigned char *pkt, size_t len) {
    // 检查数据包是否为对我们探测的有效响应
    auto *ip = (struct ip6_hdr *)(pkt + sizeof(struct ethhdr));
    auto *icmp = (struct icmp6_hdr *)(ip + 1);

    // 匹配：这是 ICMPv6 Echo Reply 吗？
    if (icmp->icmp6_type != ICMP6_ECHO_REPLY) return false;
    if (std::memcmp(&ip->ip6_dst, &conf.l3_src, sizeof(struct in6_addr)) != 0) return false;

    return true;
}

void handle_packet(const unsigned char *pkt, size_t len) {
    // 处理有效响应，写入输出
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

#### 关键要点

| 函数 | 说明 |
|------|------|
| `module_init` | 通过 `conf` 对象访问全局配置；失败时返回 `false` |
| `make_packet` | `seq` 参数是发送者的序列计数器；**返回值是发送数据包的大小（L3+负载，不包含 L2 头）** |
| `validate_packet` | 解析 Ethernet + IPv6 + 协议头；如果响应匹配则返回 `true` |
| `handle_packet` | 将结果写入 `fp`（在 `module_init` 中打开）；使用 `conf.output` 获取文件名 |

当前支持的模块：
- **icmpv6echo**：ICMPv6 Echo Request/Reply 探测（默认）

### 地址生成

YMap 使用**增强型**线性同余生成器（LCG）来遍历**分片的** IPv6 地址空间，实现确定性和高效的地址空间覆盖。

## 故障排除

### 常见问题

**打开网络接口时权限被拒绝**
```bash
sudo ./build/ymap config.ini
```

**没有收到响应**
- 验证源 IPv6 地址是否正确且可访问
- 检查防火墙规则（必须允许 ICMPv6）
- 确保网关 MAC 地址正确
- 尝试逐步增加速率

**libpcap 错误**
- 安装 libpcap 开发包
- 验证网络接口名称是否正确

### 性能调优

- 增加 `shard` 以获得更多发送线程（使用 2 的幂）
- 根据网络容量调整 `rate`
- 使用适当的 `limit` 前缀长度来集中扫描

## 贡献

欢迎贡献。请确保：

1. 新探测模块遵循 `probe_module_t` 接口
2. 代码遵循现有风格约定
3. 记录更改内容

## 许可证

本作品采用 **CC BY-NC 4.0** 许可证。

如需许可咨询，请联系作者。

[![License: CC BY-NC 4.0](https://img.shields.io/badge/License-CC%20BY--NC%204.0-blue.svg)](https://creativecommons.org/licenses/by-nc/4.0/)

## 引用

如果您在研究中使用此工具，请引用：

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

## 项目状态

本软件仍在积极开发中。如果您遇到任何错误或有功能请求，请通过 [GitHub Issues](https://github.com/latteyt/ymap/issues) 报告。

## 联系方式

如有问题或合作咨询，请直接联系作者。
