# YMap

![YMap 截图](screenshot.png)

> **英文说明** | [English](README.md)

YMap 是一个使用现代 C++ 编写的 IPv6 单包扫描器。

它面向 IPv6 互联网边界发现，同时也适用于 IPv6 研究、安全测试和拓扑分析。

本项目实现了以下论文：

> **Pruning as Scanning: Towards Internet-Wide IPv6 Network Periphery Discovery**
> IEEE INFOCOM 2025
> [[论文]](https://ieeexplore.ieee.org/document/11044733)

## 功能

- 单包扫描
- 两种扫描模式：`net` 和 `ip`
- 可插拔探测模块
- 多线程发送与限速
- 实时监控
- 基于 INI 的配置

## 编译

依赖：

- CMake 3.20+
- 支持 C++20 的编译器
- libpcap 开发库
- Boost 库
- Linux

Debian/Ubuntu 安装依赖：

```bash
sudo apt-get install build-essential cmake libpcap-dev libboost-dev
```

编译：

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build
```

可执行文件位于 `build/ymap`

## 配置

YMap 只接收一个 INI 配置文件路径作为参数。

必填项：

- `Net.IF`
- `Net.L2Dst`
- `Net.L3Src`
- `Scan.type`
- `Scan.module`
- `Scan.input`
- `Scan.iid`

说明：

- `Scan.type` 必须是 `net` 或 `ip`
- 即使在 `ip` 模式下，`Scan.iid` 也必须填写
- `Runtime.shard` 必须是正的 2 的幂
- `Runtime.limit` 必须 `<= 64`
- `Scan.output` 可选，不填则输出到 stdout
- 如果填写了 `Scan.output`，目标文件必须不存在

### `[Net]`

| 键 | 含义 |
|---|---|
| `IF` | 网卡名称 |
| `L2Dst` | 目的 MAC 地址 |
| `L3Src` | 源 IPv6 地址 |

### `[Runtime]`

| 键 | 含义 | 默认值 |
|---|---|---|
| `rate` | 每秒探测包数量 | `10000` |
| `repeat` | 重复扫描次数 | `1` |
| `shard` | 发送线程数 | `1` |
| `seed` | `net` 模式下的随机种子 | `42` |
| `limit` | `net` 模式下的前缀扩展深度 | `48` |

### `[Scan]`

| 键 | 含义 |
|---|---|
| `type` | `net` 或 `ip` |
| `module` | 探测模块名称 |
| `input` | 输入文件路径 |
| `output` | 输出文件路径 |
| `iid` | IID 模式：`rand`、十进制或十六进制 |

## 扫描模式

### `net`

每行读取一个 IPv6 前缀，并根据 `Runtime.limit` 扩展到指定深度。

示例输入：

```text
2001:db8::/32
2a00:1620::/32
```

### `ip`

每行读取一个 IPv6 地址，直接扫描这些地址。

示例输入：

```text
2001:db8::1
2001:db8::2
```

## 内置模块

### `icmp6_echo`

发送 ICMPv6 Echo Request 探测包。

输出字段：

- 目标地址
- 响应方地址
- ICMPv6 类型
- ICMPv6 Code
- 跳数估计
- 耗时

### `udp6_coap`

向 CoAP 端口 `5683` 发送 UDP 探测包，负载是固定的 `/.well-known/core` 请求。

输出字段：

- 响应方 IPv6 地址
- 源端口
- CoAP 响应 class/detail

## 示例

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

## 模块系统

每个探测模块都实现 `probe_module_t`：

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

使用 `REGISTER_PROBE_MODULE(name)` 注册模块。

## 说明

- `module_init()` 打开输出句柄。
- `module_clear()` 刷新并关闭输出句柄。
- `make_packet()` 为每个目标构造一个探测包。
- `validate_packet()` 过滤匹配响应。
- `handle_packet()` 写出最终结果。
