# YMap：又一个 IPv6 版 ZMap

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

示例配置：
- [`config_ips.ini`](./config_ips.ini) 对应 `ip` 模式
  ```ini
  [Net]
  L3Src   = 2408:8445:513:26be:6b61:58b5:408:1f62
  L2Dst   = f2:6e:ff:45:d9:58
  IF      = wlp59s0

  [Runtime]
  shard   = 2
  rate    = 10
  repeat  = 1

  [Scan]
  type    = ip
  module  = udp6_coap
  input   = other/ips
  ```
- [`config_net.ini`](./config_net.ini) 对应 `net` 模式
  ```ini
  [Net]
  L3Src   = 2408:8445:513:26be:6b61:58b5:408:1f62
  L2Dst   = f2:6e:ff:45:d9:58
  IF      = wlp59s0

  [Runtime]
  shard   = 2
  rate    = 200000
  repeat  = 1
  seed    = 521
  limit   = 64

  [Scan]
  type    = net
  module  = icmp6_echo
  input   = IANA.txt
  iid     = rand
  ```

### `[Net]`

这些字段在 `ip` 和 `net` 两种模式下都要用到。

| 键 | 含义 |
|---|---|
| `IF` | 网卡名称 |
| `L2Dst` | 目的 MAC 地址 |
| `L3Src` | 源 IPv6 地址 |

### `[Runtime]`

#### `ip` 模式

使用这些字段：

| 键 | 含义 | 默认值 |
|---|---|---|
| `rate` | 每秒探测包数量 | `10000` |
| `repeat` | 重复扫描次数 | `1` |
| `shard` | 发送线程数 | `1` |

#### `net` 模式

在 `ip` 模式字段基础上，再使用这些字段：

| 键 | 含义 | 默认值 |
|---|---|---|
| `seed` | 前缀遍历随机种子 | `42` |
| `limit` | 前缀扩展深度 | `48` |

### `[Scan]`

#### `ip` 模式

使用这些字段：

| 键 | 含义 |
|---|---|
| `type` | 必须是 `ip` |
| `module` | 探测模块名称 |
| `input` | 输入文件路径 |
| `output` | 输出文件路径，可选 |

#### `net` 模式

使用这些字段：

| 键 | 含义 |
|---|---|
| `type` | 必须是 `net` |
| `module` | 探测模块名称 |
| `input` | 输入文件路径 |
| `output` | 输出文件路径，可选 |
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

## 架构设计

### 线程模型

YMap 采用多线程架构：

1. 发送线程使用速率限制向目标地址发送探测包。
2. 接收线程使用 libpcap 捕获响应数据包。
3. 监控线程显示实时统计信息。

### 探测模块系统

YMap 使用模块化探测系统来支持自定义 payload。每个模块都实现 `probe_module_t`：

```cpp
struct probe_module_t {
  std::string name;
  bool (*module_init)();
  void (*module_clear)();
  size_t (*make_packet)(unsigned char *, struct in6_addr *);
  void (*handle_packet)(const unsigned char *);
  bool (*validate_packet)(const unsigned char *, size_t);
  std::string pcap_filter;
};
```

使用 `REGISTER_PROBE_MODULE(name)` 注册模块。

#### 函数生命周期

| 函数 | 调用时机 | 用途 |
|---|---|---|
| `module_init()` | 扫描开始前 | 初始化模块状态、打开输出文件、分配资源 |
| `make_packet()` | 每个目标，发送线程中 | 构造探测包 |
| `validate_packet()` | 每个收到的包，接收线程中 | 检查响应是否匹配探测 |
| `handle_packet()` | 验证之后，接收线程中 | 从有效响应中提取信息 |
| `module_clear()` | 扫描结束后 | 刷新缓冲区、关闭文件、释放资源 |

#### 编写自定义模块

1. 实现 `probe_module_t` 中的函数指针。
2. 使用 `make_packet()` 构建探测负载。
3. 使用 `validate_packet()` 匹配响应。
4. 使用 `handle_packet()` 格式化并输出结果。
5. 使用 `REGISTER_PROBE_MODULE(your_module_name)` 注册。

#### 当前支持的模块

- `icmp6_echo`：ICMPv6 Echo Request/Reply 探测
- `udp6_coap`：UDP/CoAP 探测

### 地址生成

#### `net` 模式

YMap 会确定性地遍历 IPv6 前缀空间，并把每个输入前缀扩展到配置的 `Runtime.limit`。

对于每个输入前缀，YMap 会：
1. 将前缀网络地址转换为起始值。
2. 计算该 `/limit` 范围内可达地址数量。
3. 使用遍历序列覆盖地址空间。

#### `ip` 模式

YMap 按行读取输入文件，并把地址分配给发送线程。

## 故障排除

### 常见问题

**打开网络接口时权限被拒绝**
```bash
sudo ./build/ymap config_net.ini
```

**没有收到响应**
- 检查源 IPv6 地址是否正确且可达。
- 确认网关 MAC 地址是否正确。
- 尝试逐步提高速率。

**libpcap 错误**
- 安装 libpcap 开发包。
- 检查网卡名称是否正确。

### 性能调优

- 增加 `shard` 以获得更多发送线程。
- 根据网络容量调整 `rate`。
- 在 `net` 模式下使用合适的 `limit`。

## 贡献

欢迎贡献。请确保：

1. 新模块遵循 `probe_module_t` 接口。
2. 代码符合现有风格。
3. 记录更改内容。

## 许可证

本作品采用 **CC BY-NC 4.0** 许可证。

如需许可咨询，请联系作者。

[![License: CC BY-NC 4.0](https://img.shields.io/badge/License-CC%20BY--NC%204.0-blue.svg)](https://creativecommons.org/licenses/by-nc/4.0/)

## 引用

如果您在研究中使用此工具，请引用：

```text
@inproceedings{yang2025pruning,
  title={{Pruning as scanning: Towards Internet-wide IPv6 Network Periphery Discovery}},
  author={Yang, Tao and Hu, Ling and Hou, Bingnan and Yang, Zhenzhong and Cai, Zhiping},
  booktitle={Proceedings of the IEEE Conference on Computer Communications},
  pages={1--10},
  year={2025},
  organization={IEEE}
}
```

## 项目状态

本软件仍在积极开发中。如果您遇到错误或有功能请求，请通过 GitHub Issues 报告。
