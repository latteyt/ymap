#ifndef CONFIG_H
#define CONFIG_H

#include <arpa/inet.h>
#include <cstddef>
#include <cstdint>
#include <netinet/ether.h>
#include <string>

#include "module/module_register.hpp"

struct config_t {
  // Interface
  struct in6_addr l3_src{};
  struct ether_addr l2_dst{};
  std::string if_name;
  unsigned int if_index;

  // Runtime
  size_t shard;
  size_t rate;
  size_t repeat;

  // Scan
  std::string type;
  const probe_module_t *probe_module{nullptr};
  std::string input;
  std::string output;

  // Optional
  // net mode only
  size_t seed;
  size_t limit;
  std::string iid;

  // tcp_syn only
  uint16_t th_dport;

  config_t() = default;
  config_t(const config_t &) = delete;
  config_t(config_t &&) = delete;
  config_t &operator=(const config_t &) = delete;
  config_t &operator=(config_t &&) = delete;
};

inline config_t conf;

#endif // CONFIG_H
