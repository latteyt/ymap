#ifndef CONFIG_H
#define CONFIG_H

#include <arpa/inet.h>
#include <cstddef>
#include <netinet/ether.h>
#include <sstream>
#include <string>

#include "module/module_register.hpp"

struct config_t {
  struct in6_addr l3_src{};
  struct ether_addr l2_dst{};
  std::string if_name;
  unsigned int if_index;

  std::string input;
  std::string output;

  size_t rate;
  size_t limit;
  size_t repeat;
  size_t seed;
  size_t shard;

  const probe_module_t *probe_module{nullptr};

  std::string iid_mode;

  config_t() = default;
  config_t(const config_t &) = delete;
  config_t(config_t &&) = delete;
  config_t &operator=(const config_t &) = delete;
  config_t &operator=(config_t &&) = delete;

  // std::string to_string() const {
  //   std::ostringstream ss;
  //
  //   char src_buf[INET6_ADDRSTRLEN] = {};
  //   inet_ntop(AF_INET6, &l3_src, src_buf, sizeof(src_buf));
  //
  //   char dst_buf[18] = {};
  //   snprintf(dst_buf, sizeof(dst_buf), "%02x:%02x:%02x:%02x:%02x:%02x",
  //            l2_dst.ether_addr_octet[0], l2_dst.ether_addr_octet[1],
  //            l2_dst.ether_addr_octet[2], l2_dst.ether_addr_octet[3],
  //            l2_dst.ether_addr_octet[4], l2_dst.ether_addr_octet[5]);
  //
  //   ss << CLR_TITLE
  //      << "==================== CONFIG ====================" << CLR_RESET
  //      << "\n"
  //      << CLR_KEY << "if_name   : " << CLR_VAL << if_name << "\n"
  //      << CLR_KEY << "if_index  : " << CLR_NUM << if_index << "\n"
  //      << CLR_KEY << "input     : " << CLR_VAL << input << "\n"
  //      << CLR_KEY << "output    : "
  //      << (output.empty() ? (std::string(CLR_NULL) + "stdout")
  //                         : (std::string(CLR_VAL) + output))
  //      << CLR_RESET << "\n"
  //      << CLR_KEY << "l3_src    : " << CLR_VAL << src_buf << "\n"
  //      << CLR_KEY << "l2_dst    : " << CLR_VAL << dst_buf << "\n"
  //      << CLR_KEY << "rate      : " << CLR_NUM << rate << "\n"
  //      << CLR_KEY << "limit     : " << CLR_NUM << limit << "\n"
  //      << CLR_KEY << "repeat    : " << CLR_NUM << repeat << "\n"
  //      << CLR_KEY << "seed      : " << CLR_NUM << seed << "\n"
  //      << CLR_KEY << "shard     : " << CLR_NUM << shard << "\n"
  //      << CLR_KEY << "probe     : "
  //      << (probe_module ? (std::string(CLR_VAL) + probe_module->name)
  //                       : (std::string(CLR_NULL) + "null"))
  //      << CLR_RESET << "\n"
  //      << CLR_KEY << "iid mode  : " << CLR_VAL << iid_mode << "\n"
  //
  //      << CLR_RESET;
  //   return ss.str();
  // }
};

inline config_t conf;

#endif // CONFIG_H
