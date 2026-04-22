#ifndef SEND_HPP
#define SEND_HPP
#include <arpa/inet.h>
#include <atomic>
#include <bit>
#include <boost/asio/ip/network_v6.hpp>
#include <boost/property_tree/ptree_fwd.hpp>
#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <random>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

#include <boost/asio.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include "config.h"
#include "iid.hpp"
#include "ratelimiter.hpp"
#include "state.h"

union range_t {
  // net
  struct {
    uint64_t stun;
    uint64_t count;
  };
  // ip
  struct {
    size_t beg;
    size_t end;
  };
};

class sender_t {
public:
  sender_t() {
    /* inital our perfix vector */
    this->space = 0;
    if (conf.type == "net") {
      std::ifstream in(conf.input);
      std::string line;
      while (std::getline(in, line)) {
        auto net = boost::asio::ip::make_network_v6(line);
        if (conf.limit < net.prefix_length())
          continue;
        uint64_t len = net.prefix_length();
        auto nbytes = net.network().to_bytes();
        uint64_t stun = std::accumulate(
            nbytes.begin(), nbytes.begin() + 8, uint64_t{0},
            [](uint64_t acc, uint8_t byte) { return (acc << 8) | byte; });
        this->ranges.push_back({.stun = stun, .count = this->space});
        this->space += (1ULL << (conf.limit - len));
      }
    } else {
      std::ifstream in(conf.input);
      std::string line;
      size_t total_line = 0;
      while (std::getline(in, line))
        total_line++;
      in.clear();
      in.seekg(0);

      size_t total_size = std::filesystem::file_size(conf.input);
      size_t shard_line = total_line / conf.shard;
      if (shard_line == 0)
        throw std::runtime_error("Input lines are fewer than shards");
      size_t count = 0;
      do {
        if (count % shard_line == 0)
          this->ranges.push_back(
              {.beg = static_cast<size_t>(in.tellg()), .end = total_size});
        count++;
      } while (std::getline(in, line));
      for (size_t i = 0; i < this->ranges.size() - 1; ++i) {
        this->ranges[i].end = this->ranges[i + 1].beg;
      }
      this->space = total_line;
    }
    state.total = conf.repeat * this->space;
  }
  ~sender_t() {}

  std::thread run(size_t shard, size_t offset) {
    return std::thread([this, shard, offset]() {
      int fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IPV6));
      /* handle for sending */
      if (fd == -1)
        throw std::system_error(
            errno, std::system_category(),
            "socket(AF_PACKET, SOCK_DGRAM, ETH_P_IPV6) failed");
      shutdown(fd, SHUT_RD);

      /* sockaddr_ll sending */
      struct sockaddr_ll tx_sockaddr;
      memset(&tx_sockaddr, 0, sizeof(struct sockaddr_ll));
      tx_sockaddr.sll_family = AF_PACKET;
      tx_sockaddr.sll_protocol = htons(ETH_P_IPV6);
      tx_sockaddr.sll_halen = ETH_ALEN;
      tx_sockaddr.sll_ifindex = conf.if_index;
      memcpy(tx_sockaddr.sll_addr, &conf.l2_dst, ETH_ALEN);
      /* sockaddr_ll gateway MAC */
      unsigned char tx_buf[1024];
      struct in6_addr l3_dst;

      /* rate limition */
      rate_limiter_t rate_limiter(conf.rate / shard);
      if (conf.type == "net") {
        /* e.g., input: /23s to probe every /48s
         *
         * |---a----||-----b-----||----c-----|
         *    23-bit     25-bit       80-bits
         *  prefix cyclic-permutation random
         */

        /* additive group 2^n */
        /* linear_congruential_random generation */
        uint64_t fullcyclic = std::bit_ceil(this->space);
        uint64_t shard_cyclic = fullcyclic / shard;
        uint64_t power = std::countr_zero(shard_cyclic);

        constexpr uint64_t GOLDEN = 11400714819323198485ULL; // 2^64 * 0.618
        uint64_t multiplier = GOLDEN >> (64 - power);
        multiplier = (multiplier & ~3ULL) | 1ULL; // multiplier: 4t + 1
        uint64_t increment = 1;
        std::mt19937_64 l_rng(conf.seed + offset);
        uint64_t lcg_state = 1; // inital state does not matter

        /* iid generation */
        struct iid_generator_t iid_generator(conf.iid);

        /* dispatch packets */
        for (size_t _ = 0; _ < conf.repeat; ++_) {
          for (size_t j = 0; j < shard_cyclic; ++j) {
            uint64_t idx = shard * lcg_state + offset;
            lcg_state = (multiplier * lcg_state + increment) % shard_cyclic;
            if (idx >= this->space) // reject sampling
              continue;
            auto it = std::upper_bound(ranges.begin(), ranges.end(),
                                       range_t{.stun = 0, .count = idx},
                                       [](const range_t &a, const range_t &b) {
                                         return a.count < b.count;
                                       });
            if (it == ranges.begin()) [[unlikely]]
              throw std::logic_error("Out-of-range index " +
                                     std::to_string(idx));
            it--;
            uint64_t network_prefix = it->stun;
            network_prefix += (idx - it->count) << (64 - conf.limit);
            network_prefix += l_rng() & ((1ULL << (64 - conf.limit)) - 1);

            uint64_t interface_identifier = iid_generator();

            std::memset(&tx_buf, 0, 1024);
            std::memset(&l3_dst, 0, sizeof(struct in6_addr));

            l3_dst.s6_addr32[0] =
                htonl(static_cast<uint32_t>(network_prefix >> 32));
            l3_dst.s6_addr32[1] =
                htonl(static_cast<uint32_t>(network_prefix & 0xffffffff));
            l3_dst.s6_addr32[2] =
                htonl(static_cast<uint32_t>(interface_identifier >> 32));
            l3_dst.s6_addr32[3] =
                htonl(static_cast<uint32_t>(interface_identifier & 0xffffffff));
            size_t len = conf.probe_module->make_packet(tx_buf, &l3_dst);

            rate_limiter.pass();

            if (sendto(fd, tx_buf, len, 0, (struct sockaddr *)&tx_sockaddr,
                       sizeof(struct sockaddr_ll)) < 0)
              throw std::system_error(errno, std::system_category(),
                                      "sendto() failed");
            state.total_sent.fetch_add(1, std::memory_order_relaxed);
          }
        }
      } else {
        auto beg = this->ranges[offset].beg;
        auto end = this->ranges[offset].end;
        std::ifstream in(conf.input);
        std::string line;
        for (size_t _ = 0; _ < conf.repeat; ++_) {
          in.clear();
          in.seekg(beg);
          while (static_cast<size_t>(in.tellg()) < end &&
                 std::getline(in, line)) {
            if (inet_pton(AF_INET6, line.c_str(), &l3_dst) == 1) {
              size_t len = conf.probe_module->make_packet(tx_buf, &l3_dst);
              rate_limiter.pass();
              if (sendto(fd, tx_buf, len, 0, (struct sockaddr *)&tx_sockaddr,
                         sizeof(struct sockaddr_ll)) < 0)
                throw std::system_error(errno, std::system_category(),
                                        "sendto() failed");
            }
            state.total_sent.fetch_add(1, std::memory_order_relaxed);
          }
        }
      }
    });
  }

private:
  uint64_t space;
  std::vector<range_t> ranges;
};

#endif
