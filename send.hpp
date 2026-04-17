#ifndef SEND_HPP
#define SEND_HPP
#include <arpa/inet.h>
#include <atomic>
#include <bit>
#include <boost/asio/ip/network_v6.hpp>
#include <boost/property_tree/ptree_fwd.hpp>
#include <cstdint>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
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

struct range_t {
  uint64_t stun;
  uint64_t count;
};

class sender_t {
public:
  sender_t() {
    /* inital our perfix vector */
    this->space = 0;
    {
      std::ifstream in(conf.input);
      std::string line;
      while (std::getline(in, line)) {
        auto net = boost::asio::ip::make_network_v6(line);
        uint64_t len = net.prefix_length();
        auto nbytes = net.network().to_bytes();
        uint64_t stun = std::accumulate(
            nbytes.begin(), nbytes.begin() + 8, uint64_t{0},
            [](uint64_t acc, uint8_t byte) { return (acc << 8) | byte; });
        this->ranges.push_back({stun, this->space});
        this->space += (1ULL << (conf.limit - len));
      }
    }
    state.total = this->space;
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

      /* e.g., input: /23s to probe every /48s
       *
       * |---a----||-----b-----||----c-----|
       *    23-bit     25-bit       80-bits
       *  prefix cyclic-permutation random
       */

      /* rate limition */
      ratelimiter_t rl(conf.rate / shard);

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

      // rng() % shard_cyclic;
      /* iid generation */
      struct iid_generator_t iid_generator(conf.iid_mode);

      /* dispatch packets */
      for (size_t _ = 0; _ < conf.repeat; ++_) {
        for (size_t j = 0; j < shard_cyclic; ++j) {
          uint64_t idx = shard * lcg_state + offset;
          lcg_state = (multiplier * lcg_state + increment) % shard_cyclic;
          if (idx >= this->space) // reject sampling
            continue;
          auto it =
              std::upper_bound(ranges.begin(), ranges.end(), range_t{0, idx},
                               [](const range_t &a, const range_t &b) {
                                 return a.count < b.count;
                               });
          if (it == ranges.begin()) [[unlikely]]
            throw std::logic_error("Out-of-range index " + std::to_string(idx));
          it--;
          uint64_t prefix = it->stun;
          prefix += (idx - it->count) << (64 - conf.limit);
          prefix += l_rng() & ((1ULL << (64 - conf.limit)) - 1);

          uint64_t iid = iid_generator();

          std::memset(&tx_buf, 0, 1024);
          std::memset(&l3_dst, 0, sizeof(struct in6_addr));

          // prefix = 0x240d001a09c20901;
          // iid = 0x0;

          l3_dst.s6_addr32[0] = htonl(static_cast<uint32_t>(prefix >> 32));
          l3_dst.s6_addr32[1] =
              htonl(static_cast<uint32_t>(prefix & 0xffffffff));
          l3_dst.s6_addr32[2] = htonl(static_cast<uint32_t>(iid >> 32));
          l3_dst.s6_addr32[3] = htonl(static_cast<uint32_t>(iid & 0xffffffff));
          size_t len = conf.probe_module->make_packet(tx_buf, &l3_dst, 0);

          rl.pass();

          if (sendto(fd, tx_buf, len, 0, (struct sockaddr *)&tx_sockaddr,
                     sizeof(struct sockaddr_ll)) < 0)
            throw std::system_error(errno, std::system_category(),
                                    "sendto() failed");
          state.total_sent.fetch_add(1, std::memory_order_relaxed);
        }
      }
    });
  }

private:
  uint64_t space;
  std::vector<range_t> ranges;
};

#endif
