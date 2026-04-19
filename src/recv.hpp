#ifndef RECV_HPP
#define RECV_HPP

#include <chrono>

#include <linux/if_ether.h>
#include <netinet/in.h>
#include <string>
#include <thread>

#include <boost/functional/hash.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include "config.h"
#include "now.hpp"
#include "state.h"
#include <netinet/ether.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <pcap.h>

class receiver_t {
public:
  receiver_t() {
    char errbuf[PCAP_ERRBUF_SIZE];
    state.handle =
        pcap_open_live(conf.if_name.c_str(), BUFSIZ, 0, 1000, errbuf);
    // only capture replies, no time out
    if (state.handle == nullptr)
      throw std::runtime_error(std::string("pcap_open_live failed: ") + errbuf);

    if (pcap_compile(state.handle, &fp, conf.probe_module->pcap_filter.c_str(),
                     0,

                     PCAP_NETMASK_UNKNOWN) != 0)
      throw std::runtime_error(std::string("pcap_compile failed: ") +
                               pcap_geterr(state.handle));

    if (pcap_setfilter(state.handle, &fp) != 0)
      throw std::runtime_error(std::string("pcap_setfilter failed: ") +
                               pcap_geterr(state.handle));

    if (pcap_setnonblock(state.handle, 1, errbuf) == -1)
      throw std::runtime_error(std::string("pcap_setnonblock error: ") +
                               errbuf);
  }
  ~receiver_t() {
    if (state.handle) {
      pcap_freecode(&fp);
      pcap_close(state.handle);
      state.handle = nullptr;
    }
  }

  std::thread run() {
    return std::thread([]() {
      do {
        int ret = pcap_dispatch(
            state.handle, -1,
            [](u_char *user, const struct pcap_pkthdr *h, const u_char *d) {
              auto &conf = *reinterpret_cast<config_t *>(user);
              if (conf.probe_module->validate_packet(d, h->caplen)) {
                state.total_recv.fetch_add(1, std::memory_order_relaxed);
                conf.probe_module->handle_packet(d, h->caplen);
              }
            },
            reinterpret_cast<u_char *>(&conf));

        if (ret == -1)
          throw std::runtime_error("pcap_dispatch error");
        else if (ret == 0)
          std::this_thread::sleep_for(std::chrono::microseconds(500));

      } while (state.finish_time == 0 ||
               (current_steady_ms<uint64_t>() - state.finish_time <
                10000)); // 10000 ms
    });
  }

private:
  struct bpf_program fp;
};

#endif
