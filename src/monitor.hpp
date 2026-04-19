#ifndef MONITOR_HPP
#define MONITOR_HPP

#include "config.h"
#include "now.hpp"
#include "state.h"
#include <cstddef>
#include <cstdio>
#include <thread>

#define CLR_RESET "\033[0m"
#define CLR_BOLD "\033[1m"
#define CLR_DIM "\033[2m"

#define CLR_TITLE "\033[1;36m" // 标题：cyan
#define CLR_KEY "\033[1;33m"   // key：yellow
#define CLR_VAL "\033[0;37m"   // 普通值：white
#define CLR_NUM "\033[1;32m"   // 数值/速率：green
#define CLR_WARN "\033[1;31m"  // 异常：red
#define CLR_NULL "\033[2;31m"  // null/弱提示：dim red
#define CLR_SEC "\033[2;36m"   // 分区标题：dim cyan
constexpr double EPS = 1e-9;

class monitor_t {

private:
  struct pcap_stat pcst;

  std::chrono::time_point<std::chrono::steady_clock> start_time;
  std::chrono::time_point<std::chrono::steady_clock> last_update_time;
  size_t last_update_sent;
  size_t last_update_recv;
  size_t last_update_drop;

  void update() {
    size_t total_sent = state.total_sent.load(std::memory_order_relaxed);
    size_t total_recv = state.total_recv.load(std::memory_order_relaxed);
    if (pcap_stats(state.handle, &pcst) != 0)
      throw std::runtime_error(std::string("pcap_stats failed: ") +
                               pcap_geterr(state.handle));
    size_t total_drop = pcst.ps_drop;

    auto update_time = std::chrono::steady_clock::now();

    double elapsed =
        std::chrono::duration<double>(update_time - start_time).count();
    if (elapsed <= 0.0)
      return;

    double tick =
        std::chrono::duration<double>(update_time - last_update_time).count();

    double sent_rate = (total_sent - last_update_sent) / tick;
    double recv_rate = (total_recv - last_update_recv) / tick;
    double drop_rate = (total_drop - last_update_drop) / tick;

    double progress = (double)total_sent / (double)state.total;
    double eta = ((double)state.total - (double)total_sent) / (sent_rate + EPS);

    /* displaying */
    fprintf(stderr, "\033[2J\033[H\n"); // clear screen

    std::string l3_src = std::format(
        "{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}",
        ntohs(conf.l3_src.s6_addr16[0]), ntohs(conf.l3_src.s6_addr16[1]),
        ntohs(conf.l3_src.s6_addr16[2]), ntohs(conf.l3_src.s6_addr16[3]),
        ntohs(conf.l3_src.s6_addr16[4]), ntohs(conf.l3_src.s6_addr16[5]),
        ntohs(conf.l3_src.s6_addr16[6]), ntohs(conf.l3_src.s6_addr16[7]));

    std::string l2_dst = std::format(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        conf.l2_dst.ether_addr_octet[0], conf.l2_dst.ether_addr_octet[1],
        conf.l2_dst.ether_addr_octet[2], conf.l2_dst.ether_addr_octet[3],
        conf.l2_dst.ether_addr_octet[4], conf.l2_dst.ether_addr_octet[5]);

    fprintf(stderr, CLR_TITLE
            "   ==================== CONFIG ====================\n" CLR_RESET);
    fprintf(stderr, "     " CLR_KEY "if_name   : " CLR_VAL "%s\n" CLR_RESET,
            conf.if_name.c_str());
    fprintf(stderr, "     " CLR_KEY "if_index  : " CLR_NUM "%d\n" CLR_RESET,
            conf.if_index);
    fprintf(stderr, "     " CLR_KEY "l3_src    : " CLR_VAL "%s\n" CLR_RESET,
            l3_src.c_str());
    fprintf(stderr, "     " CLR_KEY "l2_dst    : " CLR_VAL "%s\n" CLR_RESET,
            l2_dst.c_str());

    fprintf(stderr, "     " CLR_KEY "rate      : " CLR_NUM "%zu\n" CLR_RESET,
            conf.rate);
    fprintf(stderr, "     " CLR_KEY "repeat    : " CLR_NUM "%zu\n" CLR_RESET,
            conf.repeat);
    fprintf(stderr, "     " CLR_KEY "shard     : " CLR_NUM "%zu\n" CLR_RESET,
            conf.shard);
    if (conf.type == "net") {
      fprintf(stderr, "     " CLR_KEY "seed      : " CLR_NUM "%zu\n" CLR_RESET,
              conf.seed);
      fprintf(stderr, "     " CLR_KEY "limit     : " CLR_NUM "%zu\n" CLR_RESET,
              conf.limit);
    }

    fprintf(stderr, "     " CLR_KEY "type      : " CLR_VAL "%s\n" CLR_RESET,
            conf.type.c_str());
    fprintf(stderr, "     " CLR_KEY "input     : " CLR_VAL "%s\n" CLR_RESET,
            conf.input.c_str());
    fprintf(stderr, "     " CLR_KEY "output    : %s%s\n" CLR_RESET,
            conf.output.empty() ? CLR_NULL : CLR_VAL,
            conf.output.empty() ? "stdout" : conf.output.c_str());
    fprintf(stderr, "     " CLR_KEY "probe     : %s%s\n" CLR_RESET,
            conf.probe_module ? CLR_VAL : CLR_NULL,
            conf.probe_module ? conf.probe_module->name.c_str() : "null");

    if (conf.type == "net") {
      fprintf(stderr, "     " CLR_KEY "iid mode  : " CLR_VAL "%s\n" CLR_RESET,
              conf.iid.c_str());
    }

    fprintf(stderr, CLR_TITLE
            "   ==================== STATUS ====================\n" CLR_RESET);
    fprintf(stderr, "   " CLR_SEC "[Runtime]\n" CLR_RESET);
    fprintf(stderr,
            "     " CLR_KEY "elapsed      : " CLR_NUM "%.2f s\n" CLR_RESET,
            elapsed);
    fprintf(stderr, "\n   " CLR_SEC "[Throughput]\n" CLR_RESET);
    fprintf(stderr,
            "     " CLR_KEY "sent         : " CLR_NUM
            "%-12zu (%.2f pkt/s)\n" CLR_RESET,
            total_sent, sent_rate);
    fprintf(stderr,
            "     " CLR_KEY "recv         : " CLR_NUM
            "%-12zu (%.2f pkt/s)\n" CLR_RESET,
            total_recv, recv_rate);
    fprintf(stderr,
            "     " CLR_KEY "drop         : %s%-12zu (%.2f pkt/s)\n" CLR_RESET,
            (total_drop > 0 ? CLR_WARN : CLR_NUM), total_drop, drop_rate);
    fprintf(stderr, "\n   " CLR_SEC "[Progress]\n" CLR_RESET);
    fprintf(stderr,
            "     " CLR_KEY "task         : " CLR_NUM
            "%.2f%% (%zu/%zu)\n" CLR_RESET,
            progress * 100.0, total_sent, state.total);
    fprintf(stderr,
            "     " CLR_KEY "eta          : %s%.2f s (%.2f min)\n" CLR_RESET,
            (eta > 0 ? CLR_VAL : CLR_NULL), eta, eta / 60.0);
    fprintf(stderr, CLR_TITLE
            "   ===============================================\n" CLR_RESET);
    fflush(stderr);
    /* updating ... */

    last_update_time = update_time;
    last_update_sent = total_sent;
    last_update_recv = total_recv;
    last_update_drop = total_drop;
    //
  }

public:
  monitor_t()
      : start_time(std::chrono::steady_clock::now()),
        last_update_time(std::chrono::steady_clock::now()), last_update_sent(0),
        last_update_recv(0), last_update_drop(0) {}

  std::thread run() {
    return std::thread([this]() {
      do {
        update();
        std::this_thread::sleep_for(std::chrono::milliseconds(1000)); // 1s
      } while (state.finish_time == 0 ||
               (current_steady_ms<uint64_t>() - state.finish_time <
                10000)); // 10000 ms
    });
  }
};

#endif
