#ifndef MONITOR_HPP
#define MONITOR_HPP

#include "now.hpp"
#include "state.h"
#include <cstddef>
#include <thread>

class monitor_t {

private:
  std::string banner{};
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
    double eta = ((double)state.total - (double)total_sent) / sent_rate;

    /* displaying */
    fprintf(stderr, "\033[2J\033[H"); // clear screen

    if (!banner.empty())
      fprintf(stderr, "%s", banner.c_str());
    // fprintf(stderr, "==================== STATUS ==================\n");
    //
    // fprintf(stderr, "[Runtime]\n");
    // fprintf(stderr, "  elapsed      : %.2f s\n", elapsed);
    //
    // fprintf(stderr, "\n[Throughput]\n");
    // fprintf(stderr, "  sent         : %-12zu (%.2f pkt/s)\n", total_sent,
    //         sent_rate);
    // fprintf(stderr, "  recv         : %-12zu (%.2f pkt/s)\n", total_recv,
    //         recv_rate);
    // fprintf(stderr, "  drop         : %-12zu (%.2f pkt/s)\n", total_drop,
    //         drop_rate);
    //
    // fprintf(stderr, "\n[Progress]\n");
    // fprintf(stderr, "  task         : %.2f%% (%zu/%zu)\n", progress * 100.0,
    //         total_sent, state.total);
    // fprintf(stderr, "  eta          : %.2f s (%.2f min)\n", eta, eta / 60.0);
    //
    // fprintf(stderr, "==============================================\n");
    fprintf(stderr, CLR_TITLE
            "==================== STATUS ==================\n" CLR_RESET);

    fprintf(stderr, CLR_SEC "[Runtime]\n" CLR_RESET);
    fprintf(stderr, "  " CLR_KEY "elapsed      : " CLR_NUM "%.2f s\n" CLR_RESET,
            elapsed);

    fprintf(stderr, "\n" CLR_SEC "[Throughput]\n" CLR_RESET);

    fprintf(stderr,
            "  " CLR_KEY "sent         : " CLR_NUM
            "%-12zu (%.2f pkt/s)\n" CLR_RESET,
            total_sent, sent_rate);

    fprintf(stderr,
            "  " CLR_KEY "recv         : " CLR_NUM
            "%-12zu (%.2f pkt/s)\n" CLR_RESET,
            total_recv, recv_rate);

    fprintf(stderr,
            "  " CLR_KEY "drop         : %s%-12zu (%.2f pkt/s)\n" CLR_RESET,
            (total_drop > 0 ? CLR_WARN : CLR_NUM), total_drop, drop_rate);

    fprintf(stderr, "\n" CLR_SEC "[Progress]\n" CLR_RESET);

    fprintf(stderr,
            "  " CLR_KEY "task         : " CLR_NUM
            "%.2f%% (%zu/%zu)\n" CLR_RESET,
            progress * 100.0, total_sent, state.total);

    fprintf(stderr,
            "  " CLR_KEY "eta          : %s%.2f s (%.2f min)\n" CLR_RESET,
            (eta > 0 ? CLR_VAL : CLR_NULL), eta, eta / 60.0);

    fprintf(stderr, CLR_TITLE
            "==============================================\n" CLR_RESET);
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

  monitor_t(const std::string &banner)
      : banner(banner), start_time(std::chrono::steady_clock::now()),
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
