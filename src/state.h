#ifndef STATE_H
#define STATE_H

#include <atomic>
#include <pcap/pcap.h>

struct state_t {
  state_t() = default;

  state_t(const state_t &) = delete;
  state_t(state_t &&) = delete;
  state_t &operator=(const state_t &) = delete;
  state_t &operator=(state_t &&) = delete;

  pcap_t *handle{nullptr}; // for packet receiver/ monitor
  std::atomic<uint64_t> finish_time{0};

  std::atomic<size_t> total_sent;
  std::atomic<size_t> total_recv;

  size_t total =0;
};

inline state_t state;

#endif
