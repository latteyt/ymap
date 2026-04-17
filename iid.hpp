
#ifndef IID_H
#define IID_H
#include <charconv>
#include <cstdint>
#include <functional>
#include <random>
#include <stdexcept>
#include <string>

struct iid_generator_t {
  std::function<uint64_t()> generate;
  std::mt19937_64 rng;

  iid_generator_t(const iid_generator_t &) = delete;
  iid_generator_t &operator=(const iid_generator_t &) = delete;

  iid_generator_t(std::string mode) : rng(std::random_device{}()) {
    if (mode == "rand") {
      generate = [this]() noexcept { return this->rng(); };
    } else {
      uint64_t value;
      size_t base = 10;
      const char *begin = mode.data();
      const char *end = mode.data() + mode.size();
      if (mode.starts_with("0x")) {
        begin += 2;
        base = 16;
      }
      auto [ptr, ec] = std::from_chars(begin, end, value, base);
      if (ec != std::errc())
        throw std::runtime_error("IID Value Not Parsed");
      generate = [value]() noexcept { return value; };
    }
  }

  uint64_t operator()() const noexcept { return generate(); }
};
#endif
