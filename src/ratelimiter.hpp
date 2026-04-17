#ifndef RATELIMIT_HPP
#define RATELIMIT_HPP

#include <chrono>
#include <mutex>
#include <thread>

class ratelimiter_t {
private:
  std::mutex mtx;
  uint32_t tokens;
  uint32_t capacity;
  uint32_t refillRate;
  std::chrono::steady_clock::time_point lastRefill;
  void refill() {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(mtx);

    std::chrono::duration<double> elapsed = now - lastRefill;
    uint32_t newTokens = static_cast<uint32_t>(elapsed.count() * refillRate);

    if (newTokens > 0) {
      tokens = std::min(capacity, tokens + newTokens);
      lastRefill = now;
    }
  }
  bool consume() {
    refill();
    std::lock_guard<std::mutex> lock(mtx);
    if (tokens >= 1) {
      tokens--;
      return true;
    }
    return false;
  }

public:
  ratelimiter_t(uint32_t rate) {
    lastRefill = std::chrono::steady_clock::now();
    refillRate = rate;
    tokens = 10000;
    capacity = 10000;
  }
  void pass() {
    while (!consume()) {
      std::this_thread::yield();
      std::this_thread::sleep_for(
          std::chrono::microseconds(1000000 / refillRate));
    }
  }
};

#endif
