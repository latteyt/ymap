
#ifndef NOW_HPP
#define NOW_HPP

#include <chrono>

template <typename T> inline T current_steady_ms() noexcept {
  using namespace std::chrono;

  auto ms = duration_cast<milliseconds>(steady_clock::now().time_since_epoch())
                .count();

  return static_cast<T>(ms);
}

#endif
