#ifndef PROBE_MODULE_H
#define PROBE_MODULE_H
#include <cstddef>
#include <netinet/in.h>
#include <string>
#include <string_view>
#include <unordered_map>
struct probe_module_t {
  std::string name;
  bool (*module_init)();
  void (*module_clear)();
  size_t (*make_packet)(unsigned char *, struct in6_addr *);
  void (*handle_packet)(const unsigned char *);
  bool (*validate_packet)(const unsigned char *, size_t);
  std::string pcap_filter;
};

inline std::unordered_map<std::string_view, const probe_module_t *> &
probe_module_registry() {
  static std::unordered_map<std::string_view, const probe_module_t *> reg;
  return reg;
}

inline void register_probe_module(const probe_module_t *m) {
  probe_module_registry()[m->name] = m;
}

// ensure registerar before main
struct probe_module_registrar_t {
  probe_module_registrar_t(const probe_module_t *m) {
    register_probe_module(m);
  }
};

#define REGISTER_PROBE_MODULE(module_var)                                      \
  static probe_module_registrar_t _registrar_##module_var(&module_var);

#endif
