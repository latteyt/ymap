#include "config.h"
#include "module_register.hpp"

#include <arpa/inet.h>
#include <boost/functional/hash.hpp>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <format>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <string>

#define CoAP_PORT 5683

static FILE *file = NULL;
// Fixed CoAP request payload copied into every probe packet.
// It encodes a GET request for the standard `/.well-known/core` resource.
unsigned char CoAP_TEMP[] = {0x40, 0x1,  0x31, 0x2d, 0xbb, 0x2e, 0x77,
                             0x65, 0x6c, 0x6c, 0x2d, 0x6b, 0x6e, 0x6f,
                             0x77, 0x6e, 0x4,  0x63, 0x6f, 0x72, 0x65};

static size_t cal_sign(struct in6_addr *dst, struct in6_addr *src) {
  size_t seed = 0;
  const uint8_t *d = reinterpret_cast<const uint8_t *>(dst);
  const uint8_t *s = reinterpret_cast<const uint8_t *>(src);
  boost::hash_range(seed, d, d + 16);
  boost::hash_range(seed, s, s + 16);
  return seed;
}

static std::string to_string(const struct in6_addr *ip) {
  return std::format("{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}",
                     ntohs(ip->s6_addr16[0]), ntohs(ip->s6_addr16[1]),
                     ntohs(ip->s6_addr16[2]), ntohs(ip->s6_addr16[3]),
                     ntohs(ip->s6_addr16[4]), ntohs(ip->s6_addr16[5]),
                     ntohs(ip->s6_addr16[6]), ntohs(ip->s6_addr16[7]));
}

static bool module_init() {
  if (conf.output.empty()) {
    file = stdout;
  } else {
    file = fopen(conf.output.c_str(), "w");
  }
  return file != NULL;
}

static void module_clear() {
  if (file) {
    fflush(file);
    fclose(file);
  }
}

static void handle_packet(const unsigned char *rx_buf) {

  auto *ip6h = (struct ip6_hdr *)(rx_buf + sizeof(struct ethhdr));
  auto *udph = (struct udphdr *)(ip6h + 1);
  unsigned char *coaph = reinterpret_cast<unsigned char *>(udph + 1);

  uint8_t code = *(coaph + 1);
  fprintf(file, "%s,", to_string(&ip6h->ip6_src).c_str());
  fprintf(file, "%d,", ntohs(udph->source));
  fprintf(file, "%d.%02d,", code >> 5,
          code & 0x1f); //  class 3 bits detail 5 bits
  fprintf(file, "\n");
}

static bool validate_packet(const unsigned char *rx_buf, size_t caplen) {
  if (caplen < sizeof(struct ethhdr) + sizeof(struct ip6_hdr) +
                   sizeof(struct udphdr) + 2)
    return false;

  auto *ip6h = (struct ip6_hdr *)(rx_buf + sizeof(struct ethhdr));
  if (ip6h->ip6_nxt != IPPROTO_UDP)
    return false;
  // fprintf(file, "%s,", to_string(&ip6h->ip6_src).c_str());
  auto *udph = (struct udphdr *)(ip6h + 1);
  if (udph->source != htons(CoAP_PORT))
    return false;
  if (udph->dest !=
      static_cast<uint16_t>(cal_sign(&ip6h->ip6_src, &ip6h->ip6_dst)))
    return false;
  return true;
}

static size_t make_packet(unsigned char *tx_buf, struct in6_addr *l3_dst) {
  auto *ip6h = reinterpret_cast<struct ip6_hdr *>(tx_buf);
  auto *udph = reinterpret_cast<struct udphdr *>(ip6h + 1);
  unsigned char *coaph = reinterpret_cast<unsigned char *>(udph + 1);

  std::memcpy(coaph, CoAP_TEMP, sizeof(CoAP_TEMP));

  udph->source = 0;
  udph->dest = htons(CoAP_PORT);
  udph->len = htons(static_cast<uint16_t>(8 + sizeof(CoAP_TEMP)));
  udph->check = 0;

  ip6h->ip6_flow = std::rand() & 0xfffff;
  ip6h->ip6_vfc = 0x60; // MUST after ip6_flow
  ip6h->ip6_plen = htons(static_cast<uint16_t>(8 + sizeof(CoAP_TEMP)));
  ip6h->ip6_nxt = IPPROTO_UDP;
  ip6h->ip6_hlim = 64;
  std::memcpy(&ip6h->ip6_src, &conf.l3_src, sizeof(struct in6_addr));
  std::memcpy(&ip6h->ip6_dst, l3_dst, sizeof(struct in6_addr));

  /* calculate the src port */
  udph->source =
      static_cast<uint16_t>(cal_sign(&ip6h->ip6_dst, &ip6h->ip6_src));

  /* calculate the checksum */
  uint32_t sum = 0;
  for (int i = 0; i < 8; i++) {
    sum += ip6h->ip6_src.s6_addr16[i];
    sum += ip6h->ip6_dst.s6_addr16[i];
  }
  sum += ip6h->ip6_plen;
  sum += htons(ip6h->ip6_nxt);
  uint16_t *data = (uint16_t *)(ip6h + 1);
  ssize_t data_len = ntohs(ip6h->ip6_plen);
  while (data_len > 1) {
    sum += *data++;
    data_len -= 2;
  }
  if (data_len > 0) {
    sum += *data & ntohs(0xff00);
  }
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum = (sum >> 16) + (sum & 0xFFFF);

  udph->check = uint16_t(~sum);

  return sizeof(struct ip6_hdr) + sizeof(struct udphdr) + sizeof(CoAP_TEMP);
}

static probe_module_t udp6_coap = {
    .name = "udp6_coap",
    .module_init = module_init,
    .module_clear = module_clear,
    .make_packet = make_packet,
    .handle_packet = handle_packet,
    .validate_packet = validate_packet,
    .pcap_filter = "ip6 && udp && src port 5683",
};

REGISTER_PROBE_MODULE(udp6_coap)
