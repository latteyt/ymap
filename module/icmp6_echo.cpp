#include "config.h"
#include "module_register.hpp"
#include "now.hpp"
#include <boost/container_hash/hash_fwd.hpp>
#include <boost/functional/hash.hpp>
#include <cstddef>
#include <cstdint>
#include <format>

#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <sys/types.h>

#define MAX_HOP_LIMIT 255

#define PREDICT_MAX_HOP_LIMIT(h) (((h) < 64) ? 64 : ((h) < 128) ? 128 : 255)

static FILE *file = NULL;

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

static size_t common_prefix_length(const struct in6_addr *t,
                                   const struct in6_addr *r) {
  uint64_t t_p, r_p; // target prefix, response prefix
  memcpy(&t_p, t->s6_addr, 8);
  memcpy(&r_p, r->s6_addr, 8);
  t_p = __builtin_bswap64(t_p);
  r_p = __builtin_bswap64(r_p);
  uint64_t x = t_p ^ r_p;
  return x == 0 ? 64 : __builtin_clzll(x);
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
  file = NULL;
}

static bool validate_packet(const unsigned char *rx_buf, size_t caplen) {
  auto *recv_ip6h = (struct ip6_hdr *)(rx_buf + sizeof(struct ethhdr));
  auto *recv_icmp6h = (struct icmp6_hdr *)(recv_ip6h + 1);
  /* validate_packet */
  switch (recv_icmp6h->icmp6_type) {
  case ICMP6_DST_UNREACH:
  case ICMP6_PACKET_TOO_BIG:
  case ICMP6_TIME_EXCEEDED:
  case ICMP6_PARAM_PROB:
    goto ICMPv6_ERROR;
  case ICMP6_ECHO_REPLY:
    goto ICMPv6_REPLY;
  default:
    return false;
  }
ICMPv6_ERROR: {
  if (caplen < sizeof(struct ethhdr) + 2 * sizeof(struct ip6_hdr) +
                   2 * sizeof(struct icmp6_hdr))
    return false;
  auto *send_ip6h = (struct ip6_hdr *)(recv_icmp6h + 1);
  auto *send_icmp6h = (struct icmp6_hdr *)(send_ip6h + 1);
  if (send_icmp6h->icmp6_seq !=
      static_cast<uint16_t>(cal_sign(&send_ip6h->ip6_dst, &send_ip6h->ip6_src)))
    return false;
  return true;
}
ICMPv6_REPLY: {
  if (caplen <
      sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr))
    return false;
  if (recv_icmp6h->icmp6_seq !=
      static_cast<uint16_t>(cal_sign(&recv_ip6h->ip6_src,
                                     &recv_ip6h->ip6_dst))) // swap src and dst
    return false;
  return true;
}
}

static void handle_packet(const unsigned char *rx_buf) {

  auto *recv_ip6h = (struct ip6_hdr *)(rx_buf + sizeof(struct ethhdr));
  auto *recv_icmp6h = (struct icmp6_hdr *)(recv_ip6h + 1);
  /* extract information */
  switch (recv_icmp6h->icmp6_type) {
  case ICMP6_DST_UNREACH:
  case ICMP6_PACKET_TOO_BIG:
  case ICMP6_TIME_EXCEEDED:
  case ICMP6_PARAM_PROB:
    goto ICMPv6_ERROR;
  case ICMP6_ECHO_REPLY:
    goto ICMPv6_REPLY;
  default:
    return;
  }
ICMPv6_ERROR: {
  auto *send_ip6h = (struct ip6_hdr *)(recv_icmp6h + 1);
  auto *send_icmp6h = (struct icmp6_hdr *)(send_ip6h + 1);

  fprintf(file, "%s,", to_string(&recv_ip6h->ip6_src).c_str());

  // the common_prefix_length is IMPORTANT indicator for IPv6 routing activity
  fprintf(file, "%zu,",
          common_prefix_length(&send_ip6h->ip6_dst, &recv_ip6h->ip6_src));
  fprintf(file, "%d,", recv_icmp6h->icmp6_type);
  fprintf(file, "%d,", recv_icmp6h->icmp6_code);
  fprintf(file, "%d,", MAX_HOP_LIMIT - send_ip6h->ip6_hlim);
  fprintf(file, "%d",
          static_cast<uint16_t>(current_steady_ms<uint16_t>() -
                                send_icmp6h->icmp6_id));
  fprintf(file, "\n");
  return;
}
ICMPv6_REPLY: {
  fprintf(file, "%s,", to_string(&recv_ip6h->ip6_src).c_str());

  fprintf(file, "%zu,",
          common_prefix_length(&recv_ip6h->ip6_src, &recv_ip6h->ip6_src));

  fprintf(file, "%d,", recv_icmp6h->icmp6_type);
  fprintf(file, "%d,", recv_icmp6h->icmp6_code);
  fprintf(file, "%d,",
          PREDICT_MAX_HOP_LIMIT(recv_ip6h->ip6_hlim) - recv_ip6h->ip6_hlim);
  fprintf(file, "%d",
          static_cast<uint16_t>(current_steady_ms<uint16_t>() -
                                recv_icmp6h->icmp6_id));
  fprintf(file, "\n");
  return;
}
}

static size_t make_packet(unsigned char *tx_buf, struct in6_addr *l3_dst) {

  struct ip6_hdr *ip6h = (struct ip6_hdr *)tx_buf;
  struct icmp6_hdr *icmp6h = (struct icmp6_hdr *)(ip6h + 1);
  icmp6h->icmp6_type = ICMP6_ECHO_REQUEST;
  icmp6h->icmp6_code = 0;
  icmp6h->icmp6_cksum = 0; // defer calculate
  icmp6h->icmp6_id = current_steady_ms<uint16_t>();
  icmp6h->icmp6_seq = 0; // defer calculate

  ip6h->ip6_flow = std::rand() & 0xfffff;
  ip6h->ip6_vfc = 0x60;
  ip6h->ip6_plen = htons(sizeof(struct icmp6_hdr));
  ip6h->ip6_nxt = IPPROTO_ICMPV6;
  ip6h->ip6_hlim = 0xff;
  memcpy(&ip6h->ip6_src, &conf.l3_src, sizeof(struct in6_addr));
  memcpy(&ip6h->ip6_dst, l3_dst, sizeof(struct in6_addr));

  /* calculate the seq */
  icmp6h->icmp6_seq =
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
  icmp6h->icmp6_cksum = uint16_t(~sum);
  return sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr);
}

probe_module_t icmp6_echo = {
    .name = "icmp6_echo",
    .module_init = module_init,
    .module_clear = module_clear,
    .make_packet = make_packet,
    .handle_packet = handle_packet,
    .validate_packet = validate_packet,
    .pcap_filter = "ip6 && icmp6",
};

REGISTER_PROBE_MODULE(icmp6_echo)
