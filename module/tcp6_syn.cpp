#include "config.h"
#include "module_register.hpp"

#include <arpa/inet.h>
#include <boost/functional/hash.hpp>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <format>
#include <linux/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

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

static bool validate_packet(const unsigned char *rx_buf, size_t caplen) {
  if (caplen <
      sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + sizeof(struct tcphdr))
    return false;

  auto *ip6h = (struct ip6_hdr *)(rx_buf + sizeof(struct ethhdr));
  if (ip6h->ip6_nxt != IPPROTO_TCP)
    return false;

  auto *tcph = (struct tcphdr *)(ip6h + 1);
  if (ntohs(tcph->source) != conf.th_dport)
    return false;

  uint8_t flags = *(reinterpret_cast<const uint8_t *>(tcph) + 13);
  if (!(flags & (TH_SYN | TH_RST)))
    return false;
  if (!(flags & TH_ACK))
    return false;

  if (ntohs(tcph->th_dport) !=
      static_cast<uint16_t>(cal_sign(&ip6h->ip6_src, &ip6h->ip6_dst)))
    return false;

  return true;
}

static void handle_packet(const unsigned char *rx_buf) {
  auto *ip6h = (struct ip6_hdr *)(rx_buf + sizeof(struct ethhdr));
  auto *tcph = (struct tcphdr *)(ip6h + 1);
  uint8_t flags = *(reinterpret_cast<const uint8_t *>(tcph) + 13);

  if (flags & TH_SYN) {
    fprintf(file, "%s,%u,%u,open\n", to_string(&ip6h->ip6_src).c_str(),
            ntohs(tcph->th_sport), flags);
  } else if (flags & TH_RST) {
    fprintf(file, "%s,%u,%u,close\n", to_string(&ip6h->ip6_src).c_str(),
            ntohs(tcph->th_sport), flags);
  } else {
    fprintf(file, "%s,%u,%u,other\n", to_string(&ip6h->ip6_src).c_str(),
            ntohs(tcph->th_sport), flags);
  }
}

static size_t make_packet(unsigned char *tx_buf, struct in6_addr *l3_dst) {
  auto *ip6h = (struct ip6_hdr *)tx_buf;
  auto *tcph = (struct tcphdr *)(ip6h + 1);

  tcph->th_sport = 0;
  tcph->th_dport = htons(conf.th_dport);
  tcph->th_seq = std::rand();
  tcph->th_ack = 0;
  tcph->th_x2 = 0;
  tcph->th_off = 5; // data offset 5*4=20 -> no options
  tcph->th_flags = 0;
  tcph->th_flags |= TH_SYN;
  tcph->th_win = htons(65535); // largest possible window
  tcph->th_sum = 0;
  tcph->th_urp = 0;

  ip6h->ip6_flow = std::rand() & 0xfffff;
  ip6h->ip6_vfc = 0x60; // MUST after ip6_flow
  ip6h->ip6_plen = htons(sizeof(struct tcphdr));
  ip6h->ip6_nxt = IPPROTO_TCP;
  ip6h->ip6_hlim = 64;
  std::memcpy(&ip6h->ip6_src, &conf.l3_src, sizeof(struct in6_addr));
  std::memcpy(&ip6h->ip6_dst, l3_dst, sizeof(struct in6_addr));

  /* calculate the src port */
  tcph->th_sport = htons(static_cast<uint16_t>(cal_sign(&ip6h->ip6_dst,
                                                         &ip6h->ip6_src)));

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

  tcph->th_sum = uint16_t(~sum);

  return sizeof(struct ip6_hdr) + sizeof(struct tcphdr);
}

static probe_module_t tcp6_syn = {
    .name = "tcp6_syn",
    .module_init = module_init,
    .module_clear = module_clear,
    .make_packet = make_packet,
    .handle_packet = handle_packet,
    .validate_packet = validate_packet,
    .pcap_filter = "ip6 && tcp",
};

REGISTER_PROBE_MODULE(tcp6_syn)
