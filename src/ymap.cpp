
#include <arpa/inet.h>
#include <chrono>
#include <filesystem>
#include <format>
#include <fstream>
#include <net/if.h>
#include <random>
#include <regex>
#include <stdexcept>
#include <string>
#include <thread>

#include <fcntl.h>
#include <unistd.h>

#include "config.h"
#include "monitor.hpp"
#include "now.hpp"
#include "recv.hpp"
#include "send.hpp"
#include "state.h"
#include <boost/asio/ip/network_v6.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/property_tree/ptree.hpp>

int main(int argc, char *argv[]) {
  if (argc < 2)
    throw std::runtime_error(std::format("Usage: {:s} <argument>\n", argv[0]));

  std::string ini = argv[1];
  boost::property_tree::ptree pt;
  boost::property_tree::ini_parser::read_ini(ini, pt);

  // std::cout << std::format("{}\n", pt.get<std::string>("Net.IF"));

  conf.if_name = pt.get<std::string>("Interface.name");
  conf.if_index = if_nametoindex(conf.if_name.c_str());
  if (conf.if_index == 0)
    throw std::runtime_error("Invalid Interface");

  if (!ether_aton_r(pt.get<std::string>("Interface.l2_dst").c_str(),
                    &conf.l2_dst))
    throw std::runtime_error("Invalid L2Dst");

  if (inet_pton(AF_INET6, pt.get<std::string>("Interface.l3_src").c_str(),
                &conf.l3_src) != 1)
    throw std::runtime_error("Invalid L3Src");

  // Runtime
  conf.rate = pt.get<size_t>("Runtime.rate", 10000); // default 10kpps
  conf.repeat = pt.get<size_t>("Runtime.repeat", 1); // default once
  conf.shard =
      pt.get<size_t>("Runtime.shard", 1); // default number of send thread
  if (!(conf.shard > 0 && (conf.shard & (conf.shard - 1)) == 0))
    throw std::runtime_error("expect a positive power of two (2^n), got " +
                             std::to_string(conf.shard));
  // Scan
  {
    auto type = pt.get<std::string>("Scan.type", "ip"); // default is ip list
    if (type != "net" && type != "ip")
      throw std::runtime_error("Invalid Scan Type! Only `net` or `ip`");
    conf.type = type;
  }
  {
    auto &registry = probe_module_registry();
    std::string module_name = pt.get<std::string>("Scan.module");
    auto it = registry.find(module_name);
    if (it == registry.end())
      throw std::runtime_error("Scan Type Not Found");
    conf.probe_module = it->second;
  }
  {
    auto path = pt.get<std::string>("Scan.input");
    std::ifstream in(path);
    if (!in.is_open())
      throw std::runtime_error("Invalid Input Path");
    conf.input = path;
  }
  {
    auto path = pt.get<std::string>("Scan.output", "");
    if (!path.empty() && std::filesystem::exists(path))
      throw std::runtime_error("Output Aclready Exists");
    conf.output = path;
  }

  // Optional
  if (conf.type == "net") {
    // net mode MUST need limit, seed and iid
    conf.seed = pt.get<size_t>("Optional.seed", std::random_device{}());
    conf.limit = pt.get<size_t>("Optional.limit"); // default /48
    if (conf.limit > 64)
      throw std::runtime_error("Too Large Limit");

    std::string iid = pt.get<std::string>("Optional.iid");
    std::regex re(R"(^(\d+|0[xX][0-9a-fA-F]+)$)");
    if (!std::regex_match(iid, re) && iid != "rand")
      throw std::runtime_error("IID Mode Not Parsed");
    conf.iid = iid;
  }
  if (conf.probe_module->name == "tcp6_syn") {
    conf.th_dport = pt.get<uint16_t>("Optional.th_dport", 80);
    if (conf.th_dport == 0)
      throw std::runtime_error("Invalid dst_port");
  }

  conf.probe_module->module_init();

  receiver_t receiver{};
  sender_t sender{};
  monitor_t monitor{};

  std::thread mn_thread = monitor.run();
  std::thread rx_thread = receiver.run();
  std::vector<std::thread> tx_threads;
  for (size_t i = 0; i < conf.shard; i++) {
    tx_threads.emplace_back(sender.run(conf.shard, i));
  }
  for (auto &t : tx_threads) {
    t.join();
  }

  state.finish_time = current_steady_ms<uint64_t>();
  /* packet sending finished */

  if (rx_thread.joinable())
    rx_thread.join();

  std::this_thread::sleep_for(std::chrono::seconds(3));

  if (mn_thread.joinable())
    mn_thread.join();

  /* clear working */
  conf.probe_module->module_clear();

  return 0;
}
