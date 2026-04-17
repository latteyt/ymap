
#include <arpa/inet.h>
#include <filesystem>
#include <format>
#include <fstream>
#include <net/if.h>
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

  conf.if_name = pt.get<std::string>("Net.IF");
  conf.if_index = if_nametoindex(conf.if_name.c_str());
  if (conf.if_index == 0)
    throw std::runtime_error("Invalid Interface");

  if (!ether_aton_r(pt.get<std::string>("Net.L2Dst").c_str(), &conf.l2_dst))
    throw std::runtime_error("Invalid L2Dst");

  if (inet_pton(AF_INET6, pt.get<std::string>("Net.L3Src").c_str(),
                &conf.l3_src) != 1)
    throw std::runtime_error("Invalid L3Src");

  conf.seed = pt.get<size_t>("Runtime.seed", 42);
  conf.rate = pt.get<size_t>("Runtime.rate", 10000); // default 10kpps
  conf.limit = pt.get<size_t>("Runtime.limit", 48);  // default /48
  if (conf.limit > 64)
    throw std::runtime_error("Too Large Limit");
  conf.repeat = pt.get<size_t>("Runtime.repeat", 1); // default once
  conf.repeat = pt.get<size_t>("Runtime.seed", 42);  // default seed
  conf.shard =
      pt.get<size_t>("Runtime.shard", 1); // default number of send thread
  if (!(conf.shard > 0 && (conf.shard & (conf.shard - 1)) == 0))
    throw std::runtime_error("expect a positive power of two (2^n), got " +
                             std::to_string(conf.shard));

  {
    auto path = pt.get<std::string>("IO.input");
    std::ifstream in(path);
    if (!in.is_open())
      throw std::runtime_error("Invalid Input Path");
    std::string line;
    while (std::getline(in, line)) {
      auto net = boost::asio::ip::make_network_v6(line);
      if (conf.limit < net.prefix_length())
        throw std::runtime_error("Invalid Prefix" + line);
    }
    conf.input = path;
  }
  {
    auto path = pt.get<std::string>("IO.output", "");
    if (!path.empty() && std::filesystem::exists(path))
      throw std::runtime_error("Output Aclready Exists");
    conf.output = path;
  }
  {
    auto &registry = probe_module_registry();
    std::string module_name = pt.get<std::string>("Scan.type");
    auto it = registry.find(module_name);
    if (it == registry.end())
      throw std::runtime_error("Scan Type Not Found");
    conf.probe_module = it->second;
    conf.probe_module->module_init();
  }
  {
    std::string iid_mode = pt.get<std::string>("IID.mode");
    std::regex re(R"(^(\d+|0[xX][0-9a-fA-F]+)$)");
    if (!std::regex_match(iid_mode, re) && iid_mode != "rand")
      throw std::runtime_error("IID Mode Not Parsed");
    conf.iid_mode = iid_mode;
  }

  receiver_t receiver{};
  sender_t sender{};
  monitor_t monitor(conf.to_string());

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

  if (mn_thread.joinable())
    mn_thread.join();

  /* clear working */
  conf.probe_module->module_clear();

  return 0;
}
