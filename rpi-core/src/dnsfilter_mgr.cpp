// wirevault/dnsfilter_mgr.cpp
#include "wirevault/dnsfilter_mgr.hpp"

#include <cstdio>
#include <fstream>
#include <sstream>

#include "wirevault/logging.hpp"
#include "wirevault/subproc.hpp"

namespace wv {

std::pair<bool, std::string> DnsFilterMgr::writeDnsmasqConf() {
  // dnsmasq config pointing at our blocklist + upstream
  std::string conf =
      "no-resolv\n"
      "listen-address=127.0.0.1,10.66.0.1\n"
      "port=" + std::to_string(cfg_.dns.port) + "\n"
      "server=" + cfg_.dns.upstream + "\n";
  if (cfg_.dns.enabled && !cfg_.dns.blocklist_path.empty())
    conf += "conf-file=" + cfg_.dns.blocklist_path + "\n";
  FILE *f = fopen("/etc/dnsmasq.d/wirevault.conf", "w");
  if (!f)
    return {false, "cannot write /etc/dnsmasq.d/wirevault.conf"};
  fputs(conf.c_str(), f);
  fclose(f);
  return {true, ""};
}

std::pair<bool, std::string> DnsFilterMgr::writeBlocklist(
    const std::vector<std::string> &domains) {
  std::string out;
  for (const auto &d : domains) {
    // dnsmasq blocklist: address=/example.com/0.0.0.0
    out += "address=/" + d + "/0.0.0.0\n";
  }
  FILE *f = fopen(cfg_.dns.blocklist_path.c_str(), "w");
  if (!f)
    return {false, "cannot write blocklist"};
  fputs(out.c_str(), f);
  fclose(f);
  return {true, ""};
}

std::pair<bool, std::string> DnsFilterMgr::reload() {
  // simple SIGHUP to dnsmasq
  auto r = runCommand({"pkill", "-HUP", "dnsmasq"});
  return {r.ok(), r.stderr_text};
}

size_t DnsFilterMgr::blocklistCount() {
  std::ifstream f(cfg_.dns.blocklist_path);
  size_t n = 0;
  std::string line;
  while (std::getline(f, line))
    if (!line.empty())
      ++n;
  return n;
}

} // namespace wv
