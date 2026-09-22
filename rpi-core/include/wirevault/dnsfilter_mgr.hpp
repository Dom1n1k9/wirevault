#pragma once
// wirevault/dnsfilter_mgr.hpp - dnsmasq DNS filtering (blocklist) control.
#include <string>
#include <vector>

#include "wirevault/config.hpp"

namespace wv {

class DnsFilterMgr {
public:
  explicit DnsFilterMgr(Config cfg) : cfg_(std::move(cfg)) {}

  // Render dnsmasq config pointing at blocklist + write it.
  std::pair<bool, std::string> writeDnsmasqConf();

  // Write /etc/wirevault/dns-blocklist.conf (ad/tracker/wildcard entries).
  std::pair<bool, std::string> writeBlocklist(const std::vector<std::string> &domains);

  // Reload dnsmasq (SIGHUP).
  std::pair<bool, std::string> reload();

  // Count lines in the blocklist.
  size_t blocklistCount();

private:
  Config cfg_;
};

} // namespace wv
