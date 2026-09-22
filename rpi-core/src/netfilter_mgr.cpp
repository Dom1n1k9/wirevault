// wirevault/netfilter_mgr.cpp
#include "wirevault/netfilter_mgr.hpp"

#include <algorithm>
#include <cstdio>
#include <sstream>

#include "wirevault/logging.hpp"
#include "wirevault/subproc.hpp"

namespace wv {

std::string NetFilterMgr::render() const {
  std::ostringstream n;
  n << "#!/usr/sbin/nft -f\n";
  n << "flush ruleset\n";
  n << "table inet wirevault {\n";
  n << "  chain block_input {\n";
  n << "    type filter hook input priority 0; policy accept;\n";
  for (const auto &r : cfg_.filter_rules) {
    if (r.action == "block") {
      n << "    ip saddr " << r.host;
      if (r.proto == "tcp")
        n << " tcp sport " << (r.port ? std::to_string(r.port) : std::string("0"));
      else if (r.proto == "udp")
        n << " udp sport " << (r.port ? std::to_string(r.port) : std::string("0"));
      n << " drop\n";
    } else if (r.action == "allow") {
      n << "    ip saddr " << r.host << " accept\n";
    }
  }
  n << "  }\n";
  n << "  chain forward {\n";
  n << "    type filter hook forward priority 0; policy accept;\n";
  // by default allow the WG subnet; rules append below
  n << "    ip saddr " << "10.66.0.0/24" << " accept\n";
  for (const auto &r : cfg_.filter_rules) {
    if (r.action == "block") {
      n << "    ip saddr " << r.host;
      if (r.proto == "tcp")
        n << " tcp sport " << (r.port ? std::to_string(r.port) : std::string("0"));
      else if (r.proto == "udp")
        n << " udp sport " << (r.port ? std::to_string(r.port) : std::string("0"));
      n << " drop\n";
    }
  }
  n << "  }\n";
  n << "}\n";
  return n.str();
}

std::pair<bool, std::string> NetFilterMgr::apply() {
  std::string script = render();
  // write first to a temp file so `nft -f` gets a consistent snapshot
  FILE *f = fopen("/tmp/wirevault.rules.nft", "w");
  if (!f)
    return {false, "cannot open /tmp/wirevault.rules.nft"};
  fputs(script.c_str(), f);
  fclose(f);
  auto r = runCommand({"nft", "-f", "/tmp/wirevault.rules.nft"});
  if (!r.ok())
    return {false, r.stderr_text};
  return {true, "rules applied"};
}

Json NetFilterMgr::summary() {
  Json obj(Json::Object{});
  obj.set("rules_applied", Json((int64_t)cfg_.filter_rules.size()));
  obj.set("blocked", Json(0)); // would come from nft counters; placeholder
  return obj;
}

std::pair<bool, std::string> NetFilterMgr::addRule(const FilterRule &r) {
  cfg_.filter_rules.push_back(r);
  return apply();
}

std::pair<bool, std::string> NetFilterMgr::removeRule(const std::string &id) {
  auto it = std::find_if(cfg_.filter_rules.begin(), cfg_.filter_rules.end(),
                         [&](const FilterRule &r) { return r.id == id; });
  if (it == cfg_.filter_rules.end())
    return {false, "no such rule"};
  cfg_.filter_rules.erase(it);
  return apply();
}

} // namespace wv
