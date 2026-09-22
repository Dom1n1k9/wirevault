#pragma once
// wirevault/netfilter_mgr.hpp - nftables control.
#include <string>
#include <vector>

#include "wirevault/config.hpp"

namespace wv {

class NetFilterMgr {
public:
  explicit NetFilterMgr(Config cfg) : cfg_(std::move(cfg)) {}

  // Render the whole rule set as an nftables script and apply with `nft -f`.
  std::pair<bool, std::string> apply();

  // Returns a current summary for the GUI (rules applied, blocked_hits)
  Json summary();

  // Add a rule at runtime (appends to cfg_.filter_rules and re-applies).
  std::pair<bool, std::string> addRule(const FilterRule &r);
  std::pair<bool, std::string> removeRule(const std::string &id);

  const std::vector<FilterRule> &rules() const { return cfg_.filter_rules; }

private:
  std::string render() const;
  Config cfg_;
};

} // namespace wv
