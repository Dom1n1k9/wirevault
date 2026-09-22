#pragma once
// wirevault/watch_elems.hpp - cybersecurity watch: Suricata eve.json tail +
// fail2ban aggregator -> normalized threats published on the event bus.
#include <string>

#include "wirevault/config.hpp"
#include "wirevault/event_bus.hpp"

namespace wv {

// Tails Suricata eve.json for alert lines and normalizes them to:
//   {"kind":"threat","severity":..., "sig":"...","src":"...","dst":"...","desc":"..."}
class SuricataWatch {
public:
  SuricataWatch(Config cfg, EventBus &bus) : cfg_(std::move(cfg)), bus_(bus) {}
  // non-blocking begin tailing the log (uses an internal thread)
  void start();

private:
  void run();
  Config cfg_;
  EventBus &bus_;
};

// Reads fail2ban banned-IP output (fail2ban-client status <jail>) and
// publishes a threat event when new IPs appear.
class Fail2banWatch {
public:
  Fail2banWatch(Config cfg, EventBus &bus) : cfg_(std::move(cfg)), bus_(bus) {}
  // poll once; returns list of currently banned IPs (for GUI)
  std::vector<std::string> pollBanned();

private:
  Config cfg_;
  EventBus &bus_;
};

} // namespace wv
