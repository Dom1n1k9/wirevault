// wirevault/watch_elems.cpp
#include "wirevault/watch_elems.hpp"

#include <chrono>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "wirevault/logging.hpp"
#include "wirevault/subproc.hpp"

namespace wv {

// ---- Suricata eve.json tailer ----
// Simple tailer: tracks file offset, reads new JSON lines, publishes
// normalized threats on the event bus.
void SuricataWatch::run() {
  std::string path = cfg_.watch.suricata_eve;
  std::ifstream f;
  f.open(path);
  // seek to end on first open so we only see new alerts
  f.seekg(0, std::ios::end);
  std::streamoff last = f.tellg();
  std::string line;
  while (true) {
    // check for growth
    std::ifstream g(path);
    g.seekg(0, std::ios::end);
    std::streamoff now = g.tellg();
    g.close();
    if (now < last) {
      last = 0; // rotated
    } else if (now > last) {
      std::ifstream h(path);
      h.seekg(last);
      while (std::getline(h, line)) {
        if (line.empty())
          continue;
        try {
          Json ev = Json::parse(line);
          if (ev.at("event_type", Json(std::string{})).asStr() != "alert")
            continue;
          Json data(Json::Object{});
          data.set("kind", Json(std::string("threat")));
          data.set("src", ev.at("src_ip", Json(std::string{})).asStr());
          data.set("dst", ev.at("dest_ip", Json(std::string{})).asStr());
          data.set("sig", ev.at("signature", Json(std::string{})).asStr());
          int sev = (int)ev.at("alert", Json(Json::Object{})).at("severity", Json(3)).asInt();
          std::string sevLabel = sev <= 1 ? "critical" : sev == 2 ? "warning" : "info";
          data.set("severity", Json(sevLabel));
          bus_.publish("threat.suricata", data);
          WV_INFO("suricata alert: %s from %s", data.at("sig").asStr().c_str(),
                  data.at("src").asStr().c_str());
        } catch (const std::exception &ex) {
          WV_DEBUG("skip non-JSON suricata line: %s", ex.what());
        }
      }
      last = now;
    }
    // wait for the poll interval (reuse poll_interval_s)
    std::this_thread::sleep_for(std::chrono::seconds(cfg_.poll_interval_s));
  }
}

void SuricataWatch::start() {
  std::thread([this]() { run(); }).detach();
}

// ---- fail2ban aggregator ----
std::vector<std::string> Fail2banWatch::pollBanned() {
  std::vector<std::string> out;
  // fail2ban-client status <jail>
  auto r = runCommand({"fail2ban-client", "status", cfg_.watch.fail2ban_jail});
  if (r.ok()) {
    // lines like "        Banned IP list:   1.2.3.4 5.6.7.8"
    std::istringstream iss(r.stdout_text);
    std::string line;
    while (std::getline(iss, line)) {
      auto pos = line.find("Banned IP list:");
      if (pos != std::string::npos) {
        std::istringstream ips(line.substr(pos + 15));
        std::string ip;
        while (ips >> ip)
          out.push_back(ip);
      }
    }
  }
  return out;
}

} // namespace wv
