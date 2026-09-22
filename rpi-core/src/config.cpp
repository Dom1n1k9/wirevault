// wirevault/config.cpp
#include "wirevault/config.hpp"

#include <cstdlib>
#include <fstream>
#include <sstream>

#include "wirevault/logging.hpp"

namespace wv {

Config loadConfig(const std::string &path) {
  Config cfg;
  if (path.empty())
    return cfg;
  std::ifstream f(path);
  if (!f) {
    WV_WARN("no config at %s, using defaults", path.c_str());
    return cfg;
  }
  std::stringstream ss;
  ss << f.rdbuf();
  try {
    Json root = Json::parse(ss.str());
    cfg.wg_interface = root.at("wg_interface", Json(cfg.wg_interface)).asStr();
    cfg.listen_port = root.at("listen_port", Json(cfg.listen_port)).asStr();
    cfg.address = root.at("address", Json(cfg.address)).asStr();
    cfg.wg_private_key_path =
        root.at("wg_private_key_path", Json(cfg.wg_private_key_path)).asStr();
    cfg.db_path = root.at("db_path", Json(cfg.db_path)).asStr();
    cfg.control_socket = root.at("control_socket", Json(cfg.control_socket)).asStr();
    cfg.poll_interval_s = (int)root.at("poll_interval_s", Json((int)cfg.poll_interval_s)).asInt();

    for (const auto &pj : root.at("peers", Json(Json::Array{})).asArray()) {
      PeerConfig p;
      p.name = pj.at("name", Json(std::string{})).asStr();
      p.pubkey = pj.at("pubkey", Json(std::string{})).asStr();
      p.psk = pj.at("psk", Json(std::string{})).asStr();
      p.endpoint = pj.at("endpoint", Json(std::string{})).asStr();
      p.persistent_keepalive = (int)pj.at("persistent_keepalive", Json(0)).asInt();
      p.enabled = pj.at("enabled", Json(true)).asBool();
      for (const auto &ip : pj.at("allowed_ips", Json(Json::Array{})).asArray())
        p.allowed_ips.push_back(ip.asStr());
      cfg.peers.push_back(std::move(p));
    }

    for (const auto &rj : root.at("filter_rules", Json(Json::Array{})).asArray()) {
      FilterRule r;
      r.id = rj.at("id", Json(std::string{})).asStr();
      r.action = rj.at("action", Json(std::string{})).asStr();
      r.host = rj.at("host", Json(std::string{})).asStr();
      r.port = (int)rj.at("port", Json(0)).asInt();
      r.proto = rj.at("proto", Json(std::string{})).asStr();
      cfg.filter_rules.push_back(std::move(r));
    }

    const auto &dns = root.at("dns", Json(Json::Object{})).asObject();
    cfg.dns.enabled = dns.count("enabled") ? root.at("dns").at("enabled").asBool() : cfg.dns.enabled;
    cfg.dns.blocklist_path = dns.count("blocklist_path")
                                 ? root.at("dns").at("blocklist_path").asStr()
                                 : cfg.dns.blocklist_path;
    cfg.dns.upstream = dns.count("upstream") ? root.at("dns").at("upstream").asStr() : cfg.dns.upstream;
  } catch (const std::exception &ex) {
    WV_ERROR("config parse error: %s", ex.what());
  }
  return cfg;
}

} // namespace wv
