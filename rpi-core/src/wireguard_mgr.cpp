// wirevault/wireguard_mgr.cpp
#include "wirevault/wireguard_mgr.hpp"

#include <cstdio>
#include <ctime>
#include <sstream>

#include "wirevault/logging.hpp"
#include "wirevault/subproc.hpp"

namespace wv {

// parse `wg show <if> json` output into status
std::vector<PeerStatus> WireGuardMgr::status() {
  std::vector<PeerStatus> out;
  auto r = runCommand({"wg", "show", cfg_.wg_interface, "json"});
  if (!r.ok()) {
    WV_WARN("wg show failed (interface %s up?): %s", cfg_.wg_interface.c_str(),
            r.stderr_text.c_str());
    return out;
  }
  try {
    Json doc = Json::parse(r.stdout_text);
    std::map<std::string, const PeerConfig *> byKey;
    for (const auto &p : cfg_.peers)
      if (!p.pubkey.empty())
        byKey[p.pubkey] = &p;
    for (const auto &pj : doc.at("peers", Json(Json::Array{})).asArray()) {
      PeerStatus s;
      s.pubkey = pj.at("public_key", Json(std::string{})).asStr();
      s.endpoint = pj.at("endpoint", Json(std::string{})).asStr();
      for (const auto &ip : pj.at("allowed_ips", Json(Json::Array{})).asArray())
        s.allowed_ips.push_back(ip.asStr());
      s.latest_handshake = pj.at("latest_handshake", Json((int64_t)0)).asInt();
      s.rx_bytes = pj.at("rx_bytes", Json((int64_t)0)).asInt();
      s.tx_bytes = pj.at("tx_bytes", Json((int64_t)0)).asInt();
      // online = handshaken within the last 3 minutes
      int64_t now = (int64_t)time(nullptr);
      s.online = s.latest_handshake > 0 && (now - s.latest_handshake) < 180;
      auto it = byKey.find(s.pubkey);
      if (it != byKey.end()) {
        s.name = it->second->name;
        s.enabled = it->second->enabled;
      } else {
        s.name = s.pubkey.substr(0, 8);
      }
      out.push_back(std::move(s));
    }
  } catch (const std::exception &ex) {
    WV_WARN("wg show parse error: %s", ex.what());
  }
  return out;
}

std::pair<std::string, std::string> WireGuardMgr::generateKeypair() {
  auto priv = runCommand({"wg", "genkey"});
  auto pub = runCommand({"wg", "pubkey"}, priv.stdout_text);
  std::string privKey = priv.ok() ? priv.stdout_text : "";
  // trim trailing newline
  while (!privKey.empty() && (privKey.back() == '\n' || privKey.back() == '\r'))
    privKey.pop_back();
  return {pub.ok() ? pub.stdout_text : "", privKey};
}

bool WireGuardMgr::writeConfigFile(const std::string &path) {
  std::string conf;
  conf += "[Interface]\n";
  conf += "Address = " + cfg_.address + "\n";
  conf += "ListenPort = " + cfg_.listen_port + "\n";
  if (!cfg_.wg_private_key_path.empty())
    conf += "PrivateKey = /etc/wirevault/keys/" + cfg_.wg_interface + ".key\n";
  for (const auto &p : cfg_.peers) {
    if (!p.enabled)
      continue;
    conf += "\n[Peer]\n";
    conf += "PublicKey = " + p.pubkey + "\n";
    if (!p.psk.empty())
      conf += "PresharedKey = " + p.psk + "\n";
    if (!p.endpoint.empty())
      conf += "Endpoint = " + p.endpoint + "\n";
    if (p.persistent_keepalive > 0)
      conf += "PersistentKeepalive = " + std::to_string(p.persistent_keepalive) + "\n";
    conf += "AllowedIPs = ";
    for (size_t i = 0; i < p.allowed_ips.size(); ++i) {
      if (i)
        conf += ", ";
      conf += p.allowed_ips[i];
    }
    conf += "\n";
  }

  if (path.empty())
    return false;
  FILE *f = fopen(path.c_str(), "w");
  if (!f) {
    WV_ERROR("cannot write %s", path.c_str());
    return false;
  }
  fputs(conf.c_str(), f);
  fclose(f);
  return true;
}

bool WireGuardMgr::persist() {
  return writeConfigFile("/etc/wirevault/" + cfg_.wg_interface + ".conf");
}

std::pair<bool, std::string> WireGuardMgr::apply() {
  // Ensure interface exists (wg-quick up idempotent-ish)
  auto up = runCommand({"wg-quick", "up", cfg_.wg_interface});
  if (!up.ok()) {
    // might already be up
    WV_DEBUG("wg-quick up status note: %s", up.stderr_text.c_str());
  }
  // write config then apply via wg setconf
  if (!persist())
    return {false, "could not persist wg0.conf"};
  auto set = runCommand({"wg", "setconf", cfg_.wg_interface,
                         "/etc/wirevault/" + cfg_.wg_interface + ".conf"});
  if (!set.ok())
    return {false, "wg setconf failed"};
  return {true, "applied"};
}

} // namespace wv
