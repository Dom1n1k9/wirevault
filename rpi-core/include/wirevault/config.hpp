#pragma once
// wirevault/config.hpp - daemon configuration.
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "wirevault/json.hpp"

namespace wv {

struct PeerConfig {
  std::string name;
  std::string pubkey;          // peer public key (from generated pair or given)
  std::string psk;             // optional preshared key ("" = none)
  std::vector<std::string> allowed_ips;
  std::string endpoint;        // "" = roaming (no fixed endpoint)
  int persistent_keepalive = 0;
  bool enabled = true;
};

struct FilterRule {
  std::string id;              // rule id used for unblock
  std::string action;          // "allow" | "block"
  std::string host;            // IP or subnet (CIDR)
  int port = 0;                // 0 = any
  std::string proto;           // "tcp" | "udp" | "" (any)
};

struct DnsFilterConfig {
  bool enabled = true;
  std::string blocklist_path = "/etc/wirevault/dns-blocklist.conf";
  std::string upstream = "1.1.1.1"; // resolved by dnsmasq
  int port = 53;
};

struct WatchConfig {
  std::string suricata_eve = "/var/log/suricata/eve.json";
  std::string fail2ban_jail = "sshd";
  bool log_scan_enabled = true;
};

struct Config {
  std::string wg_interface = "wg0";
  std::string listen_port = "51820";
  std::string address = "10.66.0.1/24";
  std::string wg_private_key_path; // root-only file; content never in config
  std::vector<PeerConfig> peers;
  std::vector<FilterRule> filter_rules;
  DnsFilterConfig dns;
  WatchConfig watch;
  std::string db_path = "/var/lib/wirevault/wirevault.db";
  std::string control_socket = "/run/wirevault.sock";
  int poll_interval_s = 10;
};

Config loadConfig(const std::string &path);

} // namespace wv
