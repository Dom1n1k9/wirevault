#pragma once
// wirevault/wireguard_mgr.hpp - WireGuard control (wg / wg-quick wrappers).
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "wirevault/config.hpp"

namespace wv {

struct PeerStatus {
  std::string name;
  std::string pubkey;
  std::string endpoint;
  std::vector<std::string> allowed_ips;
  int64_t latest_handshake = 0; // epoch seconds, 0 = never
  int64_t rx_bytes = 0;
  int64_t tx_bytes = 0;
  bool online = false;
  bool enabled = true;
};

class WireGuardMgr {
public:
  explicit WireGuardMgr(Config cfg) : cfg_(std::move(cfg)) {}

  // wg show <if> json -> normalized PeerStatus list (parses "wg show json")
  std::vector<PeerStatus> status();

  // Generates a keypair; returns {pubkey, privkey}. Use out-of-process wg.
  static std::pair<std::string, std::string> generateKeypair();

  // Apply the current config's peers to the live interface via wg setconf.
  // Returns (ok, error_note).
  std::pair<bool, std::string> apply();

  // Read/write /etc/wirevault/wg0.conf from cfg.
  bool writeConfigFile(const std::string &path);
  bool persist();

private:
  Config cfg_;
};

} // namespace wv
