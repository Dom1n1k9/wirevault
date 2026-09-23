#pragma once
// wirevault/ctl_client.hpp - small control-socket client used by wvctl.
// Talks the JSON protocol from docs/PROTOCOL.md against a running wirevaultd.
#include <optional>
#include <string>

#include "wirevault/json.hpp"

namespace wv {

class CtlClient {
public:
  // sockPath: unix socket (Linux), or host:port via port != 0 (Windows/dev).
  CtlClient(std::string sockPath, std::string host = "", int port = 0);

  // Send one request, wait for the matching reply, return parsed JSON.
  // On transport errors returns an object with "error" set.
  Json request(const std::string &method, const Json &params = Json(Json::Object{}));

private:
  std::string sockPath_;
  std::string host_;
  int port_;
};

} // namespace wv
