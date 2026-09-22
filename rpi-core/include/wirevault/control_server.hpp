#pragma once
// wirevault/control_server.hpp - local unix socket control plane for the GUI.
#include <memory>
#include <string>
#include <functional>

#include "wirevault/json.hpp"

namespace wv {

// Dispatches JSON-RPC-ish requests. Handler returns a Json result or sets err.
using RequestHandler = std::function<Json(const Json & /*method*/, const Json &/*params*/, std::string &/*err*/)>;

class ControlServer {
public:
  ControlServer(const std::string &sockPath, RequestHandler handler);
  ~ControlServer();
  void start();           // spawns accept thread
  void stop();            // join + unlink socket
  void broadcast(const std::string &event, const Json &data);

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace wv
