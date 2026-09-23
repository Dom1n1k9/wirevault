// wvctl.cpp - WireVault command-line client.
//
// Usage:
//   wvctl peer.list
//   wvctl peer.list --sock /run/wirevault.sock
//   wvctl wg.apply
//   wvctl filter.block '{"id":"r9","host":"1.2.3.4","action":"block"}'
//
// Defaults to the standard control socket; use --host/--port for a TCP
// endpoint (e.g. Windows dev).
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>

#include "wirevault/ctl_client.hpp"
#include "wirevault/json.hpp"

using namespace wv;

static void usage() {
  std::cout
      << "wvctl - WireVault control client\n\n"
      << "usage: wvctl [--sock PATH] [--host H] [--port N] METHOD [PARAMS_JSON]\n"
      << "\nmethods: system.info peer.list wg.apply filter.current "
         "filter.block filter.unblock watch.incidents watch.ack\n";
}

int main(int argc, char **argv) {
  std::string sock = "/run/wirevault.sock";
  std::string host;
  int port = 0;
  int i = 1;
  for (; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--sock" && i + 1 < argc) {
      sock = argv[++i];
    } else if (a == "--host" && i + 1 < argc) {
      host = argv[++i];
    } else if (a == "--port" && i + 1 < argc) {
      port = std::atoi(argv[++i]);
    } else if (a == "--help" || a == "-h") {
      usage();
      return 0;
    } else {
      break;
    }
  }
  if (i >= argc) {
    usage();
    return 1;
  }
  std::string method = argv[i++];
  std::string paramsText = (i < argc) ? argv[i] : "{}";
  Json params;
  try {
    params = Json::parse(paramsText);
  } catch (const std::exception &) {
    params = Json(Json::Object{});
  }

  CtlClient cli(sock, host, port);
  Json res = cli.request(method, params);
  if (res.has("error") && !res.at("error").isNull()) {
    std::cerr << "error: " << res.at("error").asStr() << "\n";
    return 2;
  }
  std::cout << res.dump() << "\n";
  return 0;
}
