// tests/test_config.cpp - config + json sanity.
#include <cassert>
#include <cstdio>
#include <iostream>
#include <string>

#include "wirevault/config.hpp"

using namespace wv;

int main() {
  // json round-trip
  auto doc = Json::parse(R"({"a":{"b":[1,2.5,"x"]}})");
  assert(doc.at("a").at("b").asArray().size() == 3);
  assert(doc.at("a").at("b").at(0).asInt() == 1);
  assert(doc.at("a").at("b").at(2).asStr() == "x");

  // serialize + escape
  Json o(Json::Object{{"k", Json(3.5)}, {"s", Json(std::string("a\"b"))}});
  std::string s = o.dump();
  assert(s.find("a\\\"b") != std::string::npos);

  // config parse from a file (use local file so it works on Windows dev too)
  const char *path = "./wirevault_cfg_test.json";
  {
    FILE *f = fopen(path, "w");
    fputs(R"({"wg_interface":"wg9","listen_port":"51999","peers":[{"name":"phone","pubkey":"AAAA","allowed_ips":["10.66.0.2/32"]}],"filter_rules":[{"id":"r1","action":"block","host":"1.2.3.4"}],"dns":{"enabled":true}})", f);
    fclose(f);
  }
  Config cfg = loadConfig(path);
  assert(cfg.wg_interface == "wg9");
  assert(cfg.listen_port == "51999");
  assert(cfg.peers.size() == 1);
  assert(cfg.peers[0].name == "phone");
  assert(cfg.peers[0].allowed_ips.size() == 1);
  assert(cfg.filter_rules.size() == 1);
  assert(cfg.filter_rules[0].id == "r1");
  remove(path);

  std::cout << "CONFIG TESTS PASSED\n";
  return 0;
}
