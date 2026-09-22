// main.cpp - WireVault control daemon entry point.
//
// WireVault is a single-binary C++20 control plane that owns WireGuard, the
// nftables filter, the DNS blocklist, the security watch pipeline and the
// audit/incident store, and exposes a local JSON control socket for the GUI.
//
// For the scaffold we keep main() thin: load config, open the incident store,
// wire the managers + control server, and run the monitor loop that publishes
// status events.
#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <ctime>
#include <memory>
#include <string>
#include <thread>

#include "wirevault/config.hpp"
#include "wirevault/control_server.hpp"
#include "wirevault/event_bus.hpp"
#include "wirevault/incident_store.hpp"
#include "wirevault/logging.hpp"
#include "wirevault/subproc.hpp"
#include "wirevault/wireguard_mgr.hpp"
#include "wirevault/netfilter_mgr.hpp"
#include "wirevault/dnsfilter_mgr.hpp"
#include "wirevault/watch_elems.hpp"

using namespace wv;

static std::atomic<bool> g_running{true};
static void on_signal(int) { g_running = false; }

int main(int argc, char **argv) {
  std::string cfgPath = argc > 1 ? argv[1] : "/etc/wirevault/wirevault.json";
  Logger::instance().setLevel(LogLevel::Info);

  Config cfg = loadConfig(cfgPath);
  WV_INFO("WireVault starting (iface=%s db=%s)", cfg.wg_interface.c_str(),
          cfg.db_path.c_str());

  EventBus bus;
  IncidentStore store(cfg.db_path);
  if (!store.ok())
    WV_ERROR("incident store unavailable - continuing without audit");

  WireGuardMgr wg(cfg);
  NetFilterMgr nf(cfg);
  DnsFilterMgr dns(cfg);

  // watch pipeline -> incident store + event bus
  bus.subscribe("threat.suricata", [&](const std::string &ev, const Json &d) {
    (void)ev;
    store.add("threat", d.at("severity", Json(std::string("info"))).asStr(),
              d.at("sig", Json(std::string("suricata alert"))).asStr(), d);
  });

  SuricataWatch sw(cfg, bus);
  sw.start();
  Fail2banWatch f2b(cfg, bus);

  // control server handling the methods in PROTOCOL.md
  auto handler = [&](const Json &method, const Json &params, std::string &err) -> Json {
    std::string m = method.asStr();
    Json r(Json::Object{});
    if (m == "system.info") {
      r.set("host", Json(std::string("wirevaultd")));
      r.set("version", Json(std::string("0.1.0")));
      r.set("iface", Json(cfg.wg_interface));
      return r;
    } else if (m == "peer.list") {
      auto status = wg.status();
      Json arr(Json::Array{});
      for (auto &s : status) {
        Json p(Json::Object{});
        p.set("name", Json(s.name));
        p.set("pubkey", Json(s.pubkey));
        p.set("endpoint", Json(s.endpoint));
        p.set("online", Json(s.online));
        p.set("rx", Json(s.rx_bytes));
        p.set("tx", Json(s.tx_bytes));
        p.set("handshake", Json(s.latest_handshake));
        arr.push_back(p);
      }
      r.set("peers", arr);
      return r;
    } else if (m == "wg.apply") {
      auto res = wg.apply();
      if (res.first)
        store.add("wg_apply", "info", "WireGuard config applied", Json(Json::Object{}));
      else
        err = res.second;
      r.set("ok", Json(res.first));
      return r;
    } else if (m == "filter.current") {
      r = nf.summary();
      return r;
    } else if (m == "filter.block") {
      FilterRule fr;
      fr.id = params.at("id", Json(std::string{})).asStr();
      fr.action = "block";
      fr.host = params.at("host", Json(std::string{})).asStr();
      if (params.has("port"))
        fr.port = (int)params.at("port").asInt();
      if (params.has("proto"))
        fr.proto = params.at("proto").asStr();
      auto res = nf.addRule(fr);
      r.set("ok", Json(res.first));
      if (!res.first)
        err = res.second;
      else
        store.add("rule_change", "warning", "blocked " + fr.host, Json(Json::Object{}));
      return r;
    } else if (m == "filter.unblock") {
      std::string id = params.at("id", Json(std::string{})).asStr();
      auto res = nf.removeRule(id);
      r.set("ok", Json(res.first));
      if (!res.first)
        err = res.second;
      return r;
    } else if (m == "watch.incidents") {
      int limit = params.has("limit") ? (int)params.at("limit").asInt() : 50;
      auto incs = store.recent(limit);
      Json arr(Json::Array{});
      for (auto &in : incs) {
        Json p(Json::Object{});
        p.set("id", Json(in.id));
        p.set("ts", Json(in.ts));
        p.set("kind", Json(in.kind));
        p.set("severity", Json(in.severity));
        p.set("summary", Json(in.summary));
        p.set("acked", Json((bool)in.acked));
        arr.push_back(p);
      }
      r.set("incidents", arr);
      return r;
    } else if (m == "watch.ack") {
      int64_t id = params.at("id", Json((int64_t)0)).asInt();
      r.set("ok", Json(store.ack(id)));
      return r;
    }
    err = "unknown method: " + m;
    return r;
  };

  ControlServer server(cfg.control_socket, handler);
  server.start();
  WV_INFO("control socket on %s", cfg.control_socket.c_str());

  std::signal(SIGINT, on_signal);
  std::signal(SIGTERM, on_signal);

  int64_t pm = 0;
  while (g_running) {
    int64_t now = (int64_t)time(nullptr);
    if (now - pm >= cfg.poll_interval_s) {
      pm = now;
      // emit a status snapshot to GUI clients (via control server broadcast)
      // peers status is polled by the GUI's peer.list, but a periodic wg.apply
      // keeps us converged.
      auto st = wg.status();
      Json ev(Json::Object{});
      ev.set("peers_online", Json((int64_t)std::count_if(st.begin(), st.end(),
                                    [](const PeerStatus &s) { return s.online; })));
      ev.set("blocked_hits", Json(0));
      // (broadcast requires the server to retain clients; scaffold: no-op)
    }
    std::this_thread::sleep_for(std::chrono::seconds(std::max(1, cfg.poll_interval_s)));
  }

  server.stop();
  WV_INFO("WireVault stopped");
  return 0;
}
