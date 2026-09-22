# WireVault — Architecture

## Goal

A single daemon (`wirevaultd`, C++20) on a Raspberry Pi 5 that is the **control
plane** for:
- **WireGuard** VPN (server, peers, key mgmt),
- **nftables** traffic filtering (allow/block, per-peer, QoS shaping hooks),
- **DNS filtering** (dnsmasq blocklist — ad/tracker domains),
- **Security watch** (Suricata IDS alerts + fail2ban dictionaries + log scans),
- **Audit** (every change & alert → SQLite incidents → live events to the GUI).

Everything is Linux-native (kernel WG, in-kernel nftables, Suricata userspace
IDS); `wirevaultd` orchestrates via subprocesses (wg, nft, dnsmasq, suricata,
fail2ban-client) and parses their output into a **unified JSON event stream**.

## Data flow

```
                 ┌──────────────────────────  wirevaultd (C++20) ─────────────────────────┐
   [interfaces]  │                                                                        │
   wg / nftrules │  EventBus (thread-safe)  ┌─────► IncidentStore (SQLite)                │
   ─────────────►│  WireGuardManager        │      threats/handlers                        │
   [security]    │  NetFilterManager        │      bootstrap: read config, apply state     │
   suricata eve  │  DnsFilterManager        │                                            │
   fail2ban      │  WatchAggregator  ───────┼─────► ControlServer (unix socket / HTTP-JSON)│
   journald      │  ConfigLoader            │        ▲                                    │
                 └──────────────────────────┴────────┼────────────────────────────────────┤
                                                      │                                    │
                 ┌─── webgui (TypeScript) ───────────┐                                    
                 │ ws -> ControlServer               │  refresh + actions                  
                 └───────────────────────────────────┘                                    
```

## Components (rpi-core/)

| Component | Owns |
|-----------|------|
| `config.hpp/cpp` | /etc/wirevault/wirevault.json (interfaces, peers, rules, blocklist paths, watch settings) |
| `event_bus` | thread-safe pub/sub for internal events |
| `wireguard_mgr` | `wg show`/`wg setconf`/`wg-quick` wrappers; peer registry; key generation; `wg show` JSON parse |
| `netfilter_mgr` | `nft` rule files + `nft -f` apply; build allow/block/forward chains from config |
| `dnsfilter_mgr` | dnsmasq rebind + blocklist (`/etc/wirevault/dns-blocklist.conf`) management, DNS query logging |
| `watch_elems` | Suricata `eve.json` tailer + fail2ban-banned-IP aggregator → normalized threats |
| `incident_store` | SQLite: `incidents`, `peers`, `rules`, `alerts`, `events` tables |
| `control_server` | local unix-socket JSON-RPC + optional HTTP(s) bridge for the GUI |
| `main` | boot, config load, DI, signal handling, systemd notify |

## Security model

- `wirevaultd` runs as **root** (needs nft/WG/dnsmasq control) but drops config
  parsing/parsing into an unprivileged thread where possible; all external
  commands spawned with `execlp`-style argv arrays (no shell), and their output
  capped.
- **Runtime keys/config never committed** (`/etc/wirevault`, WG private keys,
  dnsmasq creds) — `.gitignore` + see DEPLOY.
- Dashboard is behind the daemon's auth (token) and binds localhost by default;
  expose only via an authorized tunnel (e.g. the WG VPN itself).
- Audit-first: every state change is written to incidents *before* applying.

## Why C++20 + TypeScript

A small, fast, dependency-light control plane with no Python runtime on the
gateway (the Pi is the edge device and every MB of runtime matters), and a
browser surface that needs no build-step JS. Vocabulary shared via
`docs/PROTOCOL.md` (JSON + endpoints).
