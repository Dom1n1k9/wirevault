# WireVault

> **VPN vigilance & network security control system** for a Raspberry Pi 5.
> Manages a **WireGuard** VPN, applies **nftables traffic filtering** +
> **DNS ad/tracker blocking**, and watches the edge for intrusions with
> **Suricata IDS + fail2ban** — all unified into one live event feed and a
> TypeScript dashboard.

A single-binary **C++20 control daemon** (no Python) that is the single source
of truth: it owns the WireGuard configs, nftables rules, the DNS blocklist,
the security-watch pipeline and the audit/incident store (SQLite). The web GUI
(also no Python, TypeScript + Node) is a read/write control surface that talks
to the daemon over a local control socket.

## Why (and what makes it neat)

- **One control plane** — WireGuard `wg`/`wg-quick`, `nft`, `dnsmasq`,
  `suricata`, `fail2ban` are all driven from one audited daemon with a common
  event bus: one place for config, apply and audit.
- **Legal + responsible by default** — you block/allow *your own* network.
- **Linux-native fast paths** — WG is a kernel module; filtering is nftables
  in-kernel; IDS is Suricata. The daemon only orchestrates, never hot-loops
  packets.
- **Zero Python** — C++20 (control daemon) + TypeScript (GUI).
- **Auditability** — every VPN change / rule change / alert is an incident
  row in SQLite, shown in the dashboard and flushable to syslog.

## Hardware scope

**Raspberry Pi 5 (4 GB) only.** No ESP32 / micro:bit needed — the Pi blunts
the VPN termination, filtering, IDS and dashboard all at once. (A second Pi
or a router elsewhere can be a `remote` WG peer managed from here.)

## Repo layout

```
rpi-core/        C++20 control daemon (wirevaultd) + integration commands + SQLite
webgui/          TypeScript dashboard (Node + ws), no Python
docs/            ARCHITECTURE, PROTOCOL, DEPLOY-LINUX-MINT
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design and
[docs/DEPLOY-LINUX-MINT.md](docs/DEPLOY-LINUX-MINT.md) for Linux Mint / PiOS
setup.

## Build (very quick)

```bash
cd rpi-core
./build.sh                # builds wirevaultd + wvctl + tests
./build/wirevault-tests   # config/json self-test
./build/wirevault-incident-tests   # sqlite incident round-trip
./build/wirevault-wg-tests # WG config rendering (key inline, setconf shape)
sudo ./build/wirevaultd /etc/wirevault/wirevault.json
./build/wvctl peer.list   # query the running daemon (see docs/PROTOCOL.md)
```

```bash
cd webgui
npm install && npm run build && npm start    # http://<pi>:8080
```

## License

MIT
