# WireVault on Linux Mint / Raspberry Pi OS

Everything runs on a single Raspberry Pi 5 (tested on Raspberry Pi OS
Bookworm / Debian 12–13). Linux Mint x86_64 works too (the daemon is
Linux-native; only the WG kernel module / Pi hardware differ).

## 1. Base packages

```bash
sudo apt update
sudo apt install -y build-essential cmake ninja-build pkg-config \
  sqlite3 libsqlite3-dev libmosquitto-dev mosquitto-clients \
  wireguard-tools dnsmasq nftables suricata fail2ban
```

Enable in-kernel WG + load module:

```bash
sudo modprobe wireguard
echo wireguard | sudo tee /etc/modules-load.d/wireguard.conf
```

## 2. Config + secrets

```bash
sudo mkdir -p /etc/wirevault /var/lib/wirevault
sudo install -m 600 -d /etc/wirevault/keys
```

Place `rpi-core/wirevault.json.example` at `/etc/wirevault/wirevault.json`
and adjust interface/peers. **Never commit** `/etc/wirevault`.

## 3. Build & run daemon

```bash
cd rpi-core
./build.sh                  # -> build/wirevaultd, build/wvctl, build/wirevault-tests
./build/wirevault-tests     # run config/json self-tests
./build/wirevault-incident-tests   # sqlite incident round-trip
./build/wirevault-wg-tests  # wg config rendering (key inline, setconf shape)
sudo ./build/wirevaultd /etc/wirevault/wirevault.json
```

Control client:

```bash
./build/wvctl system.info
./build/wvctl peer.list
./build/wvctl wg.apply
./build/wvctl filter.current
./build/wvctl watch.incidents '{"limit":25}'
```

systemd unit (root): `sudo cp rpi-core/systemd/wirevaultd.service /etc/systemd/system/`
then `sudo systemctl enable --now wirevaultd`.

## 4. Dashboard (TypeScript)

```bash
cd webgui
npm install
npm run build
WV_SOCKET=/run/wirevault.sock WV_PORT=8080 npm start    # http://<pi>:8080
```

For remote access, run the GUI on the WG interface IP (e.g. `10.66.0.1:8080`)
— it is only reachable through the tunnel. Add `WV_TOKEN=...` to require a
token on the HTTP bridge.

## 5. Verify

```bash
sudo wg show                 # WG state
sudo nft list ruleset        # filter state
tail -f /var/log/wirevault/incidents.db 2>/dev/null || true
# GUI: WG peers online/offline, live blocked-hits, threat counts
```
