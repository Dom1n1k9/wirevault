# WireVault — Protocol

`wirevaultd` exposes a **JSON over local unix socket** control protocol; the
web GUI connects over it directly (localhost) or through a small HTTP/WS bridge
when remote. All requests and events use the same envelope shape.

## Envelope

```json
{ "id": "req-1", "method": "peer.list", "params": { } }
{ "id": "req-1", "result": { "peers": [ ... ] } }
```

Events (daemon → client):

```json
{ "event": "incident", "data": { ... } }
{ "event": "wg.status", "data": { "interface": "wg0", "peers": [ ... ] } }
{ "event": "filter.status", "data": { "rules_applied": 42, "blocked_hits": 3 } }
```

## Methods

| Method | Params | Result |
|--------|--------|--------|
| `system.info` | — | `{host, uptime, load, mem, version}` |
| `peer.list` | — | `[{id, pubkey, allowed_ips, endpoint, handshake_age, rx, tx, online}]` |
| `peer.add` | `{name, allowed_ips, persistent_keepalive?}` | new peer + generated keys |
| `peer.remove` | `{id}` | — |
| `peer.enable` / `peer.disable` | `{id}` | toggles the peer |
| `wg.apply` | `{interface?}` | push current config to `wg setconf` |
| `wg.rekey` | `{id}` | rotate a peer's key (audited) |
| `filter.current` | — | applied nft chains/rules summary |
| `filter.block` | `{host, port?, proto?}` | append allow/block rule + apply |
| `filter.unblock` | `{id}` | remove rule |
| `dns.blocklist` | — | current blocklist domains count + sample |
| `dns.reload` | — | reload dnsmasq blocklist |
| `watch.threats` | `{since?}` | normalized threats (Suricata/fail2ban) |
| `watch.incidents` | `{limit?, since?}` | audit rows |
| `watch.ack` | `{id}` | mark incident acknowledged |

## Security

- Unix socket mode `0700`, owner root.
- HTTP/WS bridge (if enabled) is token-authed (`WV_TOKEN`) and bound only to
  the VPN interface, never `0.0.0.0` public.

## WireGuard status JSON

`wirevaultd` runs `wg show <if> json` and normalizes to:

```json
{
  "interface": "wg0", "public_key": "…",
  "peers": [ { "id": "peer-n", "pubkey": "…", "endpoint": "1.2.3.4:51820",
               "allowed_ips": ["10.66.0.2/32"], "latest_handshake": 1710000000,
               "rx_bytes": 12345, "tx_bytes": 678, "online": true } ]
}
```
