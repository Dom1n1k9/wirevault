# WireVault Web GUI (TypeScript)

Dashboard for the WireVault control daemon: WireGuard peers, nftables filter
state, incidents/audit. Bridge connects to `wirevaultd`'s local control socket
and forwards JSON-RPC over WebSockets to the browser. No Python.

## Run

```bash
npm install
npm run build                 # tsc -> dist/
WV_SOCKET=/run/wirevault.sock WV_PORT=8080 npm start
# open http://<pi>:8080  (bind :8080 on the VPN interface for remote)
```

## Env

| var | default | meaning |
|-----|---------|---------|
| `WV_SOCKET` | `/run/wirevault.sock` | wirevaultd unix socket |
| `WV_CTRL_HOST` / `WV_CTRL_PORT` | unset | alternative TCP control endpoint (Windows dev) |
| `WV_HOST` / `WV_PORT` | `0.0.0.0:8080` | dashboard bind |
| `WV_TOKEN` | unset | if set, require `Authorization: Bearer <token>` |

Methods proxied: `system.info`, `peer.list`, `wg.apply`, `filter.current`,
`filter.block/unblock`, `watch.incidents`, `watch.ack` (see
`docs/PROTOCOL.md`). Live daemon `event:` frames are broadcast to all tabs.
