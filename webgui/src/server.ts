// WireVault dashboard server (TypeScript).
//
// Bridges the wirevaultd control socket to a browser SPA over WebSockets:
//   - connects to <WV_SOCKET> (unix socket) or <WV_CTRL_HOST:WV_CTRL_PORT>
//   - forwards "peer.list", "filter.current", "watch.incidents" etc.
//   - serves public/index.html + app.js
//
// Env:  WV_SOCKET (default /run/wirevault.sock), WV_CTRL_HOST/PORT (Windows),
//       WV_PORT, WV_HOST, WV_TOKEN (optional auth on HTTP bridge)
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createConnection } from "node:net";
import { WebSocketServer, WebSocket as WSWebSocket } from "ws";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = normalize(join(__dirname, "..", "public"));
const SOCKET = process.env.WV_SOCKET ?? "/run/wirevault.sock";
const CTRL_HOST = process.env.WV_CTRL_HOST ?? "";
const CTRL_PORT = Number(process.env.WV_CTRL_PORT ?? 0);
const PORT = Number(process.env.WV_PORT ?? 8080);
const HOST = process.env.WV_HOST ?? "0.0.0.0";
const TOKEN = process.env.WV_TOKEN ?? "";

// --- control connection to wirevaultd ---
let ctrl: any = null; // net.Socket
let reqId = 0;
const pending = new Map<number, { resolve: (j: any) => void; reject: (e: Error) => void }>();
const subs = new Set<(obj: any) => void>();

function connect() {
  const onData = (buf: Buffer) => {
    const text = buf.toString("utf8");
    for (const line of text.split("\n")) {
      if (!line.trim()) continue;
      let obj: any;
      try {
        obj = JSON.parse(line);
      } catch {
        continue;
      }
      if (obj && obj.id !== undefined && pending.has(obj.id)) {
        const p = pending.get(obj.id)!;
        pending.delete(obj.id);
        obj.error ? p.reject(new Error(obj.error)) : p.resolve(obj.result);
      } else if (obj && obj.event) {
        for (const s of subs) s(obj);
      }
    }
  };
  if (CTRL_HOST) {
    const c = createConnection({ host: CTRL_HOST, port: CTRL_PORT }, () => (ctrl = c));
    c.on("data", onData);
    c.on("error", () => setTimeout(connect, 3000));
    c.on("close", () => { ctrl = null; setTimeout(connect, 3000); });
  } else {
    const c = createConnection(SOCKET, () => (ctrl = c));
    c.on("data", onData);
    c.on("error", () => setTimeout(connect, 3000));
    c.on("close", () => { ctrl = null; setTimeout(connect, 3000); });
  }
}

function call(method: string, params: Record<string, unknown> = {}) {
  return new Promise<any>((resolve, reject) => {
    const id = ++reqId;
    pending.set(id, { resolve, reject });
    const c = ctrl;
    if (!c) {
      reject(new Error("daemon not connected"));
      return;
    }
    c.write(JSON.stringify({ id: `req-${id}`, method, params }) + "\n");
  });
}

// --- websocket + http bridge (same pattern as dashboard) ---
const server = createServer(async (req, res) => {
  if (TOKEN) {
    const auth = req.headers.authorization ?? "";
    if (auth !== `Bearer ${TOKEN}`) {
      res.writeHead(401);
      res.end("unauthorized");
      return;
    }
  }
  const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
  let path = decodeURIComponent(url.pathname);
  if (path === "/") path = "/index.html";
  const filePath = normalize(join(PUBLIC_DIR, path));
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    res.end("forbidden");
    return;
  }
  try {
    const buf = await readFile(filePath);
    const type = {
      ".html": "text/html",
      ".js": "application/javascript",
      ".css": "text/css",
      ".json": "application/json",
      ".svg": "image/svg+xml",
    }[extname(filePath)] ?? "application/octet-stream";
    res.writeHead(200, { "content-type": type });
    res.end(buf);
  } catch {
    res.writeHead(404);
    res.end("not found");
  }
});

const wss = new WebSocketServer({ server });
const clients = new Set<WSWebSocket>();
function broadcast(obj: any) {
  const msg = JSON.stringify(obj);
  for (const c of clients) if (c.readyState === 1) c.send(msg);
}
subs.add(broadcast);

wss.on("connection", (ws) => {
  clients.add(ws);
  ws.on("message", async (raw) => {
    let msg: any;
    try {
      msg = JSON.parse(raw.toString());
    } catch {
      return;
    }
    if (!msg || typeof msg.method !== "string") return;
    try {
      const result = await call(msg.method, msg.params ?? {});
      ws.send(JSON.stringify({ t: "result", id: msg.id, result }));
    } catch (e: any) {
      ws.send(JSON.stringify({ t: "error", id: msg.id, error: String(e.message ?? e) }));
    }
  });
  ws.on("close", () => clients.delete(ws));
});

connect();
server.listen(PORT, HOST, () => {
  console.log(`[wirevault] dashboard on http://${HOST}:${PORT} (socket ${SOCKET})`);
});
