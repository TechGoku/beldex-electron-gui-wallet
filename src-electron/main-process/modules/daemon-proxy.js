const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const nodePath = require("path");
const { EventEmitter } = require("events");

// Requests that make up a wallet scan (get_blocks.bin, get_hashes.bin, ...)
const SYNC_PATH = /(blocks|hashes)\.bin$/;
const CACHE_LIMIT_BYTES = 100 * 1024 * 1024;
// `status: "OK"` in epee: name, type 10 (string), varint length 2 (0x08)
const STATUS_OK = Buffer.from([6, ...Buffer.from("status"), 10, 8, 79, 75]);

/**
 * Local HTTP proxy that beldex-wallet-rpc uses as its node.
 *
 * wallet-rpc refreshes on its only request thread and nothing can interrupt
 * it: once a scan starts, every call (store, close_wallet, getheight, ...)
 * waits until the wallet has caught up. So closing mid-scan could not save,
 * the process got killed, and all progress since the last save was lost.
 *
 * Failing wallet-rpc's block-sync requests ends a running scan within a
 * fraction of a second, keeping everything scanned so far; other requests
 * (transfers, pool, json_rpc) always pass. The block responses also carry the
 * scan height, which gives live progress without asking wallet-rpc.
 *
 * With cacheDir set, block-hash batches far below the chain tip (they can no
 * longer change) are kept on disk. A restore or rescan re-downloads the whole
 * hash list from the last checkpoint (~10 s); with the cache it is served
 * locally in well under a second.
 *
 * Emits "progress" with { height, target, headersOnly }.
 */
export class DaemonProxy extends EventEmitter {
  constructor({ cacheDir = null } = {}) {
    super();
    this.cacheDir = cacheDir;
    this.server = null;
    this.target = { host: "127.0.0.1", port: 0 };
    this.paused = false;
    this.inFlight = new Set();
    this.agent = new http.Agent({ keepAlive: true, maxSockets: 8 });
  }

  // Resolves with the local port wallet-rpc should use as --daemon-address
  start(host, port) {
    this.setTarget(host, port);
    this.prepareCache();
    return new Promise((resolve, reject) => {
      this.server = http.createServer((req, res) => this.handle(req, res));
      this.server.keepAliveTimeout = 30000;
      this.server.once("error", reject);
      this.server.listen(0, "127.0.0.1", () =>
        resolve(this.server.address().port)
      );
    });
  }

  // Points the proxy at another node; wallet-rpc doesn't need a restart
  setTarget(host, port) {
    this.target = { host, port: Number(port) };
  }

  // Fails block-sync requests (including ones in flight) until resume()
  pause() {
    this.paused = true;
    for (const request of this.inFlight) request.destroy();
    this.inFlight.clear();
  }

  resume() {
    this.paused = false;
  }

  close() {
    this.pause();
    this.agent.destroy();
    return new Promise(resolve => {
      if (!this.server) return resolve();
      this.server.closeAllConnections();
      this.server.close(() => resolve());
    });
  }

  handle(req, res) {
    const path = req.url.split("?")[0];
    const sync = SYNC_PATH.test(path);
    const reject = () => {
      if (res.headersSent) return res.destroy();
      res.writeHead(503, { "content-length": 0 });
      res.end();
    };

    const body = [];
    req.on("data", chunk => body.push(chunk));
    req.on("error", reject);
    req.on("end", async () => {
      if (sync && this.paused) return reject();
      const payload = Buffer.concat(body);
      const cacheKey =
        this.cacheDir && path.endsWith("hashes.bin")
          ? cacheKeyFor(path, payload)
          : null;
      if (cacheKey) {
        const cached = await this.readCache(cacheKey);
        if (cached) {
          if (this.paused) return reject();
          this.observe(path, cached);
          res.writeHead(200, {
            "content-type": "application/octet-stream",
            "content-length": cached.length
          });
          return res.end(cached);
        }
      }
      const headers = { "content-length": payload.length };
      if (req.headers["content-type"]) {
        headers["content-type"] = req.headers["content-type"];
      }

      let finished = false;
      const fail = () => {
        if (finished) return;
        finished = true;
        this.inFlight.delete(upstream);
        reject();
      };
      const upstream = http.request(
        {
          host: this.target.host,
          port: this.target.port,
          method: req.method,
          path: req.url,
          headers,
          agent: this.agent
        },
        response => {
          const parts = [];
          response.on("data", chunk => parts.push(chunk));
          response.on("error", fail);
          response.on("aborted", fail);
          response.on("end", () => {
            if (finished) return;
            finished = true;
            this.inFlight.delete(upstream);
            const data = Buffer.concat(parts);
            if (sync) {
              if (this.paused) return reject();
              this.observe(path, data);
              if (cacheKey && response.statusCode === 200 && cacheable(data)) {
                this.writeCache(cacheKey, data);
              }
            }
            const out = { "content-length": data.length };
            if (response.headers["content-type"]) {
              out["content-type"] = response.headers["content-type"];
            }
            res.writeHead(response.statusCode, out);
            res.end(data);
          });
        }
      );
      upstream.on("error", fail);
      if (sync) this.inFlight.add(upstream);
      upstream.end(payload);
    });
  }

  prepareCache() {
    if (!this.cacheDir) return;
    try {
      fs.mkdirSync(this.cacheDir, { recursive: true });
      let size = 0;
      for (const name of fs.readdirSync(this.cacheDir)) {
        size += fs.statSync(nodePath.join(this.cacheDir, name)).size;
      }
      if (size > CACHE_LIMIT_BYTES) {
        fs.rmSync(this.cacheDir, { recursive: true, force: true });
        fs.mkdirSync(this.cacheDir, { recursive: true });
      }
    } catch (e) {
      // The cache is an optimisation only
    }
  }

  async readCache(key) {
    try {
      return await fs.promises.readFile(
        nodePath.join(this.cacheDir, `${key}.bin`)
      );
    } catch (e) {
      return null;
    }
  }

  async writeCache(key, data) {
    const file = nodePath.join(this.cacheDir, `${key}.bin`);
    try {
      await fs.promises.writeFile(`${file}.tmp`, data);
      await fs.promises.rename(`${file}.tmp`, file);
    } catch (e) {
      // The cache is an optimisation only
    }
  }

  observe(path, data) {
    const height = readEpeeUint64(data, "start_height");
    if (height === null) return;
    this.emit("progress", {
      height,
      target: readEpeeUint64(data, "current_height") || 0,
      headersOnly: path.endsWith("hashes.bin")
    });
  }
}

function cacheKeyFor(path, body) {
  return crypto
    .createHash("sha256")
    .update(path)
    .update(Buffer.from([0]))
    .update(body)
    .digest("hex");
}

// A successful batch whose hashes all lie far below the node's tip. Batches
// hold at most 10,000 hashes, so starting 20,000 below the tip leaves a wide
// margin for re-organisations.
function cacheable(data) {
  const start = readEpeeUint64(data, "start_height");
  const tip = readEpeeUint64(data, "current_height");
  return (
    start !== null &&
    tip !== null &&
    start + 20000 < tip &&
    data.lastIndexOf(STATUS_OK) >= 0
  );
}

// Reads a uint64 field named `key` from an epee portable-storage body (the
// binary format of beldexd's .bin RPCs): a length-prefixed name, type 5
// (uint64), then 8 little-endian bytes. The height fields follow the large
// block/hash arrays, hence lastIndexOf.
export function readEpeeUint64(data, key) {
  const pattern = Buffer.concat([
    Buffer.from([key.length]),
    Buffer.from(key, "ascii"),
    Buffer.from([5])
  ]);
  const i = data.lastIndexOf(pattern);
  if (i < 0 || i + pattern.length + 8 > data.length) return null;
  return Number(data.readBigUInt64LE(i + pattern.length));
}
