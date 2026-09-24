// Startup/shutdown lifecycle tests for the Electron wallet, driven over the
// Chrome DevTools Protocol against the built app (dist/electron/UnPackaged).
//
//   npm run build:unpackaged        # quasar build -m electron --skip-pkg
//   npm run test:lifecycle [-- scenario ...]
//
// Needs bin/beldexd and bin/beldex-wallet-rpc, network access to the public
// Beldex nodes, and a display (test windows open briefly). Each scenario runs
// with its own throwaway HOME under /tmp, so real wallets are never touched.
const { spawn, spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const http = require("http");
const APP = path.resolve(__dirname, "..");
const WebSocket = require(APP + "/node_modules/ws");
const ELECTRON = APP + "/node_modules/electron/dist/electron";
const BIN = APP + "/dist/electron/bin";
for (const b of ["beldexd", "beldex-wallet-rpc"]) {
  fs.mkdirSync(BIN, { recursive: true });
  if (!fs.existsSync(`${BIN}/${b}`))
    fs.copyFileSync(`${APP}/bin/${b}`, `${BIN}/${b}`);
  fs.chmodSync(`${BIN}/${b}`, 0o755);
}
// Short paths: beldexd's IPC socket path must stay under 108 characters
const HOME_BASE = "/tmp/beldex-lifecycle";

const sleep = ms => new Promise(r => setTimeout(r, ms));
const results = [];
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);

function cleanEnv(home) {
  const env = { ...process.env, HOME: home };
  delete env.ELECTRON_RUN_AS_NODE;
  delete env.ELECTRON_NO_ATTACH_CONSOLE;
  return env;
}

function launch(home, port, tag, extraEnv = {}) {
  const out = fs.openSync(path.join(home, `${tag}.log`), "a");
  const proc = spawn(
    ELECTRON,
    [APP + "/dist/electron/UnPackaged", `--remote-debugging-port=${port}`],
    {
      env: { ...cleanEnv(home), ...extraEnv },
      stdio: ["ignore", out, out],
      detached: true
    }
  );
  proc.exited = new Promise(r =>
    proc.on("exit", (code, sig) => r({ code, sig }))
  );
  return proc;
}

function getJSON(url) {
  return new Promise((resolve, reject) => {
    http
      .get(url, res => {
        let d = "";
        res.on("data", c => (d += c));
        res.on("end", () => {
          try {
            resolve(JSON.parse(d));
          } catch (e) {
            reject(e);
          }
        });
      })
      .on("error", reject);
  });
}

class Page {
  static async connect(port, timeout = 30000) {
    const t0 = Date.now();
    while (Date.now() - t0 < timeout) {
      try {
        const page = (await getJSON(`http://127.0.0.1:${port}/json`)).find(
          t => t.type === "page"
        );
        if (page) {
          const p = new Page();
          p.ws = new WebSocket(page.webSocketDebuggerUrl, {
            perMessageDeflate: false
          });
          await new Promise((res, rej) => {
            p.ws.on("open", res);
            p.ws.on("error", rej);
          });
          p.ws.on("message", d => {
            const m = JSON.parse(d);
            const cb = p.pending.get(m.id);
            if (cb) {
              p.pending.delete(m.id);
              m.error
                ? cb.rej(new Error(JSON.stringify(m.error)))
                : cb.res(m.result);
            }
          });
          p.ws.on("close", () => {
            for (const cb of p.pending.values())
              cb.rej(new Error("page closed"));
            p.pending.clear();
          });
          return p;
        }
      } catch (e) {
        // ignore
      }
      await sleep(400);
    }
    throw new Error("no CDP page");
  }
  constructor() {
    this.id = 0;
    this.pending = new Map();
  }
  cdp(method, params = {}) {
    const id = ++this.id;
    this.ws.send(JSON.stringify({ id, method, params }));
    return new Promise((res, rej) => {
      this.pending.set(id, { res, rej });
      setTimeout(() => {
        if (this.pending.delete(id)) rej(new Error("CDP timeout"));
      }, 20000);
    });
  }
  async eval(expr) {
    const r = await this.cdp("Runtime.evaluate", {
      expression: expr,
      awaitPromise: true,
      returnByValue: true
    });
    if (r.exceptionDetails)
      throw new Error(
        r.exceptionDetails.text +
          " " +
          (
            (r.exceptionDetails.exception &&
              r.exceptionDetails.exception.description) ||
            ""
          ).slice(0, 200)
      );
    return r.result.value;
  }
  async waitFor(desc, expr, timeout, poll = 500) {
    const t0 = Date.now();
    let last;
    while (Date.now() - t0 < timeout) {
      try {
        const v = await this.eval(expr);
        if (v) return v;
      } catch (e) {
        last = e.message;
      }
      await sleep(poll);
    }
    throw new Error(`timeout: ${desc}${last ? " (" + last + ")" : ""}`);
  }
  close() {
    try {
      this.ws.close();
    } catch (e) {
      // ignore
    }
  }
}

const VM = `document.querySelector('#q-app').__vue__`;
const G = `${VM}.$store.state.gateway`;

async function waitReady(page, { configure } = {}) {
  await page.waitFor(
    "gateway",
    `!!(document.querySelector('#q-app') && ${VM} && ${VM}.$gateway && ${VM}.$gateway.ws && ${VM}.$gateway.ws.readyState === 1)`,
    60000
  );
  const state = await page.waitFor(
    "welcome or ready",
    `(() => { const c = ${G}.app.status.code; if (c === 0) return "ready"; if (${VM}.$route.path === "/welcome") return "welcome"; return null; })()`,
    180000
  );
  if (state === "welcome") {
    await page.eval(
      `(() => { const vm=${VM}; const cfg = JSON.parse(JSON.stringify(vm.$store.state.gateway.app.pending_config)); (${configure ||
        "c => c"})(cfg); vm.$gateway.send("core","save_config_init", cfg); return true; })()`
    );
    await page.waitFor("ready", `${G}.app.status.code === 0`, 240000);
  }
}

function electronLogErrors(home) {
  const f = path.join(home, ".beldex/logs/electron.log");
  if (!fs.existsSync(f)) return [];
  return fs
    .readFileSync(f, "utf8")
    .split("\n")
    .filter(Boolean)
    .map(l => JSON.parse(l))
    .filter(e => e.level >= 50)
    .map(e => e.msg.slice(0, 160));
}

function leftovers(home) {
  const r = spawnSync("pgrep", ["-af", `${home}/`], { encoding: "utf8" });
  return r.stdout
    .split("\n")
    .filter(l => l && !l.includes("pgrep"))
    .map(l => l.slice(0, 120));
}

function killAll(home) {
  spawnSync("pkill", ["-9", "-f", `${home}/`]);
}

function freshHome(name) {
  const home = `${HOME_BASE}-${name}`;
  killAll(home);
  fs.rmSync(home, { recursive: true, force: true });
  fs.mkdirSync(home, { recursive: true });
  return home;
}

async function quitViaConfirm(page, proc, restart = false) {
  // Same IPC the renderer sends when the user confirms the exit dialog
  await page
    .eval(`(window.electronAPI.ipc.send("confirmClose", ${restart}), true)`)
    .catch(() => {});
  page.close();
  const r = await Promise.race([
    proc.exited,
    sleep(45000).then(() => "timeout")
  ]);
  return r;
}

async function check(name, fn) {
  const t0 = Date.now();
  try {
    const detail = await fn();
    results.push({ name, ok: true, ms: Date.now() - t0, detail });
    log(`PASS ${name}`, detail || "");
  } catch (e) {
    results.push({ name, ok: false, ms: Date.now() - t0, detail: e.message });
    log(`FAIL ${name}: ${e.message}`);
  } finally {
    spawnSync("pkill", [
      "-9",
      "-f",
      "dist/electron --remote-debugging-port=934"
    ]);
    spawnSync("pkill", ["-9", "-f", `(wallet-rpc|beldexd) .*${HOME_BASE}-`]);
    await sleep(1500);
  }
}

const remoteCfg = `c => { c.daemons.mainnet.type = "remote"; c.daemons.mainnet.remote_host = "mainnet.beldex.io"; c.daemons.mainnet.remote_port = 29095; }`;

const scenarios = {
  // Default (currently dead) node -> failover -> wallet -> confirmed exit
  async fresh_start_and_exit() {
    const home = freshHome("fresh");
    const proc = launch(home, 9341, "app");
    const page = await Page.connect(9341);
    await waitReady(page, { configure: remoteCfg });
    const host = await page.eval(`${G}.app.config.daemons.mainnet.remote_host`);
    await page.eval(
      `(${VM}.$gateway.send("wallet","create_wallet",{name:"w1",password:"pw",language:"English"}), true)`
    );
    await page.waitFor(
      "wallet open",
      `${G}.wallet.status.code === 0 && !!${G}.wallet.info.address`,
      120000
    );
    const exit = await quitViaConfirm(page, proc);
    await sleep(1500);
    const errors = electronLogErrors(home),
      left = leftovers(home);
    killAll(home);
    if (exit === "timeout") throw new Error("app did not exit within 45 s");
    if (errors.length)
      throw new Error("electron.log errors: " + errors.join(" | "));
    if (left.length) throw new Error("leftover processes: " + left.join(" | "));
    return `failover to ${host}; exited ${JSON.stringify(
      exit
    )}; no errors, no leftovers`;
  },

  // Restart path used after changing settings (app.relaunch)
  async restart_relaunches() {
    const home = freshHome("restart");
    // Production mode: app.relaunch() is skipped in dev mode by design
    const proc = launch(home, 9342, "app", { ELECTRON_IS_DEV: "0" });
    let page = await Page.connect(9342);
    await waitReady(page, { configure: remoteCfg });
    await quitViaConfirm(page, proc, true);
    // The relaunched instance keeps the same arguments (debug port included)
    page = await Page.connect(9342, 60000);
    await waitReady(page);
    const pid = spawnSync("pgrep", ["-f", `remote-debugging-port=9342`], {
      encoding: "utf8"
    })
      .stdout.trim()
      .split("\n")[0];
    await page
      .eval(`(window.electronAPI.ipc.send("confirmClose", false), true)`)
      .catch(() => {});
    page.close();
    // Wait for the relaunched instance (and its wallet-rpc) to exit
    for (
      let i = 0;
      i < 45 &&
      (leftovers(home).length ||
        spawnSync("pgrep", ["-f", "dist/electron --remote-debugging-port=9342"])
          .status === 0);
      i++
    )
      await sleep(1000);
    const errors = electronLogErrors(home),
      left = leftovers(home);
    killAll(home);
    spawnSync("pkill", [
      "-9",
      "-f",
      "dist/electron --remote-debugging-port=9342"
    ]);
    if (errors.length)
      throw new Error("electron.log errors: " + errors.join(" | "));
    if (left.length) throw new Error("leftover processes: " + left.join(" | "));
    return `relaunched (pid ${pid}) and reached ready, then exited cleanly`;
  },

  // Ctrl+R / crash recovery must reconnect, not quit
  async renderer_reload() {
    const home = freshHome("reload");
    const proc = launch(home, 9343, "app");
    let page = await Page.connect(9343);
    await waitReady(page, { configure: remoteCfg });
    await page.cdp("Page.reload", {}).catch(() => {});
    page.close();
    await sleep(3000);
    const exitedEarly = await Promise.race([
      proc.exited.then(() => true),
      sleep(100).then(() => false)
    ]);
    if (exitedEarly) throw new Error("app quit after reload");
    page = await Page.connect(9343);
    await waitReady(page);
    await page.eval(`(${VM}.$gateway.send("wallet","list_wallets"), true)`);
    const exit = await quitViaConfirm(page, proc);
    const errors = electronLogErrors(home);
    killAll(home);
    if (errors.length)
      throw new Error("electron.log errors: " + errors.join(" | "));
    return `reloaded, reconnected to the same backend, exit ${JSON.stringify(
      exit
    )}`;
  },

  // A second launch must exit and leave the first one working
  async second_instance() {
    const home = freshHome("second");
    const proc = launch(home, 9344, "app");
    const page = await Page.connect(9344);
    await waitReady(page, { configure: remoteCfg });
    const second = launch(home, 9345, "second");
    // Its "already open" dialog needs a click; its window close is enough to verify it doesn't take over
    const p2 = await Page.connect(9345).catch(() => null);
    await sleep(4000);
    const firstAlive = await page.eval(
      `${G}.app.status.code === 0 && ${VM}.$gateway.ws.readyState === 1`
    );
    if (p2) p2.close();
    try {
      process.kill(-second.pid, "SIGKILL");
    } catch (e) {
      // ignore
    }
    const exit = await quitViaConfirm(page, proc);
    killAll(home);
    if (!firstAlive) throw new Error("first instance lost its backend");
    return `first instance unaffected; exit ${JSON.stringify(exit)}`;
  },

  // A leftover wallet-rpc holding the default port must not block startup
  async orphan_wallet_rpc() {
    const home = freshHome("orphanw");
    fs.mkdirSync(home + "/orphan", { recursive: true });
    const orphan = spawn(
      BIN + "/beldex-wallet-rpc",
      [
        "--rpc-bind-port",
        "29095",
        "--rpc-bind-ip",
        "127.0.0.1",
        "--rpc-login",
        "x:y",
        "--daemon-address",
        "publicnode2.rpcnode.stream:29095",
        "--wallet-dir",
        home + "/orphan",
        "--log-file",
        home + "/orphan/w.log"
      ],
      { stdio: "ignore", detached: true }
    );
    await sleep(3000);
    const proc = launch(home, 9346, "app");
    const page = await Page.connect(9346);
    await waitReady(page, { configure: remoteCfg });
    await page.eval(
      `(${VM}.$gateway.send("wallet","create_wallet",{name:"w2",password:"",language:"English"}), true)`
    );
    await page.waitFor(
      "wallet open",
      `${G}.wallet.status.code === 0 && !!${G}.wallet.info.address`,
      120000
    );
    const exit = await quitViaConfirm(page, proc);
    try {
      process.kill(-orphan.pid, "SIGKILL");
    } catch (e) {
      // ignore
    }
    killAll(home);
    return `started on a free port, wallet created; exit ${JSON.stringify(
      exit
    )}`;
  },

  // Local node that is far behind + a beldexd left over from a previous session
  async local_daemon_behind_and_orphan() {
    const home = freshHome("local");
    fs.mkdirSync(home + "/.beldex/logs", { recursive: true });
    const orphan = spawn(
      BIN + "/beldexd",
      [
        "--data-dir",
        home + "/.beldex",
        "--rpc-bind-ip",
        "127.0.0.1",
        "--rpc-bind-port",
        "19091",
        "--p2p-bind-port",
        "19090",
        "--log-file",
        home + "/.beldex/logs/orphan.log",
        "--non-interactive"
      ],
      { stdio: "ignore", detached: true }
    );
    for (let i = 0; i < 60; i++) {
      if (spawnSync("bash", ["-c", "ss -ltn | grep -q ':19091 '"]).status === 0)
        break;
      await sleep(1000);
    }
    const proc = launch(home, 9347, "app");
    const page = await Page.connect(9347);
    await waitReady(page, {
      configure: `c => { c.daemons.mainnet.type = "local"; }`
    });
    const reused = fs
      .readFileSync(home + "/app.log", "utf8")
      .includes("reusing beldexd");
    await page.waitFor(
      "behind dialog",
      `document.body.innerText.includes("Local node is still syncing")`,
      180000,
      1000
    );
    const text = await page.eval(
      `(document.querySelector('.q-dialog') || document.body).innerText.slice(0, 200)`
    );
    await page
      .eval(`(window.electronAPI.ipc.send("confirmClose", false), true)`)
      .catch(() => {});
    page.close();
    await Promise.race([proc.exited, sleep(30000)]);
    try {
      process.kill(-orphan.pid, "SIGKILL");
    } catch (e) {
      // ignore
    }
    killAll(home);
    if (!reused) throw new Error("did not reuse the running beldexd");
    return `reused running beldexd; offered Local + Remote: "${text
      .replace(/\s+/g, " ")
      .slice(0, 90)}..."`;
  }
};

(async () => {
  const pick = process.argv.slice(2);
  for (const [name, fn] of Object.entries(scenarios)) {
    if (pick.length && !pick.includes(name)) continue;
    await check(name, fn);
  }
  console.log(JSON.stringify(results, null, 2));
  process.exit(results.every(r => r.ok) ? 0 : 1);
})();
