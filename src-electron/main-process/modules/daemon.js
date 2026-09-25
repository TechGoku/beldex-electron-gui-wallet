import child_process from "child_process";

import axios from "axios";
const queue = require("promise-queue");
const http = require("http");
const fs = require("fs");
const path = require("upath");
const portscanner = require("portscanner");

export class Daemon {
  constructor(backend) {
    this.backend = backend;
    this.heartbeat = null;
    this.heartbeat_slow = null;
    this.id = 0;
    this.net_type = "mainnet";
    this.local = false; // do we have a local daemon ?

    this.agent = new http.Agent({ keepAlive: true, maxSockets: 100 });
    // The daemon serves RPC calls concurrently, so a slow call (e.g. the
    // master node list) doesn't have to hold up the heartbeat.
    this.queue = new queue(4, Infinity);

    // Last get_info result, used by the wallet to tell whether it is syncing
    this.info = null;
    // Fingerprints of the last data pushed to the renderer
    this.sent = {};

    // Settings for timestamp to height conversion
    // These are initial values used to calculate the height
    this.PIVOT_BLOCK_HEIGHT = 119681;
    this.PIVOT_BLOCK_TIMESTAMP = 1539676273;
    this.PIVOT_BLOCK_TIME = 120;
  }

  checkVersion() {
    return new Promise(resolve => {
      if (process.platform === "win32") {
        let oxend_path = path.join(__ryo_bin, "beldexd.exe");
        if (!fs.existsSync(oxend_path)) {
          resolve(false);
        }
        child_process.execFile(oxend_path, ["--version"], (error, stdout) => {
          if (error) {
            resolve(false);
          }
          resolve(stdout);
        });
      } else {
        let oxend_path = path.join(__ryo_bin, "beldexd");
        if (!fs.existsSync(oxend_path)) {
          resolve(false);
        }
        child_process.execFile(
          oxend_path,
          ["--version"],
          { detached: true },
          (error, stdout) => {
            if (error) {
              resolve(false);
            }
            resolve(stdout);
          }
        );
      }
    });
  }

  checkRemote(daemon, timeout = 20000) {
    if (daemon && daemon.type === "local") {
      return Promise.resolve({});
    }

    return this.sendRPC(
      "get_info",
      {},
      {
        protocol: "http://",
        hostname: daemon.remote_host,
        port: daemon.remote_port,
        timeout
      }
    ).then(data => {
      if (data.error) return { error: data.error };
      return {
        net_type: data.result.nettype,
        height: data.result.height
      };
    });
  }

  // Probe all known remotes in parallel and resolve with the first healthy
  // one on the requested network (null if none answer in time).
  findWorkingRemote(remotes, net_type, timeout = 8000) {
    const probes = remotes.map(remote =>
      this.checkRemote(
        { type: "remote", remote_host: remote.host, remote_port: remote.port },
        timeout
      ).then(data => {
        if (data.error || data.net_type !== net_type) {
          throw new Error("unusable remote");
        }
        return { ...remote, net_type: data.net_type };
      })
    );
    return Promise.any(probes).catch(() => null);
  }

  start(options) {
    const { net_type } = options.app;
    const daemon = options.daemons[net_type];
    if (daemon.type === "remote") {
      this.local = false;

      // save this info for later RPC calls
      this.protocol = "http://";
      this.hostname = daemon.remote_host;
      this.port = daemon.remote_port;

      return new Promise((resolve, reject) => {
        // Set a 20 second timeout on get_info incase the node is unresponsive
        this.sendRPC("get_info", {}, { timeout: 20000 }).then(data => {
          if (!data.hasOwnProperty("error")) {
            this.startHeartbeat();
            resolve();
          } else {
            reject();
          }
        });
      });
    }
    return new Promise((resolve, reject) => {
      this.local = true;
      this.type = daemon.type;

      const args = [
        "--data-dir",
        options.app.data_dir,
        "--p2p-bind-ip",
        daemon.p2p_bind_ip,
        "--p2p-bind-port",
        daemon.p2p_bind_port,
        "--rpc-bind-ip",
        daemon.rpc_bind_ip,
        "--rpc-bind-port",
        daemon.rpc_bind_port,
        "--zmq-rpc-bind-ip",
        daemon.zmq_rpc_bind_ip,
        "--out-peers",
        daemon.out_peers,
        "--in-peers",
        daemon.in_peers,
        "--limit-rate-up",
        daemon.limit_rate_up,
        "--limit-rate-down",
        daemon.limit_rate_down,
        "--log-level",
        daemon.log_level
      ];

      const dirs = {
        mainnet: options.app.data_dir,
        stagenet: path.join(options.app.data_dir, "stagenet"),
        testnet: path.join(options.app.data_dir, "testnet")
      };

      const { net_type } = options.app;
      this.net_type = net_type;

      if (net_type === "testnet") {
        args.push("--testnet");
      } else if (net_type === "stagenet") {
        args.push("--stagenet");
      }

      args.push("--log-file", path.join(dirs[net_type], "logs", "beldexd.log"));
      if (daemon.rpc_bind_ip !== "127.0.0.1") {
        reject(new Error("Local daemon RPC must bind to 127.0.0.1 only."));
        return;
      }

      // TODO: Check if we need to push this command for staging too
      if (daemon.type === "local_remote" && net_type === "mainnet") {
        args.push(
          "--bootstrap-daemon-address",
          `${daemon.remote_host}:${daemon.remote_port}`
        );
      }

      // save this info for later RPC calls
      this.protocol = "http://";
      this.hostname = daemon.rpc_bind_ip;
      this.port = daemon.rpc_bind_port;

      portscanner
        .checkPortStatus(this.port, this.hostname)
        .catch(() => "closed")
        .then(status => {
          if (status === "closed") {
            if (process.platform === "win32") {
              this.daemonProcess = child_process.spawn(
                path.join(__ryo_bin, "beldexd.exe"),
                args
              );
            } else {
              this.daemonProcess = child_process.spawn(
                path.join(__ryo_bin, "beldexd"),
                args,
                {
                  detached: true
                }
              );
            }

            this.daemonProcess.stdout.on("data", data =>
              process.stdout.write(`Daemon: ${data}`)
            );
            this.daemonProcess.on("error", err =>
              process.stderr.write(`Daemon: ${err}`)
            );
            const proc = this.daemonProcess;
            proc.on("close", code => {
              process.stderr.write(`Daemon: exited with code ${code} \n`);
              if (this.daemonProcess === proc) this.daemonProcess = null;
              if (this.runningProcess === proc) {
                // Not asked to stop: let the backend restart it
                this.runningProcess = null;
                this.backend.onLocalDaemonExit(code);
              } else if (code === null) {
                reject(new Error("Failed to start local daemon"));
              }
            });

            // To let caller know when the daemon is ready
            // We can't apply timeout to this because the local daemon might be syncing in the background
            let intrvl = setInterval(() => {
              this.sendRPC("get_info").then(data => {
                if (!data.hasOwnProperty("error")) {
                  this.runningProcess = proc;
                  this.startHeartbeat();
                  clearInterval(intrvl);
                  resolve();
                } else {
                  if (
                    this.daemonProcess &&
                    data.error.cause &&
                    data.error.cause.code === "ECONNREFUSED"
                  ) {
                    // Ignore
                  } else {
                    clearInterval(intrvl);
                    this.killProcess();
                    reject(new Error("Could not connect to local daemon"));
                  }
                }
              });
            }, 1000);
          } else {
            // Usually a beldexd left running by a previous session (it is
            // spawned detached). Reuse it if it is a healthy node on our
            // network instead of failing startup.
            this.sendRPC("get_info", {}, { timeout: 5000 }).then(data => {
              const nettype = data.result && data.result.nettype;
              if (!data.error && (!nettype || nettype === net_type)) {
                process.stderr.write(
                  `Daemon: reusing beldexd already listening on port ${this.port}\n`
                );
                this.startHeartbeat();
                resolve();
              } else {
                reject(new Error(`Local daemon port ${this.port} is in use`));
              }
            });
          }
        });
    });
  }

  // Switches to the node in `options` (same network) without touching the
  // wallet. A remote node is checked first: if it doesn't answer or is on
  // another network this throws and nothing changes. A local node is
  // (re)started.
  async switchTo(options) {
    const { net_type } = options.app;
    const daemon = options.daemons[net_type];
    if (daemon.type === "remote") {
      const check = await this.sendRPC(
        "get_info",
        {},
        {
          hostname: daemon.remote_host,
          port: daemon.remote_port,
          timeout: 15000
        }
      );
      if (check.error) {
        throw new Error(
          `${daemon.remote_host}:${daemon.remote_port} is not answering`
        );
      }
      const nettype = check.result.nettype;
      if (nettype && nettype !== net_type) {
        throw new Error(`that node is on ${nettype}, not ${net_type}`);
      }
      this.stopHeartbeats();
      this.local = false;
      this.type = "remote";
      this.protocol = "http://";
      this.hostname = daemon.remote_host;
      this.port = daemon.remote_port;
      this.failedChecks = 0;
      this.info = check.result;
      this.sent = {};
      // A local node isn't needed any more; let it shut down in the background
      this.stopProcess();
      this.startHeartbeat();
      return;
    }
    this.stopHeartbeats();
    await this.stopProcess();
    this.sent = {};
    await this.start(options);
  }

  stopHeartbeats() {
    clearInterval(this.heartbeat);
    clearInterval(this.heartbeat_slow);
    clearInterval(this.masterNodeHeartbeat);
  }

  // Stops a local beldexd gracefully: SIGTERM, then SIGKILL after 20 s. (Killing
  // a node outright risks its database, so even a syncing node gets SIGTERM.)
  stopProcess() {
    const proc = this.daemonProcess;
    this.runningProcess = null;
    this.daemonProcess = null;
    if (!proc || proc.exitCode !== null) return Promise.resolve();
    return new Promise(resolve => {
      const force = setTimeout(() => proc.kill("SIGKILL"), 20000);
      proc.once("close", () => {
        clearTimeout(force);
        resolve();
      });
      proc.kill("SIGTERM");
    });
  }

  killProcess() {
    if (this.daemonProcess) {
      this.daemonProcess.kill();
      this.daemonProcess = null;
    }
  }

  handle(data) {
    let params = data.data;
    switch (data.method) {
      case "get_info":
        this.checkRemote({});
        break;
      case "ban_peer":
        this.banPeer(params.host, params.seconds);
        break;

      default:
    }
  }

  banPeer(host, seconds = 3600) {
    if (!seconds) {
      seconds = 3600;
    }

    let params = {
      bans: [
        {
          host,
          seconds,
          ban: true
        }
      ]
    };

    this.sendRPC("set_bans", params).then(data => {
      if (data.hasOwnProperty("error") || !data.hasOwnProperty("result")) {
        this.sendGateway("show_notification", {
          type: "negative",
          i18n: "notification.errors.banningPeer",
          timeout: 2000
        });
        return;
      }

      let end_time = new Date(Date.now() + seconds * 1000).toLocaleString();
      this.sendGateway("show_notification", {
        i18n: ["notification.positive.bannedPeer", { host, time: end_time }],
        timeout: 2000
      });

      // Send updated peer and ban list
      this.heartbeatSlowAction();
    });
  }

  timestampToHeight(timestamp, pivot = null, recursion_limit = null) {
    return new Promise((resolve, reject) => {
      if (timestamp > 999999999999) {
        // We have got a JS ms timestamp, convert
        timestamp = Math.floor(timestamp / 1000);
      }

      pivot = pivot || [this.PIVOT_BLOCK_HEIGHT, this.PIVOT_BLOCK_TIMESTAMP];
      recursion_limit = recursion_limit || 0;

      let diff = Math.floor((timestamp - pivot[1]) / this.PIVOT_BLOCK_TIME);
      let estimated_height = pivot[0] + diff;

      if (estimated_height <= 0) {
        return resolve(0);
      }

      if (recursion_limit > 10) {
        return resolve(pivot[0]);
      }

      this.getRPC("block_header_by_height", {
        height: estimated_height
      }).then(data => {
        if (data.hasOwnProperty("error") || !data.hasOwnProperty("result")) {
          if (data.error.code == -2) {
            // Too big height
            this.getRPC("last_block_header").then(data => {
              if (
                data.hasOwnProperty("error") ||
                !data.hasOwnProperty("result")
              ) {
                return reject();
              }

              let new_pivot = [
                data.result.block_header.height,
                data.result.block_header.timestamp
              ];

              // If we are within an hour that is good enough
              // If for some reason there is a > 1h gap between blocks
              // the recursion limit will take care of infinite loop
              if (Math.abs(timestamp - new_pivot[1]) < 3600) {
                return resolve(new_pivot[0]);
              }

              // Continue recursion with new pivot
              resolve(new_pivot);
            });
            return;
          } else {
            return reject();
          }
        }

        let new_pivot = [
          data.result.block_header.height,
          data.result.block_header.timestamp
        ];

        // If we are within an hour that is good enough
        // If for some reason there is a > 1h gap between blocks
        // the recursion limit will take care of infinite loop
        if (Math.abs(timestamp - new_pivot[1]) < 3600) {
          return resolve(new_pivot[0]);
        }

        // Continue recursion with new pivot
        resolve(new_pivot);
      });
    })
      .then(pivot_or_height => {
        return Array.isArray(pivot_or_height)
          ? this.timestampToHeight(
              timestamp,
              pivot_or_height,
              recursion_limit + 1
            )
          : pivot_or_height;
      })
      .catch(() => {
        return false;
      });
  }

  startHeartbeat() {
    clearInterval(this.heartbeat);
    this.heartbeat = setInterval(
      () => {
        this.heartbeatAction();
      },
      this.local ? 5 * 1000 : 30 * 1000
    ); // 5 seconds for local daemon, 30 seconds for remote
    this.heartbeatAction();

    clearInterval(this.heartbeat_slow);
    this.heartbeat_slow = setInterval(() => {
      this.heartbeatSlowAction();
    }, 30 * 1000); // 30 seconds
    this.heartbeatSlowAction();

    clearInterval(this.masterNodeHeartbeat);
    this.masterNodeHeartbeat = setInterval(() => {
      this.updateMasterNodes();
    }, 5 * 60 * 1000); // 5 minutes
    this.updateMasterNodes();
  }

  heartbeatAction() {
    let actions = [];

    // No difference between local and remote heartbeat action for now
    if (this.local) {
      actions = [this.getRPC("info")];
    } else {
      actions = [this.getRPC("info")];
    }

    Promise.all(actions).then(data => {
      // A remote node that stops answering: the backend fails over
      if (!this.local) {
        const ok = data.some(n => n && n.method === "get_info" && n.result);
        if (ok) this.failedChecks = 0;
        else if (++this.failedChecks === 2) this.backend.onDaemonUnreachable();
      }
      let daemon_info = {};
      for (let n of data) {
        if (
          n == undefined ||
          !n.hasOwnProperty("result") ||
          n.result == undefined
        ) {
          continue;
        }
        if (n.method == "get_info") {
          daemon_info.info = n.result;
          this.info = n.result;
          this.checkLocalDaemonBehind(n.result);
        }
      }
      this.sendIfChanged("info", daemon_info);
    });
  }

  // A local node that is far behind can't serve the wallet until it has
  // synced (the wallet then logs out_of_hashchain_bounds errors). Tell the
  // renderer once so it can offer Local + Remote (bootstrap) mode.
  checkLocalDaemonBehind(info) {
    if (!this.local || this.type !== "local" || this.behindNoticeSent) return;
    const target = info.target_height || 0;
    const height = info.height || 0;
    if (target > 0 && target - height > 1000) {
      this.behindNoticeSent = true;
      this.sendGateway("local_daemon_behind", {
        height,
        target_height: target
      });
    }
  }

  // Skip pushing data the renderer already has
  sendIfChanged(key, data) {
    const fingerprint = JSON.stringify(data);
    if (this.sent[key] === fingerprint) return;
    this.sent[key] = fingerprint;
    this.sendGateway("set_daemon_data", data);
  }

  heartbeatSlowAction() {
    let actions = [];
    if (this.local) {
      actions = [
        this.getRPC("connections"),
        this.getRPC("bans")
        // this.getRPC("txpool_backlog"),
      ];
    } else {
      actions = [
        // this.getRPC("txpool_backlog"),
      ];
    }

    if (actions.length === 0) return;

    Promise.all(actions).then(data => {
      let daemon_info = {};
      for (let n of data) {
        if (
          n == undefined ||
          !n.hasOwnProperty("result") ||
          n.result == undefined
        ) {
          continue;
        }
        if (
          n.method == "get_connections" &&
          n.result.hasOwnProperty("connections")
        ) {
          daemon_info.connections = n.result.connections;
        } else if (n.method == "get_bans" && n.result.hasOwnProperty("bans")) {
          daemon_info.bans = n.result.bans;
        } else if (
          n.method == "get_txpool_backlog" &&
          n.result.hasOwnProperty("backlog")
        ) {
          daemon_info.tx_pool_backlog = n.result.backlog;
        }
      }
      this.sendIfChanged("slow", daemon_info);
    });
  }

  updateMasterNodes() {
    const master_nodes = {
      fetching: true
    };
    this.sendGateway("set_daemon_data", { master_nodes });
    this.getRPC("master_nodes").then(data => {
      if (!data.hasOwnProperty("result")) return;
      const nodes = data.result.master_node_states;

      const master_nodes = {
        nodes,
        fetching: false
      };
      const fingerprint = JSON.stringify(nodes);
      if (this.sent.master_nodes === fingerprint) {
        this.sendGateway("set_daemon_data", {
          master_nodes: { fetching: false }
        });
        return;
      }
      this.sent.master_nodes = fingerprint;
      this.sendGateway("set_daemon_data", { master_nodes });
    });

    this.getRPC("master_node_blacklisted_key_images").then(data => {
      if (!data.hasOwnProperty("result")) return;
      const master_nodes_deregister = data.result.blacklist;
      this.sendIfChanged("deregister", { master_nodes_deregister });
    });
  }

  async getBNSRecordsForOwners(owners) {
    if (!Array.isArray(owners) || owners.length === 0) {
      return [];
    }

    // only 256 addresses allowed in this call
    let ownersMax = owners.slice(0, 256);
    const data = await this.sendRPC("bns_owners_to_names", {
      //all values are encrpted
      entries: ownersMax
    });
    if (!data.hasOwnProperty("result")) return [];

    // We need to map request_index to owner
    const { entries } = data.result;
    const recordsWithOwners = (entries || []).map(record => {
      const owner = ownersMax[record.request_index];
      return {
        ...record,
        owner
      };
    });
    // return this._sanitizeBNSRecords(recordsWithOwners);
    return recordsWithOwners;
  }

  async getBNSRecord(nameHash) {
    if (!nameHash || nameHash.length === 0) {
      return null;
    }

    const params = {
      name_hash: [
        nameHash
        // {
        // name_hash: nameHash,
        // 0 = bchat
        // 2 = belnet
        // types: [0, 2]
        // }
      ]
    };

    const data = await this.sendRPC("bns_names_to_owners", params);

    if (!data.hasOwnProperty("result")) return null;

    const entries = data?.result?.result || [];
    // this._sanitizeBNSRecords(data.result.entries);
    if (entries.length === 0) return null;

    return entries[0];
  }

  _sanitizeBNSRecords(records) {
    return (records || []).map(record => {
      // Record type is in uint16 format
      // Bchat = 0
      // Belnet = 2
      let type = "belnet";
      if (record.type === 0) {
        type = "bchat";
      }
      return {
        ...record,
        type
      };
    });
  }

  sendGateway(method, data) {
    this.backend.send(method, data);
  }

  sendRPC(method, params = {}, options = {}) {
    let id = this.id++;

    const protocol = options.protocol || this.protocol;
    const hostname = options.hostname || this.hostname;
    const port = options.port || this.port;
    const url = `${protocol}${hostname}:${port}/json_rpc`;
    const payload = {
      jsonrpc: "2.0",
      id: `${id}`,
      method: method
    };

    if (Object.keys(params).length !== 0) {
      payload.params = params;
    }

    let requestOptions = {
      url,
      method: "POST",
      data: payload,
      httpAgent: this.agent
    };

    // If there's a timeout then set it
    if (options.timeout) {
      requestOptions.timeout = options.timeout;
    }

    return this.queue.add(() => {
      return axios(requestOptions)
        .then(({ data: response }) => {
          if (response.hasOwnProperty("error")) {
            return {
              method: method,
              params: params,
              error: response.error
            };
          }
          return {
            method: method,
            params: params,
            result: response.result
          };
        })
        .catch(error => {
          return {
            method: method,
            params: params,
            error: {
              code: -1,
              message: "Cannot connect to daemon-rpc",
              cause: error.cause || error
            }
          };
        });
    });
  }

  /**
   * Call one of the get_* RPC calls
   */
  getRPC(parameter, args) {
    return this.sendRPC(`get_${parameter}`, args);
  }

  quit() {
    this.stopHeartbeats();
    return this.stopProcess().then(() => this.agent.destroy());
  }
}
