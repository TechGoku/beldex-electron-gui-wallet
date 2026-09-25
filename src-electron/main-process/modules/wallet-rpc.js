import child_process from "child_process";
import axios from "axios";
const queue = require("promise-queue");
const http = require("http");
const os = require("os");
const fs = require("fs-extra");
const path = require("upath");
const crypto = require("crypto");
const portscanner = require("portscanner");
import { DaemonProxy } from "./daemon-proxy";

const PASSWORD_HASH_PBKDF2_ITERATIONS = 600000;
const PASSWORD_HASH_KEY_LENGTH = 64;
const PASSWORD_HASH_DIGEST = "sha512";

// Sync loop timing (see syncLoop)
const SYNC_CHUNK_MS = 30000;
const SAVE_EVERY_MS = 60000;
const IDLE_POLL_MS = 10000;
const WALLET_SWITCH_METHODS = new Set([
  "open_wallet",
  "create_wallet",
  "close_wallet",
  "restore_deterministic_wallet",
  "restore_view_wallet",
  "generate_from_keys"
]);

export class WalletRPC {
  constructor(backend) {
    this.backend = backend;
    this.data_dir = null;
    this.wallet_dir = null;
    this.auth = [];
    this.id = 0;
    this.net_type = "mainnet";
    this.heartbeat = null;
    this.bnsHeartbeat = null;
    this.wallet_state = {
      open: false,
      name: "",
      password_hash: null,
      balance: null,
      unlocked_balance: null,
      height: 0,
      address: "",
      bnsRecords: [],
      view_only: false
    };
    this.isRPCSyncing = false;
    this.dirs = null;
    this.last_height_send_time = Date.now();

    // save a pending tx here, so we don't have to send the
    // whole thing to the renderer
    this.pending_tx = null;

    // A mapping of name => type
    this.purchasedNames = {};

    this.agent = new http.Agent({ keepAlive: true, maxSockets: 10 });
    this.queue = new queue(1, Infinity);

    // Incremental transaction cache (see getTransactions)
    this.resetTxCache();

    this.heartbeat_in_flight = false;
    this.history_refresh_pending = false;

    // Sync loop state (see syncLoop)
    this.proxy = null;
    this.syncGeneration = 0;
    this.syncLoopDone = null;
    this.syncWake = null;
    this.refreshing = false;
    this.caughtUp = false;
    this.rescanFrom = null;
    this.last_progress_send_time = 0;
  }

  // this function will take an options object for testnet, data-dir, etc
  start(options) {
    const { net_type } = options.app;
    const daemon = options.daemons[net_type];
    return new Promise((resolve, reject) => {
      const upstream =
        daemon.type == "remote"
          ? [daemon.remote_host, daemon.remote_port]
          : [daemon.rpc_bind_ip, daemon.rpc_bind_port];
      this.proxy = new DaemonProxy({
        cacheDir: path.join(
          options.app.data_dir,
          "cache",
          "block-hashes",
          net_type
        )
      });
      this.proxy.on("progress", progress => this.onScanProgress(progress));

      this.proxy.start(...upstream).then(proxyPort => {
        // wallet-rpc reaches the node through the proxy (see syncLoop)
        const daemon_address = `127.0.0.1:${proxyPort}`;

        crypto.randomBytes(64 + 64 + 32, (err, buffer) => {
          if (err) throw err;

          let auth = buffer.toString("hex");

          this.auth = [
            auth.substr(0, 64), // rpc username
            auth.substr(64, 64), // rpc password
            auth.substr(128, 32) // password salt
          ];

          const args = [
            "--rpc-login",
            this.auth[0] + ":" + this.auth[1],
            "--rpc-bind-port",
            options.wallet.rpc_bind_port,
            "--daemon-address",
            daemon_address,
            "--rpc-bind-ip",
            "127.0.0.1",
            "--log-level",
            options.wallet.log_level,
            "--trusted-daemon"
          ];

          const { net_type, wallet_data_dir, data_dir } = options.app;
          this.net_type = net_type;
          this.data_dir = data_dir;
          this.wallet_data_dir = wallet_data_dir;

          this.dirs = {
            mainnet: this.wallet_data_dir,
            stagenet: path.join(this.wallet_data_dir, "stagenet"),
            testnet: path.join(this.wallet_data_dir, "testnet")
          };

          this.wallet_dir = path.join(this.dirs[net_type], "wallets");
          args.push("--wallet-dir", this.wallet_dir);

          const log_file = path.join(
            this.dirs[net_type],
            "logs",
            "wallet-rpc.log"
          );
          args.push("--log-file", log_file);

          if (net_type === "testnet") {
            args.push("--testnet");
          } else if (net_type === "stagenet") {
            args.push("--stagenet");
          }

          if (fs.existsSync(log_file)) {
            fs.truncateSync(log_file, 0);
          }

          if (!fs.existsSync(this.wallet_dir)) {
            fs.mkdirpSync(this.wallet_dir);
          }

          // save this info for later RPC calls
          this.protocol = "http://";
          this.hostname = "127.0.0.1";
          this.port = options.wallet.rpc_bind_port;

          const rpcExecutable =
            process.platform === "win32"
              ? "beldex-wallet-rpc.exe"
              : "beldex-wallet-rpc";
          // eslint-disable-next-line no-undef
          const rpcPath = path.join(__ryo_bin, rpcExecutable);

          // Check if the rpc exists
          if (!fs.existsSync(rpcPath)) {
            reject(
              new Error(
                "Failed to find Beldex Wallet RPC. Please make sure your anti-virus has not removed it."
              )
            );
            return;
          }

          portscanner
            .checkPortStatus(this.port, this.hostname)
            .catch(() => "closed")
            .then(async status => {
              if (status === "closed") return status;
              // Usually a wallet-rpc left over from a previous session. Its
              // credentials are unknown, so run ours on another free port.
              const freePort = await portscanner
                .findAPortNotInUse(
                  this.port + 1,
                  this.port + 200,
                  this.hostname
                )
                .catch(() => null);
              if (!freePort) return status;
              process.stderr.write(
                `Wallet: port ${this.port} is in use, using ${freePort}\n`
              );
              this.port = freePort;
              args[args.indexOf("--rpc-bind-port") + 1] = freePort;
              return "closed";
            })
            .then(status => {
              if (status === "closed") {
                const options =
                  process.platform === "win32" ? {} : { detached: true };
                this.walletRPCProcess = child_process.spawn(
                  rpcPath,
                  args,
                  options
                );

                this.walletRPCProcess.stdout.on("data", data => {
                  process.stdout.write(`Wallet: ${data}`);
                });
                this.walletRPCProcess.on("error", err =>
                  process.stderr.write(`Wallet: ${err}`)
                );
                this.walletRPCProcess.on("close", code => {
                  process.stderr.write(`Wallet: exited with code ${code} \n`);
                  this.walletRPCProcess = null;
                  this.agent.destroy();
                  if (code === null) {
                    reject(new Error("Failed to start wallet RPC"));
                  }
                });

                // To let caller know when the wallet is ready
                let intrvl = setInterval(() => {
                  this.sendRPC("get_languages").then(data => {
                    if (!data.hasOwnProperty("error")) {
                      clearInterval(intrvl);
                      // The app drives refreshes itself (see syncLoop)
                      this.sendRPC("auto_refresh", { enable: false }).then(() =>
                        resolve()
                      );
                    } else {
                      if (
                        this.walletRPCProcess &&
                        data.error.cause &&
                        data.error.cause.code === "ECONNREFUSED"
                      ) {
                        // Ignore
                      } else {
                        clearInterval(intrvl);
                        if (this.walletRPCProcess) this.walletRPCProcess.kill();
                        this.walletRPCProcess = null;
                        reject(new Error("Could not connect to wallet RPC"));
                      }
                    }
                  });
                }, 1000);
              } else {
                reject(new Error(`Wallet RPC port ${this.port} is in use`));
              }
            });
        });
      }, reject);
    });
  }

  async handle(data) {
    let params = data.data;
    switch (data.method) {
      case "has_password":
        this.hasPassword();
        break;

      case "validate_address":
        this.validateAddress(params.address);
        break;

      case "decrypt_record": {
        const record = await this.decryptBNSRecord(params.type, params.name);
        this.startBnsHeartBeat();
        this.sendGateway("set_decrypt_record_result", {
          record,
          decrypted: !!record
        });
        break;
      }

      case "copy_old_gui_wallets":
        this.copyOldGuiWallets(params.wallets || []);
        break;

      case "list_wallets":
        this.listWallets();
        break;

      case "create_wallet":
        this.createWallet(params.name, params.password, params.language);
        break;

      case "restore_wallet":
        this.restoreWallet(
          params.name,
          params.password,
          params.seed,
          params.refresh_type,
          params.refresh_type == "date"
            ? params.refresh_start_date
            : params.refresh_start_height
        );
        break;

      case "restore_view_wallet":
        // TODO: Decide if we want this for Beldex
        this.restoreViewWallet(
          params.name,
          params.password,
          params.address,
          params.viewkey,
          params.refresh_type,
          params.refresh_type == "date"
            ? params.refresh_start_date
            : params.refresh_start_height
        );
        break;

      case "restore_wallet_with_keys":
        // TODO: Decide if we want this for Beldex
        this.restoreWalletWithKeys(
          params.name,
          params.password,
          params.address,
          params.viewkey,
          params.spendkey,
          params.refresh_type,
          params.refresh_type == "date"
            ? params.refresh_start_date
            : params.refresh_start_height
        );
        break;

      case "import_wallet":
        this.importWallet(params.name, params.password, params.path);
        break;

      case "open_wallet":
        this.openWallet(params.name, params.password);
        break;

      case "close_wallet":
        this.closeWallet();
        break;

      case "stake":
        this.stake(
          params.password,
          params.amount,
          params.key,
          params.destination
        );
        break;

      case "register_master_node":
        this.registerMnode(params.password, params.string);
        break;

      case "update_master_node_list":
        this.updateMasterNodeList();
        break;

      case "unlock_stake":
        this.unlockStake(
          params.password,
          params.master_node_key,
          params.confirmed || false
        );
        break;

      case "transfer":
        this.transfer(
          params.password,
          params.amount,
          params.address,
          params.priority,
          !!params.isSweepAll
        );
        break;
      case "relay_tx":
        this.relayTransaction(
          params.isflash,
          params.addressSave,
          params.note,
          !!params.isSweepAll
        );
        break;
      case "purchase_bns":
        this.purchaseBNS(
          params.years,
          params.password,
          params.name,
          params.value,
          params.owner || "",
          params.backup_owner || "",
          params.value_bchat || "",
          params.value_belnet || "",
          params.value_wallet || "",
          params.value_eth_addr || ""
        );
        break;
      case "bns_renew_mapping":
        this.bnsRenewMapping(params.password, params.years, params.name);
        break;
      case "update_bns_mapping":
        this.updateBNSMapping(
          params.password,
          // // params.type,
          params.name,
          params.owner || "",
          params.backup_owner || "",
          params.value_bchat || "",
          params.value_belnet || "",
          params.value_wallet || "",
          params.value_eth_addr || "",
          params.backup_owner || ""
        );
        break;

      case "prove_transaction":
        this.proveTransaction(params.txid, params.address, params.message);
        break;

      case "check_transaction":
        this.checkTransactionProof(
          params.signature,
          params.txid,
          params.address,
          params.message
        );
        break;

      case "sign":
        this.sign(params.data);
        break;

      case "verify":
        this.verify(params.data, params.address, params.signature);
        break;

      case "add_address_book":
        this.addAddressBook(
          params.address,
          params.description,
          params.name,
          params.starred,
          params.hasOwnProperty("index") ? params.index : false
        );
        break;

      case "delete_address_book":
        this.deleteAddressBook(
          params.hasOwnProperty("index") ? params.index : false
        );
        break;

      case "save_tx_notes":
        this.saveTxNotes(params.txid, params.note);
        break;

      case "rescan_blockchain":
        this.rescanBlockchain(params || {});
        break;
      case "rescan_spent":
        this.rescanSpent();
        break;
      case "get_private_keys":
        this.getPrivateKeys(params.password);
        break;
      case "export_key_images":
        this.exportKeyImages(params.password, params.path);
        break;
      case "import_key_images":
        this.importKeyImages(params.password, params.path);
        break;

      case "change_wallet_password":
        this.changeWalletPassword(params.old_password, params.new_password);
        break;

      case "delete_wallet":
        this.deleteWallet(params.password);
        break;

      case "get_balance":
        this.getBalance("getbalance");
        break;

      case "set_router_path_rightpane":
        this.set_rightPane_value(params.data);
        break;

      case "set_sender_address":
        this.set_sender_address(params.data);
        break;

      case "deregister_images":
        this.deregisterImages(params.password);
        break;
      case "set_stepperPosition":
        this.set_stepperPosition(params.data);
        break;

      default:
    }
  }

  async getBalance(method) {
    this.getTransactions({ full: true }).then(wallet => {
      this.sendGateway("set_wallet_data", wallet);
    });
    const response = await this.sendRPC(method);
    if (response.error || method !== "getbalance") {
      return response;
    }

    let walletData = {
      info: {
        address: response.result.per_subaddress[0].address,
        balance: response.result.balance,
        unlocked_balance: response.result.unlocked_balance,
        view_only: this.wallet_state.view_only,
        load_balance: false
      }
    };
    this.sendGateway("set_wallet_data", walletData);
    return response;
  }

  derivePasswordHash(password, callback) {
    crypto.pbkdf2(
      password,
      this.auth[2],
      PASSWORD_HASH_PBKDF2_ITERATIONS,
      PASSWORD_HASH_KEY_LENGTH,
      PASSWORD_HASH_DIGEST,
      callback
    );
  }

  derivePasswordHashHex(password) {
    return new Promise((resolve, reject) => {
      this.derivePasswordHash(password, (err, hash) => {
        if (err) reject(err);
        else resolve(hash.toString("hex"));
      });
    });
  }

  isValidPasswordHash(password_hash) {
    if (this.wallet_state.password_hash === null) return true;
    const hash =
      typeof password_hash === "string"
        ? password_hash
        : password_hash.toString("hex");
    return this.wallet_state.password_hash === hash;
  }

  hasPassword() {
    if (this.wallet_state.password_hash === null) {
      this.sendGateway("set_has_password", false);
      return;
    }

    // We need to check if the hash generated with an empty string is the same as the password_hash we are storing
    this.derivePasswordHash("", (err, password_hash) => {
      if (err) {
        this.sendGateway("set_has_password", false);
        return;
      }

      // If the pass hash doesn't match empty string then we don't have a password
      this.sendGateway(
        "set_has_password",
        this.wallet_state.password_hash !== password_hash.toString("hex")
      );
    });
  }

  validateAddress(address) {
    this.sendRPC("validate_address", {
      address
    }).then(data => {
      if (data.hasOwnProperty("error")) {
        this.sendGateway("set_valid_address", {
          address,
          valid: false
        });
        return;
      }

      const { valid, nettype } = data.result;

      const netMatches = this.net_type === nettype;
      const isValid = valid && netMatches;

      this.sendGateway("set_valid_address", {
        address,
        valid: isValid,
        nettype
      });
    });
  }

  createWallet(filename, password, language) {
    // Reset the status error
    this.sendGateway("reset_wallet_error");
    this.sendRPC("create_wallet", {
      filename,
      password,
      language
    }).then(async data => {
      if (data.hasOwnProperty("error")) {
        this.sendGateway("set_wallet_error", { status: data.error });
        return;
      }

      // store hash of the password so we can check against it later when requesting private keys, or for sending txs
      this.wallet_state.password_hash = await this.derivePasswordHashHex(
        password
      );
      this.wallet_state.name = filename;
      this.wallet_state.open = true;

      this.finalizeNewWallet(filename);
    });
  }

  // the date should be in ms from epoch (Jan 1 1970)
  restoreWallet(
    filename,
    password,
    seed,
    refresh_type,
    refresh_start_timestamp_or_height
  ) {
    if (refresh_type == "date") {
      // Convert timestamp to 00:00 and move back a day
      // Core code also moved back some amount of blocks
      let timestamp = refresh_start_timestamp_or_height;
      timestamp = timestamp - (timestamp % 86400000) - 86400000;

      this.sendGateway("reset_wallet_error");
      this.backend.daemon.timestampToHeight(timestamp).then(height => {
        if (height === false) {
          this.sendGateway("set_wallet_error", {
            status: {
              code: -1,
              i18n: "notification.errors.invalidRestoreDate"
            }
          });
        } else {
          this.restoreWallet(filename, password, seed, "height", height);
        }
      });
      return;
    }
    let restore_height = Number.parseInt(refresh_start_timestamp_or_height);

    // if the height can't be parsed just start from block 0
    if (!restore_height) {
      restore_height = 0;
    }
    seed = seed.trim().replace(/\s{2,}/g, " ");

    this.sendGateway("reset_wallet_error");
    this.sendRPC("restore_deterministic_wallet", {
      filename,
      password,
      seed,
      restore_height
    }).then(async data => {
      if (data.hasOwnProperty("error")) {
        this.sendGateway("set_wallet_error", { status: data.error });
        return;
      }

      // store hash of the password so we can check against it later when requesting private keys, or for sending txs
      this.wallet_state.password_hash = await this.derivePasswordHashHex(
        password
      );
      this.wallet_state.name = filename;
      this.wallet_state.open = true;

      this.finalizeNewWallet(filename);
    });
  }

  restoreViewWallet(
    filename,
    password,
    address,
    viewkey,
    refresh_type,
    refresh_start_timestamp_or_height
  ) {
    if (refresh_type == "date") {
      // Convert timestamp to 00:00 and move back a day
      // Core code also moved back some amount of blocks
      let timestamp = refresh_start_timestamp_or_height;
      timestamp = timestamp - (timestamp % 86400000) - 86400000;

      this.backend.daemon.timestampToHeight(timestamp).then(height => {
        if (height === false) {
          this.sendGateway("set_wallet_error", {
            status: {
              code: -1,
              i18n: "notification.errors.invalidRestoreDate"
            }
          });
        } else {
          this.restoreViewWallet(
            filename,
            password,
            address,
            viewkey,
            "height",
            height
          );
        }
      });
      return;
    }

    let refresh_start_height = Number.parseInt(
      refresh_start_timestamp_or_height
    );

    // if the height can't be parsed just start from block 0
    if (!refresh_start_height) {
      refresh_start_height = 0;
    }

    this.sendRPC("restore_view_wallet", {
      filename,
      password,
      address,
      viewkey,
      refresh_start_height
    }).then(async data => {
      if (data.hasOwnProperty("error")) {
        this.sendGateway("set_wallet_error", { status: data.error });
        return;
      }

      // store hash of the password so we can check against it later when requesting private keys, or for sending txs
      this.wallet_state.password_hash = await this.derivePasswordHashHex(
        password
      );
      this.wallet_state.name = filename;
      this.wallet_state.open = true;

      this.finalizeNewWallet(filename);
    });
  }

  restoreWalletWithKeys(
    filename,
    password,
    address,
    viewkey,
    spendkey,
    refresh_type,
    refresh_start_timestamp_or_height
  ) {
    if (refresh_type == "date") {
      // Convert timestamp to 00:00 and move back a day
      // Core code also moved back some amount of blocks
      let timestamp = refresh_start_timestamp_or_height;
      timestamp = timestamp - (timestamp % 86400000) - 86400000;

      this.backend.daemon.timestampToHeight(timestamp).then(height => {
        if (height === false) {
          this.sendGateway("set_wallet_error", {
            status: {
              code: -1,
              i18n: "notification.errors.invalidRestoreDate"
            }
          });
        } else {
          this.restoreWalletWithKeys(
            filename,
            password,
            address,
            viewkey,
            spendkey,
            "height",
            height
          );
        }
      });
      return;
    }

    let restore_height = Number.parseInt(refresh_start_timestamp_or_height);

    // if the height can't be parsed just start from block 0
    if (!restore_height) {
      restore_height = 0;
    }
    this.sendRPC("generate_from_keys", {
      filename,
      password,
      address,
      viewkey,
      spendkey,
      restore_height
    }).then(async data => {
      if (data.hasOwnProperty("error")) {
        this.sendGateway("set_wallet_error", { status: data.error });
        return;
      }

      // store hash of the password so we can check against it later when requesting private keys, or for sending txs
      this.wallet_state.password_hash = await this.derivePasswordHashHex(
        password
      );
      this.wallet_state.name = filename;
      this.wallet_state.open = true;

      this.finalizeNewWallet(filename);
    });
  }

  importWallet(wallet_name, password, import_path) {
    // Reset the status error
    this.sendGateway("reset_wallet_error");

    // trim off suffix if exists
    if (import_path.endsWith(".keys")) {
      import_path = import_path.substring(
        0,
        import_path.length - ".keys".length
      );
    } else if (import_path.endsWith(".address.txt")) {
      import_path = import_path.substring(
        0,
        import_path.length - ".address.txt".length
      );
    }

    if (!fs.existsSync(import_path)) {
      this.sendGateway("set_wallet_error", {
        status: {
          code: -1,
          i18n: "notification.errors.invalidWalletPath"
        }
      });
      return;
    } else {
      let destination = path.join(this.wallet_dir, wallet_name);
      if (fs.existsSync(destination) || fs.existsSync(destination + ".keys")) {
        this.sendGateway("set_wallet_error", {
          status: {
            code: -1,
            i18n: "notification.errors.walletAlreadyExists"
          }
        });
        return;
      }

      try {
        fs.copySync(import_path, destination, { errorOnExist: true });
        if (fs.existsSync(import_path + ".keys")) {
          fs.copySync(import_path + ".keys", destination + ".keys", {
            errorOnExist: true
          });
        }
      } catch (e) {
        this.sendGateway("set_wallet_error", {
          status: {
            code: -1,
            i18n: "notification.errors.copyWalletFail"
          }
        });
        return;
      }
      this.sendRPC("open_wallet", {
        filename: wallet_name,
        password
      })
        .then(async data => {
          if (data.hasOwnProperty("error")) {
            if (fs.existsSync(destination)) fs.unlinkSync(destination);
            if (fs.existsSync(destination + ".keys"))
              fs.unlinkSync(destination + ".keys");
            this.sendGateway("set_wallet_error", {
              status: data.error
            });
            return;
          }
          // store hash of the password so we can check against it later when requesting private keys, or for sending txs
          this.wallet_state.password_hash = await this.derivePasswordHashHex(
            password
          );
          this.wallet_state.name = wallet_name;
          this.wallet_state.open = true;
          this.finalizeNewWallet(wallet_name);
        })
        .catch(() => {
          this.sendGateway("set_wallet_error", {
            status: {
              code: -1,
              i18n: "notification.errors.unknownError"
            }
          });
        });
    }
  }

  finalizeNewWallet(filename) {
    Promise.all([
      this.sendRPC("get_address"),
      this.sendRPC("getheight"),
      this.sendRPC("getbalance", { account_index: 0 }),
      this.sendRPC("query_key", { key_type: "mnemonic" }),
      this.sendRPC("query_key", { key_type: "spend_key" }),
      this.sendRPC("query_key", { key_type: "view_key" })
    ]).then(data => {
      let wallet = {
        info: {
          name: filename,
          address: "",
          balance: 0,
          unlocked_balance: 0,
          height: 0,
          view_only: false,
          load_balance: false
        },
        secret: {
          mnemonic: "",
          spend_key: "",
          view_key: ""
        }
      };
      for (let n of data) {
        if (n.hasOwnProperty("error") || !n.hasOwnProperty("result")) {
          if (n.params.key_type == "spend_key") {
            if (n.error?.code == -29) {
              wallet.info.view_only = true;
              this.wallet_state.view_only = true;
            }
          }
          continue;
        }
        if (n.method == "get_address") {
          wallet.info.address = n.result.address;
        } else if (n.method == "getheight") {
          wallet.info.height = n.result.height;
        } else if (n.method == "getbalance") {
          wallet.info.balance = n.result.balance;
          wallet.info.unlocked_balance = n.result.unlocked_balance;
        } else if (n.method == "query_key") {
          wallet.secret[n.params.key_type] = n.result.key;
          if (n.params.key_type == "spend_key") {
            if (/^0*$/.test(n.result.key)) {
              wallet.info.view_only = true;
              this.wallet_state.view_only = true;
            }
          }
        }
      }

      this.saveWallet().then(() => {
        let address_txt_path = path.join(
          this.wallet_dir,
          filename + ".address.txt"
        );
        if (!fs.existsSync(address_txt_path)) {
          fs.writeFile(address_txt_path, wallet.info.address, "utf8", () => {
            this.listWallets();
          });
        } else {
          this.listWallets();
        }
      });

      this.sendGateway("set_wallet_data", wallet);

      this.startHeartbeat();
    });
  }

  openWallet(filename, password) {
    this.sendGateway("reset_wallet_error");
    this.sendRPC("open_wallet", {
      filename,
      password
    }).then(async data => {
      if (data.hasOwnProperty("error")) {
        this.sendGateway("set_wallet_error", { status: data.error });
        return;
      }

      let address_txt_path = path.join(
        this.wallet_dir,
        filename + ".address.txt"
      );
      if (!fs.existsSync(address_txt_path)) {
        this.sendRPC("get_address", { account_index: 0 }).then(data => {
          if (data.hasOwnProperty("error") || !data.hasOwnProperty("result")) {
            return;
          }
          fs.writeFile(address_txt_path, data.result.address, "utf8", () => {
            this.listWallets();
          });
        });
      }

      // store hash of the password so we can check against it later when requesting private keys, or for sending txs
      this.wallet_state.password_hash = await this.derivePasswordHashHex(
        password
      );
      this.wallet_state.name = filename;
      this.wallet_state.open = true;

      this.startHeartbeat();

      this.purchasedNames = {};

      // Check if we have a view only wallet by querying the spend key
      this.sendRPC("query_key", { key_type: "spend_key" }).then(data => {
        if (data.hasOwnProperty("error") || !data.hasOwnProperty("result")) {
          if (data.params.key_type == "spend_key") {
            if (data.error?.code == -29) {
              // wallet.info.view_only = true;
              this.wallet_state.view_only = true;
              this.sendGateway("set_wallet_data", {
                info: {
                  view_only: true
                }
              });
            }
          }
          return;
        }
        if (/^0*$/.test(data.result.key)) {
          this.sendGateway("set_wallet_data", {
            info: {
              view_only: true
            }
          });
        }
      });
    });
  }

  startHeartbeat() {
    clearInterval(this.heartbeat);
    this.history_refresh_pending = true;
    this.startBnsHeartBeat();
    this.startSyncLoop();
  }

  // Sync design: wallet-rpc talks to the node through DaemonProxy and the app
  // drives every refresh itself (wallet-rpc's auto refresh is off). A scan
  // runs in chunks of SYNC_CHUNK_MS: the proxy then ends it, the app reads
  // height and balance, saves every SAVE_EVERY_MS, and starts the next chunk,
  // which carries on from the same block. Closing, switching or quitting ends
  // a scan at once and saves it, so progress is never lost. A user action
  // while a chunk runs ends that chunk early (see sendRPC).
  startSyncLoop() {
    const generation = ++this.syncGeneration;
    if (!this.rescanFrom) this.rescanFrom = this.readRescanFrom();
    this.syncLoopDone = this.syncLoop(generation).catch(e =>
      console.debug("Wallet sync loop failed: ", e)
    );
  }

  async syncLoop(generation) {
    const current = () =>
      generation === this.syncGeneration && this.wallet_state.open;
    // History from the wallet cache before scanning starts
    await this.heartbeatAction(true);
    let lastSave = Date.now();
    let savedHeight = this.wallet_state.height;
    let failures = 0;
    while (current()) {
      let chunkEnded = false;
      const chunk = setTimeout(() => {
        chunkEnded = true;
        this.proxy.pause();
      }, SYNC_CHUNK_MS);
      this.refreshing = true;
      const data = await this.sendRPC(
        "refresh",
        this.rescanFrom ? { start_height: this.rescanFrom } : {}
      );
      this.refreshing = false;
      clearTimeout(chunk);
      const interrupted = chunkEnded || this.proxy.paused;
      this.proxy.resume();
      if (generation !== this.syncGeneration) break;

      await this.heartbeatAction();
      if (!current()) break;

      const error = data.hasOwnProperty("error");
      const caughtUp = !error && !interrupted;
      if (caughtUp !== this.caughtUp) {
        this.caughtUp = caughtUp;
        this.isRPCSyncing = !caughtUp;
        this.sendGateway("set_wallet_data", { isRPCSyncing: !caughtUp });
        if (caughtUp) this.updateLocalBNSRecords();
      }
      // "Rescan from height" passes start_height until the wallet reaches it
      // (wallet2 skips blocks below the wallet's own restore height anyway)
      if (this.rescanFrom && this.wallet_state.height >= this.rescanFrom) {
        this.setRescanFrom(null);
      }
      // Save regularly while scanning (crash / power loss) and once caught up
      if (
        this.wallet_state.height > savedHeight &&
        (caughtUp || Date.now() - lastSave >= SAVE_EVERY_MS)
      ) {
        await this.sendRPC("store");
        lastSave = Date.now();
        savedHeight = this.wallet_state.height;
      }
      if (caughtUp) {
        failures = 0;
        await this.idle(IDLE_POLL_MS, generation);
      } else if (error && !interrupted) {
        // Node unreachable or busy: back off, but keep trying
        failures++;
        await this.idle(Math.min(30000, 2000 * failures), generation);
      }
    }
  }

  // Ends a running scan within a second and waits for the sync loop to exit.
  // Everything scanned so far stays in the wallet (the caller saves it).
  async stopSync() {
    this.syncGeneration++;
    this.wakeSync();
    const done = this.syncLoopDone;
    this.syncLoopDone = null;
    if (!done) return;
    if (this.proxy) this.proxy.pause();
    await Promise.race([done, new Promise(r => setTimeout(r, 20000))]);
    if (this.proxy) this.proxy.resume();
  }

  // An unfinished "rescan from height" is kept next to the wallet, so it
  // carries on after a restart (in either app: they share the wallet folder)
  rescanFromFile() {
    return path.join(this.wallet_dir, `${this.wallet_state.name}.rescan-from`);
  }

  readRescanFrom() {
    try {
      return (
        Number.parseInt(fs.readFileSync(this.rescanFromFile(), "utf8")) || null
      );
    } catch (e) {
      return null;
    }
  }

  setRescanFrom(height) {
    this.rescanFrom = height;
    try {
      if (height) fs.writeFileSync(this.rescanFromFile(), String(height));
      else fs.removeSync(this.rescanFromFile());
    } catch (e) {
      // Only matters if the app is closed mid-rescan
    }
  }

  // Starts the next refresh now instead of after the idle wait
  wakeSync() {
    const wake = this.syncWake;
    this.syncWake = null;
    if (wake) wake();
  }

  idle(ms, generation) {
    if (generation !== this.syncGeneration) return Promise.resolve();
    return new Promise(resolve => {
      const wake = () => {
        clearTimeout(timer);
        resolve();
      };
      const timer = setTimeout(() => {
        if (this.syncWake === wake) this.syncWake = null;
        resolve();
      }, ms);
      this.syncWake = wake;
    });
  }

  // Live scan progress from the block responses the proxy sees
  onScanProgress({ height }) {
    if (!this.wallet_state.open || height <= this.wallet_state.height) return;
    this.wallet_state.height = height;
    if (Date.now() - this.last_progress_send_time > 500) {
      this.last_progress_send_time = Date.now();
      this.sendGateway("set_wallet_data", { info: { height } });
    }
  }

  startBnsHeartBeat() {
    clearInterval(this.bnsHeartbeat);
    this.bnsHeartbeat = setInterval(() => {
      // BNS lookups compete with the wallet refresh for wallet-rpc, so they
      // wait until the wallet has caught up with the chain.
      if (!this.isWalletSyncing()) this.updateLocalBNSRecords();
    }, 80000);

    this.updateLocalBNSRecords();
  }

  // True until the wallet has caught up with the node
  isWalletSyncing() {
    return this.wallet_state.open && !this.caughtUp;
  }

  // The heartbeat only polls cheap calls. Transaction history, subaddresses
  // and the address book are refreshed when the balance changes, and while
  // the wallet is syncing that work is deferred (at most once a minute) so
  // wallet-rpc can spend its time scanning blocks, like the CLI wallet does.
  heartbeatAction(extended = false) {
    if (this.heartbeat_in_flight && !extended) return Promise.resolve();
    this.heartbeat_in_flight = true;

    const calls = [
      this.sendRPC("getheight", {}, 5000),
      this.sendRPC("getbalance", { account_index: 0 }, 5000)
    ];
    if (extended || !this.wallet_state.address) {
      calls.push(this.sendRPC("get_address", { account_index: 0 }, 5000));
    }

    return Promise.all(calls)
      .then(data => {
        let didError = false;
        const info = {};
        let balanceChanged = false;

        for (let n of data) {
          if (n.hasOwnProperty("error") || !n.hasOwnProperty("result")) {
            // Error -13: No wallet file - This occurs when you call open wallet while another wallet is still syncing
            if (extended && n.error && n.error.code === -13) {
              didError = true;
            }
            continue;
          }

          if (n.method == "getheight") {
            if (n.result.height !== this.wallet_state.height) {
              this.wallet_state.height = info.height = n.result.height;
            }
          } else if (n.method == "get_address") {
            if (n.result.address !== this.wallet_state.address) {
              this.wallet_state.address = info.address = n.result.address;
            }
          } else if (n.method == "getbalance") {
            if (
              this.wallet_state.balance !== n.result.balance ||
              this.wallet_state.unlocked_balance !== n.result.unlocked_balance
            ) {
              this.wallet_state.balance = info.balance = n.result.balance;
              this.wallet_state.unlocked_balance = info.unlocked_balance =
                n.result.unlocked_balance;
              balanceChanged = true;
            }
          }
        }

        if (extended) {
          if (didError) {
            this.heartbeat_in_flight = false;
            this.closeWallet().then(() => {
              this.sendGateway("set_wallet_error", {
                status: {
                  code: -1,
                  i18n: "notification.errors.failedWalletOpen"
                }
              });
            });
            return;
          }

          // Initial state for the opened wallet
          this.sendGateway("set_wallet_data", {
            status: {
              code: 0,
              message: "OK"
            },
            info: {
              name: this.wallet_state.name,
              ...info
            },
            transactions: {
              tx_list: []
            },
            address_list: {
              primary: [],
              used: [],
              unused: [],
              address_book: [],
              address_book_starred: []
            }
          });
        } else if (Object.keys(info).length > 0) {
          this.sendGateway("set_wallet_data", { info });
        }

        if (balanceChanged || extended) {
          this.history_refresh_pending = true;
        }

        const refreshDue =
          extended ||
          !this.isWalletSyncing() ||
          Date.now() - this.last_history_refresh_time > 60000;
        if (this.history_refresh_pending && refreshDue) {
          this.history_refresh_pending = false;
          return this.refreshWalletLists();
        }
      })
      .catch(e => {
        console.debug("Wallet heartbeat failed: ", e);
      })
      .finally(() => {
        this.heartbeat_in_flight = false;
      });
  }

  async refreshWalletLists() {
    this.last_history_refresh_time = Date.now();
    const parts = await Promise.all([
      this.getTransactions(),
      this.getAddressList(),
      this.getAddressBook()
    ]);

    const payload = {};
    for (const part of parts) {
      for (const key of Object.keys(part || {})) {
        payload[key] = Object.assign(payload[key] || {}, part[key]);
      }
    }
    if (Object.keys(payload).length > 0) {
      this.sendGateway("set_wallet_data", payload);
    }
  }

  async updateLocalBNSRecords() {
    try {
      const addressData = await this.sendRPC(
        "get_address",
        { account_index: 0 },
        0,
        { background: true }
      );
      if (
        addressData.hasOwnProperty("error") ||
        !addressData.hasOwnProperty("result")
      ) {
        return;
      }

      // Pull out all our addresses from the data and make sure they're valid
      const results = addressData.result.addresses || [];
      const addresses = results.map(a => a.address).filter(a => !!a);
      if (addresses.length === 0) return;
      const records = await this.backend.daemon.getBNSRecordsForOwners(
        addresses
      );
      // We need to ensure that we decrypt any incoming records that we already have
      const currentRecords = this.wallet_state.bnsRecords;
      const recordsToUpdate = { ...this.purchasedNames };
      const newRecords = records.map(record => {
        // If we have a new record or we haven't decrypted our current record then we should return the new record
        const current = currentRecords.find(
          c => c.name_hash === record.name_hash
        );
        if (!current || !current.name) return record;

        // We need to check if we need to re-decrypt the record.
        // This is only necessary if the encrypted_value changed.
        const needsToUpdate =
          current.encrypted_value !== record.encrypted_value;
        if (needsToUpdate) {
          const { name, type } = current;
          recordsToUpdate[name] = type;
          return {
            name,
            ...record
          };
        }
        // Otherwise just update our current record with new information (in the case that owner or backup_owner was updated)
        return {
          ...current,
          ...record
        };
      });
      this.wallet_state.bnsRecords = newRecords;
      // fetch the known (cached) records from the wallet and add the data
      // to the records being set in state
      let known_names = await this.bnsKnownNames({ background: true });
      for (let r of newRecords) {
        for (let k of known_names) {
          if (k.hashed === r.name_hash) {
            r["name"] = k.name;
            r["expiration_height"] = k.expiration_height;
            k["name_hash"] = k.hashed;
            r["name_hash"] = k.hashed;
            r["value_wallet"] = k.value_wallet ? k.value_wallet : "";
            r["value_bchat"] = k.value_bchat ? k.value_bchat : "";
            r["value_belnet"] = k.value_belnet ? k.value_belnet : "";
            r["value_eth_addr"] = k.value_eth_addr ? k.value_eth_addr : "";
          }
        }
      }
      this.sendGateway("set_wallet_data", { bnsRecords: newRecords });
    } catch (e) {
      console.debug("Something went wrong when updating bns records: ", e);
    }
  }

  /*
  Get the BNS records cached in this wallet. 
  */
  async bnsKnownNames(options = {}) {
    try {
      let params = {
        decrypt: true,
        include_expired: false
      };
      let data = await this.sendRPC("bns_known_names", params, 0, options);
      if (data.result && data.result.known_names) {
        return data.result.known_names;
      } else {
        return [];
      }
    } catch (e) {
      console.debug("There was an error getting known records: " + e);
      return [];
    }
  }

  /*
  Renews an BNS (Belnet) mapping, since they can expire
  type can be:
  belnet_1y, belnet_2y, belnet_5y, belnet_10y
  */
  bnsRenewMapping(password, years, name) {
    let _name = name.trim().toLowerCase();

    // the RPC accepts names with the .bdx already appeneded only
    // can be belnet_1y, belnet_2y, belnet_5y, belnet_10y
    // if (type.startsWith("belnet")) {
    //   _name = _name + ".bdx";
    // }

    this.derivePasswordHash(password, (err, password_hash) => {
      if (err) {
        this.sendGateway("set_bns_status", {
          code: -1,
          i18n: "notification.errors.internalError",
          sending: false
        });
        return;
      }
      if (!this.isValidPasswordHash(password_hash)) {
        this.sendGateway("set_bns_status", {
          code: -1,
          i18n: "notification.errors.invalidPassword",
          sending: false
        });
        return;
      }
      const params = {
        years,
        name: _name
      };
      this.sendRPC("bns_renew_mapping", params).then(data => {
        if (data.hasOwnProperty("error")) {
          let error =
            data.error.message.charAt(0).toUpperCase() +
            data.error.message.slice(1);
          this.sendGateway("set_bns_status", {
            code: -1,
            message: error,
            sending: false
          });
          return;
        }

        // this.purchasedNames[name.trim()] = type;

        setTimeout(() => this.updateLocalBNSRecords(), 5000);

        this.sendGateway("set_bns_status", {
          code: 0,
          i18n: "notification.positive.nameRenewed",
          message: "notification.positive.nameRenewed",
          sending: false
        });
      });
    });
  }

  /*
  Get our BNS record and update our wallet state with decrypted values.
  This will return `null` if the record is not in our currently stored records.
  */
  async decryptBNSRecord(type, name) {
    let _type = type;
    try {
      const record = await this.getBNSRecord(_type, name);
      if (!record) return null;

      // Update our current records with the new decrypted record
      const currentRecords = this.wallet_state.bnsRecords;
      const isOurRecord = currentRecords.find(
        c => c.name_hash === record.name_hash
      );
      if (!isOurRecord) {
        return null;
      } else {
        // if it's our record, we can cache it
        const _record = {
          name: record.name
        };
        const params = {
          names: [_record]
        };
        this.sendRPC("bns_add_known_names", params);
      }

      const newRecords = currentRecords.map(current => {
        if (current.name_hash === record.name_hash) {
          return record;
        }
        return current;
      });
      this.wallet_state.bnsRecords = newRecords;
      this.sendGateway("set_wallet_data", { bnsRecords: newRecords });
      return record;
    } catch (e) {
      console.debug("Something went wrong decrypting bns record: ", e);
      return null;
    }
  }

  /*
  Get a BNS record associated with the given name
  */
  async getBNSRecord(type, name) {
    if (!name || name.trim().length === 0) return null;

    const lowerCaseName = name.toLowerCase();

    let fullName = lowerCaseName;
    if (!name.endsWith(".bdx")) {
      fullName = fullName + ".bdx";
    }
    const nameHash = await this.hashBNSName(fullName);
    if (!nameHash) return null;

    const record = await this.backend.daemon.getBNSRecord(nameHash);
    if (!record) return null;
    return {
      name: fullName,
      // [key]: value,
      ...record
    };
    // Decrypt the value if possible
    // let encryptedValue;
    // let key;
    // if (record.encrypted_bchat_value) {
    //   encryptedValue = record.encrypted_bchat_value;
    //   key = "value_bchat";
    //   type = "bchat";
    // } else if (record.encrypted_belnet_value) {
    //   encryptedValue = record.encrypted_belnet_value;
    //   key = "value_belnet";
    //   type = "belnet";
    // } else {
    //   encryptedValue = record.encrypted_wallet_value;
    //   key = "value_wallet";
    //   type = "wallet";
    // }
    // const value = await this.decryptBNSValue(type, fullName, encryptedValue);
    // return {
    //   name: fullName,
    //   [key]: value,
    //   ...record
    // };
  }

  async hashBNSName(fullName) {
    if (!fullName) return null;
    if (!fullName.endsWith(".bdx")) {
      fullName = fullName + ".bdx";
    }

    try {
      const data = await this.sendRPC("bns_hash_name", {
        name: fullName
      });
      if (data.hasOwnProperty("error")) {
        let error =
          data.error.message.charAt(0).toUpperCase() +
          data.error.message.slice(1);
        throw new Error(error);
      }

      return (data.result && data.result.name) || null;
    } catch (e) {
      console.debug("Failed to hash bns name: ", e);
      return null;
    }
  }

  async decryptBNSValue(type, name, encrypted_value) {
    if (!type || !name || !encrypted_value) return null;

    let fullName = name;
    if (type === "belnet" && !name.endsWith(".bdx")) {
      fullName = fullName + ".bdx";
    }

    try {
      const data = await this.sendRPC("bns_decrypt_value", {
        type,
        name: fullName,
        encrypted_value
      });
      if (data.hasOwnProperty("error")) {
        let error =
          data.error.message.charAt(0).toUpperCase() +
          data.error.message.slice(1);
        throw new Error(error);
      }

      return (data.result && data.result.value) || null;
    } catch (e) {
      console.debug("Failed to decrypt bns value: ", e);
      return null;
    }
  }

  async sign(data) {
    // set to loading
    this.sendGateway("set_sign_status", {
      code: 0,
      sending: true
    });
    try {
      const rpcData = await this.sendRPC("sign", { data });
      if (
        !rpcData ||
        rpcData.hasOwnProperty("error") ||
        !rpcData.hasOwnProperty("result")
      ) {
        const error = rpcData?.error?.message || "Unknown error";
        this.sendGateway("set_sign_status", {
          code: -1,
          message: error,
          sending: false
        });

        return;
      }
      const signature = rpcData.result.signature;

      this.sendGateway("set_sign_status", {
        code: 1,
        sending: false,
        signature: signature
      });
      return;
    } catch (err) {
      console.debug(`Failed to sign data: ${data} with error: ${err}`);
      this.sendGateway("set_sign_status", {
        code: -1,
        message: err,
        sending: false
      });
    }
  }

  async verify(data, address, signature) {
    this.sendGateway("set_verify_status", {
      code: 0,
      sending: true
    });
    try {
      const rpcData = await this.sendRPC("verify", {
        data,
        address,
        signature
      });
      if (
        !rpcData ||
        rpcData.hasOwnProperty("error") ||
        !rpcData.hasOwnProperty("result")
      ) {
        let errorI18n = "";
        const error = rpcData.error.message || "Unknown error";
        if (error && error.includes("Invalid address")) {
          errorI18n = "notification.errors.invalidAddress";
        }
        this.sendGateway("set_verify_status", {
          code: -1,
          message: "",
          i18n: errorI18n || "Unknown error",
          sending: false
        });
        return;
      }
      const good = rpcData.result.good;
      if (good) {
        // success
        this.sendGateway("set_verify_status", {
          code: 1,
          sending: false,
          i18n: "notification.positive.signatureVerified",
          message: ""
        });
      } else {
        // error
        this.sendGateway("set_verify_status", {
          code: -1,
          sending: false,
          i18n: "notification.errors.invalidSignature",
          message: ""
        });
      }

      return;
    } catch (err) {
      this.sendGateway("set_verify_status", {
        code: -1,
        message: err.toString(),
        i18n: "",
        sending: false
      });
    }
  }

  stake(password, amount, master_node_key, destination) {
    this.derivePasswordHash(password, (err, password_hash) => {
      if (err) {
        this.sendGateway("set_mnode_status", {
          stake: {
            code: -1,
            i18n: "notification.errors.internalError",
            sending: false
          }
        });
        return;
      }
      if (!this.isValidPasswordHash(password_hash)) {
        this.sendGateway("set_mnode_status", {
          stake: {
            code: -1,
            i18n: "notification.errors.invalidPassword",
            sending: false
          }
        });
        return;
      }

      amount = (parseFloat(amount) * 1e9).toFixed(0);

      this.sendRPC("stake", {
        amount,
        destination,
        master_node_key
      }).then(data => {
        if (data.hasOwnProperty("error")) {
          let error =
            data.error.message.charAt(0).toUpperCase() +
            data.error.message.slice(1);
          this.sendGateway("set_mnode_status", {
            stake: {
              code: -1,
              message: error,
              sending: false
            }
          });
          return;
        }

        // Update the new mnode list
        this.backend.daemon.updateMasterNodes();

        this.sendGateway("set_mnode_status", {
          stake: {
            code: 0,
            i18n: "notification.positive.stakeSuccess",
            sending: false
          }
        });
      });
    });
  }

  registerMnode(password, register_master_node_str) {
    this.derivePasswordHash(password, (err, password_hash) => {
      if (err) {
        this.sendGateway("set_mnode_status", {
          registration: {
            code: -1,
            i18n: "notification.errors.internalError",
            sending: false
          }
        });
        return;
      }

      if (!this.isValidPasswordHash(password_hash)) {
        this.sendGateway("set_mnode_status", {
          registration: {
            code: -1,
            i18n: "notification.errors.invalidPassword",
            sending: false
          }
        });
        return;
      }

      this.sendRPC("register_master_node", {
        register_master_node_str
      }).then(data => {
        if (data.hasOwnProperty("error")) {
          const error =
            data.error.message.charAt(0).toUpperCase() +
            data.error.message.slice(1);
          this.sendGateway("set_mnode_status", {
            registration: {
              code: -1,
              message: error,
              sending: false
            }
          });
          return;
        }

        // Update the new mnode list
        this.backend.daemon.updateMasterNodes();

        this.sendGateway("set_mnode_status", {
          registration: {
            code: 0,
            i18n: "notification.positive.registerMasterNodeSuccess",
            sending: false
          }
        });
      });
    });
  }

  async updateMasterNodeList() {
    this.backend.daemon.updateMasterNodes();
  }

  unlockStake(password, master_node_key, confirmed = false) {
    const sendError = (message, i18n = true) => {
      const key = i18n ? "i18n" : "message";
      this.sendGateway("set_mnode_status", {
        unlock: {
          code: -1,
          [key]: message,
          sending: false
        }
      });
    };

    // Unlock code 0 means success, 1 means can unlock, -1 means error
    this.derivePasswordHash(password, (err, password_hash) => {
      if (err) {
        sendError("notification.errors.internalError");
        return;
      }

      if (!this.isValidPasswordHash(password_hash)) {
        sendError("notification.errors.invalidPassword");
        return;
      }

      const sendRPC = path => {
        return this.sendRPC(path, {
          master_node_key
        }).then(data => {
          if (data.hasOwnProperty("error")) {
            const error =
              data.error.message.charAt(0).toUpperCase() +
              data.error.message.slice(1);
            sendError(error, false);
            return null;
          }

          if (!data.hasOwnProperty("result")) {
            sendError("notification.errors.failedMasterNodeUnlock");
            return null;
          }

          return data.result;
        });
      };

      if (confirmed) {
        sendRPC("request_stake_unlock").then(data => {
          if (!data) return;

          const unlock = {
            code: data.unlocked ? 0 : -1,
            message: data.msg,
            sending: false
          };

          // Update the new mnode list
          if (data.unlocked) {
            this.backend.daemon.updateMasterNodes();
          }

          this.sendGateway("set_mnode_status", { unlock });
        });
      } else {
        sendRPC("can_request_stake_unlock").then(data => {
          if (!data) return;

          const unlock = {
            code: data.can_unlock ? 1 : -1,
            message: data.msg,
            sending: false
          };

          this.sendGateway("set_mnode_status", { unlock });
        });
      }
    });
  }

  // submits the transaction to the blockchain, irreversible from here
  async relayTransaction(isflash, addressSave, note, isSweepAll) {
    // for a sweep these don't exist
    let address = "";
    let address_book = "";
    if (addressSave) {
      address = addressSave.address;
      address_book = addressSave.address_book;
    }

    let failed = false;
    let errorMessage = "Failed to relay transaction";

    // submit each transaction individually
    for (let hex of this.pending_tx.metadataList) {
      const params = {
        hex,
        flash: isflash
      };

      // don't try submit more txs if a prev one failed
      if (failed) break;
      try {
        let data = await this.sendRPC("relay_tx", params);
        if (data.hasOwnProperty("error")) {
          errorMessage = data.error.message || errorMessage;
          failed = true;
          break;
        } else if (data.hasOwnProperty("result")) {
          const tx_hash = data.result.tx_hash;
          if (note && note !== "") {
            this.saveTxNotes(tx_hash, note);
          }
        } else {
          errorMessage = "Invalid format of relay_tx RPC return message";
          failed = true;
          break;
        }
      } catch (e) {
        failed = true;
        errorMessage = e.toString();
      }
    }

    // for updating state on the correct page
    const gatewayEndpoint = isSweepAll
      ? "set_sweep_all_status"
      : "set_tx_status";

    if (!failed) {
      this.sendGateway(gatewayEndpoint, {
        code: 0,
        i18n: "notification.positive.sendSuccess",
        sending: false
      });

      if (address_book.hasOwnProperty("save") && address_book.save) {
        this.addAddressBook(
          address,
          address_book.description,
          address_book.name
        );
      }
      // no more pending txs, clear it out.
      this.pending_tx = null;
      return;
    }

    // no more pending txs, clear it out.
    this.pending_tx = null;
    this.sendGateway(gatewayEndpoint, {
      code: -1,
      message: errorMessage,
      sending: false
    });
  }

  // prepares params and provides a "confirm" popup to allow the user to check
  // send address and tx fees before sending
  // isSweepAll refers to if it's the sweep from master nodes page
  transfer(password, amount, address, priority, isSweepAll) {
    const cryptoCallback = (err, password_hash) => {
      if (err) {
        this.sendGateway("set_tx_status", {
          code: -1,
          i18n: "notification.errors.internalError",
          sending: false
        });
        return;
      }
      if (!this.isValidPasswordHash(password_hash)) {
        this.sendGateway("set_tx_status", {
          code: -1,
          i18n: "notification.errors.invalidPassword",
          sending: false
        });
        return;
      }

      amount = (parseFloat(amount) * 1e9).toFixed(0);

      const isSweepAllRPC = amount == this.wallet_state.unlocked_balance;
      const rpc_endpoint = isSweepAllRPC ? "sweep_all" : "transfer_split";

      // the call coming from the SN page will have address = wallet primary address
      const rpcSpecificParams = isSweepAllRPC
        ? {
            address,
            // gui wallet only supports one account currently
            account_index: 0,
            // sweep *all* funds from all subaddresses to the address specified
            subaddr_indices_all: true
          }
        : {
            destinations: [{ amount: amount, address: address }]
          };
      const params = {
        ...rpcSpecificParams,
        priority,
        do_not_relay: true,
        get_tx_metadata: true
      };

      // for updating state on the correct page
      const gatewayEndpoint = isSweepAll
        ? "set_sweep_all_status"
        : "set_tx_status";

      this.sendRPC(rpc_endpoint, params)
        .then(data => {
          if (data.hasOwnProperty("error") || !data.hasOwnProperty("result")) {
            let error = "";
            if (data.error && data.error.message) {
              error =
                data.error.message.charAt(0).toUpperCase() +
                data.error.message.slice(1);
            } else {
              error = `Incorrect result from ${rpc_endpoint} RPC call`;
            }
            this.sendGateway(gatewayEndpoint, {
              code: -1,
              message: error,
              sending: false
            });
            return;
          }

          this.pending_tx = {
            metadataList: data.result.tx_metadata_list
          };

          // async relayTransaction(metadataList, isflash, addressSave, note, isSweepAll)
          // update state to show a confirm popup
          this.sendGateway(gatewayEndpoint, {
            code: 1,
            i18n: "strings.awaitingConfirmation",
            sending: false,
            txData: {
              // target address for a sweep all
              address: data.params.address,
              isSweepAll: isSweepAllRPC,
              amountList: data.result.amount_list,
              feeList: data.result.fee_list,
              priority: data.params.priority,
              // for a "send" tx
              destinations: data.params.destinations
            }
          });
        })
        .catch(err => {
          this.sendGateway(gatewayEndpoint, {
            code: -1,
            message: err.message,
            sending: false
          });
        });
    };

    this.derivePasswordHash(password, cryptoCallback);
  }

  purchaseBNS(
    years,
    password,
    name,
    value,
    owner,
    backupOwner,
    bchatId,
    belnetId,
    walletAddress,
    ethAddress
  ) {
    let _name = name.trim().toLowerCase();
    const _owner = owner.trim() === "" ? null : owner;
    const backup_owner = backupOwner.trim() === "" ? null : backupOwner;

    // the RPC accepts names with the .bdx already appeneded only
    // can be belnet_1y, belnet_2y, belnet_5y, belnet_10y
    // if (type.startsWith("belnet")) {
    //   _name = _name + ".bdx";

    //   value = value + ".bdx";
    // }

    this.derivePasswordHash(password, (err, password_hash) => {
      if (err) {
        this.sendGateway("set_bns_status", {
          code: -1,
          i18n: "notification.errors.internalError",
          sending: false
        });
        return;
      }
      if (!this.isValidPasswordHash(password_hash)) {
        this.sendGateway("set_bns_status", {
          code: -1,
          i18n: "notification.errors.invalidPassword",
          sending: false
        });
        return;
      }

      const params = {
        years: years,
        owner: _owner,
        backup_owner: backup_owner,
        name: _name,
        value_bchat: bchatId,

        value_belnet: belnetId,
        value_wallet: walletAddress,
        value_eth_addr: ethAddress
      };
      this.sendRPC("bns_buy_mapping", params).then(data => {
        if (data.hasOwnProperty("error")) {
          let error =
            data.error.message.charAt(0).toUpperCase() +
            data.error.message.slice(1);
          if (
            error.includes("Cannot buy an BNS name that is already registered")
          ) {
            error = "Cannot buy a BNS name that is already registered";
          }
          if (error.includes("Transaction is too big")) {
            error =
              "Transaction is too big, please do the sweep_all from [masternode -> stakings]";
          }
          this.sendGateway("set_bns_status", {
            code: -1,
            message: error,
            sending: false
          });
          return;
        }
        this.purchasedNames[name.trim()] = years;

        // Fetch new records and then get the decrypted record for the one we just inserted
        setTimeout(() => this.updateLocalBNSRecords(), 5000);

        this.sendGateway("set_bns_status", {
          code: 0,
          i18n: "notification.positive.namePurchased",
          sending: false
        });
      });
    });
  }

  updateBNSMapping(
    password,
    name,
    owner,
    backupOwner,
    value_bchat,
    value_belnet,
    value_wallet,
    value_eth_addr
  ) {
    // let _name = name.trim().toLowerCase();
    // const _owner = owner.trim() === "" ? null : owner;
    // const _owner = null

    // const backup_owner = backupOwner.trim() === "" ? null : backupOwner;

    // updated records have type "belnet" or "bchat"
    // UI passes the values without the extension
    // if (type === "belnet") {
    //   _name = _name + ".bdx";
    //   value = value + ".bdx";
    // }

    this.derivePasswordHash(password, (err, password_hash) => {
      if (err) {
        this.sendGateway("set_bns_status", {
          code: -1,
          i18n: "notification.errors.internalError",
          sending: false
        });
        return;
      }
      if (!this.isValidPasswordHash(password_hash)) {
        this.sendGateway("set_bns_status", {
          code: -1,
          i18n: "notification.errors.invalidPassword",
          sending: false
        });
        return;
      }

      let params = {
        name
      };
      if (owner) {
        params.owner = owner;
      }
      if (backupOwner) {
        params.backup_owner = backupOwner;
      }
      if (value_bchat) {
        params.value_bchat = value_bchat;
      }
      if (value_belnet) {
        params.value_belnet = value_belnet;
      }
      if (value_wallet) {
        params.value_wallet = value_wallet;
      }
      if (value_eth_addr) {
        params.value_eth_addr = value_eth_addr;
      }
      this.sendRPC("bns_update_mapping", params).then(data => {
        if (data.hasOwnProperty("error")) {
          let error =
            data.error.message.charAt(0).toUpperCase() +
            data.error.message.slice(1);
          if (
            error.includes("Cannot buy an BNS name that is already registered")
          ) {
            error = "Cannot buy an BNS name that is already registered";
          }
          this.sendGateway("set_bns_status", {
            code: -1,
            message: error,
            sending: false
          });
          return;
        }

        // this.purchasedNames[name.trim()] = type;

        // Fetch new records and then get the decrypted record for the one we just inserted
        setTimeout(() => this.startBnsHeartBeat(), 5000);

        // Optimistically update our record
        const { bnsRecords } = this.wallet_state;
        const newRecords = bnsRecords.map(record => {
          if (
            // record.type === type &&
            record.name &&
            record.name.toLowerCase() === name
          ) {
            return {
              ...record,
              ...params
            };
          }

          return record;
        });
        this.wallet_state.bnsRecords = newRecords;
        this.sendGateway("set_wallet_data", { bnsRecords: newRecords });

        this.sendGateway("set_bns_status", {
          code: 0,
          i18n: "notification.positive.bnsRecordUpdated",
          sending: false,
          message: "notification.positive.bnsRecordUpdated"
        });
      });
    });
  }

  proveTransaction(txid, address, message) {
    const _address = address.trim() === "" ? null : address;
    const _message = message.trim() === "" ? null : message;

    const rpc_endpoint = _address ? "get_tx_proof" : "get_spend_proof";
    const params = {
      txid,
      address: _address,
      message: _message
    };

    this.sendGateway("set_prove_transaction_status", {
      code: 1,
      message: "",
      state: {}
    });

    this.sendRPC(rpc_endpoint, params).then(data => {
      if (data.hasOwnProperty("error")) {
        let error =
          data.error.message.charAt(0).toUpperCase() +
          data.error.message.slice(1);
        this.sendGateway("set_prove_transaction_status", {
          code: -1,
          message: error,
          state: {}
        });
        return;
      }

      this.sendGateway("set_prove_transaction_status", {
        code: 0,
        message: "",
        state: {
          txid,
          ...(data.result || {})
        }
      });
    });
  }

  checkTransactionProof(signature, txid, address, message) {
    const _address = address.trim() === "" ? null : address;
    const _message = message.trim() === "" ? null : message;

    const rpc_endpoint = _address ? "check_tx_proof" : "check_spend_proof";
    const params = {
      txid,
      signature,
      address: _address,
      message: _message
    };

    this.sendGateway("set_check_transaction_status", {
      code: 1,
      message: "",
      state: {}
    });

    this.sendRPC(rpc_endpoint, params).then(data => {
      if (data.hasOwnProperty("error")) {
        let error =
          data.error.message.charAt(0).toUpperCase() +
          data.error.message.slice(1);
        this.sendGateway("set_check_transaction_status", {
          code: -1,
          message: error,
          state: {}
        });
        return;
      }

      this.sendGateway("set_check_transaction_status", {
        code: 0,
        message: "",
        state: {
          txid,
          ...(data.result || {})
        }
      });
    });
  }

  // Rescans from the restore height, or from params.from_height /
  // params.from_timestamp (ms): blocks below it are skipped, which is much
  // faster when you know roughly when the funds arrived. Runs in the sync
  // loop, so it shows progress and survives closing the wallet.
  async rescanBlockchain(params = {}) {
    let fromHeight = Number.parseInt(params.from_height) || null;
    if (!fromHeight && params.from_timestamp) {
      const day = 86400000;
      const timestamp =
        params.from_timestamp - (params.from_timestamp % day) - day;
      const height = await this.backend.daemon.timestampToHeight(timestamp);
      if (height === false) {
        this.sendGateway("show_notification", {
          type: "negative",
          i18n: "notification.errors.invalidRestoreDate",
          timeout: 3000
        });
        return;
      }
      fromHeight = height;
    }
    await this.stopSync();
    clearInterval(this.bnsHeartbeat);
    this.wallet_state.balance = null;
    this.wallet_state.unlocked_balance = null;
    this.wallet_state.height = 0;
    this.resetTxCache();
    // rescan_blockchain clears the wallet and then refreshes inline; with
    // block sync paused that refresh ends at once and the loop takes over.
    this.proxy.pause();
    await this.sendRPC("rescan_blockchain", { hard: false });
    this.proxy.resume();
    this.caughtUp = false;
    this.setRescanFrom(fromHeight);
    this.startHeartbeat();
  }

  rescanSpent() {
    this.sendRPC("rescan_spent");
  }

  getPrivateKeys(password) {
    this.derivePasswordHash(password, (err, password_hash) => {
      if (err) {
        this.sendGateway("set_wallet_data", {
          secret: {
            mnemonic: "notification.errors.internalError",
            spend_key: -1,
            view_key: -1
          }
        });
        return;
      }
      if (!this.isValidPasswordHash(password_hash)) {
        this.sendGateway("set_wallet_data", {
          secret: {
            mnemonic: "notification.errors.invalidPassword",
            spend_key: -1,
            view_key: -1
          }
        });
        return;
      }
      Promise.all([
        this.sendRPC("query_key", { key_type: "mnemonic" }),
        this.sendRPC("query_key", { key_type: "spend_key" }),
        this.sendRPC("query_key", { key_type: "view_key" })
      ]).then(data => {
        let wallet = {
          secret: {
            mnemonic: "",
            spend_key: "",
            view_key: ""
          }
        };
        for (let n of data) {
          if (n.hasOwnProperty("error") || !n.hasOwnProperty("result")) {
            continue;
          }
          wallet.secret[n.params.key_type] = n.result.key;
        }

        this.sendGateway("set_wallet_data", wallet);
      });
    });
  }

  async getAddressList() {
    const [addressData, balanceData] = await Promise.all([
      this.sendRPC("get_address", { account_index: 0 }),
      this.sendRPC("getbalance", { account_index: 0 })
    ]);
    for (const n of [addressData, balanceData]) {
      if (n.hasOwnProperty("error") || !n.hasOwnProperty("result")) {
        return {};
      }
    }

    const num_unused_addresses = 10;
    const address_list = {
      primary: [],
      used: [],
      unused: []
    };

    const perSubaddress = new Map();
    for (const address_balance of balanceData.result.per_subaddress || []) {
      perSubaddress.set(address_balance.address_index, address_balance);
    }

    for (let address of addressData.result.addresses) {
      const address_balance = perSubaddress.get(address.address_index);
      address.balance = address_balance ? address_balance.balance : null;
      address.unlocked_balance = address_balance
        ? address_balance.unlocked_balance
        : null;
      address.num_unspent_outputs = address_balance
        ? address_balance.num_unspent_outputs
        : null;

      if (address.address_index == 0) {
        address_list.primary.push(address);
      } else if (address.used) {
        address_list.used.push(address);
      } else {
        address_list.unused.push(address);
      }
    }

    // limit to 10 unused addresses, topping up if needed
    address_list.unused = address_list.unused.slice(0, num_unused_addresses);
    while (address_list.unused.length < num_unused_addresses) {
      const created = await this.sendRPC("create_address", {
        account_index: 0
      });
      if (!created.result) break;
      address_list.unused.push(created.result);
    }

    const fingerprint = JSON.stringify(address_list);
    if (fingerprint === this.address_list_fingerprint) {
      return {};
    }
    this.address_list_fingerprint = fingerprint;

    return {
      info: {
        address: addressData.result.address,
        balance: balanceData.result.balance,
        unlocked_balance: balanceData.result.unlocked_balance
      },
      address_list
    };
  }

  resetTxCache() {
    this.tx_cache = {
      confirmed: [],
      transient: [],
      max_height: 0,
      fingerprint: null,
      loaded: false
    };
    this.address_list_fingerprint = null;
    this.address_book_fingerprint = null;
    this.last_history_refresh_time = 0;
  }

  txKey(tx) {
    const minor = tx.subaddr_index ? tx.subaddr_index.minor : "";
    return `${tx.txid}:${tx.type}:${minor}:${tx.amount}:${tx.height}`;
  }

  sortedTxList() {
    const tx_list = this.tx_cache.transient.concat(this.tx_cache.confirmed);
    tx_list.sort((a, b) => b.timestamp - a.timestamp);
    return tx_list;
  }

  // Transfers are fetched incrementally: after the first full load only
  // transfers at or above (newest confirmed height - 10) are requested, which
  // also absorbs small reorgs. Pending/pool/failed entries are always refetched.
  // Resolves to {} when nothing changed so no data is pushed to the renderer.
  getTransactions({ full = false } = {}) {
    if (full) {
      this.tx_cache.loaded = false;
      this.tx_cache.fingerprint = null;
    }
    const cache = this.tx_cache;
    const minHeight = Math.max(0, cache.max_height - 10);
    const incremental = cache.loaded && minHeight > 0;

    const params = {
      in: true,
      out: true,
      pending: true,
      failed: true,
      pool: true
    };
    if (incremental) {
      params.filter_by_height = true;
      params.min_height = minHeight; // inclusive in wallet2
      params.max_height = 500000000;
    }

    return this.sendRPC("get_transfers", params).then(data => {
      if (data.hasOwnProperty("error") || !data.hasOwnProperty("result")) {
        return {};
      }

      const types = [
        "in",
        "out",
        "pending",
        "failed",
        "pool",
        "miner",
        "mnode",
        "gov",
        "stake",
        "bns"
      ];
      const transientTypes = ["pending", "failed", "pool"];

      const fetched = [];
      types.forEach(type => {
        if (Array.isArray(data.result[type])) {
          fetched.push(...data.result[type]);
        }
      });

      const transient = [];
      const confirmed = new Map();
      if (incremental) {
        for (const tx of cache.confirmed) {
          if (tx.height < minHeight) confirmed.set(this.txKey(tx), tx);
        }
      }
      for (const tx of fetched) {
        if (!tx.height || transientTypes.includes(tx.type)) {
          transient.push(tx);
        } else {
          confirmed.set(this.txKey(tx), tx);
        }
      }

      cache.confirmed = Array.from(confirmed.values());
      cache.transient = transient;
      cache.max_height = cache.confirmed.reduce(
        (max, tx) => (tx.height > max ? tx.height : max),
        0
      );
      cache.loaded = true;

      const fingerprint =
        `${cache.confirmed.length}|` +
        fetched
          .map(tx => `${this.txKey(tx)}:${tx.note || ""}:${tx.confirmations}`)
          .join(",");
      if (fingerprint === cache.fingerprint) {
        return {};
      }
      cache.fingerprint = fingerprint;

      return {
        transactions: {
          tx_list: this.sortedTxList()
        }
      };
    });
  }

  getAddressBook() {
    return new Promise(resolve => {
      this.sendRPC("get_address_book").then(data => {
        if (data.hasOwnProperty("error") || !data.hasOwnProperty("result")) {
          resolve({});
          return;
        }
        let wallet = {
          address_list: {
            address_book: [],
            address_book_starred: []
          }
        };

        const entries = data.result.entries || [];
        const addresses = entries.map(e => {
          const entry = { ...e };
          const desc = entry.description.split("::");
          if (desc.length == 3) {
            entry.starred = desc[0] == "starred";
            entry.name = desc[1];
            entry.description = desc[2];
          } else if (desc.length == 2) {
            entry.starred = false;
            entry.name = desc[0];
            entry.description = desc[1];
          } else {
            entry.starred = false;
            entry.name = entry.description;
            entry.description = "";
          }

          return entry;
        });

        for (const entry of addresses) {
          const list = entry.starred
            ? wallet.address_list.address_book_starred
            : wallet.address_list.address_book;
          const hasAddress = list.find(a => {
            return a.address === entry.address && a.name === entry.name;
          });
          if (!hasAddress) {
            list.push(entry);
          }
        }

        const fingerprint = JSON.stringify(wallet.address_list);
        if (fingerprint === this.address_book_fingerprint) {
          resolve({});
          return;
        }
        this.address_book_fingerprint = fingerprint;
        resolve(wallet);
      });
    });
  }

  deleteAddressBook(index = false) {
    if (index !== false) {
      this.sendRPC("delete_address_book", { index: index }).then(() => {
        this.saveWallet().then(() => {
          this.getAddressBook().then(data => {
            this.sendGateway("set_wallet_data", data);
          });
        });
      });
    }
  }

  addAddressBook(
    address,
    description = "",
    name = "",
    starred = false,
    index = false
  ) {
    if (index !== false) {
      this.sendRPC("delete_address_book", { index: index }).then(() => {
        this.addAddressBook(address, description, name, starred);
      });
      return;
    }

    let params = {
      address
    };

    let desc = [];
    if (starred) {
      desc.push("starred");
    }
    desc.push(name, description);

    params.description = desc.join("::");

    this.sendRPC("add_address_book", params).then(() => {
      this.saveWallet().then(() => {
        this.getAddressBook().then(data => {
          this.sendGateway("set_wallet_data", data);
        });
      });
    });
  }

  saveTxNotes(txid, note) {
    this.sendRPC("set_tx_notes", { txids: [txid], notes: [note] }).then(
      data => {
        if (data.hasOwnProperty("error")) return;
        const cache = this.tx_cache;
        const update = tx => (tx.txid === txid ? { ...tx, note } : tx);
        cache.confirmed = cache.confirmed.map(update);
        cache.transient = cache.transient.map(update);
        cache.fingerprint = null;
        this.sendGateway("set_wallet_data", {
          transactions: { tx_list: this.sortedTxList() }
        });
      }
    );
  }

  set_rightPane_value(val) {
    this.sendGateway("set_router_path_rightpane", val);
  }
  set_sender_address(val) {
    this.sendGateway("set_sender_address", val);
  }

  set_stepperPosition(val) {
    this.sendGateway("set_stepperPosition", val);
  }

  deregisterImages(password) {
    this.derivePasswordHash(password, (err, password_hash) => {
      if (err) {
        this.sendGateway("show_notification", {
          type: "negative",
          i18n: "notification.errors.internalError",
          timeout: 2000
        });
        return;
      }
      if (!this.isValidPasswordHash(password_hash)) {
        this.sendGateway("show_notification", {
          type: "negative",
          i18n: "notification.errors.invalidPassword",
          timeout: 2000
        });
        return;
      }
      this.sendRPC("export_key_images")
        .then(data => {
          if (data.hasOwnProperty("error") || !data.hasOwnProperty("result")) {
            // onError();
            return [];
          }
          if (data.result.signed_key_images) {
            const signed_key_images = data.result.signed_key_images;
            return this.sendGateway("set_daemon_data", { signed_key_images });
            // return data.result.signed_key_images;
          } else {
            return [];
          }
        })
        .catch();
    });
  }
  exportKeyImages(password, filename = null) {
    this.derivePasswordHash(password, (err, password_hash) => {
      if (err) {
        this.sendGateway("show_notification", {
          type: "negative",
          i18n: "notification.errors.internalError",
          timeout: 2000
        });
        return;
      }
      if (!this.isValidPasswordHash(password_hash)) {
        this.sendGateway("show_notification", {
          type: "negative",
          i18n: "notification.errors.invalidPassword",
          timeout: 2000
        });
        return;
      }

      if (filename == null) {
        filename = path.join(
          this.wallet_data_dir,
          "images",
          this.wallet_state.name,
          "key_image_export"
        );
      } else {
        filename = path.join(filename, "key_image_export");
      }

      const onError = () =>
        this.sendGateway("show_notification", {
          type: "negative",
          i18n: "notification.errors.keyImages.exporting",
          timeout: 2000
        });

      this.sendRPC("export_key_images")
        .then(data => {
          if (data.hasOwnProperty("error") || !data.hasOwnProperty("result")) {
            onError();
            return;
          }

          if (data.result.signed_key_images) {
            fs.outputJSONSync(filename, data.result.signed_key_images);
            this.sendGateway("show_notification", {
              i18n: ["notification.positive.keyImages.exported", { filename }],
              timeout: 2000
            });
          } else {
            this.sendGateway("show_notification", {
              type: "warning",
              textColor: "black",
              i18n: "notification.warnings.noKeyImageExport",
              timeout: 2000
            });
          }
        })
        .catch(onError);
    });
  }

  importKeyImages(password, filename = null) {
    this.derivePasswordHash(password, (err, password_hash) => {
      if (err) {
        this.sendGateway("show_notification", {
          type: "negative",
          i18n: "notification.errors.internalError",
          timeout: 2000
        });
        return;
      }
      if (!this.isValidPasswordHash(password_hash)) {
        this.sendGateway("show_notification", {
          type: "negative",
          i18n: "notification.errors.invalidPassword",
          timeout: 2000
        });
        return;
      }

      if (filename == null) {
        filename = path.join(
          this.wallet_data_dir,
          "images",
          this.wallet_state.name,
          "key_image_export"
        );
      }

      const onError = i18n =>
        this.sendGateway("show_notification", {
          type: "negative",
          i18n,
          timeout: 2000
        });

      fs.readJSON(filename)
        .then(signed_key_images => {
          this.sendRPC("import_key_images", {
            signed_key_images
          }).then(data => {
            if (
              data.hasOwnProperty("error") ||
              !data.hasOwnProperty("result")
            ) {
              onError("notification.errors.keyImages.importing");
              return;
            }

            this.sendGateway("show_notification", {
              i18n: "notification.positive.keyImages.imported",
              timeout: 2000
            });
          });
        })
        .catch(() => onError("notification.errors.keyImages.reading"));
    });
  }

  copyOldGuiWallets(wallets) {
    this.sendGateway("set_old_gui_import_status", {
      code: 1,
      failed_wallets: []
    });

    /*
        Old wallets were in the following format:
            wallets:
                <name>:
                    <name>
                    <name>.keys
                    <name>.address.txt

        We need to change it so it becomes:
            wallets:
                <name>
                <name>.keys
                <name>.address.txt
        */

    const failed_wallets = [];

    for (const wallet of wallets) {
      const { type, directory } = wallet;

      const old_gui_path = path.join(this.wallet_dir, "old-gui");
      const dir_path = path.join(this.wallet_dir, directory);
      const stat = fs.statSync(dir_path);
      if (!stat.isDirectory()) continue;

      // Make sure the directory has the keys file
      const wallet_file = path.join(dir_path, directory);
      const key_file = wallet_file + ".keys";

      // If we don't have them then don't bother copying
      if (!fs.existsSync(key_file)) {
        failed_wallets.push(directory);
        continue;
      }

      // Copy out the file into the relevant directory
      const destination = path.join(this.dirs[type], "wallets");
      if (!fs.existsSync(destination)) fs.mkdirpSync(destination);

      try {
        // Don't move file if we already have copied the keys file
        if (fs.existsSync(path.join(destination, directory) + ".keys")) {
          failed_wallets.push(directory);
          continue;
        }

        // Archive the folder
        if (!fs.existsSync(old_gui_path)) fs.mkdirpSync(old_gui_path);
        const archive_path = path.join(old_gui_path, directory);
        fs.moveSync(dir_path, archive_path, { overwrite: true });

        // Copy contents of archived folder into the wallet folder
        fs.copySync(archive_path, this.wallet_dir, { overwrite: true });
      } catch (e) {
        failed_wallets.push(directory);
        continue;
      }
    }

    this.sendGateway("set_old_gui_import_status", {
      code: 0,
      failed_wallets
    });
    this.listWallets();
  }

  async listWallets(legacy = false) {
    let wallets = {
      list: [],
      directories: []
    };
    let walletFiles = [];
    try {
      walletFiles = await fs.promises.readdir(this.wallet_dir, {
        withFileTypes: true
      });
    } catch (e) {
      this.sendGateway("show_notification", {
        type: "negative",
        i18n: "notification.errors.failedWalletRead",
        timeout: 2000
      });
      return;
    }

    const ignored = new Set([
      ".DS_Store",
      ".DS_Store?",
      "._.DS_Store",
      ".Spotlight-V100",
      ".Trashes",
      "ehthumbs.db",
      "Thumbs.db",
      "old-gui"
    ]);
    const exists = file =>
      fs.promises.access(file).then(
        () => true,
        () => false
      );
    const names = new Set(walletFiles.map(f => f.name));

    const results = await Promise.all(
      walletFiles.map(async entry => {
        const filename = entry.name;
        try {
          if (ignored.has(filename)) return null;

          // If it's a directory then check if it's an old gui wallet
          if (entry.isDirectory()) {
            const key_file =
              path.join(this.wallet_dir, filename, filename) + ".keys";
            if (await exists(key_file)) {
              return { directory: filename };
            }
            return null;
          }

          // Exclude all files without a keys extension
          if (path.extname(filename) !== ".keys") return null;

          const wallet_name = path.parse(filename).name;
          if (!wallet_name) return null;

          let wallet_data = {
            name: wallet_name,
            address: null,
            password_protected: null
          };

          if (names.has(wallet_name + ".meta.json")) {
            const meta = await fs.promises.readFile(
              path.join(this.wallet_dir, wallet_name + ".meta.json"),
              "utf8"
            );
            if (meta) {
              const parsed = JSON.parse(meta);
              wallet_data.address = parsed.address;
              wallet_data.password_protected = parsed.password_protected;
            }
          } else if (names.has(wallet_name + ".address.txt")) {
            const address = await fs.promises.readFile(
              path.join(this.wallet_dir, wallet_name + ".address.txt"),
              "utf8"
            );
            if (address) {
              wallet_data.address = address;
            }
          }
          return { wallet: wallet_data };
        } catch (e) {
          // Something went wrong
          return null;
        }
      })
    );

    for (const result of results) {
      if (!result) continue;
      if (result.directory) wallets.directories.push(result.directory);
      if (result.wallet) wallets.list.push(result.wallet);
    }

    // Check for legacy wallet files
    if (legacy) {
      wallets.legacy = [];
      let legacy_paths = [];
      if (os.platform() == "win32") {
        legacy_paths = ["C:\\ProgramData\\Beldex"];
      } else {
        legacy_paths = [path.join(os.homedir(), "Beldex")];
      }
      for (var i = 0; i < legacy_paths.length; i++) {
        try {
          let legacy_config_path = path.join(
            legacy_paths[i],
            "config",
            "wallet_info.json"
          );
          if (this.net_type === "test") {
            legacy_config_path = path.join(
              legacy_paths[i],
              "testnet",
              "config",
              "wallet_info.json"
            );
          }
          if (!fs.existsSync(legacy_config_path)) {
            continue;
          }

          let legacy_config = JSON.parse(
            fs.readFileSync(legacy_config_path, "utf8")
          );
          let legacy_wallet_path = legacy_config.wallet_filepath;
          if (!fs.existsSync(legacy_wallet_path)) {
            continue;
          }

          let legacy_address = "";
          if (fs.existsSync(legacy_wallet_path + ".address.txt")) {
            legacy_address = fs.readFileSync(
              legacy_wallet_path + ".address.txt",
              "utf8"
            );
          }
          wallets.legacy.push({
            path: legacy_wallet_path,
            address: legacy_address
          });
        } catch (e) {
          // Something went wrong
        }
      }
    }

    this.sendGateway("wallet_list", wallets);
  }

  changeWalletPassword(old_password, new_password) {
    this.derivePasswordHash(old_password, (err, password_hash) => {
      if (err) {
        this.sendGateway("show_notification", {
          type: "negative",
          i18n: "notification.errors.internalError",
          timeout: 2000
        });
        return;
      }
      if (!this.isValidPasswordHash(password_hash)) {
        this.sendGateway("show_notification", {
          type: "negative",
          i18n: "notification.errors.invalidOldPassword",
          timeout: 2000
        });
        return;
      }

      this.sendRPC("change_wallet_password", {
        old_password,
        new_password
      }).then(async data => {
        if (data.hasOwnProperty("error") || !data.hasOwnProperty("result")) {
          this.sendGateway("show_notification", {
            type: "negative",
            i18n: "notification.errors.changingPassword",
            timeout: 2000
          });
          return;
        }

        // store hash of the password so we can check against it later when requesting private keys, or for sending txs
        this.wallet_state.password_hash = await this.derivePasswordHashHex(
          new_password
        );

        this.sendGateway("show_notification", {
          i18n: "notification.positive.passwordUpdated",
          timeout: 2000
        });
      });
    });
  }

  deleteWallet(password) {
    this.derivePasswordHash(password, (err, password_hash) => {
      if (err) {
        this.sendGateway("show_notification", {
          type: "negative",
          i18n: "notification.errors.internalError",
          timeout: 2000
        });
        return;
      }
      if (!this.isValidPasswordHash(password_hash)) {
        this.sendGateway("show_notification", {
          type: "negative",
          i18n: "notification.errors.invalidPassword",
          timeout: 2000
        });
        return;
      }

      this.sendGateway("show_loading", {
        message: "Deleting wallet"
      });

      let wallet_path = path.join(this.wallet_dir, this.wallet_state.name);
      this.closeWallet().then(() => {
        try {
          if (fs.existsSync(wallet_path + ".keys"))
            fs.unlinkSync(wallet_path + ".keys");
          if (fs.existsSync(wallet_path + ".address.txt"))
            fs.unlinkSync(wallet_path + ".address.txt");
          if (fs.existsSync(wallet_path)) fs.unlinkSync(wallet_path);
        } catch (e) {
          console.warn(`Failed to delete wallet files: ${e}`);
        }

        this.listWallets();
        this.sendGateway("hide_loading");
        this.sendGateway("return_to_wallet_select");
      });
    });
  }

  async saveWallet() {
    await this.sendRPC("store");
  }

  async closeWallet() {
    await this.stopSync();
    clearInterval(this.heartbeat);
    clearInterval(this.bnsHeartbeat);
    this.wallet_state = {
      open: false,
      name: "",
      password_hash: null,
      balance: null,
      unlocked_balance: null,
      height: 0,
      address: "",
      bnsRecords: [],
      view_only: false
    };

    this.purchasedNames = {};
    this.resetTxCache();
    this.history_refresh_pending = false;
    this.caughtUp = false;
    this.rescanFrom = null;

    await this.sendRPC("close_wallet", { autosave_current: true });
  }

  sendGateway(method, data) {
    // if wallet is closed, do not send any wallet data to gateway
    // this is for the case that we close the wallet at the same
    // after another action has started, but before it has finished
    if (!this.wallet_state.open && method == "set_wallet_data") {
      return;
    }
    this.backend.send(method, data);
  }

  // Background callers (BNS refreshes) pass { background: true }: they wait
  // for the current scan chunk instead of ending it.
  sendRPC(method, params = {}, timeout = 0, { background = false } = {}) {
    // A scan holds wallet-rpc's only request thread: end the current chunk so
    // this call is answered now (the sync loop then carries on).
    if (this.refreshing && !background && method !== "refresh" && this.proxy) {
      this.proxy.pause();
    }
    // Opening, creating or closing a wallet ends the current wallet's sync
    // loop (the new wallet starts its own)
    if (WALLET_SWITCH_METHODS.has(method)) {
      this.syncGeneration++;
      this.wakeSync();
    }
    let id = this.id++;
    const url = `${this.protocol}${this.hostname}:${this.port}/json_rpc`;
    let payload = {
      jsonrpc: "2.0",
      id: `${id}`,
      method: method
    };
    if (Object.keys(params).length !== 0) {
      payload.params = params;
    }

    let options = {
      url,
      method: "POST",
      data: payload,
      auth: {
        username: this.auth[0],
        password: this.auth[1]
      },
      httpAgent: this.agent
    };
    if (timeout > 0) {
      options.timeout = timeout;
    }

    return this.queue.add(() => {
      return axios(options)
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
              message: "Cannot connect to wallet-rpc",
              cause: error.cause || error
            }
          };
        });
    });
  }

  getRPC(parameter, params = {}) {
    return this.sendRPC(`get_${parameter}`, params);
  }

  async quit() {
    const proc = this.walletRPCProcess;
    if (proc && proc.exitCode === null) {
      const exited = new Promise(resolve => proc.once("close", resolve));
      const wait = ms =>
        new Promise(resolve => setTimeout(resolve, ms, "timeout"));
      // Ends a running scan and saves the wallet (see syncLoop)
      await Promise.race([this.closeWallet().catch(() => {}), wait(20000)]);
      // wallet-rpc only exits once idle keep-alive connections are gone
      this.agent.destroy();
      this.agent = new http.Agent({ keepAlive: false });
      this.sendRPC("stop_wallet", {}, 5000);
      if ((await Promise.race([exited, wait(10000)])) === "timeout") {
        proc.kill("SIGTERM");
        if ((await Promise.race([exited, wait(5000)])) === "timeout") {
          proc.kill("SIGKILL");
        }
      }
    }
    this.agent.destroy();
    if (this.proxy) await this.proxy.close();
  }
}
