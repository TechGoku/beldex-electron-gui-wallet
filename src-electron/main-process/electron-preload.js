const crypto = require("crypto");
const {
  clipboard,
  contextBridge,
  ipcRenderer,
  nativeImage,
  shell,
  webUtils
} = require("electron");

function cleanArgsForIPC(args) {
  const redactKeyPattern = /(password|seed|mnemonic|secret|spend[_-]?key|view[_-]?key|private[_-]?key|auth|token)/i;
  const redactValue = item => {
    if (Array.isArray(item)) {
      return item.map(redactValue);
    }

    if (item && typeof item === "object") {
      return Object.keys(item).reduce((result, key) => {
        result[key] = redactKeyPattern.test(key)
          ? "[REDACTED]"
          : redactValue(item[key]);
        return result;
      }, {});
    }

    return item;
  };

  return args
    .map(item => {
      if (typeof item !== "string") {
        try {
          return JSON.stringify(redactValue(item));
        } catch (error) {
          return item;
        }
      }

      return redactKeyPattern.test(item) ? "[REDACTED]" : item;
    })
    .join(" ");
}

function now() {
  return new Date().toJSON();
}

function installRendererLogging() {
  if (typeof window === "undefined") {
    return;
  }

  function logAtLevel(level, prefix, ...args) {
    const fn = `_${level}`;
    if (typeof console[fn] === "function") {
      console[fn](prefix, now(), ...args);
    }

    ipcRenderer.send(`log-${level}`, cleanArgsForIPC(args));
  }

  function log(...args) {
    logAtLevel("info", "INFO ", ...args);
  }

  if (window.console) {
    console._log = console.log;
    console.log = log;
    console._trace = console.trace;
    console._debug = console.debug;
    console._info = console.info;
    console._warn = console.warn;
    console._error = console.error;
    console._fatal = console.error;
  }

  window.log = {
    fatal: (...args) => logAtLevel("fatal", "FATAL", ...args),
    error: (...args) => logAtLevel("error", "ERROR", ...args),
    warn: (...args) => logAtLevel("warn", "WARN ", ...args),
    info: (...args) => logAtLevel("info", "INFO ", ...args),
    debug: (...args) => logAtLevel("debug", "DEBUG", ...args),
    trace: (...args) => logAtLevel("trace", "TRACE", ...args)
  };

  window.onerror = (message, script, line, col, error) => {
    const errorInfo =
      error && error.stack ? error.stack : JSON.stringify(error);
    window.log.error(`Top-level unhandled error: ${errorInfo}`);
  };

  window.addEventListener("unhandledrejection", rejectionEvent => {
    const error = rejectionEvent.reason;
    const errorInfo = error && error.stack ? error.stack : error;
    window.log.error("Top-level unhandled promise rejection:", errorInfo);
  });
}

installRendererLogging();

// Keep in sync with src-electron/main-process/modules/SCEE-Node.js.
// The key is derived once per token (HKDF) and cached; each frame is
// base64(nonce[12] | ciphertext | tag[16]) under AES-256-GCM.
class SCEE {
  constructor() {
    this.algorithmName = "aes-256-gcm";
    this.algorithmNonceSize = 12;
    this.algorithmTagSize = 16;
    this.algorithmKeySize = 32;
    this.hkdfDigest = "sha256";
    this.hkdfSalt = "beldex-electron-wallet/ws/v2";
    this.hkdfInfo = "aes-256-gcm";
    this.keys = new Map();
  }

  getKey(password) {
    let key = this.keys.get(password);
    if (!key) {
      key = Buffer.from(
        crypto.hkdfSync(
          this.hkdfDigest,
          Buffer.from(password, "utf8"),
          Buffer.from(this.hkdfSalt, "utf8"),
          Buffer.from(this.hkdfInfo, "utf8"),
          this.algorithmKeySize
        )
      );
      if (this.keys.size >= 4) {
        this.keys.delete(this.keys.keys().next().value);
      }
      this.keys.set(password, key);
    }
    return key;
  }

  encryptString(plaintext, password) {
    const key = this.getKey(password);
    const nonce = crypto.randomBytes(this.algorithmNonceSize);
    const cipher = crypto.createCipheriv(this.algorithmName, key, nonce);
    const ciphertext = Buffer.concat([
      cipher.update(plaintext, "utf8"),
      cipher.final()
    ]);
    return Buffer.concat([nonce, ciphertext, cipher.getAuthTag()]).toString(
      "base64"
    );
  }

  decryptString(base64Frame, password) {
    const key = this.getKey(password);
    const frame = Buffer.from(base64Frame, "base64");
    if (frame.length < this.algorithmNonceSize + this.algorithmTagSize) {
      throw new Error("Encrypted frame too short");
    }
    const nonce = frame.subarray(0, this.algorithmNonceSize);
    const tag = frame.subarray(frame.length - this.algorithmTagSize);
    const ciphertext = frame.subarray(
      this.algorithmNonceSize,
      frame.length - this.algorithmTagSize
    );
    const decipher = crypto.createDecipheriv(this.algorithmName, key, nonce);
    decipher.setAuthTag(tag);
    return Buffer.concat([
      decipher.update(ciphertext),
      decipher.final()
    ]).toString("utf8");
  }
}

const scee = new SCEE();

const electronAPI = {
  clipboard: {
    writeText: text => clipboard.writeText(text),
    writeImageFromDataUrl: dataUrl => {
      const image = nativeImage.createFromDataURL(dataUrl);
      clipboard.writeImage(image);
    }
  },
  ipc: {
    allowedSendChannels: new Set(["confirmClose"]),
    allowedReceiveChannels: new Set([
      "initialize",
      "confirmClose",
      "showQuitScreen",
      "appSuspend",
      "appResumed"
    ]),
    on: (channel, listener) => {
      if (!electronAPI.ipc.allowedReceiveChannels.has(channel)) {
        return () => {};
      }

      const wrappedListener = (_, data) => listener(data);
      ipcRenderer.on(channel, wrappedListener);
      return () => ipcRenderer.removeListener(channel, wrappedListener);
    },
    send: (channel, ...args) => {
      if (electronAPI.ipc.allowedSendChannels.has(channel)) {
        ipcRenderer.send(channel, ...args);
      }
    }
  },
  secureCrypto: {
    encryptString: (plaintext, password) =>
      scee.encryptString(plaintext, password),
    decryptString: (ciphertext, password) =>
      scee.decryptString(ciphertext, password)
  },
  shell: {
    openExternal: url => shell.openExternal(url)
  },
  dialog: {
    selectDirectory: defaultPath =>
      ipcRenderer.invoke("select-directory", defaultPath || "")
  },
  // File.path was removed in Electron 32; this is the supported replacement.
  files: {
    getPathForFile: file => {
      try {
        return webUtils.getPathForFile(file) || "";
      } catch (error) {
        return "";
      }
    }
  }
};

if (process.contextIsolated) {
  contextBridge.exposeInMainWorld("electronAPI", electronAPI);
} else if (typeof window !== "undefined") {
  window.electronAPI = electronAPI;
}
